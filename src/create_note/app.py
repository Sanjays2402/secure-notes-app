"""POST /notes — create a note under envelope encryption.

Request body (JSON): {"title": str, "body": str}
Response (201):      {"noteId": str}

Security posture: the note body is NEVER logged. Logs carry only the noteId
and byte counts, so a leaked log stream reveals nothing about content.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import uuid

import boto3
from botocore.exceptions import ClientError

from common.crypto import encrypt_note, EnvelopeError

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE_NAME = os.environ.get("NOTES_TABLE_NAME", "")
KMS_KEY_ID = os.environ.get("KMS_KEY_ID", "")

kms = boto3.client("kms")
dynamodb = boto3.resource("dynamodb")

MAX_TITLE_CHARS = 200
# 100k chars keeps the base64'd ciphertext (~133 KB) far under DynamoDB's
# 400 KB item limit, even for multi-byte UTF-8.
MAX_BODY_CHARS = 100_000


def _bad_request(message: str, status: int = 400) -> dict:
    return {
        "statusCode": status,
        "headers": _cors_headers(),
        "body": json.dumps({"error": message}),
    }


def _cors_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }


def _parse_body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("request body must be valid JSON")
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    return data


def lambda_handler(event: dict, context) -> dict:
    try:
        data = _parse_body(event)
    except ValueError as exc:
        return _bad_request(str(exc))

    title = data.get("title")
    body = data.get("body")

    if not isinstance(title, str) or not title.strip():
        return _bad_request("title is required and must be a non-empty string")
    if not isinstance(body, str) or not body:
        return _bad_request("body is required and must be a non-empty string")
    if len(title) > MAX_TITLE_CHARS:
        return _bad_request(f"title must be at most {MAX_TITLE_CHARS} characters", 413)
    if len(body) > MAX_BODY_CHARS:
        return _bad_request(f"body must be at most {MAX_BODY_CHARS} characters", 413)

    note_id = uuid.uuid4().hex
    payload = {"title": title.strip(), "body": body}

    try:
        envelope = encrypt_note(kms, KMS_KEY_ID, payload)
    except EnvelopeError as exc:
        # Log the failure class, never the content that failed.
        logger.exception("envelope encryption failed for note %s", note_id)
        return _bad_request("could not encrypt note", 500)

    item = {
        "noteId": note_id,
        "ciphertext": envelope["ciphertext"],
        "encryptedDataKey": envelope["encrypted_data_key"],
        "kmsKeyId": envelope["kms_key_id"],
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "schemaVersion": envelope["schema_version"],
        # Ciphertext length only — enough for debugging, reveals nothing.
        "ciphertextBytes": len(envelope["ciphertext"]),
    }

    table = dynamodb.Table(TABLE_NAME)
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(noteId)")
    except ClientError:
        logger.exception("DynamoDB put_item failed for note %s", note_id)
        return _bad_request("could not store note", 500)

    logger.info("note created: id=%s ciphertext_bytes=%d", note_id, item["ciphertextBytes"])
    return {
        "statusCode": 201,
        "headers": _cors_headers(),
        "body": json.dumps({"noteId": note_id}),
    }
