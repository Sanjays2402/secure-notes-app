"""POST /notes — create a note under envelope encryption.

Request body (JSON):
    {"title": str, "body": str, "tags": [str] (optional), "expiresAt": str|int (optional)}
Response (201):      {"noteId": str}

Optional fields:
  * tags — up to 10 short labels, stored as PLAINTEXT metadata (DynamoDB
    String Set) so the list endpoint can filter server-side. Title and body
    stay inside the encrypted payload; tags are searchable by design, so
    never put secrets in them. Normalized to lowercase, deduplicated.
  * expiresAt — ISO-8601 timestamp or epoch seconds, must be in the future.
    Stored as epoch seconds in the `expiresAt` attribute, which is the
    table's DynamoDB TTL attribute: expired notes vanish automatically.

Security posture: the note body is NEVER logged. Logs carry only the noteId
and byte counts, so a leaked log stream reveals nothing about content.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import re
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
MAX_TAGS = 10
MAX_TAG_CHARS = 50
# Tags are plaintext metadata: letters, digits, spaces, hyphens, underscores.
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9 _-]*")


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


def _parse_tags(value) -> set:
    """Validate optional tags; returns a normalized (lowercase) set."""
    if value is None:
        return set()
    if not isinstance(value, list):
        raise ValueError("tags must be an array of strings")
    if len(value) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags per note")
    tags = set()
    for tag in value:
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError("tags must be non-empty strings")
        norm = tag.strip().lower()
        if len(norm) > MAX_TAG_CHARS:
            raise ValueError(f"each tag must be at most {MAX_TAG_CHARS} characters")
        if not _TAG_RE.fullmatch(norm):
            raise ValueError(
                f"invalid tag {tag!r}: use letters, digits, spaces, hyphens, underscores"
            )
        tags.add(norm)
    return tags


def _parse_expiry(value):
    """Validate optional expiry; returns epoch seconds or None.

    Accepts ISO-8601 strings (naive assumed UTC) or epoch seconds. Must be in
    the future — DynamoDB TTL deletes the item once this time passes.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("expiresAt must be ISO-8601 or epoch seconds")
    if isinstance(value, (int, float)):
        epoch = int(value)
    elif isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("expiresAt must be ISO-8601 or epoch seconds")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        epoch = int(parsed.timestamp())
    else:
        raise ValueError("expiresAt must be ISO-8601 or epoch seconds")
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    if epoch <= now:
        raise ValueError("expiresAt must be in the future")
    return epoch


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

    try:
        tags = _parse_tags(data.get("tags"))
        expires_at = _parse_expiry(data.get("expiresAt"))
    except ValueError as exc:
        return _bad_request(str(exc))

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
    if tags:
        # Plaintext String Set BY DESIGN: tags exist so the list endpoint can
        # filter server-side without decrypting. Users must not put secrets
        # in tags; title/body stay inside the encrypted payload.
        item["tags"] = tags
    if expires_at is not None:
        # DynamoDB TTL attribute (Number, epoch seconds): the table's TTL
        # spec deletes the item automatically once this time passes.
        item["expiresAt"] = expires_at

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
