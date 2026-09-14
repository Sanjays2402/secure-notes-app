"""GET /notes/{id} — fetch a note and decrypt it via KMS.

Response (200):
    {"noteId": str, "title": str, "body": str, "createdAt": str,
     "tags": [str], "expiresAt": str | null}
Response (404): {"error": "not found"}

The plaintext body is returned to the caller (that's the point of the app)
but is NEVER written to logs — only the noteId is logged.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from common.crypto import decrypt_note, EnvelopeError

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE_NAME = os.environ.get("NOTES_TABLE_NAME", "")

kms = boto3.client("kms")
dynamodb = boto3.resource("dynamodb")


def _response(status: int, payload: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(payload),
    }


def lambda_handler(event: dict, context) -> dict:
    note_id = (event.get("pathParameters") or {}).get("id")
    if not note_id:
        return _response(400, {"error": "note id is required"})

    table = dynamodb.Table(TABLE_NAME)
    try:
        result = table.get_item(Key={"noteId": note_id})
    except ClientError:
        logger.exception("DynamoDB get_item failed for note %s", note_id)
        return _response(500, {"error": "could not read note"})

    item = result.get("Item")
    if not item:
        return _response(404, {"error": "not found"})

    try:
        payload = decrypt_note(kms, item["encryptedDataKey"], item["ciphertext"])
    except (EnvelopeError, KeyError) as exc:
        # KeyError: stored item is malformed. Either way: generic 500, and the
        # log line carries the noteId only — never key material or plaintext.
        logger.exception("decryption failed for note %s: %s", note_id, type(exc).__name__)
        return _response(500, {"error": "could not decrypt note"})

    logger.info("note retrieved: id=%s", note_id)
    expires = item.get("expiresAt")
    return _response(
        200,
        {
            "noteId": note_id,
            "title": payload.get("title", ""),
            "body": payload.get("body", ""),
            "createdAt": item.get("createdAt", ""),
            # Plaintext metadata (tags were stored unencrypted by design).
            "tags": sorted({str(t) for t in item.get("tags", set())}),
            "expiresAt": (
                dt.datetime.fromtimestamp(expires, dt.timezone.utc).isoformat()
                if isinstance(expires, (int, float)) else None
            ),
        },
    )
