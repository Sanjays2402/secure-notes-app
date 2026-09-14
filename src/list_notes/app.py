"""GET /notes — list note METADATA with server-side tag/search filtering.

Query params:
    q         substring match over tags (case-insensitive), e.g. ?q=fin
    tag       exact tag match, e.g. ?tag=finance
    limit     1..100, default 25
    nextToken opaque page cursor from a previous response

Response (200):
    {"notes": [{"noteId","createdAt","tags","expiresAt","ciphertextBytes"}],
     "count": n, "nextToken": str | null}

SECURITY: this endpoint NEVER decrypts. Titles and bodies live inside the
envelope-encrypted payload; only plaintext metadata (tags, timestamps) is
returned. The list role is granted dynamodb:Scan only — no KMS permissions
at all — so even a compromised list Lambda cannot read note contents.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE_NAME = os.environ.get("NOTES_TABLE_NAME", "")

dynamodb = boto3.resource("dynamodb")

DEFAULT_LIMIT = 25
MAX_LIMIT = 100
# Safety cap on how many raw items one request will scan while filtering
# (personal-notes scale; DynamoDB FilterExpression would scale further).
MAX_SCAN_ITEMS = 2_000


def _response(status: int, payload: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(payload),
    }


def _parse_params(params: dict | None):
    params = params or {}
    tag = params.get("tag")
    if tag is not None and (not isinstance(tag, str) or not tag.strip()):
        raise ValueError("tag must be a non-empty string")
    q = params.get("q")
    if q is not None and not isinstance(q, str):
        raise ValueError("q must be a string")

    limit_raw = params.get("limit", DEFAULT_LIMIT)
    try:
        limit = int(limit_raw)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")

    token = params.get("nextToken")
    start_key = None
    if token:
        try:
            note_id = base64.urlsafe_b64decode(token.encode()).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            raise ValueError("nextToken is invalid")
        start_key = {"noteId": note_id}

    return (tag.strip().lower() if tag else None,
            q.strip().lower() if q else None, limit, start_key)


def _matches(item: dict, tag: str | None, q: str | None) -> bool:
    tags = {t.lower() for t in item.get("tags", set())}
    if tag is not None and tag not in tags:
        return False
    if q and not any(q in t for t in tags):
        return False
    return True


def _public_item(item: dict) -> dict:
    """Project one DynamoDB item to its safe metadata shape.

    Deliberately excludes ciphertext, encryptedDataKey, kmsKeyId — and of
    course never touches the encrypted payload, so nothing is decrypted here.
    """
    expires = item.get("expiresAt")
    return {
        "noteId": item["noteId"],
        "createdAt": item.get("createdAt", ""),
        "tags": sorted({str(t) for t in item.get("tags", set())}),
        "expiresAt": (
            dt.datetime.fromtimestamp(expires, dt.timezone.utc).isoformat()
            if isinstance(expires, (int, float)) else None
        ),
        "ciphertextBytes": item.get("ciphertextBytes", 0),
    }


def _encode_token(note_id: str) -> str:
    return base64.urlsafe_b64encode(note_id.encode()).decode()


def lambda_handler(event: dict, context) -> dict:
    try:
        tag, q, limit, start_key = _parse_params(event.get("queryStringParameters"))
    except ValueError as exc:
        return _response(400, {"error": str(exc)})

    table = dynamodb.Table(TABLE_NAME)
    matched: list[dict] = []
    scanned = 0
    exclusive_start = start_key
    next_token = None

    try:
        while scanned < MAX_SCAN_ITEMS:
            kwargs = {"Limit": min(500, MAX_SCAN_ITEMS - scanned)}
            if exclusive_start:
                kwargs["ExclusiveStartKey"] = exclusive_start
            page = table.scan(**kwargs)
            items = page.get("Items", [])
            scanned += page.get("Count", len(items))
            for item in items:
                if _matches(item, tag, q):
                    matched.append(item)
                    if len(matched) == limit:
                        # Resume the NEXT request from this exact item so the
                        # unscanned tail of this page is not skipped.
                        next_token = _encode_token(item["noteId"])
                        break
            else:
                exclusive_start = page.get("LastEvaluatedKey")
                if not exclusive_start:
                    break  # table exhausted
                continue
            break
    except ClientError:
        logger.exception("DynamoDB scan failed")
        return _response(500, {"error": "could not list notes"})

    # Newest first; ISO-8601 sorts lexicographically.
    matched.sort(key=lambda i: i.get("createdAt", ""), reverse=True)

    logger.info("notes listed: matched=%d scanned=%d tag=%s q=%s",
                len(matched), scanned, tag, bool(q))
    return _response(200, {
        "notes": [_public_item(i) for i in matched],
        "count": len(matched),
        "nextToken": next_token,
    })
