"""DELETE /notes/{id} — delete a note.

Response (204): empty body, note removed.
Response (400): {"error": "note id is required"}
Response (404): {"error": "not found"} — idempotent in effect: deleting a
    note that does not exist reports "not found" instead of silently 204 so
    clients can tell a typo'd id apart from a real delete.
Response (500): {"error": ...} — DynamoDB failure.

Deletion never touches KMS: the stored item holds only ciphertext plus the
wrapped data key, so destroying it requires no decryption. The Lambda role
consequently gets dynamodb:DeleteItem and zero KMS permissions.

Only the noteId is ever logged — no note contents flow through here at all.
"""

from __future__ import annotations

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE_NAME = os.environ.get("NOTES_TABLE_NAME", "")

dynamodb = boto3.resource("dynamodb")


def _response(status: int, payload: dict | None = None) -> dict:
    resp = {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(payload) if payload is not None else "",
    }
    return resp


def lambda_handler(event: dict, context) -> dict:
    note_id = (event.get("pathParameters") or {}).get("id")
    if not note_id:
        return _response(400, {"error": "note id is required"})

    table = dynamodb.Table(TABLE_NAME)
    try:
        table.delete_item(
            Key={"noteId": note_id},
            ConditionExpression="attribute_exists(noteId)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return _response(404, {"error": "not found"})
        logger.exception("DynamoDB delete_item failed for note %s", note_id)
        return _response(500, {"error": "could not delete note"})

    logger.info("note deleted: id=%s", note_id)
    return _response(204)
