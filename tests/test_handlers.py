"""Handler tests — mocked KMS + DynamoDB, real crypto + real validation."""

import base64
import json
import logging

import pytest

from create_note import app as create_app
from get_note import app as get_app
from conftest import fake_table, reset_fakes

SECRET = "the-secret-body-must-never-appear-in-logs-9f8e7d"


@pytest.fixture(autouse=True)
def _clean():
    reset_fakes()
    yield


def _event(body=None, raw=None, b64=False, path_id=None):
    if raw is None:
        raw = json.dumps(body) if body is not None else ""
    if b64:
        raw = base64.b64encode(raw.encode()).decode()
    return {
        "body": raw,
        "isBase64Encoded": b64,
        "pathParameters": {"id": path_id} if path_id else None,
        "requestContext": {"http": {"method": "POST"}},
    }


def _create(title="t", body=SECRET):
    resp = create_app.lambda_handler(_event({"title": title, "body": body}), None)
    assert resp["statusCode"] == 201, resp["body"]
    return json.loads(resp["body"])["noteId"]


# --- create ---------------------------------------------------------------

def test_create_happy_path():
    note_id = _create()
    item = fake_table().items[note_id]
    assert item["kmsKeyId"].endswith("test-key-id")
    assert item["schemaVersion"] == 1
    assert "createdAt" in item
    # Nothing resembling plaintext survives in storage.
    blob = json.dumps(item)
    assert SECRET not in blob
    assert "the-secret" not in blob


def test_create_base64_encoded_event():
    raw = json.dumps({"title": "t", "body": SECRET})
    resp = create_app.lambda_handler(_event(raw=raw, b64=True), None)
    assert resp["statusCode"] == 201


@pytest.mark.parametrize("body", [
    None,
    {"title": "only-title"},
    {"body": "only-body"},
    {"title": "", "body": "x"},
    {"title": "x", "body": ""},
    {"title": 123, "body": "x"},
    "not-a-dict",
    None,
])
def test_create_rejects_bad_input(body):
    # None body -> empty event body -> invalid JSON -> 400
    resp = create_app.lambda_handler(_event(body), None)
    assert resp["statusCode"] == 400
    assert "error" in json.loads(resp["body"])


def test_create_rejects_garbage_json():
    resp = create_app.lambda_handler(_event(raw="{not json"), None)
    assert resp["statusCode"] == 400


def test_create_rejects_oversized_title():
    resp = create_app.lambda_handler(_event({"title": "x" * 201, "body": "b"}), None)
    assert resp["statusCode"] == 413


def test_create_rejects_oversized_body():
    resp = create_app.lambda_handler(
        _event({"title": "t", "body": "x" * 100_001}), None)
    assert resp["statusCode"] == 413


def test_create_never_logs_plaintext(caplog):
    with caplog.at_level(logging.INFO):
        _create(title="some title", body=SECRET)
    assert SECRET not in caplog.text
    # …but the note id IS logged (operational visibility without content).
    assert "note created" in caplog.text


# --- get ------------------------------------------------------------------

def test_create_then_get_round_trip():
    note_id = _create(title="my title", body=SECRET)
    resp = get_app.lambda_handler(_event(path_id=note_id), None)
    assert resp["statusCode"] == 200
    data = json.loads(resp["body"])
    assert data["noteId"] == note_id
    assert data["title"] == "my title"
    assert data["body"] == SECRET
    assert data["createdAt"]


def test_get_unknown_id_404():
    resp = get_app.lambda_handler(_event(path_id="nope-not-real"), None)
    assert resp["statusCode"] == 404
    assert json.loads(resp["body"])["error"] == "not found"


def test_get_missing_id_400():
    resp = get_app.lambda_handler(_event(), None)
    assert resp["statusCode"] == 400


def test_get_corrupted_ciphertext_500_without_leak():
    note_id = _create()
    item = fake_table().items[note_id]
    raw = bytearray(base64.b64decode(item["ciphertext"]))
    raw[10] ^= 0xFF
    item["ciphertext"] = base64.b64encode(bytes(raw)).decode()

    resp = get_app.lambda_handler(_event(path_id=note_id), None)
    assert resp["statusCode"] == 500
    assert SECRET not in resp["body"]


def test_get_malformed_item_500_without_leak(caplog):
    fake_table().items["broken"] = {"noteId": "broken"}  # no crypto fields
    with caplog.at_level(logging.INFO):
        resp = get_app.lambda_handler(_event(path_id="broken"), None)
    assert resp["statusCode"] == 500
    assert "could not decrypt" in resp["body"]
    assert SECRET not in caplog.text


def test_get_never_logs_plaintext(caplog):
    note_id = _create(body=SECRET)
    with caplog.at_level(logging.INFO):
        get_app.lambda_handler(_event(path_id=note_id), None)
    assert SECRET not in caplog.text
    assert "note retrieved" in caplog.text


def test_responses_carry_cors_headers():
    resp = get_app.lambda_handler(_event(path_id="missing"), None)
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
    resp = create_app.lambda_handler(_event({"title": "t", "body": "b"}), None)
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
