"""List-endpoint tests — mocked DynamoDB, real filtering/sorting/pagination."""

import json

import pytest

from create_note import app as create_app
from list_notes import app as list_app
from conftest import fake_kms, fake_table, reset_fakes


@pytest.fixture(autouse=True)
def _clean():
    reset_fakes()
    yield


def _event(params=None):
    return {"queryStringParameters": params}


def _create(title="t", body="b", **kwargs):
    payload = {"title": title, "body": body}
    payload.update(kwargs)
    resp = create_app.lambda_handler(
        {"body": json.dumps(payload), "isBase64Encoded": False}, None)
    assert resp["statusCode"] == 201, resp["body"]
    return json.loads(resp["body"])["noteId"]


def _list(params=None):
    resp = list_app.lambda_handler(_event(params), None)
    return resp, json.loads(resp["body"])


# --- metadata-only, never decrypts ----------------------------------------

def test_empty_list():
    resp, data = _list()
    assert resp["statusCode"] == 200
    assert data == {"notes": [], "count": 0, "nextToken": None}


def test_list_returns_metadata_only():
    _create(title="secret title", body="secret body", tags=["Finance"])
    _create(title="t2", body="b2")
    resp, data = _list()
    assert resp["statusCode"] == 200
    assert data["count"] == 2
    for note in data["notes"]:
        assert set(note) == {"noteId", "createdAt", "tags",
                             "expiresAt", "ciphertextBytes"}
        assert note["tags"] in (["finance"], [])
    blob = json.dumps(data)
    assert "secret title" not in blob and "secret body" not in blob


def test_list_never_touches_kms():
    _create(tags=["a"])
    _create(tags=["b"])
    _list()
    _list({"tag": "a"})
    assert fake_kms().decrypt_calls == 0
    assert fake_kms().generate_calls == 2  # create path still mints keys


def test_newest_first():
    ids = [_create(title=f"t{i}") for i in range(3)]
    # Force distinct, ordered timestamps (ISO-8601 sorts lexicographically).
    table = fake_table()
    for i, nid in enumerate(ids):
        table.items[nid]["createdAt"] = f"2026-09-14T00:00:0{i}Z"
    _, data = _list()
    assert [n["noteId"] for n in data["notes"]] == ids[::-1]


# --- filtering -------------------------------------------------------------

def test_tag_exact_match():
    _create(tags=["finance", "taxes"])
    _create(tags=["recipes"])
    _create()  # untagged
    _, data = _list({"tag": "finance"})
    assert data["count"] == 1
    assert data["notes"][0]["tags"] == ["finance", "taxes"]
    _, data = _list({"tag": "FINANCE"})  # case-insensitive
    assert data["count"] == 1
    _, data = _list({"tag": "nope"})
    assert data["count"] == 0


def test_q_substring_over_tags():
    _create(tags=["finance"])
    _create(tags=["financial-planning"])
    _create(tags=["recipes"])
    _, data = _list({"q": "fin"})
    assert data["count"] == 2
    _, data = _list({"q": "REC"})  # case-insensitive
    assert data["count"] == 1


def test_q_never_matches_title_or_body():
    _create(title="finance report", body="about money")
    _, data = _list({"q": "finance"})
    # Titles/bodies are encrypted; only tags are searchable by design.
    assert data["count"] == 0


def test_tag_and_q_combine():
    _create(tags=["finance", "2026"])
    _create(tags=["finance"])
    _, data = _list({"tag": "finance", "q": "202"})
    assert data["count"] == 1


# --- pagination ------------------------------------------------------------

def test_limit_and_next_token_paginate():
    ids = {_create(title=f"t{i}") for i in range(5)}
    seen, token, pages = set(), None, 0
    while True:
        params = {"limit": "2"}
        if token:
            params["nextToken"] = token
        resp, data = _list(params)
        assert resp["statusCode"] == 200
        pages += 1
        for note in data["notes"]:
            assert note["noteId"] not in seen  # no duplicates across pages
            seen.add(note["noteId"])
        token = data["nextToken"]
        if not token:
            break
        assert pages < 10, "pagination did not terminate"
    assert seen == ids


def test_last_page_has_no_next_token():
    _create()
    _create()
    _, data = _list({"limit": "5"})
    assert data["count"] == 2
    assert data["nextToken"] is None


@pytest.mark.parametrize("limit", ["0", "-3", "101", "abc", "1.5"])
def test_bad_limit_400(limit):
    resp, data = _list({"limit": limit})
    assert resp["statusCode"] == 400
    assert "error" in data


def test_bad_next_token_400():
    resp, data = _list({"nextToken": "!!!not-base64!!!"})
    assert resp["statusCode"] == 400


def test_responses_carry_cors_headers():
    resp, _ = _list()
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
