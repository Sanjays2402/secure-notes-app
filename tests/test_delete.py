"""DELETE /notes/{id} handler tests — deletion semantics, least privilege.

The delete path never calls KMS: stored items are ciphertext plus the wrapped
data key, so destroying one needs no decryption. Tests pin that property —
a decrypt-capable double must see zero calls — and that no note contents
are ever logged or returned.
"""

import json
import sys

import pytest

from delete_note import app as delete_app
from create_note import app as create_app
from get_note import app as get_app
import conftest


@pytest.fixture(autouse=True)
def _clean():
    conftest.reset_fakes()
    yield


def _create(note_body="hello, delete me", title="t"):
    event = {
        "body": json.dumps({"title": title, "body": note_body, "tags": ["wip"]}),
    }
    resp = create_app.lambda_handler(event, None)
    assert resp["statusCode"] == 201
    return json.loads(resp["body"])["noteId"]


def _delete(note_id):
    return delete_app.lambda_handler({"pathParameters": {"id": note_id}}, None)


def test_delete_existing_note_returns_204():
    note_id = _create()
    resp = _delete(note_id)
    assert resp["statusCode"] == 204
    assert resp["body"] == ""


def test_deleted_note_is_gone():
    note_id = _create()
    assert _delete(note_id)["statusCode"] == 204
    # The note can no longer be fetched.
    get_resp = get_app.lambda_handler({"pathParameters": {"id": note_id}}, None)
    assert get_resp["statusCode"] == 404
    # Nor listed.
    assert conftest.fake_table().items.get(note_id) is None


def test_delete_missing_note_returns_404():
    resp = _delete("note-that-never-existed")
    assert resp["statusCode"] == 404
    assert json.loads(resp["body"])["error"] == "not found"


def test_double_delete_second_is_404():
    note_id = _create()
    assert _delete(note_id)["statusCode"] == 204
    assert _delete(note_id)["statusCode"] == 404


def test_delete_missing_id_returns_400():
    for event in [{"pathParameters": {}}, {"pathParameters": None}, {}]:
        resp = delete_app.lambda_handler(event, None)
        assert resp["statusCode"] == 400


def test_delete_never_calls_kms():
    note_id = _create()
    conftest.fake_kms().decrypt_calls = 0
    conftest.fake_kms().generate_calls = 0
    assert _delete(note_id)["statusCode"] == 204
    assert conftest.fake_kms().decrypt_calls == 0
    assert conftest.fake_kms().generate_calls == 0
    # Deleting a missing note must also never touch KMS.
    assert _delete("missing")["statusCode"] == 404
    assert conftest.fake_kms().decrypt_calls == 0


def test_delete_does_not_affect_sibling_notes():
    keep = _create(note_body="keep me", title="keep")
    drop = _create(note_body="drop me", title="drop")
    assert _delete(drop)["statusCode"] == 204
    get_resp = get_app.lambda_handler({"pathParameters": {"id": keep}}, None)
    assert get_resp["statusCode"] == 200
    assert json.loads(get_resp["body"])["body"] == "keep me"


def test_delete_handler_does_not_import_kms_modules():
    # Deleting ciphertext should not need any KMS machinery at all.
    src = sys.modules["delete_note.app"]
    assert not hasattr(src, "kms")
