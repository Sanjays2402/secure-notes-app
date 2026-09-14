"""Envelope-encryption unit tests — real Fernet crypto, mocked KMS."""

import base64

import pytest

from common.crypto import decrypt_note, encrypt_note, EnvelopeError, SCHEMA_VERSION
from conftest import fake_kms, reset_fakes

KEY_ID = "arn:aws:kms:us-west-2:123456789012:key/test-key-id"


@pytest.fixture(autouse=True)
def _clean():
    reset_fakes()
    yield


def test_round_trip():
    kms = fake_kms()
    payload = {"title": "hello", "body": "super secret body ✨"}
    env = encrypt_note(kms, KEY_ID, payload)

    assert env["kms_key_id"] == KEY_ID
    assert env["schema_version"] == SCHEMA_VERSION
    # Stored fields are opaque base64 — the plaintext is nowhere in them.
    assert payload["body"] not in env["ciphertext"]
    assert payload["body"] not in env["encrypted_data_key"]
    base64.b64decode(env["ciphertext"], validate=True)
    base64.b64decode(env["encrypted_data_key"], validate=True)

    assert decrypt_note(kms, env["encrypted_data_key"], env["ciphertext"]) == payload


def test_each_note_gets_a_unique_data_key():
    kms = fake_kms()
    a = encrypt_note(kms, KEY_ID, {"title": "a", "body": "same body"})
    b = encrypt_note(kms, KEY_ID, {"title": "b", "body": "same body"})
    assert a["encrypted_data_key"] != b["encrypted_data_key"]
    assert a["ciphertext"] != b["ciphertext"]
    # …yet both still decrypt.
    assert decrypt_note(kms, b["encrypted_data_key"], b["ciphertext"])["title"] == "b"


def test_plaintext_data_key_never_leaves():
    kms = fake_kms()
    env = encrypt_note(kms, KEY_ID, {"title": "t", "body": "b"})
    assert "Plaintext" not in env
    assert "plaintext" not in str(env).lower()


def test_tampered_ciphertext_fails_closed():
    kms = fake_kms()
    env = encrypt_note(kms, KEY_ID, {"title": "t", "body": "b"})
    raw = bytearray(base64.b64decode(env["ciphertext"]))
    raw[20] ^= 0xFF  # flip a bit in the Fernet token
    with pytest.raises(EnvelopeError):
        decrypt_note(kms, env["encrypted_data_key"],
                     base64.b64encode(bytes(raw)).decode())


def test_wrong_data_key_fails_closed():
    kms = fake_kms()
    env = encrypt_note(kms, KEY_ID, {"title": "t", "body": "b"})
    blob = bytearray(base64.b64decode(env["encrypted_data_key"]))
    blob[-1] ^= 0xFF  # corrupt the wrapped key -> KMS unwraps a different key
    with pytest.raises(EnvelopeError):
        decrypt_note(kms, base64.b64encode(bytes(blob)).decode(), env["ciphertext"])


def test_forged_encrypted_key_rejected_by_kms():
    kms = fake_kms()
    env = encrypt_note(kms, KEY_ID, {"title": "t", "body": "b"})
    forged = base64.b64encode(b"definitely-not-from-kms").decode()
    with pytest.raises(EnvelopeError):
        decrypt_note(kms, forged, env["ciphertext"])


def test_invalid_base64_rejected():
    kms = fake_kms()
    with pytest.raises(EnvelopeError):
        decrypt_note(kms, "!!!not-base64!!!", "!!!not-base64!!!")


def test_empty_payload_round_trip():
    kms = fake_kms()
    env = encrypt_note(kms, KEY_ID, {"title": "", "body": ""})
    assert decrypt_note(kms, env["encrypted_data_key"], env["ciphertext"]) == {
        "title": "", "body": ""}


def test_large_body_round_trip():
    kms = fake_kms()
    big = "x" * 100_000
    env = encrypt_note(kms, KEY_ID, {"title": "big", "body": big})
    out = decrypt_note(kms, env["encrypted_data_key"], env["ciphertext"])
    assert out["body"] == big
    # Ciphertext must stay comfortably under DynamoDB's 400 KiB item limit.
    assert len(env["ciphertext"]) < 200_000
