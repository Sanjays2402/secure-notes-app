"""Envelope-encryption helpers for the Secure Notes App.

Every note gets its OWN data key — the KMS customer key never touches note
bytes directly:

    CREATE
        1. kms:GenerateDataKey  ->  256-bit plaintext data key + encrypted copy
        2. JSON {"title","body"} -> Fernet(plaintext data key) -> ciphertext
        3. DynamoDB stores: ciphertext + ENCRYPTED data key + key ARN.
           The plaintext data key lives only in memory and is discarded.

    READ
        1. DynamoDB -> ciphertext + encrypted data key
        2. kms:Decrypt(encrypted data key) -> plaintext data key
        3. Fernet decrypt -> original {"title","body"}

Why envelope encryption instead of calling kms:Encrypt on the note?
  * KMS has a 4 KiB plaintext limit per Encrypt call; notes can be bigger.
  * One KMS call per note instead of per 4 KiB chunk (cheaper, faster).
  * Compromise of a data key exposes exactly one note, not all of them.
  * Rotating the KMS key only re-wraps data keys; note ciphertext is untouched.

INTERVIEW TALKING POINT — data-key caching:
  GenerateDataKey/Decrypt cost ~$0.03 per 10k requests and add ~5-20 ms of
  latency. At high throughput you can cache plaintext data keys in memory
  with a strict TTL (the AWS Encryption SDK defaults to 10 minutes / max 100
  messages per cached key). Caching trades a slightly larger blast radius for
  fewer KMS calls and lower latency.

  We deliberately do NOT cache here: this is a personal notes app, so the
  safest default is one fresh data key per note and immediate disposal.
  Pseudocode for where caching would slot in, if throughput ever demanded it:

      _cache = {}  # encrypted_data_key_b64 -> (plaintext_key, expires_at)

      def get_data_key(kms, key_id, encrypted_key_b64=None):
          now = time.monotonic()
          if encrypted_key_b64 in _cache:
              key, exp = _cache[encrypted_key_b64]
              if now < exp:
                  return key                      # cache hit: skip KMS
          key = kms.Decrypt(...)["Plaintext"]     # cache miss: ask KMS
          _cache[encrypted_key_b64] = (key, now + 600)  # 10-minute TTL
          return key
"""

from __future__ import annotations

import base64
import json

from cryptography.fernet import Fernet, InvalidToken

# Version tag stored alongside every item so the format can evolve
# (e.g. switching ciphers) without breaking old notes.
SCHEMA_VERSION = 1


class EnvelopeError(Exception):
    """Raised when envelope encrypt/decrypt cannot complete safely."""


def generate_data_key(kms_client, key_id: str) -> tuple[bytes, bytes]:
    """Mint a fresh 256-bit data key from KMS.

    Returns (plaintext_key, encrypted_key). The caller must treat the
    plaintext key as toxic: use it, then drop the reference.
    """
    resp = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    return resp["Plaintext"], resp["CiphertextBlob"]


def _fernet(plaintext_key: bytes) -> Fernet:
    # Fernet expects a 32-byte URL-safe base64-encoded key — exactly what
    # KMS AES_256 gives us after encoding.
    return Fernet(base64.urlsafe_b64encode(plaintext_key))


def encrypt_note(kms_client, key_id: str, payload: dict) -> dict:
    """Encrypt a note payload; returns the DynamoDB-safe item fields.

    Returns dict with: ciphertext (b64 str), encrypted_data_key (b64 str),
    kms_key_id, schema_version. Never returns the plaintext data key.
    """
    plaintext_key, encrypted_key = generate_data_key(kms_client, key_id)
    token = _fernet(plaintext_key).encrypt(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    # NOTE: the plaintext data key is intentionally NOT scrubbed here — bytes
    # are immutable in CPython so zeroing is theater. Instead we drop the
    # reference immediately and never store, log, or return the key, so the
    # only live copy dies with this frame.
    del plaintext_key
    return {
        "ciphertext": base64.b64encode(token).decode("ascii"),
        "encrypted_data_key": base64.b64encode(encrypted_key).decode("ascii"),
        "kms_key_id": key_id,
        "schema_version": SCHEMA_VERSION,
    }


def decrypt_note(kms_client, encrypted_data_key_b64: str, ciphertext_b64: str) -> dict:
    """Unwrap the data key via KMS and decrypt the note payload."""
    try:
        encrypted_key = base64.b64decode(encrypted_data_key_b64, validate=True)
        token = base64.b64decode(ciphertext_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise EnvelopeError("stored note is not valid base64") from exc

    try:
        plaintext_key = kms_client.decrypt(CiphertextBlob=encrypted_key)["Plaintext"]
    except Exception as exc:  # KMS errors: key disabled, bad ciphertext, no access
        raise EnvelopeError("KMS could not unwrap the data key") from exc

    try:
        raw = _fernet(plaintext_key).decrypt(token)
    except InvalidToken as exc:
        raise EnvelopeError("ciphertext failed authentication") from exc
    finally:
        del plaintext_key  # see NOTE in encrypt_note: drop, don't pretend to scrub

    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise EnvelopeError("decrypted payload is not valid JSON") from exc
