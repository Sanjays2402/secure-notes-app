"""Shared test doubles: fake KMS + fake DynamoDB, patched over boto3.

No AWS credentials, no network. Handler modules create boto3 clients at
import time, so the patching here happens at conftest import — before any
test module imports the handlers.
"""

import base64
import os
import sys

import boto3
from botocore.exceptions import ClientError

# --- environment the Lambdas expect (values are fake but well-formed) --------
os.environ.setdefault("AWS_REGION", "us-west-2")
os.environ.setdefault("NOTES_TABLE_NAME", "test-notes")
os.environ.setdefault("KMS_KEY_ID", "arn:aws:kms:us-west-2:123456789012:key/test-key-id")

# --- make src/ importable (handlers + common.crypto) --------------------------
SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(SRC))


class FakeKMS:
    """Pretends to be KMS: 'encryption' is a reversible prefix tag.

    decrypt() strips the tag and returns the original key. Anything without
    the tag raises the same ClientError shape KMS uses for bad ciphertext.
    """

    PREFIX = b"vault-enc:"

    def __init__(self):
        self.decrypt_calls = 0
        self.generate_calls = 0

    def generate_data_key(self, KeyId, KeySpec):  # noqa: N803 (boto3 naming)
        assert KeySpec == "AES_256"
        self.generate_calls += 1
        key = os.urandom(32)
        return {"Plaintext": key, "CiphertextBlob": self.PREFIX + key, "KeyId": KeyId}

    def decrypt(self, CiphertextBlob):  # noqa: N803
        self.decrypt_calls += 1
        if not CiphertextBlob.startswith(self.PREFIX):
            raise ClientError(
                {"Error": {"Code": "InvalidCiphertextException",
                           "Message": "not a data key we minted"}},
                "Decrypt",
            )
        return {"Plaintext": CiphertextBlob[len(self.PREFIX):], "KeyId": "test"}


class FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None):  # noqa: N803
        if (ConditionExpression == "attribute_not_exists(noteId)"
                and Item["noteId"] in self.items):
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException",
                           "Message": "already exists"}},
                "PutItem",
            )
        self.items[Item["noteId"]] = Item
        return {}

    def get_item(self, Key):  # noqa: N803
        item = self.items.get(Key["noteId"])
        return {"Item": item} if item else {}

    def delete_item(self, Key, ConditionExpression=None):  # noqa: N803
        if (ConditionExpression == "attribute_exists(noteId)"
                and Key["noteId"] not in self.items):
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException",
                           "Message": "not exists"}},
                "DeleteItem",
            )
        self.items.pop(Key["noteId"], None)
        return {}

    def scan(self, Limit=None, ExclusiveStartKey=None):  # noqa: N803        # Deterministic order for tests: sorted by noteId.
        keys = sorted(self.items)
        start = 0
        if ExclusiveStartKey:
            after = ExclusiveStartKey["noteId"]
            start = keys.index(after) + 1 if after in keys else 0
        page_keys = keys[start:(start + Limit) if Limit else None]
        resp = {
            "Items": [self.items[k] for k in page_keys],
            "Count": len(page_keys),
        }
        if start + len(page_keys) < len(keys):
            resp["LastEvaluatedKey"] = {"noteId": page_keys[-1]}
        return resp


class FakeDynamoDB:
    def __init__(self):
        self.tables = {}

    def Table(self, name):  # noqa: N802
        return self.tables.setdefault(name, FakeTable())


_FAKE_KMS = FakeKMS()
_FAKE_DDB = FakeDynamoDB()


def _fake_client(service, *args, **kwargs):
    assert service == "kms", f"unexpected client: {service}"
    return _FAKE_KMS


def _fake_resource(service, *args, **kwargs):
    assert service == "dynamodb", f"unexpected resource: {service}"
    return _FAKE_DDB


# Patch before test modules import the handlers.
boto3.client = _fake_client
boto3.resource = _fake_resource


def reset_fakes():
    """Clear stored items between tests (keys are unique per test anyway)."""
    _FAKE_DDB.tables.clear()
    _FAKE_KMS.decrypt_calls = 0
    _FAKE_KMS.generate_calls = 0


def fake_kms():
    return _FAKE_KMS


def fake_table(name="test-notes"):
    return _FAKE_DDB.Table(name)
