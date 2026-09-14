"""Export-script tests — stdlib urllib is stubbed; no network."""

import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import export_notes


class _FakeHTTPResponse:
    def __init__(self, payload):
        self._buf = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self._buf

    def __exit__(self, *exc):
        return False


def _stub_urlopen(monkeypatch, routes):
    def fake_urlopen(url, timeout=30):
        for exact, payload in routes:
            if url == exact:
                return _FakeHTTPResponse(payload)
        raise AssertionError(f"unexpected URL: {url}")
    monkeypatch.setattr(export_notes.urllib.request, "urlopen", fake_urlopen)


NOTE_META = {"noteId": "abc123", "createdAt": "2026-09-14T00:00:00+00:00",
             "tags": ["finance"], "expiresAt": None, "ciphertextBytes": 120}
NOTE_FULL = dict(NOTE_META, title="t", body="secret body")


def test_export_paginates_and_fetches_each_note(monkeypatch):
    routes = [
        ("https://api.test/notes?limit=100", {"notes": [NOTE_META], "count": 1,
                                              "nextToken": "tok2"}),
        ("https://api.test/notes?limit=100&nextToken=tok2",
         {"notes": [], "count": 0, "nextToken": None}),
        ("https://api.test/notes/abc123", NOTE_FULL),
    ]
    _stub_urlopen(monkeypatch, routes)
    notes = export_notes.export_notes("https://api.test")
    assert notes == [NOTE_FULL]


def test_export_passes_tag_filter(monkeypatch):
    seen = []

    def fake_urlopen(url, timeout=30):
        seen.append(url)
        return _FakeHTTPResponse({"notes": [], "count": 0, "nextToken": None})
    monkeypatch.setattr(export_notes.urllib.request, "urlopen", fake_urlopen)
    export_notes.export_notes("https://api.test/", tag="finance", q="fin")
    assert seen[0].startswith("https://api.test/notes?")
    assert "tag=finance" in seen[0] and "q=fin" in seen[0]


def test_export_http_error_becomes_runtime_error(monkeypatch):
    import urllib.error
    def boom(url, timeout=30):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b'{"error":"nope"}'))
    monkeypatch.setattr(export_notes.urllib.request, "urlopen", boom)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        export_notes.export_notes("https://api.test")


def test_write_export_produces_valid_json(tmp_path):
    out = str(tmp_path / "out.json")
    export_notes.write_export([NOTE_FULL], out)
    data = json.loads(open(out).read())
    assert data["count"] == 1
    assert data["notes"][0]["body"] == "secret body"
    assert "exportedAt" in data


def test_default_out_path_is_timestamped():
    name = export_notes.default_out_path()
    assert name.startswith("notes-export-") and name.endswith(".json")
