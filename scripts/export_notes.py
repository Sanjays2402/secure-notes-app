#!/usr/bin/env python3
"""Export all notes (decrypted) from a deployed Secure Notes API to JSON.

Flow:  GET /notes?limit=100  ->  GET /notes/{id} for each note  ->  notes-export-<ts>.json

Decryption happens inside the Get Lambda (KMS), so this script needs no AWS
credentials — only the API endpoint. The output contains PLAINTEXT note
bodies: store it somewhere private (encrypted disk, password manager import).

Usage:
    python3 scripts/export_notes.py --api-base https://abc123.execute-api.us-west-2.amazonaws.com
    python3 scripts/export_notes.py --api-base <url> --out my-notes.json --tag finance
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def fetch_json(url: str):
    """GET a URL and parse the JSON body; raises RuntimeError on failure."""
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc).get("error", exc.reason)
        except Exception:
            detail = exc.reason
        raise RuntimeError(f"GET {url} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GET {url} failed: {exc.reason}") from exc


def export_notes(api_base: str, tag: str | None = None, q: str | None = None) -> list[dict]:
    """List all notes via the API and fetch each one decrypted."""
    base = api_base.rstrip("/")
    notes: list[dict] = []
    params = {"limit": "100"}
    if tag:
        params["tag"] = tag
    if q:
        params["q"] = q
    next_token = None
    seen_tokens = set()
    while True:
        if next_token:
            params["nextToken"] = next_token
        page = fetch_json(f"{base}/notes?{urllib.parse.urlencode(params)}")
        for meta in page.get("notes", []):
            note_id = meta["noteId"]
            note = fetch_json(f"{base}/notes/{urllib.parse.quote(note_id)}")
            notes.append(note)
            print(f"  exported {note_id}  tags={','.join(note.get('tags', [])) or '-'}",
                  file=sys.stderr)
        next_token = page.get("nextToken")
        params.pop("nextToken", None)
        if not next_token or next_token in seen_tokens:
            break
        seen_tokens.add(next_token)
    return notes


def write_export(notes: list[dict], path: str) -> None:
    payload = {
        "exportedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "count": len(notes),
        "notes": notes,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def default_out_path() -> str:
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"notes-export-{ts}.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export decrypted notes to JSON.")
    parser.add_argument("--api-base", required=True, help="API base URL (ApiEndpoint output)")
    parser.add_argument("--out", default=None, help="output file (default: notes-export-<ts>.json)")
    parser.add_argument("--tag", default=None, help="only export notes with this tag")
    parser.add_argument("--q", default=None, help="only export notes whose tags match")
    args = parser.parse_args(argv)

    out = args.out or default_out_path()
    print(f"Exporting notes from {args.api_base} ...", file=sys.stderr)
    try:
        notes = export_notes(args.api_base, tag=args.tag, q=args.q)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    write_export(notes, out)
    print(f"Wrote {len(notes)} notes to {out} — keep this file private.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
