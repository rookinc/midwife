#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def load_pubkey(pub_path: Path) -> Ed25519PublicKey:
    if not pub_path.exists():
        die(f"missing pubkey: {pub_path}")
    raw = base64.b64decode(pub_path.read_text(encoding="utf-8").strip())
    if len(raw) != 32:
        die(f"unexpected ed25519 pubkey length {len(raw)} (expected 32 bytes): {pub_path}")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_event(env: dict, pub: Ed25519PublicKey, expected_prev: str) -> str:
    """
    Verify a single event envelope and return its envelope_hash (which becomes next expected prev).
    """
    required = ["schema", "event_id", "ts", "kind", "prev", "payload", "payload_hash", "envelope_hash", "signatures"]
    for k in required:
        if k not in env:
            die(f"missing field {k} in event")

    # payload hash
    ph = sha256_hex(canonical(env["payload"]))
    if ph != env["payload_hash"]:
        die(f"payload_hash mismatch: computed={ph} file={env['payload_hash']}")

    # envelope hash (core fields only)
    core = {
        "schema": env["schema"],
        "event_id": env["event_id"],
        "ts": env["ts"],
        "kind": env["kind"],
        "prev": env["prev"],
        "payload_hash": env["payload_hash"],
        "redactions": env.get("redactions", []),
    }
    eh = sha256_hex(canonical(core))
    if eh != env["envelope_hash"]:
        die(f"envelope_hash mismatch: computed={eh} file={env['envelope_hash']}")

    # chain
    if env["prev"] != expected_prev:
        die(f"prev mismatch: expected={expected_prev} file={env['prev']} (event_id={env['event_id']})")

    # signature
    sigs = env["signatures"]
    if not isinstance(sigs, list) or not sigs:
        die("missing signatures array")
    s0 = sigs[0]
    if s0.get("kind") != "ed25519":
        die(f"unsupported signature kind: {s0.get('kind')}")
    sig = base64.b64decode(s0["sig"])

    msg = (
        env["kind"] + "\n" +
        env["ts"] + "\n" +
        env["prev"] + "\n" +
        env["payload_hash"] + "\n" +
        env["envelope_hash"]
    ).encode("utf-8")

    pub.verify(sig, msg)
    return eh


def main() -> None:
    # If run from anywhere, locate this file, then treat its parent as xitadel root.
    here = Path(__file__).resolve()
    xroot = here.parent

    log_dir = xroot / "log"
    if not log_dir.exists():
        die(f"missing log dir: {log_dir}")

    pub = load_pubkey(xroot / "keys" / "governor_ed25519.pub")

    events = sorted(log_dir.glob("*_event.json"))
    if not events:
        die(f"no events found in {log_dir}")

    prev = "0" * 64
    for p in events:
        env = json.loads(p.read_text(encoding="utf-8"))
        prev = verify_event(env, pub, prev)
        print("OK:", p.name, env.get("kind"))

    # Optional HEAD check (if present)
    head_path = xroot / "HEAD"
    if head_path.exists():
        head = head_path.read_text(encoding="utf-8").strip()
        if head != prev:
            die(f"HEAD mismatch: HEAD={head} computed={prev}")
        print("OK: HEAD matches")

    print("\n✔ midwife xitadel verified end-to-end")


if __name__ == "__main__":
    main()
