#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def die(msg: str, code: int = 1) -> None:
    raise SystemExit(f"ERROR: {msg}")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_b64(path: Path) -> bytes:
    s = path.read_text(encoding="utf-8").strip()
    return base64.b64decode(s)


def load_ed25519_pub_b64(path: Path) -> Ed25519PublicKey:
    raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
    return Ed25519PublicKey.from_public_bytes(raw)


def walk_payload(payload_dir: Path) -> List[Tuple[str, str, int]]:
    """
    Returns list of (rel_path, sha256_hex, bytes) sorted by rel_path.
    """
    out: List[Tuple[str, str, int]] = []
    for p in payload_dir.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(payload_dir).as_posix()
        b = p.read_bytes()
        out.append((rel, sha256_bytes(b), len(b)))
    out.sort(key=lambda t: t[0])
    return out


def files_tree_hash(entries: List[Tuple[str, str, int]]) -> str:
    """
    Deterministic “tree hash”:
      path\\0sha256\\0bytes\\n (UTF-8)
    """
    buf = []
    for rel, h, n in entries:
        buf.append(f"{rel}\0{h}\0{n}\n")
    return hashlib.sha256("".join(buf).encode("utf-8")).hexdigest()


def canonical_manifest_bytes(m: Dict) -> bytes:
    """
    Canonical bytes for hashing/signing, NON-SELF-REFERENTIAL:

    - Remove hashes.manifest_canon_sha256 if present
    - JSON serialize with sort_keys=True and separators=(',', ':')
    - UTF-8, no trailing newline
    """
    mm = json.loads(json.dumps(m))  # deep-ish copy
    hashes = mm.get("hashes")
    if isinstance(hashes, dict):
        hashes.pop("manifest_canon_sha256", None)

    s = json.dumps(mm, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


@dataclass(frozen=True)
class VerifyResult:
    toolpack_id: str
    manifest_canon_sha256: str
    files_tree_sha256: str
    issuer_kid: str
    issuer_pubkey_sha256: str


def verify_toolkit_dir(toolkit_dir: Path, issuer_pub_path: Path) -> VerifyResult:
    if not toolkit_dir.exists():
        die(f"toolkit dir not found: {toolkit_dir}")

    manifest_path = toolkit_dir / "manifest.json"
    sig_path = toolkit_dir / "manifest.sig"
    if not manifest_path.exists():
        die(f"missing manifest.json: {manifest_path}")
    if not sig_path.exists():
        die(f"missing manifest.sig: {sig_path}")

    # Load JSON object (manifest file format can be pretty; verification uses canonical bytes)
    try:
        m: Dict = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"manifest.json is not valid JSON: {e}")

    hashes = (m.get("hashes") or {})
    expected_canon = hashes.get("manifest_canon_sha256")
    expected_tree = hashes.get("files_tree_sha256")
    if not expected_canon or not isinstance(expected_canon, str):
        die("manifest.hashes.manifest_canon_sha256 missing/invalid")
    if not expected_tree or not isinstance(expected_tree, str):
        die("manifest.hashes.files_tree_sha256 missing/invalid")

    # Canonical hash over canonical bytes (with self-hash omitted)
    canon_bytes = canonical_manifest_bytes(m)
    canon = sha256_bytes(canon_bytes)

    if expected_canon != canon:
        die(
            "manifest canonical sha256 mismatch:\n"
            f"  expected: {expected_canon}\n"
            f"  actual  : {canon}"
        )

    # Verify signature over canonical bytes
    pub = load_ed25519_pub_b64(issuer_pub_path)
    sig_bytes = read_b64(sig_path)
    try:
        pub.verify(sig_bytes, canon_bytes)
    except Exception as e:
        die(f"signature verify failed: {e}")

    # Verify payload tree hash
    payload_dir = toolkit_dir / (m.get("payload_dir") or "payload")
    if not payload_dir.exists():
        die(f"payload dir missing: {payload_dir}")

    entries = walk_payload(payload_dir)
    tree = files_tree_hash(entries)
    if tree != expected_tree:
        die(
            "files tree sha256 mismatch:\n"
            f"  expected: {expected_tree}\n"
            f"  actual  : {tree}"
        )

    issuer = m.get("issuer") or {}
    issuer_kid = str(issuer.get("kid") or "")
    issuer_pubkey_sha = str(issuer.get("pubkey_sha256") or "")
    toolpack_id = str(m.get("toolpack_id") or "")

    if not toolpack_id:
        die("manifest.toolpack_id missing")
    if not issuer_kid:
        die("manifest.issuer.kid missing")
    if not issuer_pubkey_sha:
        die("manifest.issuer.pubkey_sha256 missing")

    return VerifyResult(
        toolpack_id=toolpack_id,
        manifest_canon_sha256=canon,
        files_tree_sha256=tree,
        issuer_kid=issuer_kid,
        issuer_pubkey_sha256=issuer_pubkey_sha,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--toolkit", required=True, help="Path to toolkit dir (contains manifest.json, manifest.sig, payload/)")
    ap.add_argument("--issuer-pub", required=True, help="Path to issuer governor_ed25519.pub (base64 raw)")
    args = ap.parse_args()

    res = verify_toolkit_dir(Path(args.toolkit).expanduser(), Path(args.issuer_pub).expanduser())
    print("OK: toolkit verified")
    print("toolpack_id            :", res.toolpack_id)
    print("manifest_canon_sha256  :", res.manifest_canon_sha256)
    print("files_tree_sha256      :", res.files_tree_sha256)
    print("issuer_kid             :", res.issuer_kid)
    print("issuer_pubkey_sha256   :", res.issuer_pubkey_sha256)


if __name__ == "__main__":
    main()
