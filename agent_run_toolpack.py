#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def die(msg: str, code: int = 1) -> None:
    raise SystemExit(f"ERROR: {msg}")


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_b64_text(path: Path) -> bytes:
    return base64.b64decode(path.read_text(encoding="utf-8").strip())


def load_ed25519_pub_b64(path: Path) -> Ed25519PublicKey:
    raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
    return Ed25519PublicKey.from_public_bytes(raw)


def walk_payload(payload_dir: Path) -> List[Tuple[str, str, int]]:
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
    buf = []
    for rel, h, n in entries:
        buf.append(f"{rel}\0{h}\0{n}\n")
    return hashlib.sha256("".join(buf).encode("utf-8")).hexdigest()


def verify_toolpack(toolpack_dir: Path, issuer_pub_path: Path) -> Dict[str, str]:
    """
    Verifies:
      - manifest.json exists
      - manifest.sig exists
      - manifest.hashes.manifest_canon_sha256 equals sha256(raw_bytes(manifest.json))
      - signature verifies over raw bytes
      - payload files tree matches manifest.hashes.files_tree_sha256
    Returns key fields used for receipts.
    """
    manifest = toolpack_dir / "manifest.json"
    sig = toolpack_dir / "manifest.sig"
    if not manifest.exists():
        die(f"missing manifest.json: {manifest}")
    if not sig.exists():
        die(f"missing manifest.sig: {sig}")

    manifest_bytes = manifest.read_bytes()
    canon = sha256_bytes(manifest_bytes)

    try:
        m = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as e:
        die(f"manifest.json invalid JSON: {e}")

    hashes = m.get("hashes") or {}
    exp_canon = hashes.get("manifest_canon_sha256")
    exp_tree = hashes.get("files_tree_sha256")
    if not isinstance(exp_canon, str) or len(exp_canon) != 64:
        die("manifest.hashes.manifest_canon_sha256 missing/invalid")
    if not isinstance(exp_tree, str) or len(exp_tree) != 64:
        die("manifest.hashes.files_tree_sha256 missing/invalid")
    if exp_canon != canon:
        die(
            "manifest canonical sha256 mismatch:\n"
            f"  expected: {exp_canon}\n"
            f"  actual  : {canon}"
        )

    pub = load_ed25519_pub_b64(issuer_pub_path)
    sig_bytes = read_b64_text(sig)
    try:
        pub.verify(sig_bytes, manifest_bytes)
    except Exception as e:
        die(f"signature verify failed: {e}")

    payload_dir = toolpack_dir / (m.get("payload_dir") or "payload")
    if not payload_dir.exists():
        die(f"payload dir missing: {payload_dir}")

    tree = files_tree_hash(walk_payload(payload_dir))
    if tree != exp_tree:
        die(
            "files tree sha256 mismatch:\n"
            f"  expected: {exp_tree}\n"
            f"  actual  : {tree}"
        )

    issuer = m.get("issuer") or {}
    toolpack_id = str(m.get("toolpack_id") or "")
    issuer_name = str(issuer.get("name") or "")
    issuer_kid = str(issuer.get("kid") or "")
    issuer_pubkey_sha256 = str(issuer.get("pubkey_sha256") or "")

    if not toolpack_id:
        die("manifest.toolpack_id missing")
    if not issuer_kid:
        die("manifest.issuer.kid missing")
    if not issuer_pubkey_sha256:
        die("manifest.issuer.pubkey_sha256 missing")

    return {
        "toolpack_id": toolpack_id,
        "issuer_name": issuer_name,
        "issuer_kid": issuer_kid,
        "issuer_pubkey_sha256": issuer_pubkey_sha256,
        "manifest_canon_sha256": canon,
        "files_tree_sha256": tree,
        "payload_dir": str(payload_dir),
    }


def next_event_path(log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted([p for p in log_dir.glob("*_event.json") if p.name[:6].isdigit()])
    if not existing:
        n = 0
    else:
        n = int(existing[-1].name[:6]) + 1
    return log_dir / f"{n:06d}_event.json"


def append_event(agent_root: Path, event: Dict) -> Path:
    log_dir = agent_root / "xitadel" / "log"
    p = next_event_path(log_dir)
    p.write_text(json.dumps(event, indent=2) + "\n", encoding="utf-8")
    return p


def main() -> None:
    ap = argparse.ArgumentParser(prog="agent_run_toolpack")
    ap.add_argument("--agent-root", required=True, help="Agent root dir (contains xitadel/)")
    ap.add_argument("--toolpack-id", required=True, help="Toolpack directory name under agent xitadel public toolpacks/")
    ap.add_argument(
        "--issuer-pub",
        default="~/.xagents/xkernelorg_governor.pub",
        help="Path to issuer pub key (base64 raw). Recommend point at xkernelorg/xitadel/keys/governor_ed25519.pub",
    )
    ap.add_argument(
        "--payload",
        default="bootstrap_keygen.sh",
        help="Payload script name within toolpack payload/ to execute",
    )
    ap.add_argument("--yes", action="store_true", help="Non-interactive: assume yes")
    args = ap.parse_args()

    agent_root = Path(args.agent_root).expanduser().resolve()
    if not agent_root.exists():
        die(f"agent root not found: {agent_root}")

    toolpack_dir = agent_root / "xitadel" / "public" / "toolpacks" / args.toolpack_id
    if not toolpack_dir.exists():
        die(f"toolpack not found in agent xitadel: {toolpack_dir}")

    issuer_pub = Path(args.issuer_pub).expanduser().resolve()
    if not issuer_pub.exists():
        die(f"issuer pub key not found: {issuer_pub}")

    # Verify toolpack
    meta = verify_toolpack(toolpack_dir, issuer_pub)
    payload_dir = Path(meta["payload_dir"])
    payload = payload_dir / args.payload
    if not payload.exists():
        die(f"payload not found: {payload}")

    # Policy: agent-only writes happen under its own keys dir
    keys_dir = agent_root / "xitadel" / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Refuse to overwrite existing governor keys (safety)
    priv = keys_dir / "governor_ed25519.priv"
    pub = keys_dir / "governor_ed25519.pub"
    kid = keys_dir / "governor_ed25519.kid"
    if priv.exists() or pub.exists() or kid.exists():
        die(f"refusing to overwrite existing governor keys in: {keys_dir}")

    # Execute payload with explicit environment (no guessing)
    env = os.environ.copy()
    env["AGENT_ROOT"] = str(agent_root)
    env["XITADEL_DIR"] = str(agent_root / "xitadel")
    env["XITADEL_KEYS_DIR"] = str(keys_dir)
    env["TOOLPACK_ID"] = meta["toolpack_id"]
    env["TOOLPACK_MANIFEST_CANON_SHA256"] = meta["manifest_canon_sha256"]
    env["TOOLPACK_FILES_TREE_SHA256"] = meta["files_tree_sha256"]
    env["TOOLPACK_ISSUER_KID"] = meta["issuer_kid"]

    # Mark payload executable if needed
    try:
        payload.chmod(payload.stat().st_mode | 0o111)
    except Exception:
        pass

    print("OK: toolpack verified")
    print("toolpack :", meta["toolpack_id"])
    print("issuer   :", meta["issuer_kid"])
    print("payload  :", payload)

    if not args.yes:
        ans = input("Run payload now to generate agent governor keys? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            die("aborted by user", code=0)

    r = subprocess.run(
        ["/data/data/com.termux/files/usr/bin/bash", str(payload)],
        env=env,
        cwd=str(payload_dir),
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        die(f"payload failed with code {r.returncode}")

    # Post-check keys exist
    if not (priv.exists() and pub.exists() and kid.exists()):
        die(f"payload completed but expected keys missing in: {keys_dir}")

    # Receipt event (does NOT leak private key)
    pub_raw = base64.b64decode(pub.read_text(encoding="utf-8").strip())
    pub_sha = hashlib.sha256(pub_raw).hexdigest()

    event = {
        "schema": "agent.toolpack.executed.v1",
        "at": iso_now(),
        "agent_root": str(agent_root),
        "toolpack": {
            "toolpack_id": meta["toolpack_id"],
            "issuer_kid": meta["issuer_kid"],
            "manifest_canon_sha256": meta["manifest_canon_sha256"],
            "files_tree_sha256": meta["files_tree_sha256"],
        },
        "result": {
            "governor_kid": kid.read_text(encoding="utf-8").strip(),
            "governor_pub_sha256": pub_sha,
            "keys_written_under": str(keys_dir),
        },
    }
    ep = append_event(agent_root, event)
    print("OK: keys generated and receipt appended")
    print("event:", ep)


if __name__ == "__main__":
    main()
