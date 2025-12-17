#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from uuid import uuid4

from toolkit_verify import verify_toolkit_dir


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def die(msg: str, code: int = 1) -> None:
    raise SystemExit(f"ERROR: {msg}")


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-root", required=True)
    ap.add_argument("--request-id", required=True)
    ap.add_argument("--toolkit", required=True)
    ap.add_argument("--issuer-pub", required=True)
    args = ap.parse_args()

    agent_root = Path(args.agent_root).expanduser().resolve()
    toolkit = Path(args.toolkit).expanduser().resolve()
    issuer_pub = Path(args.issuer_pub).expanduser().resolve()

    if not agent_root.exists():
        die(f"agent root not found: {agent_root}")

    # Verify toolkit (xkernelorg authority)
    res = verify_toolkit_dir(toolkit, issuer_pub)

    # Copy to agent xitadel public toolpacks
    dest = agent_root / "xitadel" / "public" / "toolpacks" / res.toolpack_id
    safe_mkdir(dest.parent)

    if dest.exists():
        # replace (idempotent update)
        shutil.rmtree(dest)

    shutil.copytree(toolkit, dest)

    # Write a receipt into agent registry responses
    resp_dir = agent_root / "xitadel" / "registry" / "responses"
    safe_mkdir(resp_dir)

    response_id = f"resp-{uuid4().hex[:16]}"
    receipt = {
        "schema": "registry.response.toolkit.handoff.v1",
        "response_id": response_id,
        "request_id": args.request_id,
        "delivered_at": iso_now(),
        "toolpack": {
            "toolpack_id": res.toolpack_id,
            "manifest_canon_sha256": res.manifest_canon_sha256,
            "files_tree_sha256": res.files_tree_sha256
        },
        "issuer": {
            "name": "xkernelorg",
            "kid": res.issuer_kid,
            "pubkey_sha256": res.issuer_pubkey_sha256
        },
        "delivery": {
            "by": "midwife",
            "from_path": str(toolkit),
            "to_path": str(dest)
        }
    }

    out = resp_dir / f"{response_id}.json"
    out.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    print("OK: handoff complete")
    print("copied_to :", dest)
    print("receipt   :", out)


if __name__ == "__main__":
    main()
