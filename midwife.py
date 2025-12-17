#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ============================================================
# Canonical encoding / hashing
# ============================================================

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# ============================================================
# Key handling (base64 files, matching your layout)
# ============================================================

@dataclass(frozen=True)
class Signer:
    kid: str
    priv: Ed25519PrivateKey
    pub: Ed25519PublicKey


def load_signer(keys_dir: Path) -> Signer:
    kid_path = keys_dir / "governor_ed25519.kid"
    pub_path = keys_dir / "governor_ed25519.pub"
    priv_path = keys_dir / "governor_ed25519.priv"

    if not kid_path.exists():
        die(f"missing signer kid: {kid_path}")
    if not pub_path.exists():
        die(f"missing signer pub: {pub_path}")
    if not priv_path.exists():
        die(f"missing signer priv: {priv_path}")

    kid = kid_path.read_text(encoding="utf-8").strip()
    pub_raw = base64.b64decode(pub_path.read_text(encoding="utf-8").strip())
    priv_raw = base64.b64decode(priv_path.read_text(encoding="utf-8").strip())

    priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
    pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    return Signer(kid=kid, priv=priv, pub=pub)


# ============================================================
# Xitadel layout helpers
# ============================================================

def xitadel_root_from_agent_root(agent_root: Path) -> Path:
    return agent_root / "xitadel"


def ensure_dirs(xroot: Path) -> None:
    (xroot / "log").mkdir(parents=True, exist_ok=True)
    (xroot / "keys").mkdir(parents=True, exist_ok=True)
    (xroot / "registry" / "responses").mkdir(parents=True, exist_ok=True)
    (xroot / "registry" / "requests").mkdir(parents=True, exist_ok=True)


def next_event_path(log_dir: Path) -> Path:
    # event files are like 000002_event.json
    existing = sorted(log_dir.glob("*_event.json"))
    if not existing:
        n = 0
    else:
        last = existing[-1].name.split("_", 1)[0]
        n = int(last) + 1
    return log_dir / f"{n:06d}_event.json"


def read_head(xroot: Path) -> str:
    head_path = xroot / "HEAD"
    if not head_path.exists():
        return "0" * 64
    return head_path.read_text(encoding="utf-8").strip()


def write_head(xroot: Path, head: str) -> None:
    (xroot / "HEAD").write_text(head + "\n", encoding="utf-8")


def append_event(xroot: Path, signer: Signer, kind: str, payload: Dict[str, Any], ts: Optional[str] = None) -> Path:
    ensure_dirs(xroot)
    log_dir = xroot / "log"
    ts = ts or now_utc_iso()

    prev = read_head(xroot)
    payload_hash = sha256_hex(canonical(payload))

    env_core = {
        "schema": "xitadel.event.local.v1",
        "event_id": f"{kind}:{ts}",
        "ts": ts,
        "kind": kind,
        "prev": prev,
        "payload_hash": payload_hash,
        "redactions": [],
    }
    envelope_hash = sha256_hex(canonical(env_core))

    msg = (
        kind + "\n" +
        ts + "\n" +
        prev + "\n" +
        payload_hash + "\n" +
        envelope_hash
    ).encode("utf-8")
    sig = signer.priv.sign(msg)
    sig_b64 = base64.b64encode(sig).decode("utf-8")

    env = dict(env_core)
    env["payload"] = payload
    env["envelope_hash"] = envelope_hash
    env["signatures"] = [{
        "kind": "ed25519",
        "kid": signer.kid,
        "sig": sig_b64,
    }]

    out_path = next_event_path(log_dir)
    out_path.write_text(json.dumps(env, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_head(xroot, envelope_hash)
    return out_path


# ============================================================
# Query helper (simple: kind:XYZ filter)
# ============================================================

def query_events(xroot: Path, q: str) -> List[Dict[str, Any]]:
    # supported: "kind:agent.birth.v1"
    log_dir = xroot / "log"
    if not log_dir.exists():
        return []
    want_kind = None
    q = q.strip()
    if q.startswith("kind:"):
        want_kind = q.split(":", 1)[1].strip()

    out: List[Dict[str, Any]] = []
    for p in sorted(log_dir.glob("*_event.json")):
        env = json.loads(p.read_text(encoding="utf-8"))
        if want_kind and env.get("kind") != want_kind:
            continue
        out.append({
            "event_file": p.name,
            "ts": env.get("ts"),
            "kind": env.get("kind"),
            "event_id": env.get("event_id"),
            "prev": env.get("prev"),
            "payload_hash": env.get("payload_hash"),
            "envelope_hash": env.get("envelope_hash"),
            "signer_kid": (env.get("signatures") or [{}])[0].get("kid"),
            "signature_b64": (env.get("signatures") or [{}])[0].get("sig"),
            "payload": env.get("payload"),
        })
    return out


# ============================================================
# Commands
# ============================================================

def cmd_init(args: argparse.Namespace) -> None:
    agent_root = Path(args.root).expanduser()
    agent_root.mkdir(parents=True, exist_ok=True)

    xroot = xitadel_root_from_agent_root(agent_root)
    ensure_dirs(xroot)

    signer = load_signer(xroot / "keys")

    ts = now_utc_iso()
    payload = {
        "kind": "agent.birth.v1",
        "agent_name": args.name,
        "governor_hint": args.name,
        "spawn_time": ts,
        "host_claims": {
            "platform": args.platform,
            "device": args.device,
        },
        "instance_root": str(agent_root),
        "xitadel_root": str(xroot),
        "last_known_location": {
            "provenance": "host_context",
            "observed_at": ts,
            "confidence": float(args.location_confidence),
            "precision": args.location_precision,
            "value": {"kind": "text", "display": args.location_display},
        },
    }
    p = append_event(xroot, signer, "agent.birth.v1", payload, ts=ts)
    print(str(p))


def cmd_verify(args: argparse.Namespace) -> None:
    # Minimal verify: hashes + chain + signature check
    agent_root = Path(args.root).expanduser()
    xroot = xitadel_root_from_agent_root(agent_root)
    log_dir = xroot / "log"
    if not log_dir.exists():
        die(f"missing log dir: {log_dir}")

    pub_path = xroot / "keys/governor_ed25519.pub"
    if not pub_path.exists():
        die(f"missing pubkey: {pub_path}")
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_path.read_text().strip()))

    prev = "0" * 64
    for p in sorted(log_dir.glob("*_event.json")):
        env = json.loads(p.read_text(encoding="utf-8"))

        ph = sha256_hex(canonical(env["payload"]))
        if ph != env["payload_hash"]:
            die(f"payload_hash mismatch in {p.name}")

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
            die(f"envelope_hash mismatch in {p.name}")

        if env["prev"] != prev:
            die(f"prev mismatch in {p.name}")
        prev = eh

        sig = base64.b64decode(env["signatures"][0]["sig"])
        msg = (
            env["kind"] + "\n" +
            env["ts"] + "\n" +
            env["prev"] + "\n" +
            env["payload_hash"] + "\n" +
            env["envelope_hash"]
        ).encode("utf-8")
        pub.verify(sig, msg)

        # If registry.response.v1, ensure artifact exists
        if env["kind"] == "registry.response.v1":
            resp_id = env["payload"]["response_id"]
            resp_path = xroot / "registry" / "responses" / f"{resp_id}.json"
            if not resp_path.exists():
                die(f"missing registry response file for {resp_id}")

        print(f"OK: {p.name}")

    print("✔ xitadel verified end-to-end")


def cmd_query(args: argparse.Namespace) -> None:
    agent_root = Path(args.root).expanduser()
    xroot = xitadel_root_from_agent_root(agent_root)

    results = query_events(xroot, args.q)
    out = {
        "schema": "xkernelorg.public_query_response.local.v1",
        "q": args.q,
        "count": len(results),
        "results": results,
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_register(args: argparse.Namespace) -> None:
    # Register this agent's birth with a local xkernelorg registry agent.
    agent_root = Path(args.root).expanduser()
    registry_agent_root = Path(args.registry_root).expanduser()

    agent_xroot = xitadel_root_from_agent_root(agent_root)
    reg_xroot = xitadel_root_from_agent_root(registry_agent_root)

    ensure_dirs(agent_xroot)
    ensure_dirs(reg_xroot)

    agent_signer = load_signer(agent_xroot / "keys")
    reg_signer = load_signer(reg_xroot / "keys")

    request_id = "req-" + secrets.token_hex(8)
    response_id = "resp-" + secrets.token_hex(8)
    ts = now_utc_iso()

    # 1) Append a request event in the agent xitadel
    req_payload = {
        "kind": "registry.request.v1",
        "request_id": request_id,
        "registry": "xkernelorg",
        "agent_name": args.agent_name or agent_root.name,
        "agent_root": str(agent_root),
        "ts": ts,
    }
    append_event(agent_xroot, agent_signer, "registry.request.v1", req_payload, ts=ts)

    # 2) Registry records receipt (optional but useful)
    reg_recv_payload = {
        "kind": "registry.request.received.v1",
        "request_id": request_id,
        "from_agent_root": str(agent_root),
        "observed_at": ts,
    }
    append_event(reg_xroot, reg_signer, "registry.request.received.v1", reg_recv_payload, ts=ts)

    # 3) Registry produces a signed response artifact file
    resp_artifact = {
        "schema": "xkernelorg.registry_response.local.v1",
        "response_id": response_id,
        "request_id": request_id,
        "registry": "xkernelorg",
        "issued_at": ts,
        "agent_root": str(agent_root),
        "agent_name": args.agent_name or agent_root.name,
    }
    sig = reg_signer.priv.sign(canonical(resp_artifact))
    resp_file_obj = dict(resp_artifact)
    resp_file_obj["registry_signature"] = {
        "kind": "ed25519",
        "kid": reg_signer.kid,
        "sig": base64.b64encode(sig).decode("utf-8"),
    }

    reg_resp_dir = reg_xroot / "registry" / "responses"
    agent_resp_dir = agent_xroot / "registry" / "responses"
    reg_resp_path = reg_resp_dir / f"{response_id}.json"
    agent_resp_path = agent_resp_dir / f"{response_id}.json"

    reg_resp_path.write_text(json.dumps(resp_file_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    agent_resp_path.write_text(json.dumps(resp_file_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 4) Agent appends registry.response.v1 pointing to the artifact
    resp_payload = {"kind": "registry.response.v1", "response_id": response_id, "request_id": request_id}
    append_event(agent_xroot, agent_signer, "registry.response.v1", resp_payload, ts=ts)

    print(json.dumps({
        "ok": True,
        "request_id": request_id,
        "response_id": response_id,
        "registry_response_path": str(agent_resp_path),
    }, indent=2))


def main() -> None:
    p = argparse.ArgumentParser(prog="midwife")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--name", required=True)
    p_init.add_argument("--root", required=True)
    p_init.add_argument("--platform", default=os.environ.get("HOST_PLATFORM", "termux"))
    p_init.add_argument("--device", default=os.environ.get("HOST_DEVICE", "android"))
    p_init.add_argument("--location-display", default=os.environ.get("DEFAULT_LOCATION_DISPLAY", "unknown"))
    p_init.add_argument("--location-precision", default=os.environ.get("DEFAULT_LOCATION_PRECISION", "city"))
    p_init.add_argument("--location-confidence", default=os.environ.get("DEFAULT_LOCATION_CONFIDENCE", "0.3"))
    p_init.set_defaults(fn=cmd_init)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--root", required=True)
    p_verify.set_defaults(fn=cmd_verify)

    p_query = sub.add_parser("query")
    p_query.add_argument("--root", required=True)
    p_query.add_argument("--q", required=True)
    p_query.set_defaults(fn=cmd_query)

    p_reg = sub.add_parser("register")
    p_reg.add_argument("--root", required=True, help="agent root being registered")
    p_reg.add_argument("--registry-root", required=True, help="xkernelorg agent root")
    p_reg.add_argument("--agent-name", default=None)
    p_reg.set_defaults(fn=cmd_register)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
