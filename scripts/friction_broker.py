#!/usr/bin/env python3
"""Broker de fricción multi-host (plantilla ejecutable).

Sustituto de Redis cuando no hay infra: un proceso, muchos workers.
Producción: SMART_TOKEN_FRICTION_REDIS=redis://... y el mismo cliente.

Uso:
  python3 scripts/friction_broker.py --host 0.0.0.0 --port 9379
  export SMART_TOKEN_FRICTION_BROKER=127.0.0.1:9379
"""
from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from typing import Any, Dict, Optional


class _State:
    def __init__(self) -> None:
        self.data: Dict[str, Dict[str, Any]] = {}
        self.expiry: Dict[str, float] = {}
        self.locks: Dict[str, threading.Lock] = {}
        self.held: Dict[str, threading.Lock] = {}
        self.meta = threading.Lock()

    def _id_lock(self, identity: str) -> threading.Lock:
        with self.meta:
            if identity not in self.locks:
                self.locks[identity] = threading.Lock()
            return self.locks[identity]

    def _expired(self, identity: str) -> None:
        exp = self.expiry.get(identity)
        if exp is not None and time.time() > exp:
            self.data.pop(identity, None)
            self.expiry.pop(identity, None)

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        self._expired(identity)
        snap = self.data.get(identity)
        return dict(snap) if snap else None

    def save(self, identity: str, snap: Dict[str, Any], ttl: Optional[int]) -> None:
        self.data[identity] = dict(snap)
        if ttl:
            self.expiry[identity] = time.time() + int(ttl)
        else:
            self.expiry.pop(identity, None)

    def clear(self, identity: str) -> None:
        self.data.pop(identity, None)
        self.expiry.pop(identity, None)


STATE = _State()


def handle(msg: Dict[str, Any]) -> Dict[str, Any]:
    op = msg.get("op")
    identity = str(msg.get("id") or "")
    if not identity:
        return {"error": "missing id"}
    if op == "load":
        return {"snap": STATE.load(identity)}
    if op == "save":
        STATE.save(identity, msg.get("snap") or {}, msg.get("ttl"))
        return {"ok": True}
    if op == "clear":
        STATE.clear(identity)
        return {"ok": True}
    if op == "lock_load":
        lk = STATE._id_lock(identity)
        lk.acquire()
        STATE.held[identity] = lk
        return {"snap": STATE.load(identity)}
    if op == "lock_save":
        STATE.save(identity, msg.get("snap") or {}, msg.get("ttl"))
        lk = STATE.held.pop(identity, None)
        if lk and lk.locked():
            lk.release()
        return {"ok": True}
    if op in ("lock_clear", "lock_abort"):
        if op == "lock_clear":
            STATE.clear(identity)
        lk = STATE.held.pop(identity, None)
        if lk and lk.locked():
            lk.release()
        return {"ok": True}
    return {"error": f"unknown op {op}"}


def serve(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)
    print(f"friction-broker {host}:{port}", flush=True)

    def client(conn: socket.socket) -> None:
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                        resp = handle(msg)
                    except Exception as e:
                        resp = {"error": str(e)}
                    conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))

    while True:
        conn, _ = sock.accept()
        threading.Thread(target=client, args=(conn,), daemon=True).start()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9379)
    args = p.parse_args()
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
