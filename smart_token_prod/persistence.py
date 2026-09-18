"""
Persistencia compartida del estado de fricción.

Sin store + lock, cada réplica tiene su propio fail_count y el atacante
reparte intentos. FileFrictionStore usa un archivo por identidad y flock
exclusivo: N procesos / workers sobre el mismo disco ven UN contador.

RedisFrictionStore usa SET NX + TTL como lock de sección crítica.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore


class FrictionStore(ABC):
    @abstractmethod
    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        ...

    @abstractmethod
    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        ...

    @abstractmethod
    def clear(self, identity: str) -> None:
        ...

    def locked_update(
        self,
        identity: str,
        mutator: Callable[[Optional[Dict[str, Any]]], Optional[Dict[str, Any]]],
        ttl_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Load → mutator → save/clear under exclusive lock. Default: no lock."""
        current = self.load(identity)
        nxt = mutator(current)
        if nxt is None:
            self.clear(identity)
            return None
        self.save(identity, nxt, ttl_seconds)
        return nxt


class InMemoryFrictionStore(FrictionStore):
    """Un solo proceso. No sirve como store de réplicas."""

    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._expiry: Dict[str, float] = {}

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        exp = self._expiry.get(identity)
        if exp is not None and time.time() > exp:
            self._data.pop(identity, None)
            self._expiry.pop(identity, None)
            return None
        snap = self._data.get(identity)
        return dict(snap) if snap is not None else None

    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        self._data[identity] = dict(snapshot)
        if ttl_seconds is not None:
            self._expiry[identity] = time.time() + ttl_seconds
        else:
            self._expiry.pop(identity, None)

    def clear(self, identity: str) -> None:
        self._data.pop(identity, None)
        self._expiry.pop(identity, None)


class FileFrictionStore(FrictionStore):
    """Store compartido en disco. Réplicas locales / NFS con flock."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _safe(self, identity: str) -> str:
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def _data_path(self, identity: str) -> Path:
        return self.root / f"{self._safe(identity)}.json"

    def _lock_path(self, identity: str) -> Path:
        return self.root / f"{self._safe(identity)}.lock"

    @contextmanager
    def _lock(self, identity: str) -> Iterator[None]:
        """Exclusive flock on a durable per-identity lock inode.

        The `.lock` file is created once and NEVER unlinked by this store
        (clear only removes `.json`). Unlink+recreate of the lock path by an
        attacker is still possible; callers needing stronger guarantees should
        use Redis/broker. Best-effort: we also refuse to proceed if the lock
        path inode changes mid-section (detects replacement).
        """
        lock_path = self._lock_path(identity)
        lock_path.touch(exist_ok=True)
        with open(lock_path, "a+b") as fh:
            if fcntl is None:
                yield
                return
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            st0 = os.fstat(fh.fileno())
            try:
                st_path = os.stat(lock_path)
                if (st_path.st_dev, st_path.st_ino) != (st0.st_dev, st0.st_ino):
                    raise RuntimeError(
                        f"FileFrictionStore lock path replaced under flock: {lock_path}"
                    )
                yield
                st_path2 = os.stat(lock_path)
                if (st_path2.st_dev, st_path2.st_ino) != (st0.st_dev, st0.st_ino):
                    raise RuntimeError(
                        f"FileFrictionStore lock path replaced under flock: {lock_path}"
                    )
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        path = self._data_path(identity)
        if not path.is_file():
            return None
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return None
        data = json.loads(raw)
        exp = data.get("_expires_at")
        if exp is not None and time.time() > float(exp):
            path.unlink(missing_ok=True)
            return None
        data.pop("_expires_at", None)
        return data

    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        payload = dict(snapshot)
        if ttl_seconds is not None:
            payload["_expires_at"] = time.time() + int(ttl_seconds)
        target = self._data_path(identity)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.replace(tmp, target)

    def clear(self, identity: str) -> None:
        # Only data file — durable .lock inode retained to avoid unlink bypass.
        self._data_path(identity).unlink(missing_ok=True)

    def locked_update(
        self,
        identity: str,
        mutator: Callable[[Optional[Dict[str, Any]]], Optional[Dict[str, Any]]],
        ttl_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock(identity):
            current = self.load(identity)
            nxt = mutator(current)
            if nxt is None:
                self.clear(identity)
                return None
            self.save(identity, nxt, ttl_seconds)
            return nxt


class RedisFrictionStore(FrictionStore):
    """Lock SET NX + GET/SET. Requiere cliente redis-py conectado."""

    def __init__(self, redis_client, key_prefix: str = "smarttoken:friction:"):
        self._r = redis_client
        self._prefix = key_prefix

    def _key(self, identity: str) -> str:
        return f"{self._prefix}{identity}"

    def _lock_key(self, identity: str) -> str:
        return f"{self._prefix}lock:{identity}"

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        raw = self._r.get(self._key(identity))
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)

    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        payload = json.dumps(snapshot)
        if ttl_seconds is not None:
            self._r.setex(self._key(identity), ttl_seconds, payload)
        else:
            self._r.set(self._key(identity), payload)

    def clear(self, identity: str) -> None:
        self._r.delete(self._key(identity))

    def locked_update(
        self,
        identity: str,
        mutator: Callable[[Optional[Dict[str, Any]]], Optional[Dict[str, Any]]],
        ttl_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        token = f"{os.getpid()}-{time.time_ns()}"
        lock_key = self._lock_key(identity)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if self._r.set(lock_key, token, nx=True, ex=5):
                try:
                    current = self.load(identity)
                    nxt = mutator(current)
                    if nxt is None:
                        self.clear(identity)
                    else:
                        self.save(identity, nxt, ttl_seconds)
                    return nxt
                finally:
                    if self._r.get(lock_key) in (token, token.encode()):
                        self._r.delete(lock_key)
            time.sleep(0.01)
        raise TimeoutError(f"RedisFrictionStore lock timeout for {identity}")


class PersistentTarpit:
    """Tarpit cuyo fail_count vive en un FrictionStore (con lock si el store lo da)."""

    def __init__(self, tarpit, store: FrictionStore, identity: str, ttl_seconds: Optional[int] = None):
        self._tarpit = tarpit
        self._store = store
        self._identity = identity
        self._ttl = ttl_seconds
        saved = self._store.load(self._identity)
        if saved:
            if hasattr(self._tarpit, "restore_snapshot"):
                self._tarpit.restore_snapshot(saved)
            else:
                for _ in range(int(saved.get("fail_count", 0) or 0)):
                    self._tarpit.register_failure()

    def register_failure(self):
        def mutator(current):
            if current and hasattr(self._tarpit, "restore_snapshot"):
                self._tarpit.restore_snapshot(current)
            result_holder["info"] = self._tarpit.register_failure()
            return self._tarpit.snapshot()

        result_holder: Dict[str, Any] = {}
        self._store.locked_update(self._identity, mutator, self._ttl)
        return result_holder.get("info") or self._tarpit.snapshot()

    def reset(self) -> None:
        self._tarpit.reset()
        self._store.clear(self._identity)

    def snapshot(self) -> Dict[str, Any]:
        saved = self._store.load(self._identity)
        if saved:
            return dict(saved)
        return self._tarpit.snapshot()


def merge_friction(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Keep the harsher snapshot so a stale replica cannot reset the trap."""
    if not a:
        return dict(b) if b else None
    if not b:
        return dict(a)
    fa, fb = int(a.get("fail_count", 0) or 0), int(b.get("fail_count", 0) or 0)
    if fb > fa:
        return dict(b)
    if fa > fb:
        return dict(a)
    oa, ob = int(a.get("validations_ok", 0) or 0), int(b.get("validations_ok", 0) or 0)
    return dict(b if ob >= oa else a)


class BrokerFrictionStore(FrictionStore):
    """Cliente del broker TCP (scripts/friction_broker.py). Misma API que Redis."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9379, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)

    def _rpc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        import socket
        raw = (json.dumps(payload) + "\n").encode("utf-8")
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
            s.sendall(raw)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        if not buf:
            raise ConnectionError("friction broker closed")
        resp = json.loads(buf.decode("utf-8"))
        if resp.get("error"):
            raise RuntimeError(resp["error"])
        return resp

    def load(self, identity: str) -> Optional[Dict[str, Any]]:
        snap = self._rpc({"op": "load", "id": identity}).get("snap")
        return dict(snap) if snap else None

    def save(self, identity: str, snapshot: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        self._rpc({"op": "save", "id": identity, "snap": snapshot, "ttl": ttl_seconds})

    def clear(self, identity: str) -> None:
        self._rpc({"op": "clear", "id": identity})

    def locked_update(
        self,
        identity: str,
        mutator: Callable[[Optional[Dict[str, Any]]], Optional[Dict[str, Any]]],
        ttl_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        current = self._rpc({"op": "lock_load", "id": identity}).get("snap")
        current = dict(current) if current else None
        try:
            nxt = mutator(current)
            if nxt is None:
                self._rpc({"op": "lock_clear", "id": identity})
                return None
            self._rpc({"op": "lock_save", "id": identity, "snap": nxt, "ttl": ttl_seconds})
            return nxt
        except Exception:
            self._rpc({"op": "lock_abort", "id": identity})
            raise


def store_from_env() -> Optional[FrictionStore]:
    """Plantilla: cambia una variable y corre.

    SMART_TOKEN_FRICTION_REDIS=redis://host:6379/0
    SMART_TOKEN_FRICTION_BROKER=127.0.0.1:9379
    SMART_TOKEN_FRICTION_DIR=/var/lib/smart-token/friction
    """
    redis_url = os.environ.get("SMART_TOKEN_FRICTION_REDIS", "").strip()
    if redis_url:
        try:
            import redis as redis_lib
        except ImportError as e:
            raise ImportError("pip install redis") from e
        return RedisFrictionStore(redis_lib.Redis.from_url(redis_url))
    broker = os.environ.get("SMART_TOKEN_FRICTION_BROKER", "").strip()
    if broker:
        host, _, port = broker.partition(":")
        return BrokerFrictionStore(host or "127.0.0.1", int(port or "9379"))
    root = os.environ.get("SMART_TOKEN_FRICTION_DIR", "").strip()
    if root:
        return FileFrictionStore(root)
    return None
