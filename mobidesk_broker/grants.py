from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import secrets
import time


class SessionBusy(Exception):
    pass


class GrantRateLimited(Exception):
    pass


@dataclass
class Grant:
    user_id: str
    vm_id: str
    vm_name: str
    access_token: str | None
    deadline_monotonic: float


class GrantStore:
    """In-memory one-process grant store. Raw grants are returned once, never retained."""

    def __init__(
        self,
        ttl_seconds: int = 60,
        max_active_sessions: int = 5,
        cooldown_seconds: float = 2.0,
        clock=time.monotonic,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_active_sessions = max_active_sessions
        self.cooldown_seconds = cooldown_seconds
        self.clock = clock
        self._grants: dict[str, Grant] = {}
        self._user_to_hash: dict[str, str] = {}
        self._active_users: set[str] = set()
        self._last_issue: dict[str, float] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _digest(raw_grant: str) -> str:
        return hashlib.sha256(raw_grant.encode("utf-8")).hexdigest()

    def _purge_expired(self, now: float) -> None:
        expired = [digest for digest, grant in self._grants.items() if grant.deadline_monotonic <= now]
        for digest in expired:
            grant = self._grants.pop(digest)
            grant.access_token = None
            if self._user_to_hash.get(grant.user_id) == digest:
                self._user_to_hash.pop(grant.user_id, None)
        cooldown_lifetime = max(self.ttl_seconds, self.cooldown_seconds * 2, 60.0)
        stale_users = [user_id for user_id, issued_at in self._last_issue.items() if now - issued_at > cooldown_lifetime]
        for user_id in stale_users:
            self._last_issue.pop(user_id, None)

    async def purge_expired(self) -> None:
        async with self._lock:
            self._purge_expired(self.clock())

    async def issue(self, user_id: str, vm_id: str, vm_name: str, access_token: str) -> tuple[str, str]:
        async with self._lock:
            now = self.clock()
            self._purge_expired(now)
            if user_id in self._active_users or len(self._active_users) >= self.max_active_sessions:
                raise SessionBusy
            previous_issue = self._last_issue.get(user_id)
            if previous_issue is not None and now - previous_issue < self.cooldown_seconds:
                raise GrantRateLimited

            old_digest = self._user_to_hash.pop(user_id, None)
            if old_digest is not None:
                old_grant = self._grants.pop(old_digest, None)
                if old_grant is not None:
                    old_grant.access_token = None

            raw = secrets.token_urlsafe(32)
            digest = self._digest(raw)
            self._grants[digest] = Grant(
                user_id=user_id,
                vm_id=vm_id,
                vm_name=vm_name,
                access_token=access_token,
                deadline_monotonic=now + self.ttl_seconds,
            )
            self._user_to_hash[user_id] = digest
            self._last_issue[user_id] = now
            expires_at = (datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)).isoformat().replace("+00:00", "Z")
            return raw, expires_at

    async def consume(self, raw_grant: str) -> Grant | None:
        async with self._lock:
            now = self.clock()
            self._purge_expired(now)
            digest = self._digest(raw_grant)
            grant = self._grants.pop(digest, None)
            if grant is None:
                return None
            if self._user_to_hash.get(grant.user_id) == digest:
                self._user_to_hash.pop(grant.user_id, None)
            if grant.deadline_monotonic <= now:
                grant.access_token = None
                return None
            if grant.user_id in self._active_users or len(self._active_users) >= self.max_active_sessions:
                grant.access_token = None
                raise SessionBusy
            self._active_users.add(grant.user_id)
            return grant

    async def release(self, user_id: str) -> None:
        async with self._lock:
            self._active_users.discard(user_id)
