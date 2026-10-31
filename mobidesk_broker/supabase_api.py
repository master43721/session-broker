from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import aiohttp


MAX_SUPABASE_RESPONSE_BYTES = 32 * 1024


class InvalidAccessToken(Exception):
    """The Supabase Auth endpoint did not accept the supplied access token."""


class SupabaseUnavailable(Exception):
    """Supabase could not provide a valid, bounded response."""


class SupabaseAPI:
    def __init__(self, base_url: str, publishable_key: str, session: aiohttp.ClientSession):
        self.base_url = base_url.rstrip("/")
        self.publishable_key = publishable_key
        self.session = session

    def _headers(self, access_token: str) -> dict[str, str]:
        return {
            "apikey": self.publishable_key,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

    async def _read_json_limited(self, response: aiohttp.ClientResponse) -> Any:
        if response.content_length is not None and response.content_length > MAX_SUPABASE_RESPONSE_BYTES:
            raise SupabaseUnavailable
        raw = await response.content.read(MAX_SUPABASE_RESPONSE_BYTES + 1)
        if len(raw) > MAX_SUPABASE_RESPONSE_BYTES:
            raise SupabaseUnavailable
        return json.loads(raw.decode("utf-8"))

    async def resolve_user_vm(self, access_token: str) -> tuple[str, list[dict[str, str]]]:
        """Validate the bearer with Auth, then read only its RLS-visible VM assignments."""
        user_id = await self._resolve_user_id(access_token)
        assignments = await self._resolve_assignments(access_token, user_id)
        return user_id, assignments

    async def _resolve_user_id(self, access_token: str) -> str:
        try:
            async with self.session.get(
                f"{self.base_url}/auth/v1/user",
                headers=self._headers(access_token),
            ) as response:
                if response.status in (401, 403):
                    raise InvalidAccessToken
                if response.status != 200:
                    raise SupabaseUnavailable
                payload: Any = await self._read_json_limited(response)
        except InvalidAccessToken:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise SupabaseUnavailable from exc

        if not isinstance(payload, dict) or not payload.get("id"):
            raise InvalidAccessToken
        try:
            return str(uuid.UUID(str(payload["id"])))
        except (ValueError, AttributeError) as exc:
            raise InvalidAccessToken from exc

    async def _resolve_assignments(self, access_token: str, user_id: str) -> list[dict[str, str]]:
        params = {
            "select": "student_id,vm_id,vms(id,name)",
            "student_id": f"eq.{user_id}",
            "limit": "2",
        }
        try:
            async with self.session.get(
                f"{self.base_url}/rest/v1/student_vm_access",
                params=params,
                headers=self._headers(access_token),
            ) as response:
                if response.status in (401, 403):
                    raise InvalidAccessToken
                if response.status != 200:
                    raise SupabaseUnavailable
                payload: Any = await self._read_json_limited(response)
        except InvalidAccessToken:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise SupabaseUnavailable from exc

        if not isinstance(payload, list):
            raise SupabaseUnavailable

        assignments: list[dict[str, str]] = []
        for row in payload:
            if not isinstance(row, dict) or row.get("student_id") != user_id:
                raise SupabaseUnavailable
            try:
                vm_id = str(uuid.UUID(str(row["vm_id"])))
            except (KeyError, ValueError, AttributeError) as exc:
                raise SupabaseUnavailable from exc

            vm = row.get("vms")
            if isinstance(vm, list):
                if len(vm) != 1:
                    raise SupabaseUnavailable
                vm = vm[0]
            if not isinstance(vm, dict) or str(vm.get("id", "")) != vm_id:
                raise SupabaseUnavailable
            name = vm.get("name")
            if not isinstance(name, str) or not name or len(name) > 80 or any(ord(ch) < 32 for ch in name):
                raise SupabaseUnavailable
            assignments.append({"vm_id": vm_id, "vm_name": name})

        return assignments
