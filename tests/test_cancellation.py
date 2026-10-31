from __future__ import annotations

import asyncio
import unittest

from aiohttp.test_utils import make_mocked_request

from mobidesk_broker.app import GRANT_STORE_KEY, SUPABASE_KEY, create_app, rdp_websocket
from mobidesk_broker.config import BrokerConfig
from mobidesk_broker.grants import GrantStore


USER_ID = "b4f6658a-c29d-4aab-9c02-3b3d5a1ff3d2"
VM_ID = "640bfd92-7418-4266-b439-2a39169d7b2e"


class BlockingSupabase:
    def __init__(self):
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def resolve_user_vm(self, _access_token):
        self.started.set()
        await self.release.wait()
        return USER_ID, [{"vm_id": VM_ID, "vm_name": "win-01"}]


class CancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_assignment_recheck_releases_user_and_clears_token(self):
        config = BrokerConfig(
            supabase_url="https://unit-test.supabase.co",
            supabase_publishable_key="not-a-real-key",
            vm_endpoints={
                VM_ID: "192.168.122.11",
                "00000000-0000-4000-8000-000000000002": "192.168.122.12",
                "00000000-0000-4000-8000-000000000003": "192.168.122.13",
                "00000000-0000-4000-8000-000000000004": "192.168.122.14",
                "00000000-0000-4000-8000-000000000005": "192.168.122.15",
            },
            grant_cooldown_seconds=0,
        )
        store = GrantStore(ttl_seconds=60, cooldown_seconds=0)
        app = create_app(config, supabase_api=BlockingSupabase(), grant_store=store)
        raw, _ = await store.issue(USER_ID, VM_ID, "win-01", "short-lived-access-token")

        consumed_grants = []
        original_consume = store.consume

        async def capture_consume(value):
            grant = await original_consume(value)
            consumed_grants.append(grant)
            return grant

        store.consume = capture_consume
        request = make_mocked_request(
            "GET",
            "/v1/rdp",
            headers={"Authorization": f"Bearer {raw}"},
            app=app,
        )
        handler_task = asyncio.create_task(rdp_websocket(request))
        await app[SUPABASE_KEY].started.wait()
        handler_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await handler_task

        self.assertEqual(len(consumed_grants), 1)
        self.assertIsNone(consumed_grants[0].access_token)
        replacement, _ = await store.issue(USER_ID, VM_ID, "win-01", "new-token")
        self.assertTrue(replacement)
