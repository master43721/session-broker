from __future__ import annotations

import asyncio
import unittest

from mobidesk_broker.grants import GrantStore, SessionBusy


USER_ID = "b4f6658a-c29d-4aab-9c02-3b3d5a1ff3d2"
VM_ID = "640bfd92-7418-4266-b439-2a39169d7b2e"


class GrantConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_simultaneous_consumption_has_exactly_one_winner(self):
        store = GrantStore(ttl_seconds=60, cooldown_seconds=0)
        raw, _ = await store.issue(USER_ID, VM_ID, "win-01", "token")
        results = await asyncio.gather(store.consume(raw), store.consume(raw))
        self.assertEqual(sum(result is not None for result in results), 1)
        await store.release(USER_ID)

    async def test_active_user_cannot_issue_another_grant(self):
        store = GrantStore(ttl_seconds=60, cooldown_seconds=0)
        raw, _ = await store.issue(USER_ID, VM_ID, "win-01", "token")
        self.assertIsNotNone(await store.consume(raw))
        with self.assertRaises(SessionBusy):
            await store.issue(USER_ID, VM_ID, "win-01", "token")
        await store.release(USER_ID)
