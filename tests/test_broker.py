from __future__ import annotations

import asyncio
import unittest

import aiohttp
from aiohttp import WSMsgType
from aiohttp.test_utils import TestClient, TestServer

from mobidesk_broker.app import create_app
from mobidesk_broker.config import BrokerConfig, validate_vm_endpoint
from mobidesk_broker.grants import GrantStore
from mobidesk_broker.supabase_api import InvalidAccessToken


USER_ID = "b4f6658a-c29d-4aab-9c02-3b3d5a1ff3d2"
VM_ID = "640bfd92-7418-4266-b439-2a39169d7b2e"
OTHER_VM_ID = "57475869-28ff-45a1-a17c-212497ef935f"


class FakeSupabase:
    def __init__(self, assignments=None):
        self.assignments = assignments if assignments is not None else [{"vm_id": VM_ID, "vm_name": "win-01"}]
        self.calls = 0

    async def resolve_user_vm(self, token: str):
        self.calls += 1
        if token != "valid-user-token":
            raise InvalidAccessToken
        return USER_ID, list(self.assignments)


class FakeWriter:
    def __init__(self):
        self.data = bytearray()
        self.wrote = asyncio.Event()
        self.closed = False

    def write(self, data: bytes):
        self.data.extend(data)
        self.wrote.set()

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.reader = asyncio.StreamReader()
        self.writer = FakeWriter()
        self.connector_calls = []
        self.fake_supabase = FakeSupabase()
        endpoints = {
            VM_ID: "192.168.122.11",
            OTHER_VM_ID: "fe80::1%br0",
            "00000000-0000-4000-8000-000000000003": "192.168.122.13",
            "00000000-0000-4000-8000-000000000004": "192.168.122.14",
            "00000000-0000-4000-8000-000000000005": "192.168.122.15",
        }
        self.config = BrokerConfig(
            supabase_url="https://unit-test.supabase.co",
            supabase_publishable_key="not-a-real-key",
            vm_endpoints=endpoints,
            grant_ttl_seconds=60,
            grant_cooldown_seconds=0,
            connect_timeout_seconds=1,
            heartbeat_seconds=2,
            max_message_bytes=1024 * 1024,
            max_session_seconds=60,
            idle_timeout_seconds=60,
            max_sessions=5,
        )

        async def fake_connector(host, port, timeout):
            self.connector_calls.append((host, port, timeout))
            return self.reader, self.writer

        self.app = create_app(
            self.config,
            supabase_api=self.fake_supabase,
            grant_store=GrantStore(ttl_seconds=60, cooldown_seconds=0, max_active_sessions=5),
            tcp_connector=fake_connector,
        )

    async def asyncSetUp(self):
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()

    async def _create_grant(self):
        response = await self.client.post(
            "/v1/session-grants",
            headers={"Authorization": "Bearer valid-user-token"},
        )
        self.assertEqual(response.status, 201)
        return await response.json()

    async def test_health_has_no_configuration_details(self):
        response = await self.client.get("/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.json(), {"status": "ok"})

    async def test_missing_bearer_is_rejected(self):
        response = await self.client.post("/v1/session-grants")
        self.assertEqual(response.status, 401)
        self.assertEqual(self.fake_supabase.calls, 0)

    async def test_grant_ignores_client_supplied_identity_and_endpoint(self):
        response = await self.client.post(
            "/v1/session-grants",
            headers={"Authorization": "Bearer valid-user-token"},
            json={"user_id": "attacker", "vm_id": OTHER_VM_ID, "hostname": "127.0.0.1"},
        )
        self.assertEqual(response.status, 201)
        body = await response.json()
        self.assertEqual(body["vm"], {"id": VM_ID, "name": "win-01"})
        self.assertEqual(body["websocketPath"], "/v1/rdp")
        self.assertNotIn("hostname", body)
        self.assertEqual(self.connector_calls, [])

    async def test_invalid_supabase_token_is_rejected(self):
        response = await self.client.post(
            "/v1/session-grants",
            headers={"Authorization": "Bearer invalid"},
        )
        self.assertEqual(response.status, 401)

    async def test_no_assignment_is_rejected(self):
        self.fake_supabase.assignments = []
        response = await self.client.post(
            "/v1/session-grants",
            headers={"Authorization": "Bearer valid-user-token"},
        )
        self.assertEqual(response.status, 403)

    async def test_multiple_assignments_fail_closed(self):
        self.fake_supabase.assignments = [
            {"vm_id": VM_ID, "vm_name": "win-01"},
            {"vm_id": OTHER_VM_ID, "vm_name": "win-02"},
        ]
        response = await self.client.post(
            "/v1/session-grants",
            headers={"Authorization": "Bearer valid-user-token"},
        )
        self.assertEqual(response.status, 409)

    async def test_vm_not_in_server_allowlist_is_rejected(self):
        self.fake_supabase.assignments = [{"vm_id": "a3ed8e5f-1054-4bc3-b982-1686a2d85642", "vm_name": "unknown"}]
        response = await self.client.post(
            "/v1/session-grants",
            headers={"Authorization": "Bearer valid-user-token"},
        )
        self.assertEqual(response.status, 503)

    async def test_assignment_is_rechecked_before_websocket_upgrade(self):
        body = await self._create_grant()
        self.fake_supabase.assignments = []
        with self.assertRaises(aiohttp.WSServerHandshakeError) as error:
            await self.client.ws_connect(
                "/v1/rdp",
                headers={"Authorization": f"Bearer {body['grant']}"},
            )
        self.assertEqual(error.exception.status, 403)
        self.assertEqual(self.connector_calls, [])

    async def test_binary_websocket_bridges_both_directions_and_grant_is_single_use(self):
        body = await self._create_grant()
        websocket = await self.client.ws_connect(
            "/v1/rdp",
            headers={"Authorization": f"Bearer {body['grant']}"},
        )
        self.assertEqual(self.connector_calls[0][0:2], ("192.168.122.11", 3389))
        await websocket.send_bytes(b"client-to-rdp")
        await asyncio.wait_for(self.writer.wrote.wait(), timeout=1)
        self.assertEqual(bytes(self.writer.data), b"client-to-rdp")

        self.reader.feed_data(b"rdp-to-client")
        frame = await websocket.receive(timeout=1)
        self.assertEqual(frame.type, WSMsgType.BINARY)
        self.assertEqual(frame.data, b"rdp-to-client")
        await websocket.close()

        with self.assertRaises(aiohttp.WSServerHandshakeError) as error:
            await self.client.ws_connect(
                "/v1/rdp",
                headers={"Authorization": f"Bearer {body['grant']}"},
            )
        self.assertEqual(error.exception.status, 401)
        self.assertTrue(self.writer.closed)


class GrantStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_grant_is_one_use_and_raw_token_is_not_retained(self):
        store = GrantStore(ttl_seconds=60, cooldown_seconds=0)
        raw, _ = await store.issue(USER_ID, VM_ID, "win-01", "supabase-access-token")
        self.assertNotIn(raw, store._grants)
        grant = await store.consume(raw)
        self.assertIsNotNone(grant)
        self.assertEqual(grant.access_token, "supabase-access-token")
        self.assertIsNone(await store.consume(raw))
        await store.release(USER_ID)

    async def test_expired_grant_is_rejected_and_token_cleared(self):
        now = [100.0]
        store = GrantStore(ttl_seconds=3, cooldown_seconds=0, clock=lambda: now[0])
        raw, _ = await store.issue(USER_ID, VM_ID, "win-01", "token")
        stored_grant = next(iter(store._grants.values()))
        now[0] = 104.0
        self.assertIsNone(await store.consume(raw))
        self.assertIsNone(stored_grant.access_token)

    async def test_new_grant_revokes_previous_pending_grant(self):
        store = GrantStore(ttl_seconds=60, cooldown_seconds=0)
        first, _ = await store.issue(USER_ID, VM_ID, "win-01", "token")
        second, _ = await store.issue(USER_ID, VM_ID, "win-01", "token")
        self.assertIsNone(await store.consume(first))
        self.assertIsNotNone(await store.consume(second))


class EndpointValidationTests(unittest.TestCase):
    def test_private_and_scoped_link_local_endpoints_are_accepted(self):
        self.assertEqual(validate_vm_endpoint("172.16.33.137"), "172.16.33.137")
        self.assertEqual(validate_vm_endpoint("fe80::c44d:f2ee:aca8:652e%br0"), "fe80::c44d:f2ee:aca8:652e%br0")

    def test_public_hostname_and_unscoped_link_local_are_rejected(self):
        for value in ("rdp.example.com", "8.8.8.8", "fe80::1", "127.0.0.1"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_vm_endpoint(value)

    def test_non_loopback_bind_is_rejected(self):
        with self.assertRaises(ValueError):
            BrokerConfig(
                supabase_url="https://unit-test.supabase.co",
                supabase_publishable_key="not-a-real-key",
                vm_endpoints={
                    VM_ID: "192.168.122.11",
                    OTHER_VM_ID: "192.168.122.12",
                    "00000000-0000-4000-8000-000000000003": "192.168.122.13",
                    "00000000-0000-4000-8000-000000000004": "192.168.122.14",
                    "00000000-0000-4000-8000-000000000005": "192.168.122.15",
                },
                bind_host="0.0.0.0",
            )

    def test_endpoint_mapping_is_copied_and_immutable(self):
        endpoints = {
            VM_ID: "192.168.122.11",
            OTHER_VM_ID: "192.168.122.12",
            "00000000-0000-4000-8000-000000000003": "192.168.122.13",
            "00000000-0000-4000-8000-000000000004": "192.168.122.14",
            "00000000-0000-4000-8000-000000000005": "192.168.122.15",
        }
        config = BrokerConfig(
            supabase_url="https://unit-test.supabase.co",
            supabase_publishable_key="not-a-real-key",
            vm_endpoints=endpoints,
        )
        endpoints[VM_ID] = "8.8.8.8"
        self.assertEqual(config.vm_endpoints[VM_ID], "192.168.122.11")
        with self.assertRaises(TypeError):
            config.vm_endpoints[VM_ID] = "8.8.8.8"


if __name__ == "__main__":
    unittest.main()
