from __future__ import annotations

import unittest

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer

from mobidesk_broker.supabase_api import InvalidAccessToken, SupabaseAPI, SupabaseUnavailable


USER_ID = "b4f6658a-c29d-4aab-9c02-3b3d5a1ff3d2"
VM_ID = "640bfd92-7418-4266-b439-2a39169d7b2e"


class SupabaseAPITests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.auth_requests = []
        self.rest_requests = []
        self.auth_status = 200
        self.assignment_body = [{"student_id": USER_ID, "vm_id": VM_ID, "vms": {"id": VM_ID, "name": "win-01"}}]
        self.large_assignment_response = False

        async def auth_handler(request: web.Request) -> web.Response:
            normalized_headers = {key.lower(): value for key, value in request.headers.items()}
            self.auth_requests.append((normalized_headers, dict(request.query)))
            if self.auth_status != 200:
                return web.Response(status=self.auth_status, text="rejected")
            return web.json_response({"id": USER_ID, "email": "student@example.invalid"})

        async def assignment_handler(request: web.Request) -> web.Response:
            normalized_headers = {key.lower(): value for key, value in request.headers.items()}
            self.rest_requests.append((normalized_headers, dict(request.query)))
            if self.large_assignment_response:
                return web.Response(text="[" + (" " * 40_000) + "]", content_type="application/json")
            return web.json_response(self.assignment_body)

        app = web.Application()
        app.router.add_get("/auth/v1/user", auth_handler)
        app.router.add_get("/rest/v1/student_vm_access", assignment_handler)
        self.server = TestServer(app)

    async def asyncSetUp(self):
        await self.server.start_server()
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3))
        self.api = SupabaseAPI(str(self.server.make_url("/")).rstrip("/"), "test-publishable-key", self.session)

    async def asyncTearDown(self):
        await self.session.close()
        await self.server.close()

    async def test_validates_user_and_queries_only_rls_assignment(self):
        user_id, assignments = await self.api.resolve_user_vm("valid-access-token")
        self.assertEqual(user_id, USER_ID)
        self.assertEqual(assignments, [{"vm_id": VM_ID, "vm_name": "win-01"}])
        self.assertEqual(self.auth_requests[0][0]["authorization"], "Bearer valid-access-token")
        self.assertEqual(self.auth_requests[0][0]["apikey"], "test-publishable-key")
        headers, query = self.rest_requests[0]
        self.assertEqual(headers["authorization"], "Bearer valid-access-token")
        self.assertEqual(headers["apikey"], "test-publishable-key")
        self.assertEqual(query["student_id"], f"eq.{USER_ID}")
        self.assertEqual(query["limit"], "2")
        self.assertEqual(query["select"], "student_id,vm_id,vms(id,name)")

    async def test_invalid_auth_token_fails_before_assignment_query(self):
        self.auth_status = 401
        with self.assertRaises(InvalidAccessToken):
            await self.api.resolve_user_vm("bad-token")
        self.assertEqual(self.rest_requests, [])

    async def test_oversized_assignment_response_fails_closed(self):
        self.large_assignment_response = True
        with self.assertRaises(SupabaseUnavailable):
            await self.api.resolve_user_vm("valid-access-token")

    async def test_assignment_for_another_user_fails_closed(self):
        self.assignment_body = [{"student_id": "a55953f1-3166-4714-9c64-ac2440b19e6c", "vm_id": VM_ID, "vms": {"id": VM_ID, "name": "win-01"}}]
        with self.assertRaises(SupabaseUnavailable):
            await self.api.resolve_user_vm("valid-access-token")


if __name__ == "__main__":
    unittest.main()
