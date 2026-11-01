from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp
from aiohttp import WSMsgType, web

from .config import BrokerConfig
from .grants import Grant, GrantCapacityExceeded, GrantRateLimited, GrantStore, SessionBusy
from .supabase_api import InvalidAccessToken, SupabaseAPI, SupabaseUnavailable


TcpConnector = Callable[[str, int, float], Awaitable[tuple[asyncio.StreamReader, Any]]]
CONFIG_KEY = web.AppKey("config", BrokerConfig)
SUPABASE_KEY = web.AppKey("supabase_api", object)
GRANT_STORE_KEY = web.AppKey("grant_store", GrantStore)
TCP_CONNECTOR_KEY = web.AppKey("tcp_connector", object)


def _bearer(headers: Any) -> str | None:
    value = headers.get("Authorization", "")
    scheme, separator, token = value.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token or token.strip() != token:
        return None
    return token


async def _default_tcp_connector(host: str, port: int, timeout: float) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)


async def _supabase_context(app: web.Application):
    config: BrokerConfig = app[CONFIG_KEY]
    timeout = aiohttp.ClientTimeout(total=config.supabase_timeout_seconds, connect=min(3.0, config.supabase_timeout_seconds))
    session = aiohttp.ClientSession(timeout=timeout)
    app[SUPABASE_KEY] = SupabaseAPI(config.supabase_url, config.supabase_publishable_key, session)
    try:
        yield
    finally:
        await session.close()


async def _grant_sweeper(app: web.Application):
    store: GrantStore = app[GRANT_STORE_KEY]

    async def sweep() -> None:
        interval = min(10.0, max(1.0, store.ttl_seconds / 2))
        while True:
            await asyncio.sleep(interval)
            await store.purge_expired()

    task = asyncio.create_task(sweep())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def create_app(
    config: BrokerConfig,
    *,
    supabase_api: Any | None = None,
    grant_store: GrantStore | None = None,
    tcp_connector: TcpConnector | None = None,
) -> web.Application:
    config.validate()
    app = web.Application(client_max_size=64 * 1024)
    app[CONFIG_KEY] = config
    app[SUPABASE_KEY] = supabase_api
    app[GRANT_STORE_KEY] = grant_store or GrantStore(
        ttl_seconds=config.grant_ttl_seconds,
        max_active_sessions=config.max_sessions,
        max_pending_grants=config.max_pending_grants,
        cooldown_seconds=config.grant_cooldown_seconds,
    )
    app[TCP_CONNECTOR_KEY] = tcp_connector or _default_tcp_connector
    app.cleanup_ctx.append(_grant_sweeper)
    if supabase_api is None:
        app.cleanup_ctx.append(_supabase_context)

    app.router.add_get("/health", health)
    app.router.add_post("/v1/session-grants", create_session_grant)
    app.router.add_get("/v1/rdp", rdp_websocket)
    return app


async def health(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"}, headers={"Cache-Control": "no-store"})


async def create_session_grant(request: web.Request) -> web.Response:
    access_token = _bearer(request.headers)
    if access_token is None:
        return web.json_response({"error": "authentication_required"}, status=401, headers={"Cache-Control": "no-store"})

    config: BrokerConfig = request.app[CONFIG_KEY]
    supabase: SupabaseAPI = request.app[SUPABASE_KEY]
    store: GrantStore = request.app[GRANT_STORE_KEY]
    try:
        user_id, assignments = await supabase.resolve_user_vm(access_token)
    except InvalidAccessToken:
        return web.json_response({"error": "invalid_or_expired_session"}, status=401, headers={"Cache-Control": "no-store"})
    except SupabaseUnavailable:
        return web.json_response({"error": "identity_service_unavailable"}, status=502, headers={"Cache-Control": "no-store"})

    if len(assignments) == 0:
        return web.json_response({"error": "no_vm_assigned"}, status=403, headers={"Cache-Control": "no-store"})
    if len(assignments) != 1:
        return web.json_response({"error": "assignment_conflict"}, status=409, headers={"Cache-Control": "no-store"})

    assignment = assignments[0]
    vm_id = assignment["vm_id"]
    vm_name = assignment["vm_name"]
    if vm_id not in config.vm_endpoints:
        return web.json_response({"error": "vm_not_available"}, status=503, headers={"Cache-Control": "no-store"})

    try:
        raw_grant, expires_at = await store.issue(
            user_id=user_id,
            vm_id=vm_id,
            vm_name=vm_name,
            access_token=access_token,
        )
    except GrantRateLimited:
        return web.json_response({"error": "please_wait_before_retrying"}, status=429, headers={"Cache-Control": "no-store", "Retry-After": "2"})
    except GrantCapacityExceeded:
        return web.json_response({"error": "broker_temporarily_busy"}, status=503, headers={"Cache-Control": "no-store", "Retry-After": "2"})
    except SessionBusy:
        return web.json_response({"error": "session_limit_reached"}, status=409, headers={"Cache-Control": "no-store"})

    return web.json_response(
        {
            "grant": raw_grant,
            "expiresAt": expires_at,
            "websocketPath": "/v1/rdp",
            "vm": {"id": vm_id, "name": vm_name},
        },
        status=201,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _cleanup_session(writer: Any | None, store: GrantStore, grant: Grant) -> None:
    try:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    finally:
        grant.access_token = None
        await store.release(grant.user_id)


async def rdp_websocket(request: web.Request) -> web.StreamResponse:
    raw_grant = _bearer(request.headers)
    if raw_grant is None:
        return web.json_response({"error": "grant_required"}, status=401, headers={"Cache-Control": "no-store"})

    store: GrantStore = request.app[GRANT_STORE_KEY]
    try:
        grant: Grant | None = await store.consume(raw_grant)
    except SessionBusy:
        return web.json_response({"error": "session_limit_reached"}, status=409, headers={"Cache-Control": "no-store"})
    if grant is None:
        return web.json_response({"error": "invalid_or_expired_grant"}, status=401, headers={"Cache-Control": "no-store"})

    writer: Any | None = None
    try:
        config: BrokerConfig = request.app[CONFIG_KEY]
        supabase: SupabaseAPI = request.app[SUPABASE_KEY]
        access_token = grant.access_token
        try:
            if not access_token:
                return web.json_response({"error": "invalid_or_expired_session"}, status=401, headers={"Cache-Control": "no-store"})
            current_user_id, current_assignments = await supabase.resolve_user_vm(access_token)
        except InvalidAccessToken:
            return web.json_response({"error": "invalid_or_expired_session"}, status=401, headers={"Cache-Control": "no-store"})
        except SupabaseUnavailable:
            return web.json_response({"error": "identity_service_unavailable"}, status=502, headers={"Cache-Control": "no-store"})
        finally:
            grant.access_token = None
            access_token = None

        if (
            current_user_id != grant.user_id
            or len(current_assignments) != 1
            or current_assignments[0]["vm_id"] != grant.vm_id
        ):
            return web.json_response({"error": "assignment_changed"}, status=403, headers={"Cache-Control": "no-store"})

        endpoint = config.vm_endpoints.get(grant.vm_id)
        if endpoint is None:
            return web.json_response({"error": "vm_not_available"}, status=503, headers={"Cache-Control": "no-store"})

        connector: TcpConnector = request.app[TCP_CONNECTOR_KEY]
        try:
            reader, writer = await connector(endpoint, 3389, config.connect_timeout_seconds)
        except (OSError, asyncio.TimeoutError, ValueError):
            return web.json_response({"error": "vm_unreachable"}, status=502, headers={"Cache-Control": "no-store"})

        websocket = web.WebSocketResponse(
            heartbeat=config.heartbeat_seconds,
            max_msg_size=config.max_message_bytes,
            autoping=True,
            autoclose=True,
        )
        await websocket.prepare(request)
        await _bridge(websocket, reader, writer, config)
        return websocket
    finally:
        cleanup_task = asyncio.create_task(_cleanup_session(writer, store, grant))
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await cleanup_task
            raise


async def _bridge(
    websocket: web.WebSocketResponse,
    reader: asyncio.StreamReader,
    writer: Any,
    config: BrokerConfig,
) -> None:
    last_activity = [time.monotonic()]

    async def tcp_to_websocket() -> None:
        while not websocket.closed:
            data = await reader.read(32 * 1024)
            if not data:
                if not websocket.closed:
                    await websocket.close(code=1001, message=b"RDP stream closed")
                return
            last_activity[0] = time.monotonic()
            await websocket.send_bytes(data)

    async def websocket_to_tcp() -> None:
        async for message in websocket:
            if message.type == WSMsgType.BINARY:
                writer.write(message.data)
                await writer.drain()
                last_activity[0] = time.monotonic()
            elif message.type == WSMsgType.TEXT:
                await websocket.close(code=1003, message=b"Binary frames required")
                return
            elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
                return

    async def idle_watchdog() -> None:
        while not websocket.closed:
            await asyncio.sleep(min(30, max(1, config.idle_timeout_seconds // 4)))
            if time.monotonic() - last_activity[0] >= config.idle_timeout_seconds:
                await websocket.close(code=1001, message=b"Idle timeout")
                return

    tasks = {
        asyncio.create_task(tcp_to_websocket()),
        asyncio.create_task(websocket_to_tcp()),
        asyncio.create_task(idle_watchdog()),
    }
    try:
        done, _ = await asyncio.wait(
            tasks,
            timeout=config.max_session_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not done and not websocket.closed:
            await websocket.close(code=1001, message=b"Session time limit")
        elif done and not websocket.closed:
            await websocket.close(code=1000, message=b"Session ended")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    config = BrokerConfig.from_env()
    app = create_app(config)
    web.run_app(app, host=config.bind_host, port=config.port, access_log=None)


if __name__ == "__main__":
    main()
