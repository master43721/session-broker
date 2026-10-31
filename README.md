# MobiDesk session broker and RDP relay

This isolated Python prototype authorizes short-lived access to one assigned Windows VM and relays binary WebSocket frames to that VM's RDP TCP port. It does not change the Android checkout or replace Google AI Studio as the Android development workspace.

## Security model

1. Android signs in with Supabase Auth and sends its access token to `POST /v1/session-grants` in an HTTPS `Authorization: Bearer` header.
2. The broker validates that token through Supabase Auth (`/auth/v1/user`) using the Supabase **publishable/anon key**. It then reads `student_vm_access` and the related `vms(id,name)` using the same student's bearer token, so Supabase RLS remains in force. No service-role key is used.
3. The broker requires exactly one assignment and requires that VM ID to exist in a server-local allowlist. The client cannot select a VM, hostname, IP, or port.
4. The broker returns a random, single-use, 60-second grant. Only its SHA-256 digest is retained. The associated Supabase access token is held only in the pending in-memory grant, proactively cleared on expiry/replacement, and erased immediately after the WebSocket assignment recheck.
5. `GET /v1/rdp` accepts `Authorization: Bearer <grant>`, consumes it once, revalidates the assignment, and connects only to the configured private endpoint on TCP/3389. Binary WebSocket and TCP data are relayed bidirectionally with bounded message sizes, heartbeat, idle timeout, maximum session duration, per-user exclusion, and a five-session global cap.

The process defaults to `127.0.0.1:8766`; both environment-loaded and directly constructed configurations enforce loopback binding, exactly five UUID-keyed private VM endpoints, and bounded runtime settings. Do not expose the port directly. No public tunnel is configured by this prototype.

## Important credential boundary

Supabase sign-in only authorizes which VM a student may reach. This relay does **not** authenticate Windows/RDP, inject credentials, or provide Windows SSO. Students still need valid Windows guest credentials, provisioned separately from Supabase. Never reuse Supabase passwords. No Windows accounts or passwords have been created or stored by this project.

## Current integration state

The broker's server-side endpoint file must be keyed by the authorized VM UUIDs and their private server-reachable IP literals. Keep student assignments, VM identifiers, and private endpoint addresses in access-controlled systems; do not publish them in this repository. The broker must not read a target host from the client or from a public request field.

Before deployment, choose an authorized process-persistence method and configure the publishable key and endpoint addresses in a mode-0600 server-side environment file. Do not put credentials or private VM addresses into this public repository. This prototype does not include production credentials, VM endpoint configuration, or deployment automation.

The current AI Studio workspace did not transfer its ZIP source into the sandbox. Native FreeRDP source/JNI libraries and Android's local TCP-to-WebSocket client still need verification and implementation in AI Studio. This backend prototype is not an end-to-end APK.

## Development and tests

Python 3.10+ is supported. Install dependencies in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Run only after supplying all server-side configuration:

```bash
set -a
. ./.env
set +a
python -m mobidesk_broker.app
```

`MOBIDESK_VM_ENDPOINTS_JSON` must contain exactly five UUID-to-private-IP mappings. IPv6 link-local endpoints must include their server interface scope (for example `%br0`). The service hardcodes destination port 3389 and rejects hostnames, public addresses, loopback endpoints, and unscoped link-local IPv6.

## API contract

### Create grant

`POST /v1/session-grants`

Headers: `Authorization: Bearer <Supabase access token>`

Response: HTTP 201 with `{ "grant", "expiresAt", "websocketPath", "vm": {"id", "name"} }`. The response is marked `Cache-Control: no-store`. No client-supplied identity or VM target is used.

### Open relay

`GET /v1/rdp`

Upgrade to WebSocket with `Authorization: Bearer <one-time grant>`. Send and receive binary frames only. The app must bridge this WebSocket byte stream to FreeRDP over an Android loopback TCP socket; this Android component must be developed and tested in AI Studio.

## Not yet production-ready

The final local suite has 23 automated tests passing. A second independent review found that the VM endpoint mapping could be mutated after validation; the config now defensively copies and freezes that mapping, and a regression test covers it. The preceding 22-test revision also passed under the server's Python 3.10.12, but the final immutability change was not rerun on the server under the user's local-only approval scope. The broker still requires real Android integration, production endpoint/key configuration, an approved process-persistence method, and an approved secure route. The Cloudflare Quick Tunnel used for Guacamole is temporary and is not reused or altered here. Before publishing the broker, separately review tunnel routing, access controls, rate limiting, and log redaction. Assignment revocation is checked at WebSocket start; an already established RDP connection remains active until disconnect, idle timeout, or maximum session duration.

## Production hardening notes

- Deploy as a **single process**. Grant consumption, active-user exclusion, pending grants, and session caps are held in process memory; multiple workers or replicas would not share those controls.
- Pending grants are globally bounded (default 10), and the allowlist now accepts only RFC1918 IPv4, IPv6 ULA, or interface-scoped IPv6 link-local endpoints.
- Runtime limits can be configured through the `MOBIDESK_*` variables shown in `deploy/broker.env.example`; all values are range-checked at startup.
- The included `deploy/` files are templates only. They do not configure VM addresses, install a service, or publish a WSS route.
- Assignment changes are checked again when the one-time grant is exchanged for a WebSocket. An established RDP relay is not actively revoked mid-session; it is closed by the client, idle timeout, or maximum session duration.
