# Host deployment template

This is a deployment template, not an installation script. Do not install until the five UUID-to-IP entries have been reconciled against the live `student_vm_access`/`vms` records and the current libvirt domains. Keep the unit bound to loopback and expose it only through an independently secured WSS reverse proxy or tunnel.

## Required operating constraints

- Run exactly one broker process. Grant/session state is in-memory and process-local; do not use multiple workers, replicas, or a load-balanced pool without first moving grants and active-session coordination to shared storage.
- Keep port 8766 on `127.0.0.1`. Do not open it in UFW, campus firewall rules, or the router.
- Run as the dedicated unprivileged `mobidesk-broker` account, not `administrator`, `root`, or `docker`.
- Store the environment file outside the Git checkout at `/etc/mobidesk-session-broker/broker.env`; it must contain only the Supabase publishable/anon key and verified private VM endpoints. Never put secrets in the APK or repository.
- Do not use the Supabase service-role key. Assignment reads must continue using the student's bearer token so RLS applies.
- The broker only relays RDP bytes. It does not authenticate Windows users. Windows credentials must remain separate from Supabase credentials.

## Installation outline (requires administrator approval)

1. Create `mobidesk-broker` system user/group and `/opt/mobidesk-session-broker`.
2. Deploy a reviewed source revision; create its virtual environment and install the pinned requirements.
3. Create `/etc/mobidesk-session-broker`, install `broker.env` with owner `root:mobidesk-broker` and mode `0640`.
4. Confirm every configured UUID is a live student VM UUID and each endpoint is its actual reachable private IP. Test TCP/3389 from the host for each entry.
5. Install `mobidesk-session-broker.service` to `/etc/systemd/system/`, then `systemctl daemon-reload`, enable and start it.
6. Verify `ss -ltnp` shows only `127.0.0.1:8766` and `curl http://127.0.0.1:8766/health` returns `{"status":"ok"}`.
7. Only then configure a separately secured WSS route to `http://127.0.0.1:8766`. The temporary Guacamole Quick Tunnel is not reused by this template.
