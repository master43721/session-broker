from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import ipaddress
import json
import os
import re
import uuid
from types import MappingProxyType
from urllib.parse import urlparse


_SCOPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


_IPV4_ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
_IPV6_ULA = ipaddress.ip_network("fc00::/7")
_IPV6_LINK_LOCAL = ipaddress.ip_network("fe80::/10")


def validate_vm_endpoint(host: str) -> str:
    """Accept RFC1918 IPv4, IPv6 ULA, or scoped IPv6 link-local only."""
    if not isinstance(host, str) or not host or host.strip() != host or host.count("%") > 1:
        raise ValueError("VM endpoint must be a non-empty IP literal")

    address_text, separator, scope = host.partition("%")
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise ValueError("VM endpoint must be an IP literal, not a hostname") from exc

    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_reserved:
        raise ValueError("VM endpoint is not an allowed private address")

    if address.version == 4:
        allowed = any(address in network for network in _IPV4_ALLOWED_NETWORKS)
        if separator or not allowed:
            raise ValueError("IPv4 VM endpoint must be RFC1918 or link-local")
        return str(address)

    in_ula = address in _IPV6_ULA
    in_link_local = address in _IPV6_LINK_LOCAL
    if in_ula and not separator:
        return str(address)
    if in_link_local and separator and _SCOPE_RE.fullmatch(scope):
        return f"{address}%{scope}"
    if in_link_local and not separator:
        raise ValueError("Link-local IPv6 endpoint requires an interface scope")
    raise ValueError("IPv6 VM endpoint must be ULA or scoped link-local")


@dataclass(frozen=True)
class BrokerConfig:
    supabase_url: str
    supabase_publishable_key: str
    vm_endpoints: Mapping[str, str]
    bind_host: str = "127.0.0.1"
    port: int = 8766
    grant_ttl_seconds: int = 60
    grant_cooldown_seconds: float = 2.0
    connect_timeout_seconds: float = 5.0
    supabase_timeout_seconds: float = 8.0
    heartbeat_seconds: int = 20
    max_message_bytes: int = 1_048_576
    max_session_seconds: int = 14_400
    idle_timeout_seconds: int = 1_800
    max_sessions: int = 5
    max_pending_grants: int = 10

    def __post_init__(self) -> None:
        if not isinstance(self.vm_endpoints, Mapping):
            raise ValueError("VM endpoint allowlist must be a mapping")
        normalized: dict[str, str] = {}
        for raw_id, endpoint in self.vm_endpoints.items():
            normalized_id = str(uuid.UUID(str(raw_id)))
            if normalized_id in normalized:
                raise ValueError("VM endpoint IDs must be unique after UUID normalization")
            normalized[normalized_id] = validate_vm_endpoint(endpoint)
        object.__setattr__(self, "vm_endpoints", MappingProxyType(normalized))
        self.validate()

    def validate(self) -> None:
        parsed_url = urlparse(self.supabase_url)
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or not parsed_url.hostname.endswith(".supabase.co")
            or parsed_url.username
            or parsed_url.password
            or parsed_url.port is not None
            or parsed_url.path not in ("", "/")
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError("SUPABASE_URL must be the HTTPS URL of a Supabase project")
        if not self.supabase_publishable_key.strip():
            raise ValueError("SUPABASE_PUBLISHABLE_KEY is required")
        if not isinstance(self.vm_endpoints, Mapping) or len(self.vm_endpoints) != 5:
            raise ValueError("Exactly five allowlisted VM endpoint entries are required")
        normalized_ids: set[str] = set()
        for vm_id, host in self.vm_endpoints.items():
            normalized_id = str(uuid.UUID(str(vm_id)))
            if normalized_id in normalized_ids:
                raise ValueError("VM endpoint IDs must be unique")
            normalized_ids.add(normalized_id)
            validate_vm_endpoint(host)
        try:
            if not ipaddress.ip_address(self.bind_host).is_loopback:
                raise ValueError("Broker must bind only to a loopback address")
        except ValueError as exc:
            raise ValueError("MOBIDESK_BIND_HOST must be a loopback IP address") from exc
        if not 1024 <= self.port <= 65535:
            raise ValueError("MOBIDESK_PORT must be between 1024 and 65535")
        if not 5 <= self.grant_ttl_seconds <= 120:
            raise ValueError("Grant TTL must be between 5 and 120 seconds")
        if self.grant_cooldown_seconds < 0:
            raise ValueError("Grant cooldown cannot be negative")
        if not 0 < self.connect_timeout_seconds <= 30 or not 0 < self.supabase_timeout_seconds <= 30:
            raise ValueError("Upstream timeouts must be between 0 and 30 seconds")
        if not 1 <= self.heartbeat_seconds <= 60:
            raise ValueError("Heartbeat interval must be between 1 and 60 seconds")
        if not 1 <= self.max_message_bytes <= 4 * 1024 * 1024:
            raise ValueError("WebSocket message limit must be between 1 byte and 4 MiB")
        if not 60 <= self.max_session_seconds <= 86_400:
            raise ValueError("Maximum session duration must be between 60 seconds and 24 hours")
        if not 1 <= self.idle_timeout_seconds <= 86_400:
            raise ValueError("Idle timeout must be between 1 second and 24 hours")
        if not 1 <= self.max_sessions <= 5:
            raise ValueError("Maximum concurrent sessions must be between 1 and 5")
        if not self.max_sessions <= self.max_pending_grants <= 50:
            raise ValueError("Maximum pending grants must be between max sessions and 50")

    @classmethod
    def from_env(cls) -> "BrokerConfig":
        supabase_url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
        publishable_key = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
        raw_endpoints = os.environ.get("MOBIDESK_VM_ENDPOINTS_JSON", "").strip()
        if not supabase_url or not publishable_key or not raw_endpoints:
            raise ValueError("SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY and MOBIDESK_VM_ENDPOINTS_JSON are required")
        try:
            raw_mapping = json.loads(raw_endpoints)
        except json.JSONDecodeError as exc:
            raise ValueError("MOBIDESK_VM_ENDPOINTS_JSON must be a JSON object") from exc
        if not isinstance(raw_mapping, dict):
            raise ValueError("MOBIDESK_VM_ENDPOINTS_JSON must be a JSON object")
        endpoints = {str(uuid.UUID(str(vm_id))): host for vm_id, host in raw_mapping.items()}
        return cls(
            supabase_url=supabase_url,
            supabase_publishable_key=publishable_key,
            vm_endpoints=endpoints,
            bind_host=os.environ.get("MOBIDESK_BIND_HOST", "127.0.0.1").strip(),
            port=int(os.environ.get("MOBIDESK_PORT", "8766")),
            grant_ttl_seconds=int(os.environ.get("MOBIDESK_GRANT_TTL_SECONDS", "60")),
            grant_cooldown_seconds=float(os.environ.get("MOBIDESK_GRANT_COOLDOWN_SECONDS", "2")),
            connect_timeout_seconds=float(os.environ.get("MOBIDESK_CONNECT_TIMEOUT_SECONDS", "5")),
            supabase_timeout_seconds=float(os.environ.get("MOBIDESK_SUPABASE_TIMEOUT_SECONDS", "8")),
            heartbeat_seconds=int(os.environ.get("MOBIDESK_HEARTBEAT_SECONDS", "20")),
            max_message_bytes=int(os.environ.get("MOBIDESK_MAX_MESSAGE_BYTES", "1048576")),
            max_session_seconds=int(os.environ.get("MOBIDESK_MAX_SESSION_SECONDS", "14400")),
            idle_timeout_seconds=int(os.environ.get("MOBIDESK_IDLE_TIMEOUT_SECONDS", "1800")),
            max_sessions=int(os.environ.get("MOBIDESK_MAX_SESSIONS", "5")),
            max_pending_grants=int(os.environ.get("MOBIDESK_MAX_PENDING_GRANTS", "10")),
        )
