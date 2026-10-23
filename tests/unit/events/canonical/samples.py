"""Valid canonical event documents (schema 1.0), one builder per category."""

from collections.abc import Callable

BASE: dict[str, object] = {
    "schema_version": "1.0",
    "timestamp": "2026-09-25T12:00:00Z",
    "source_type": "agent",
    "source_name": "adis-agent@web-1",
    "host_id": "web-1",
    "agent_id": "agent-7",
}


def system(**overrides: object) -> dict[str, object]:
    """A service-stopped system event."""
    return {**BASE, "category": "system", "event_type": "system.service_stopped", **overrides}


def authentication(**overrides: object) -> dict[str, object]:
    """A failed SSH password login from a remote address."""
    return {
        **BASE,
        "category": "authentication",
        "event_type": "authentication.login",
        "username": "alice",
        "auth_method": "password",
        "success": False,
        "failure_reason": "invalid_credentials",
        "src_ip": "203.0.113.7",
        "src_port": 50522,
        "dst_ip": "10.0.0.9",
        "dst_port": 22,
        "protocol": "tcp",
        **overrides,
    }


def network(**overrides: object) -> dict[str, object]:
    """A TCP flow."""
    return {
        **BASE,
        "category": "network",
        "event_type": "network.flow",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.9",
        "src_port": 51514,
        "dst_port": 443,
        "protocol": "tcp",
        "bytes_sent": 1_200,
        "bytes_received": 5_400,
        **overrides,
    }


def process(**overrides: object) -> dict[str, object]:
    """A process start."""
    return {
        **BASE,
        "category": "process",
        "event_type": "process.started",
        "process_name": "sshd",
        "process_id": 4_242,
        "parent_process_id": 1,
        "executable_path": "/usr/sbin/sshd",
        **overrides,
    }


def security(**overrides: object) -> dict[str, object]:
    """An IDS alert with network and process context."""
    return {
        **BASE,
        "category": "security",
        "event_type": "security.alert",
        "severity_hint": "high",
        "src_ip": "198.51.100.23",
        "dst_ip": "10.0.0.9",
        "dst_port": 22,
        "protocol": "tcp",
        "process_name": "nc",
        "process_id": 9_001,
        "metadata": {"rule_id": "ET-2001219", "signature": "ET SCAN Potential SSH Scan"},
        **overrides,
    }


BUILDERS: dict[str, Callable[..., dict[str, object]]] = {
    "system": system,
    "authentication": authentication,
    "network": network,
    "process": process,
    "security": security,
}
