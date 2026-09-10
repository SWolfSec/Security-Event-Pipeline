"""Small adapters for documented vendor records inside a collector envelope."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field

from security_event_pipeline.models import Event, Model

Source = Literal["aws_cloudtrail", "gcp_audit", "okta", "github", "osquery_linux", "osquery_macos"]


class Envelope(Model):
    source: Source
    tenant: str = Field(min_length=1, max_length=100)
    record: dict[str, object]


def field(record: object, *path: str) -> object:
    for key in path:
        if record is None:
            return None
        if not isinstance(record, dict):
            raise ValueError("expected nested object")
        record = record.get(key)
    return record


def required_text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected nonempty string")
    return value


def epoch(value: object, divisor: int = 1) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("expected integer epoch")
    timestamp = int(value)
    if not 0 <= timestamp <= 253402300799 * divisor:
        raise ValueError("epoch out of range")
    return datetime.fromtimestamp(timestamp / divisor, UTC)


def provider_ip(value: object) -> object:
    # Cloud APIs also report service callers and redacted addresses in IP fields.
    if value in (None, "", "private", "gce-internal-ip"):
        return None
    if isinstance(value, str) and value.endswith(".amazonaws.com"):
        return None
    return value


def aws(record: dict[str, object]) -> dict[str, object]:
    action = required_text(record.get("eventName"))
    outcome = "failure" if record.get("errorCode") else "success"
    kind = "cloud"
    if action == "ConsoleLogin":
        kind, action = "authentication", "login"
        outcome = {"Success": "success", "Failure": "failure"}.get(
            required_text(field(record, "responseElements", "ConsoleLogin")), "unknown"
        )
    return {
        "timestamp": record.get("eventTime"),
        "type": kind,
        "action": action,
        "outcome": outcome,
        "user": field(record, "userIdentity", "arn"),
        "asset": field(record, "requestParameters", "name") or record.get("recipientAccountId"),
        "source_ip": provider_ip(record.get("sourceIPAddress")),
    }


def gcp(record: dict[str, object]) -> dict[str, object]:
    payload = field(record, "protoPayload")
    if field(payload, "@type") != "type.googleapis.com/google.cloud.audit.AuditLog":
        raise ValueError("expected AuditLog payload")
    code = field(payload, "status", "code")
    if code is not None and (isinstance(code, bool) or not isinstance(code, int)):
        raise ValueError("expected integer status code")
    return {
        "timestamp": record.get("timestamp"),
        "type": "cloud",
        "action": field(payload, "methodName"),
        "outcome": "success" if code in (None, 0) else "failure",
        "user": field(payload, "authenticationInfo", "principalEmail"),
        "asset": field(payload, "resourceName"),
        "source_ip": provider_ip(field(payload, "requestMetadata", "callerIp")),
    }


def okta(record: dict[str, object], tenant: str) -> dict[str, object]:
    action = required_text(record.get("eventType"))
    result = required_text(field(record, "outcome", "result"))
    return {
        "timestamp": record.get("published"),
        "type": "authentication",
        "action": "login" if action == "user.session.start" else action,
        "outcome": {"SUCCESS": "success", "FAILURE": "failure"}.get(result, "unknown"),
        "user": field(record, "actor", "alternateId") or field(record, "actor", "id"),
        "asset": tenant,
        "source_ip": field(record, "client", "ipAddress"),
    }


def github(record: dict[str, object]) -> dict[str, object]:
    return {
        "timestamp": epoch(record.get("@timestamp"), 1000),
        "type": "saas",
        "action": record.get("action"),
        "user": record.get("actor"),
        "asset": record.get("repo") or record.get("org"),
        "source_ip": record.get("actor_ip"),
        # GitHub audit records have no common success/failure field.
        "outcome": "unknown",
    }


def osquery(record: dict[str, object], source: Source) -> dict[str, object]:
    name = required_text(record.get("name"))
    columns = field(record, "columns")
    if record.get("action") != "added":
        raise ValueError("expected event-format added record")
    outcome = "unknown"
    if source == "osquery_macos" and name == "es_process_events":
        if field(columns, "event_type") not in ("exec", "fork", "exit"):
            raise ValueError("unsupported EndpointSecurity event type")
        action = "process_start" if field(columns, "event_type") == "exec" else "process_observe"
    elif source == "osquery_linux" and name == "process_events":
        action = "process_start"
    elif source == "osquery_linux" and name == "socket_events":
        status = field(columns, "status")
        outcome = {"succeeded": "success", "failed": "failure"}.get(
            required_text(status), "unknown"
        )
        action = (
            "network_connect"
            if field(columns, "action") == "connect" and status == "succeeded"
            else "network_observe"
        )
    else:
        raise ValueError("unsupported osquery query name for platform")
    pid = field(columns, "pid")
    if isinstance(pid, bool) or not isinstance(pid, (str, int)) or not str(pid).isdigit():
        raise ValueError("expected process ID")
    return {
        "timestamp": epoch(field(columns, "time")),
        "type": "endpoint",
        "action": action,
        "outcome": outcome,
        "asset": record.get("hostIdentifier"),
        "user": field(columns, "username"),
        "process": field(columns, "path"),
        "process_id": str(pid),
        "destination_ip": field(columns, "remote_address") if action == "network_connect" else None,
    }


def normalize_vendor(raw: object) -> Event:
    envelope = Envelope.model_validate(raw)
    source, tenant, record = envelope.source, envelope.tenant, envelope.record
    if source == "aws_cloudtrail":
        identity: object = required_text(record.get("eventID"))
        fields = aws(record)
        original = {
            "record_id": record.get("eventID"),
            "action": record.get("eventName"),
            "event_type": record.get("eventType"),
            "outcome": field(record, "responseElements", "ConsoleLogin") or record.get("errorCode"),
        }
    elif source == "gcp_audit":
        identity = [required_text(record.get(key)) for key in ("logName", "insertId", "timestamp")]
        fields = gcp(record)
        original = {
            "record_id": record.get("insertId"),
            "action": field(record, "protoPayload", "methodName"),
            "event_type": field(record, "protoPayload", "@type"),
            "outcome": field(record, "protoPayload", "status", "code"),
        }
    elif source == "okta":
        identity = required_text(record.get("uuid"))
        fields = okta(record, tenant)
        original = {
            "record_id": record.get("uuid"),
            "action": record.get("eventType"),
            "event_type": record.get("eventType"),
            "outcome": field(record, "outcome", "result"),
        }
    elif source == "github":
        identity = required_text(record.get("_document_id"))
        fields = github(record)
        original = {
            "record_id": record.get("_document_id"),
            "action": record.get("action"),
            "event_type": None,
            "outcome": None,
        }
    else:
        # Event result logs have no universal record ID. Hash the complete result.
        identity = record
        fields = osquery(record, source)
        original = {
            "record_id": field(record, "columns", "eid"),
            "action": field(record, "columns", "event_type")
            or field(record, "columns", "action")
            or record.get("action"),
            "event_type": record.get("name"),
            "outcome": field(record, "columns", "status"),
        }
    digest = hashlib.sha256(
        json.dumps([source, tenant, identity], sort_keys=True).encode()
    ).hexdigest()
    return Event.from_record(
        {**fields, "id": f"{source}:{digest}", "source": source, "tenant": tenant},
        record,
        original,
    )
