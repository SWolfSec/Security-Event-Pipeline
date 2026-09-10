"""Validated contracts for input, policy, and output."""

import hashlib
import json
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EventType = Literal["authentication", "endpoint", "cloud", "saas"]
Severity = Literal["low", "medium", "high", "critical"]
IPAddress = IPv4Address | IPv6Address


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Provenance(Model):
    """Exact source values and a fingerprint of the complete parsed source record."""

    model_config = ConfigDict(str_strip_whitespace=False, strict=True)
    record_id: str | None
    action: str
    event_type: str | None
    outcome: str | int | None
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Event(Model):
    id: str = Field(min_length=1, max_length=200)
    timestamp: datetime
    type: EventType
    source: str = Field(default="generic", min_length=1, max_length=100)
    tenant: str = Field(default="local", min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=200)
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    user: str | None = Field(default=None, min_length=1, max_length=200)
    asset: str | None = Field(default=None, min_length=1, max_length=200)
    source_ip: IPAddress | None = None
    destination_ip: IPAddress | None = None
    process: str | None = Field(default=None, min_length=1, max_length=500)
    process_id: str | None = Field(default=None, min_length=1, max_length=200)
    provenance: Provenance | None = None
    original_json: str | None = Field(default=None, exclude=True, repr=False)

    @classmethod
    def from_record(
        cls, fields: dict[str, object], record: object, original_fields: dict[str, object]
    ) -> Self:
        # Immutable text preserves all parsed fields without retaining mutable input references.
        snapshot = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
        provenance = Provenance.model_validate(
            {
                **original_fields,
                "record_sha256": hashlib.sha256(snapshot.encode("utf-8")).hexdigest(),
            }
        )
        return cls.model_validate({**fields, "provenance": provenance, "original_json": snapshot})

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def require_context(self) -> Self:
        if self.type == "authentication" and (not self.user or not self.source_ip):
            raise ValueError("authentication requires user and source_ip")
        if self.type == "endpoint" and not self.asset:
            raise ValueError("endpoint requires asset")
        if self.action == "process_start" and not self.process:
            raise ValueError("process_start requires process")
        if self.action == "network_connect" and not self.destination_ip:
            raise ValueError("network_connect requires destination_ip")
        return self


class EnrichedEvent(Model):
    event: Event
    privileged_user: bool
    sensitive_asset: bool
    source_scope: Literal["internal", "external", "unknown"]
    destination_scope: Literal["internal", "external", "unknown"]


class Rule(Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    risk: int = Field(ge=0, le=100)
    event_type: EventType
    source: str | None = Field(default=None, min_length=1, max_length=100)
    action: str = Field(min_length=1)
    outcome: Literal["success", "failure", "unknown"] | None = None
    process_names: tuple[str, ...] = ()
    privileged_only: bool = False
    external_destination_only: bool = False
    enabled: bool = True


class CorrelationConfig(Model):
    enabled: bool = True
    window_seconds: int = Field(default=300, ge=1, le=86400)
    failed_login_threshold: int = Field(default=3, ge=2, le=100)
    suspicious_processes: tuple[str, ...] = ("powershell.exe", "nc", "ncat")

    @property
    def window(self) -> timedelta:
        return timedelta(seconds=self.window_seconds)


class Config(Model):
    privileged_users: frozenset[str] = frozenset()
    sensitive_assets: frozenset[str] = frozenset()
    internal_networks: tuple[str, ...] = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
    rules: tuple[Rule, ...] = ()
    correlation: CorrelationConfig = CorrelationConfig()

    @field_validator("internal_networks")
    @classmethod
    def validate_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for network in value:
            ip_network(network, strict=True)
        return value

    @model_validator(mode="after")
    def unique_rules(self) -> Self:
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule IDs must be unique")
        return self


class Evidence(Model):
    event_id: str
    source: str
    tenant: str
    timestamp: datetime
    action: str
    outcome: Literal["success", "failure", "unknown"]
    provenance: Provenance | None


class Alert(Model):
    id: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    contributing_events: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    reason: str
    timestamp: datetime
