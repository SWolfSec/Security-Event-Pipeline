"""Behavioral tests for validation, enrichment, rules, and correlation."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from security_event_pipeline.engine import Pipeline, matches
from security_event_pipeline.ingest import MAX_BYTES, load_events, normalize, read_text
from security_event_pipeline.models import Config, CorrelationConfig, Event, Rule


def auth(identifier: str, seconds: int, outcome: str = "failure", **changes: object) -> Event:
    return Event.model_validate(
        {
            "id": identifier,
            "timestamp": datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
            "type": "authentication",
            "action": "login",
            "outcome": outcome,
            "user": "alice",
            "asset": "server",
            "source_ip": "203.0.113.1",
            **changes,
        }
    )


def endpoint(identifier: str, seconds: int, action: str, **changes: object) -> Event:
    return Event.model_validate(
        {
            "id": identifier,
            "timestamp": datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
            "type": "endpoint",
            "action": action,
            "asset": "server",
            "process_id": "10",
            "process": "C:\\Windows\\PowerShell.EXE",
            "destination_ip": "198.51.100.1",
            **changes,
        }
    )


@pytest.mark.parametrize(
    ("kind", "fields", "expected_user"),
    [
        ("authentication", {"username": "alice", "src_ip": "10.0.0.1"}, "alice"),
        ("endpoint", {"username": "bob", "host": "server"}, "bob"),
        ("cloud", {"actor": "service", "resource": "bucket"}, "service"),
    ],
)
def test_normalize_sources(kind: str, fields: dict[str, str], expected_user: str) -> None:
    event = normalize(
        {
            "id": "1",
            "timestamp": "2026-01-01T00:00:00Z",
            "type": kind,
            "action": "observe",
            "secret": "discard-me",
            **fields,
        }
    )
    assert event.user == expected_user
    assert "discard-me" not in event.model_dump_json()


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": "2026-01-01T00:00:00"},
        {"source_ip": "bad-ip"},
        {"user": None},
        {"id": " "},
        {"outcome": "maybe"},
        {"type": "unsupported"},
    ],
)
def test_invalid_models(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        auth("1", 0, **changes) if "id" not in changes else auth("", 0)


@pytest.mark.parametrize("payload", [None, [], {"type": "other"}])
def test_invalid_source(payload: object) -> None:
    with pytest.raises(ValueError):
        normalize(payload)


def test_ingestion_recovers_and_deduplicates(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    raw = {"id": "1", "type": "cloud", "action": "Read", "timestamp": "2026-01-01T00:00:00Z"}
    path.write_text("\n".join([json.dumps(raw), "{broken", "null", json.dumps(raw)]))
    diagnostics: list[tuple[str, int]] = []
    events = load_events(path, "jsonl", lambda code, line: diagnostics.append((code, line)))
    assert [event.id for event in events] == ["1"]
    assert set(diagnostics) == {
        ("invalid_json", 2),
        ("invalid_event", 3),
        ("duplicate_event_id", 4),
    }


def test_file_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    with path.open("wb") as stream:
        stream.truncate(MAX_BYTES + 1)
    with pytest.raises(ValueError, match="10 MiB"):
        read_text(path)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("10.0.0.1", "internal"),
        ("fc00::1", "internal"),
        ("203.0.113.1", "external"),
        ("2001:db8::1", "external"),
        (None, "unknown"),
    ],
)
def test_enrichment(address: str | None, expected: str) -> None:
    pipeline = Pipeline(
        Config(privileged_users=frozenset({"alice"}), sensitive_assets=frozenset({"server"}))
    )
    enriched = pipeline.enrich(endpoint("1", 0, "observe", source_ip=address, user="alice"))
    assert enriched.source_scope == expected
    assert enriched.privileged_user and enriched.sensitive_asset


def test_login_correlation_sorted_and_risk() -> None:
    events = [auth("1", 0), auth("2", 1), auth("3", 2), auth("4", 300, "success")]
    pipeline = Pipeline(
        Config(privileged_users=frozenset({"alice"}), sensitive_assets=frozenset({"server"}))
    )
    alerts = pipeline.run(reversed(events))
    assert len(alerts) == 1
    assert alerts[0].contributing_events == ("1", "2", "3", "4")
    assert alerts[0].risk_score == 90
    assert alerts == pipeline.run(events)


@pytest.mark.parametrize(
    "changes", [{"user": "bob"}, {"source_ip": "203.0.113.2"}, {"asset": "other"}]
)
def test_login_keys_are_isolated(changes: dict[str, object]) -> None:
    events = [auth("1", 0), auth("2", 1), auth("3", 2), auth("4", 3, "success", **changes)]
    assert Pipeline(Config()).run(events) == []


def test_login_expiry_and_reset() -> None:
    pipeline = Pipeline(Config())
    assert pipeline.run([auth("1", 0), auth("2", 1), auth("3", 2), auth("4", 301, "success")]) == []
    assert (
        len(
            pipeline.run(
                [
                    auth("1", 0),
                    auth("2", 1),
                    auth("3", 2),
                    auth("4", 3, "success"),
                    auth("5", 4, "success"),
                ]
            )
        )
        == 1
    )
    assert (
        pipeline.run(
            [
                auth("1", 0),
                auth("2", 1),
                auth("3", 2, "success"),
                auth("4", 3),
                auth("5", 4, "success"),
            ]
        )
        == []
    )


@pytest.mark.parametrize("seconds", [0, 301])
def test_process_requires_later_event_within_window(seconds: int) -> None:
    assert (
        Pipeline(Config()).run(
            [endpoint("1", 0, "process_start"), endpoint("2", seconds, "network_connect")]
        )
        == []
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"asset": "other"},
        {"process_id": "11"},
        {"process_id": None},
        {"destination_ip": "10.0.0.1"},
    ],
)
def test_process_connection_keys_and_scope(changes: dict[str, object]) -> None:
    assert (
        Pipeline(Config()).run(
            [endpoint("1", 0, "process_start"), endpoint("2", 1, "network_connect", **changes)]
        )
        == []
    )


def test_process_correlates_once_and_pid_reuse_resets() -> None:
    pipeline = Pipeline(Config())
    start = endpoint("1", 0, "process_start")
    connection = endpoint("2", 300, "network_connect")
    alerts = pipeline.run([start, connection, endpoint("3", 300, "network_connect")])
    assert len(alerts) == 1
    assert alerts[0].contributing_events == ("1", "2")
    assert (
        pipeline.run([start, endpoint("4", 1, "process_start", process="safe.exe"), connection])
        == []
    )


def test_rule_filters_and_risk_cap() -> None:
    rule = Rule(
        id="test",
        title="Test",
        severity="critical",
        risk=95,
        event_type="endpoint",
        action="process_start",
        process_names=("powershell.exe",),
        privileged_only=True,
        external_destination_only=True,
        outcome="success",
    )
    config = Config(
        rules=(rule,), privileged_users=frozenset({"alice"}), sensitive_assets=frozenset({"server"})
    )
    pipeline = Pipeline(config)
    event = endpoint("1", 0, "process_start", user="alice", outcome="success")
    assert pipeline.run([event])[0].risk_score == 100
    for changes in [
        {"user": "bob"},
        {"outcome": "failure"},
        {"process": "safe.exe"},
        {"destination_ip": "10.1.1.1"},
        {"action": "observe"},
    ]:
        altered = Event.model_validate({**event.model_dump(), **changes})
        assert not matches(rule, pipeline.enrich(altered))
    assert not matches(rule.model_copy(update={"enabled": False}), pipeline.enrich(event))


def test_configuration_validation() -> None:
    with pytest.raises(ValidationError):
        Config(internal_networks=("10.1.1.1/8",))
    with pytest.raises(ValidationError):
        Config.model_validate({"typo": True})
    rule = Rule(id="same", title="Test", severity="low", risk=0, event_type="cloud", action="Read")
    with pytest.raises(ValidationError):
        Config(rules=(rule, rule))
    with pytest.raises(ValidationError):
        CorrelationConfig(window_seconds=0)


def test_disabled_correlation_and_duplicate_api_input() -> None:
    events = [auth("1", 0), auth("2", 1), auth("3", 2), auth("4", 3, "success")]
    assert Pipeline(Config(correlation=CorrelationConfig(enabled=False))).run(events) == []
    with pytest.raises(ValueError, match="unique"):
        Pipeline(Config()).run([events[0], events[0]])


@pytest.mark.parametrize(
    ("start_outcome", "connection_outcome"),
    [
        pytest.param("failure", "success", id="failed-start"),
        pytest.param("success", "failure", id="failed-connection"),
    ],
)
def test_failed_endpoint_activity_cannot_complete_egress(
    start_outcome: str, connection_outcome: str
) -> None:
    events = [
        endpoint("start", 0, "process_start", outcome=start_outcome),
        endpoint("connection", 1, "network_connect", outcome=connection_outcome),
    ]
    assert Pipeline(Config()).run(events) == []


def test_failed_connection_does_not_consume_suspicious_start() -> None:
    events = [
        endpoint("start", 0, "process_start"),
        endpoint("failed", 1, "network_connect", outcome="failure"),
        endpoint("connected", 2, "network_connect", outcome="success"),
    ]
    assert Pipeline(Config()).run(events)[0].contributing_events == ("start", "connected")


def test_process_window_at_datetime_upper_boundary() -> None:
    events = [
        endpoint("start", 0, "process_start", timestamp="9999-12-31T23:59:58Z"),
        endpoint("connection", 0, "network_connect", timestamp="9999-12-31T23:59:59Z"),
    ]
    assert Pipeline(Config()).run(events)[0].contributing_events == ("start", "connection")


def test_failed_new_start_invalidates_old_pid_attribution() -> None:
    events = [
        endpoint("old", 0, "process_start"),
        endpoint("failed-new", 1, "process_start", outcome="failure"),
        endpoint("connection", 2, "network_connect"),
    ]
    assert Pipeline(Config()).run(events) == []
