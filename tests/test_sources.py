"""Native field mappings and isolation across sources and tenants."""

from copy import deepcopy

import pytest

from security_event_pipeline.engine import Pipeline
from security_event_pipeline.ingest import normalize
from security_event_pipeline.models import Config


def okta(identifier: str, second: int, result: str = "FAILURE") -> dict[str, object]:
    return {
        "source": "okta",
        "tenant": "acme",
        "record": {
            "uuid": identifier,
            "published": f"2026-01-15T10:00:{second:02d}Z",
            "eventType": "user.session.start",
            "actor": {"alternateId": "alice@example.test"},
            "client": {"ipAddress": "203.0.113.10"},
            "outcome": {"result": result},
        },
    }


def test_okta_login_uses_native_outcome_and_existing_correlation() -> None:
    events = [normalize(okta(str(i), i)) for i in range(3)]
    events.append(normalize(okta("success", 4, "SUCCESS")))
    assert events[0].outcome == "failure"
    assert events[-1].action == "login"
    alerts = Pipeline(Config()).run(events)
    assert len(alerts) == 1
    assert alerts[0].contributing_events == tuple(event.id for event in events)


def test_tenants_cannot_complete_each_others_login_sequences() -> None:
    events = [normalize(okta(str(i), i)) for i in range(3)]
    success = okta("success", 4, "SUCCESS")
    success["tenant"] = "other"
    assert Pipeline(Config()).run([*events, normalize(success)]) == []
    same_id = okta("0", 0)
    same_id["tenant"] = "other"
    assert normalize(same_id).id != events[0].id


@pytest.mark.parametrize("result", ["CHALLENGE", "SKIPPED", "ALLOW", "DENY"])
def test_okta_policy_results_are_not_completed_logins(result: str) -> None:
    assert normalize(okta("1", 0, result)).outcome == "unknown"


@pytest.mark.parametrize("changes", [{"record": []}, {"tenant": ""}, {"source": "typo"}])
def test_invalid_envelopes(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        normalize({**okta("1", 0), **changes})


def test_native_input_is_not_mutated() -> None:
    raw = okta("1", 0)
    before = deepcopy(raw)
    normalize(raw)
    assert raw == before


# Checked-in native records exercise adapter contracts without live vendor accounts.
def sample(source: str, scenario: str) -> dict[str, object]:
    import json
    from pathlib import Path

    path = Path(__file__).parent / "fixtures/source_events.json"
    return json.loads(path.read_text())[source][scenario]


@pytest.mark.parametrize(
    ("source", "scenario", "action", "outcome"),
    [
        ("aws_cloudtrail", "audit_disabled", "StopLogging", "success"),
        ("aws_cloudtrail", "audit_disable_denied", "StopLogging", "failure"),
        ("aws_cloudtrail", "console_login_failed", "login", "failure"),
        ("gcp_audit", "iam_changed", "SetIamPolicy", "success"),
        ("gcp_audit", "iam_denied", "SetIamPolicy", "failure"),
        ("github", "visibility_changed", "repo.access", "unknown"),
        ("osquery_linux", "connection_failed", "network_observe", "failure"),
        ("osquery_linux", "connection_succeeded", "network_connect", "success"),
        ("osquery_linux", "socket_bind", "network_observe", "success"),
        ("osquery_macos", "suspicious_exec", "process_start", "unknown"),
        ("osquery_macos", "process_exit", "process_observe", "unknown"),
    ],
)
def test_native_actions_and_outcomes(source: str, scenario: str, action: str, outcome: str) -> None:
    event = normalize(sample(source, scenario))
    assert (event.action, event.outcome, event.source) == (action, outcome, source)
    assert event.timestamp.isoformat().startswith("2026-01-15T10:")


@pytest.mark.parametrize(
    ("source", "scenario"), [("aws_cloudtrail", "service_caller"), ("gcp_audit", "redacted_caller")]
)
def test_service_and_redacted_ips_remain_unknown(source: str, scenario: str) -> None:
    assert normalize(sample(source, scenario)).source_ip is None


def test_native_context_and_time_mapping() -> None:
    aws = normalize(sample("aws_cloudtrail", "audit_disabled"))
    assert (aws.user, aws.asset) == ("arn:aws:iam::111122223333:user/admin", "audit-trail")
    assert normalize(sample("gcp_audit", "iam_changed")).user == "admin@example.test"
    assert normalize(sample("github", "visibility_changed")).asset == "acme-example/payments"
    process = normalize(sample("osquery_linux", "suspicious_start"))
    assert (process.process, process.process_id, process.asset) == (
        "/usr/bin/nc",
        "4812",
        "linux-build-01",
    )
    assert process.timestamp.second == 6  # columns.time, not the logger's delayed unixTime
    assert normalize(sample("osquery_macos", "suspicious_exec")).user == "analyst"


@pytest.mark.parametrize("changes", [{"tenant": "other"}, {"source": "different-collector"}])
def test_process_correlation_isolates_source_and_tenant(changes: dict[str, str]) -> None:
    start = normalize(sample("osquery_linux", "suspicious_start"))
    connection = normalize(sample("osquery_linux", "connection_succeeded"))
    assert len(Pipeline(Config()).run([start, connection])) == 1
    assert Pipeline(Config()).run([start, connection.model_copy(update=changes)]) == []


@pytest.mark.parametrize(
    ("source", "path", "value"),
    [
        ("okta", ("actor",), []),
        ("okta", ("client", "ipAddress"), "invalid"),
        ("gcp_audit", ("protoPayload", "status"), []),
        ("gcp_audit", ("protoPayload", "status"), {"code": "0"}),
        ("github", ("@timestamp",), "9" * 400),
        ("github", ("@timestamp",), True),
        ("osquery_linux", ("columns", "pid"), None),
        ("osquery_macos", ("columns", "event_type"), None),
    ],
)
def test_malformed_native_fields(source: str, path: tuple[str, ...], value: object) -> None:
    raw = sample(source, "valid")
    record = raw["record"]
    assert isinstance(record, dict)
    for key in path[:-1]:
        record = record[key]
    record[path[-1]] = value
    with pytest.raises(ValueError):
        normalize(raw)


@pytest.mark.parametrize(
    ("source", "scenario", "original_action"),
    [
        ("aws_cloudtrail", "console_login", "ConsoleLogin"),
        ("gcp_audit", "iam_changed", "SetIamPolicy"),
        ("okta", "login_success", "user.session.start"),
        ("github", "visibility_changed", "repo.access"),
        ("osquery_linux", "suspicious_start", "added"),
        ("osquery_linux", "connection_succeeded", "connect"),
        ("osquery_macos", "suspicious_exec", "exec"),
        ("osquery_macos", "process_exit", "exit"),
    ],
)
def test_every_adapter_retains_source_provenance(
    source: str, scenario: str, original_action: str
) -> None:
    import json

    raw = sample(source, scenario)
    before = deepcopy(raw)
    event = normalize(raw)
    assert event.provenance.action == original_action
    assert json.loads(event.original_json) == raw["record"]
    assert raw == before


def test_snapshot_is_exact_immutable_and_content_addressed() -> None:
    import hashlib
    import json

    from pydantic import ValidationError

    raw = okta("1", 0, "CHALLENGE")
    record = raw["record"]
    record["eventType"] = " user.session.start "
    record["unmapped"] = {"sensitive": "DO-NOT-EMIT"}
    event = normalize(raw)
    snapshot = event.original_json
    assert event.provenance.action == " user.session.start "
    assert event.provenance.outcome == "CHALLENGE"
    assert event.provenance.record_id == "1"
    assert event.provenance.record_sha256 == hashlib.sha256(snapshot.encode()).hexdigest()
    assert json.loads(snapshot) == record
    assert "DO-NOT-EMIT" not in event.model_dump_json() + repr(event)
    reordered = {**raw, "record": dict(reversed(list(record.items())))}
    assert normalize(reordered).provenance == event.provenance
    record["unmapped"]["sensitive"] = "changed"
    assert event.original_json == snapshot
    assert normalize(raw).provenance.record_sha256 != event.provenance.record_sha256
    with pytest.raises(ValidationError):
        event.provenance.action = "rewritten"


def test_generic_records_also_retain_original_values() -> None:
    import json

    raw = {
        "id": " generic-1 ",
        "type": "cloud",
        "action": " Read ",
        "timestamp": "2026-01-15T10:00:00Z",
        "extra": {"data": [1, 2]},
    }
    event = normalize(raw)
    assert event.action == "Read"
    assert event.provenance.action == " Read "
    assert event.provenance.record_id == " generic-1 "
    assert event.provenance.outcome is None
    assert json.loads(event.original_json) == raw
