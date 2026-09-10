"""Exercise the installed CLI through real local input and output files."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "security_event_pipeline.cli", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_sample_end_to_end(tmp_path: Path) -> None:
    output = tmp_path / "alerts.jsonl"
    result = run_cli(
        str(ROOT / "samples/events.jsonl"),
        "--config",
        str(ROOT / "samples/config.json"),
        "--output",
        str(output),
    )
    assert result.returncode == 0, result.stderr
    alerts = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(alerts) == 5
    assert [alert["risk_score"] for alert in alerts] == [40, 90, 60, 95, 100]
    assert alerts[1]["contributing_events"] == ["auth-1", "auth-2", "auth-3", "auth-4"]
    assert output.read_text() == (ROOT / "samples/expected-alerts.jsonl").read_text()
    assert result.stdout == ""
    assert json.loads(result.stderr)["level"] == "info"


def test_json_array_matches_jsonl(tmp_path: Path) -> None:
    source = ROOT / "samples/events.jsonl"
    path = tmp_path / "events.json"
    path.write_text(json.dumps([json.loads(line) for line in source.read_text().splitlines()]))
    config = str(ROOT / "samples/config.json")
    result = run_cli(str(path), "--config", config)
    assert result.returncode == 0
    assert result.stdout == run_cli(str(source), "--config", config).stdout


def test_partial_processing_redacts_payload(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        (ROOT / "samples/events.jsonl").read_text() + '\n{"secret":"DO-NOT-LOG"}\n{broken\n'
    )
    result = run_cli(str(path), "--config", str(ROOT / "samples/config.json"))
    assert result.returncode == 2
    assert len(result.stdout.splitlines()) == 5
    assert "DO-NOT-LOG" not in result.stderr + result.stdout
    assert len([json.loads(line) for line in result.stderr.splitlines()]) == 3


@pytest.mark.parametrize("content", ["{broken", "{}", "[NaN]", "[" * 2000])
def test_bad_json_does_not_replace_output(tmp_path: Path, content: str) -> None:
    path = tmp_path / "events.json"
    path.write_text(content)
    output = tmp_path / "output.jsonl"
    output.write_text("previous")
    result = run_cli(
        str(path), "--config", str(ROOT / "samples/config.json"), "--output", str(output)
    )
    if content == "[NaN]":
        assert result.returncode == 2
        assert output.read_text() == ""
    else:
        assert result.returncode == 1
        assert output.read_text() == "previous"


def test_input_overwrite_rejected(tmp_path: Path) -> None:
    path = tmp_path / "events.json"
    path.write_text("[]")
    result = run_cli(
        str(path), "--config", str(ROOT / "samples/config.json"), "--output", str(path)
    )
    assert result.returncode == 1
    assert path.read_text() == "[]"


def test_invalid_config_and_missing_input(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"secret":"DO-NOT-LOG"}')
    result = run_cli(str(ROOT / "samples/events.jsonl"), "--config", str(path))
    assert result.returncode == 1
    assert "DO-NOT-LOG" not in result.stderr
    assert (
        run_cli(
            str(tmp_path / "missing.json"), "--config", str(ROOT / "samples/config.json")
        ).returncode
        == 1
    )


def test_atomic_output_failure_preserves_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from security_event_pipeline.cli import write_alerts

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError("simulated filesystem failure")

    output = tmp_path / "alerts.jsonl"
    output.write_text("previous")
    monkeypatch.setattr("security_event_pipeline.cli.os.replace", fail_replace)
    with pytest.raises(OSError):
        write_alerts(output, [])
    assert output.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [output]


def test_mixed_sources_end_to_end(tmp_path: Path) -> None:
    source = ROOT / "samples/mixed-events.jsonl"
    result = run_cli(str(source), "--config", str(ROOT / "samples/mixed-config.json"))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stderr)["accepted"] == 266
    assert result.stdout == (ROOT / "samples/mixed-expected-alerts.jsonl").read_text()
    alerts = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(alerts) == 12
    assert [a["risk_score"] for a in alerts] == [100, 80, 45, 45, 80, 90, 30, 100, 80, 40, 90, 85]
    assert sum(a["rule_id"].startswith("correlation:") for a in alerts) == 2
    # Combine legacy and vendor records, plus a malformed nested vendor payload.
    path = tmp_path / "combined.jsonl"
    path.write_text(
        source.read_text()
        + (ROOT / "samples/events.jsonl").read_text()
        + '{"source":"okta","tenant":"acme","record":{"actor":[]}}\n'
    )
    result = run_cli(str(path), "--config", str(ROOT / "samples/mixed-config.json"))
    assert result.returncode == 2
    assert len(result.stdout.splitlines()) == 17
    assert json.loads(result.stderr.splitlines()[-1])["rejected"] == 1


def test_alert_evidence_preserves_source_meaning_without_raw_payloads(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    records = (
        json.loads(line) for line in (ROOT / "samples/vendors/okta.jsonl").read_text().splitlines()
    )
    raw = [
        record
        for record in records
        if record["record"]["eventType"] == "user.session.start"
        and record["record"]["actor"]["alternateId"] == "admin@example.test"
    ]
    for item in raw:
        item["record"]["debugContext"] = {"private": "DO-NOT-EMIT"}
    contents = "\n".join(json.dumps(item) for item in raw) + "\n"
    path.write_text(contents)
    result = run_cli(str(path), "--config", str(ROOT / "samples/mixed-config.json"))
    assert result.returncode == 0
    assert path.read_text() == contents
    assert "DO-NOT-EMIT" not in result.stdout + result.stderr
    correlation = [json.loads(line) for line in result.stdout.splitlines()][-1]
    evidence = correlation["evidence"]
    assert [item["event_id"] for item in evidence] == correlation["contributing_events"]
    assert [item["provenance"]["record_id"] for item in evidence] == [
        item["record"]["uuid"] for item in raw
    ]
    assert [item["provenance"]["outcome"] for item in evidence] == ["FAILURE"] * 3 + ["SUCCESS"]
    assert all(
        item["action"] == "login" and item["provenance"]["action"] == "user.session.start"
        for item in evidence
    )


def test_conflicting_ids_and_duplicate_json_keys_are_reported(tmp_path: Path) -> None:
    raw = json.loads((ROOT / "samples/events.jsonl").read_text().splitlines()[0])
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(raw),
                json.dumps(raw),
                json.dumps({**raw, "outcome": "success"}),
                '{"type":"cloud","action":"Read","action":"Delete"}',
            ]
        )
    )
    result = run_cli(str(path), "--config", str(ROOT / "samples/config.json"))
    assert result.returncode == 2
    messages = [json.loads(line)["message"] for line in result.stderr.splitlines()]
    assert set(messages) == {
        "invalid_json",
        "duplicate_event_id",
        "conflicting_event_id",
        "completed",
    }
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("start_outcome", "connection_outcome", "year", "expected_alerts"),
    [
        pytest.param("failure", "success", "2026", 0, id="failed-generic-start"),
        pytest.param("success", "failure", "2026", 0, id="failed-generic-connection"),
        pytest.param("unknown", "unknown", "9999", 1, id="maximum-datetime"),
    ],
)
def test_generic_endpoint_regressions_through_cli(
    tmp_path: Path,
    start_outcome: str,
    connection_outcome: str,
    year: str,
    expected_alerts: int,
) -> None:
    events = [
        {
            "id": "start",
            "timestamp": f"{year}-12-31T23:59:58Z",
            "type": "endpoint",
            "action": "process_start",
            "outcome": start_outcome,
            "host": "build-01",
            "pid": "42",
            "image": "/usr/bin/nc",
        },
        {
            "id": "connection",
            "timestamp": f"{year}-12-31T23:59:59Z",
            "type": "endpoint",
            "action": "network_connect",
            "outcome": connection_outcome,
            "host": "build-01",
            "pid": "42",
            "dst_ip": "198.51.100.10",
        },
    ]
    path, config = tmp_path / "events.json", tmp_path / "config.json"
    path.write_text(json.dumps(events))
    config.write_text("{}")
    result = run_cli(str(path), "--config", str(config))
    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == expected_alerts
    assert json.loads(result.stderr)["accepted"] == 2
