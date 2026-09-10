"""Parse bounded local files and normalize generic exports or vendor envelopes."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from security_event_pipeline.models import Event
from security_event_pipeline.sources import normalize_vendor

MAX_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 50_000
Diagnostic = Callable[[str, int], None]

# Only documented fields drive detections; Event retains a separate source snapshot.
FIELDS = {
    "authentication": {"username": "user", "host": "asset", "src_ip": "source_ip"},
    "endpoint": {
        "username": "user",
        "host": "asset",
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
        "image": "process",
        "pid": "process_id",
    },
    "cloud": {"actor": "user", "resource": "asset", "src_ip": "source_ip"},
}


def read_text(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("file exceeds 10 MiB limit")
    return data.decode("utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON objects before a parser can overwrite source fields."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def normalize(raw: object) -> Event:
    if not isinstance(raw, dict):
        raise ValueError("event must be an object")
    if "source" in raw and "type" not in raw:
        return normalize_vendor(raw)
    source = raw.get("type")
    if not isinstance(source, str) or source not in FIELDS:
        raise ValueError("unsupported event type")
    fields = {
        key: raw[key] for key in ("id", "timestamp", "type", "action", "outcome") if key in raw
    }
    fields.update({target: raw[key] for key, target in FIELDS[source].items() if key in raw})
    return Event.from_record(
        fields,
        raw,
        {
            "record_id": raw.get("id"),
            "action": raw.get("action"),
            "event_type": raw.get("type"),
            "outcome": raw.get("outcome"),
        },
    )


def load_events(
    path: Path,
    format: Literal["json", "jsonl"],
    diagnostic: Diagnostic,
) -> list[Event]:
    text = read_text(path)
    records: list[tuple[int, object]] = []
    if format == "json":
        payload: object = json.loads(text, object_pairs_hook=unique_object)
        if not isinstance(payload, list):
            raise ValueError("JSON input must be an array")
        if len(payload) > MAX_EVENTS:
            raise ValueError("input exceeds 50000 records")
        records = list(enumerate(payload, 1))
    else:
        lines = [(number, line) for number, line in enumerate(text.splitlines(), 1) if line.strip()]
        if len(lines) > MAX_EVENTS:
            raise ValueError("input exceeds 50000 records")
        for number, line in lines:
            try:
                records.append((number, json.loads(line, object_pairs_hook=unique_object)))
            except (ValueError, RecursionError):
                diagnostic("invalid_json", number)
    events: list[Event] = []
    seen: dict[str, str | None] = {}
    for number, raw in records:
        try:
            event = normalize(raw)
        except (ValueError, ValidationError, RecursionError):
            diagnostic("invalid_event", number)
            continue
        fingerprint = event.provenance.record_sha256 if event.provenance else None
        if event.id in seen:
            diagnostic(
                "duplicate_event_id" if seen[event.id] == fingerprint else "conflicting_event_id",
                number,
            )
            continue
        seen[event.id] = fingerprint
        events.append(event)
    return sorted(events, key=lambda event: event.timestamp)
