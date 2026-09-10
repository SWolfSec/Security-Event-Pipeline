"""Local file CLI with machine-readable diagnostics and atomic output."""

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

from security_event_pipeline.engine import Pipeline
from security_event_pipeline.ingest import load_events, read_text
from security_event_pipeline.models import Alert, Config

LOGGER = logging.getLogger("security_event_pipeline")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = {
            key: record.__dict__[key]
            for key in ("record", "accepted", "rejected", "alerts", "phase", "error_type")
            if key in record.__dict__
        }
        return json.dumps(
            {"level": record.levelname.lower(), "message": record.getMessage(), **fields}
        )


def write_alerts(path: Path, alerts: list[Alert]) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            for alert in alerts:
                stream.write(alert.model_dump_json() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Process local security events into JSONL alerts.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="Atomically replace this file; default: stdout")
    parser.add_argument(
        "--format", choices=("json", "jsonl"), help="Default: infer from file suffix"
    )
    args = parser.parse_args(argv)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    LOGGER.handlers = [handler]
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    rejected = 0

    def diagnostic(code: str, record: int) -> None:
        nonlocal rejected
        rejected += 1
        LOGGER.warning(code, extra={"record": record})

    phase = "arguments"
    try:
        if args.output and args.output.resolve() in {args.input.resolve(), args.config.resolve()}:
            raise ValueError("output must differ from input and config")
        format = args.format or args.input.suffix.removeprefix(".").lower()
        if format not in ("json", "jsonl"):
            raise ValueError("specify --format json or jsonl")
        phase = "configuration"
        config = Config.model_validate_json(read_text(args.config))
        phase = "ingestion"
        events = load_events(args.input, format, diagnostic)
        phase = "detection"
        alerts = Pipeline(config).run(events)
        phase = "output"
        if args.output:
            write_alerts(args.output, alerts)
        else:
            for alert in alerts:
                print(alert.model_dump_json())
        LOGGER.info(
            "completed",
            extra={"accepted": len(events), "rejected": rejected, "alerts": len(alerts)},
        )
        return 2 if rejected else 0
    except (OSError, ValueError, RecursionError) as error:
        # Exception messages may contain input values, credentials, or filesystem details.
        LOGGER.error(
            "processing_failed", extra={"phase": phase, "error_type": type(error).__name__}
        )
        return 1
    finally:
        LOGGER.removeHandler(handler)
        handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
