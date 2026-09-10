# Input, detection policy, and operation

Detailed contracts for the local CLI. See the [quickstart](../README.md) and [vendor source guide](sources.md).

## Input contract

Generic records require a nonempty string `id`, a timezone-aware `timestamp`, `type`, and `action`. `outcome` is `success`, `failure`, or `unknown` (default). Use ISO 8601 timestamps in exported files. IDs must be unique within a batch.

| Type | Source fields mapped to common fields | Requirements |
| --- | --- | --- |
| `authentication` | `username` → `user`, `host` → `asset`, `src_ip` → `source_ip` | Username and source IP |
| `endpoint` | `username` → `user`, `host` → `asset`, `image` → `process`, `pid` → `process_id`, `src_ip` → `source_ip`, `dst_ip` → `destination_ip` | Host; image for `process_start`; destination IP for `network_connect` |
| `cloud` | `actor` → `user`, `resource` → `asset`, `src_ip` → `source_ip` | Common required fields |

`pid` is a string. Endpoint correlation requires it on both events. These are the original generic export formats. Vendor envelopes use the adapters described in the source guide. Unknown source fields are excluded from detection fields and retained in a separate immutable source snapshot. Unknown configuration fields fail validation.

Example input:

```json
{"id":"cloud-1","timestamp":"2026-01-15T10:03:00Z","type":"cloud","action":"StopLogging","outcome":"success","actor":"admin@example.test","resource":"audit-trail","src_ip":"203.0.113.10"}
```

Selected corresponding alert fields (full output also includes `id` and structured `evidence`):

```json
{
  "rule_id": "rule:audit-disabled",
  "title": "Cloud audit logging disabled",
  "severity": "critical",
  "risk_score": 100,
  "contributing_events": ["cloud-1"],
  "reason": "Matched configured rule audit-disabled: cloud/StopLogging. Risk: base 80, privileged +15, sensitive +10 (capped at 100).",
  "timestamp": "2026-01-15T10:03:00Z"
}
```

## Detection policy

[samples/config.json](../samples/config.json) supplies privileged identities, sensitive assets, internal CIDRs, rules, and correlation settings. Identity and asset matching is exact and case-sensitive. Process matching uses a case-insensitive basename and understands Windows and Unix separators.

Each rule specifies an ID, title, severity, base risk, event type, and action. Optional predicates are `source`, `outcome`, `process_names`, `privileged_only`, and `external_destination_only`; all predicates must match. Set `enabled` to false to disable a rule. An empty rule list still permits correlation.

Correlations stay within one source and tenant and use the configured `window_seconds` (default 300):

- **Failed logins followed by success:** the latest threshold failures for the same user, source IP, and asset precede a successful login. The oldest contributing failure must be within the window. Success clears the history. Default threshold: three.
- **Suspicious process followed by outbound connection:** a configured executable starts, then connects outside the configured internal networks on the same host and process ID. A new process start replaces prior state for that ID. The first matching connection consumes the start. Explicitly failed starts cannot seed correlation, and failed connections cannot complete or consume a sequence. Unknown outcomes remain eligible for generic exporters that omit outcome; adapters must distinguish observations from connection events. Single-event rules use their configured outcome predicate independently.

Events at exactly the window boundary qualify. The completing event must have a later timestamp than its precursor. Equal timestamps retain input order. Set `correlation.enabled` to false to disable both correlations.

Risk is `min(100, base + 15 if privileged + 10 if sensitive)`. Each modifier applies once across all contributing events. Correlation base risks are 65 and 70, respectively. Severity is the rule's triage label and remains independent of risk. Scores are prioritization heuristics, not probabilities of compromise.

## Operation and failure handling

Alerts go to stdout or an atomically replaced `--output` file. Diagnostics go to stderr as JSON:

```json
{"level":"warning","message":"invalid_event","record":10}
{"level":"info","message":"completed","accepted":9,"rejected":1,"alerts":5}
```

| Exit status | Meaning |
| --- | --- |
| `0` | All records accepted, including an empty batch |
| `1` | Fatal input, configuration, processing, or output failure |
| `2` | Partial processing with rejected records; also used by argparse for invalid CLI arguments |

JSONL errors are isolated per nonblank line. JSON arrays must parse completely before record validation. Duplicate IDs keep the first valid occurrence and reject later occurrences, distinguishing exact duplicates from conflicting content. Record numbers refer to physical JSONL lines or one-based JSON array positions.

Limits are 10 MiB per input/configuration file and 50,000 input records. Fatal failures before output preserve an existing output file. Output-file writes use a private temporary file in the destination directory and atomic replacement; stdout cannot provide transactional delivery. Parent directories must exist. Input and configuration paths cannot be used as output paths.

Logs omit raw records, validation exception messages, and user-controlled paths. Fatal logs identify the failing phase and exception type. Alerts retain event IDs and source provenance for evidence lookup; protect source files and alert output according to their data sensitivity. The pipeline never executes event contents or rule expressions.


## Verification scenarios

- Failed generic process starts and failed connections cannot produce egress correlations.
- A failed connection followed by a successful one preserves the original start until success.
- A new failed start for the same PID invalidates old attribution.
- Window comparisons work at the maximum supported datetime without constructing a future timestamp.
- Existing unknown-outcome generic events retain their supported behavior.

Tests exercise these contracts independently of the public sample corpus. Native adapter fixtures use named scenarios in `tests/fixtures/source_events.json`. Synthetic scenarios establish expected behavior; they do not measure detection accuracy on operational logs.
