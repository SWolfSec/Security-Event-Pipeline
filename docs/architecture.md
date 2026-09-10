# Architecture

## Components and ownership

| Module | Responsibility |
| --- | --- |
| `models.py` | Event, policy, provenance, evidence, and alert contracts |
| `ingest.py` | Bounded reads, JSON parsing, validation, duplicate handling, sorting |
| `sources.py` | Native-to-common field mappings and source identity |
| `engine.py` | Enrichment, rule evaluation, correlation state, risk, evidence |
| `cli.py` | Arguments, structured diagnostics, exit status, output replacement |

The engine has no filesystem or network operations. Each `Pipeline.run` call creates independent correlation state. It sorts defensively for direct Python callers and rejects duplicate IDs; the CLI ingestion path already sorts and diagnoses duplicates.

Configuration is validated before input processing. Alerts are written after evaluation completes. For output files, the CLI writes a private temporary file in the destination directory, flushes and fsyncs it, then replaces the destination. Cleanup runs on failure. Directory metadata is not fsynced, so atomic visibility does not guarantee durability across sudden power loss.

## Correlation state

Login history is a dictionary keyed by `(source, tenant, user, source IP, asset)`. Each value is a deque capped at the failure threshold. Expired failures are removed when that key is visited. A success clears history, whether or not it produces an alert.

Process history is keyed by `(source, tenant, asset, process ID)` and holds the latest suspicious start. Every start invalidates the previous entry, including a failed start; only starts without explicit failure can seed a sequence. Failed connections leave history untouched. The first eligible external connection consumes its start.

Both patterns use event time. Process windows compare elapsed time through subtraction, avoiding overflow when a timestamp is close to the datetime upper boundary. Equal timestamps preserve input order, but a completing event must be later than its precursor. Inactive expired dictionary entries remain until the batch ends and cannot match outside the window.

Alert order follows completing-event time, with configured rules before correlation for the same event. Risk modifiers apply once across the contributing events. The behavioral contracts and unknown-outcome policy are in [usage](usage.md).

## Provenance and trust boundaries

All ingestion adapters call `Event.from_record`. Normalized fields drive detection; a separate immutable JSON snapshot retains the complete parsed source record. Compact provenance is shared with alert evidence. Snapshots are excluded from serialization and representation.

Source/tenant labels come from collector routing metadata, which the tool does not authenticate. Configuration is trusted operator input but is schema-validated. No record or rule expression is executed. Logs use fixed codes and positions instead of raw payloads or validation exception bodies.

The [source guide](sources.md#provenance-contract) defines original-field mappings, fingerprint serialization, ID construction, and evidence lookup. Direct Python Events without source data have null provenance. Deserializing an Event cannot restore the excluded snapshot; retain original input for full evidence.

## Scale and tradeoffs

For N events and R rules, sorting costs O(N log N); rule evaluation costs O(NR) for fixed-size predicates. Network and executable list sizes also affect evaluation cost. Correlation uses dictionary lookups and bounded per-key queues.

Memory grows with events, alerts, and input size. Source snapshots add a serialized copy of accepted records; multiple alerts repeat evidence in JSON output. CLI input limits bound batches, while direct Python callers must impose their own limits. A large trusted rule configuration can amplify alert volume.

The current design intentionally has no persistent correlation history. Cross-run suppression, cross-provider identity resolution, and richer process attribution require additional contracts before implementation.
