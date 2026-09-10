# Source formats and sample scenarios

The expanded corpus contains 266 synthetic records using documented vendor fields. Each of six source files contains 40 routine records plus targeted scenarios. These are authored fixtures, not customer logs or captures from live accounts. The records preserve vendor field names and nesting; optional vendor fields are selectively included.

| Source file in `samples/vendors/` | Records | Additional scenarios | Alerts with mixed policy |
| --- | ---: | --- | ---: |
| `aws_cloudtrail.jsonl` | 44 | Successful and denied StopLogging; console success and failure | 2 |
| `gcp_audit.jsonl` | 43 | Allowed and denied IAM policy changes; logging sink deletion | 2 |
| `okta.jsonl` | 47 | Three failed logins then success; MFA reset; policy challenge and denial | 3 |
| `osquery_linux.jsonl` | 46 | nc execution, failed and successful egress, internal traffic, bind, unrelated host | 2 |
| `osquery_macos.jsonl` | 43 | nc execution, exit, and a benign fork | 1 |
| `github.jsonl` | 43 | Repository visibility change, deletion, and member removal | 2 |

The first 40 records per file produce no alerts under `mixed-config.json`. Routine activity includes cloud inventory, SSO and MFA events, developer processes, repository administration, and expected access denials. The mixed file interleaves all six source files, including out-of-order delivery. All records have distinct normalized IDs.

```sh
uv run security-event-pipeline samples/mixed-events.jsonl --config samples/mixed-config.json
uv run security-event-pipeline samples/vendors/okta.jsonl --config samples/mixed-config.json
uv run security-event-pipeline samples/vendors/osquery_linux.jsonl --config samples/mixed-config.json
```

Expected mixed output is in [mixed-expected-alerts.jsonl](../samples/mixed-expected-alerts.jsonl). The original compact sample remains a separate compatibility example.

## Collector envelope

The CLI accepts one envelope per JSONL line, or a JSON array of envelopes. Generic records and envelopes can share a file. The envelope is this project's routing metadata; `record` contains the native event:

```json
{
  "source": "okta",
  "tenant": "acme.okta.example.test",
  "record": {
    "uuid": "51a230be-5c23-4b67-b18d-f5dce86225ee",
    "published": "2026-01-15T10:00:00Z",
    "eventType": "user.session.start",
    "actor": {"id": "00u00000000000000099", "alternateId": "admin@example.test"},
    "client": {"ipAddress": "203.0.113.10"},
    "outcome": {"result": "FAILURE"}
  }
}
```

`source` must match one of the six supported identifiers. `tenant` is a required stable account, project, organization, or endpoint-fleet label supplied by the collector. Unknown envelope fields are rejected. The collector must assign trustworthy routing metadata; this local tool cannot authenticate tenant ownership. AWS `Records` bundles, API pagination wrappers, compressed files, and osquery snapshot/batch formats must be unpacked before ingestion. No vendor API calls occur.

The common event schema gains `source` and `tenant`; generic records retain defaults `generic` and `local`. SaaS audit events use the `saas` category. Both correlation keys include source and tenant in addition to their existing identity/host keys. Identity and asset enrichment lists remain exact global matches, so choose unambiguous identifiers when combining tenants.

Native event IDs are `source:sha256`, using SHA-256 over JSON serialization of `[source, tenant, identity]` with sorted object keys and default Python JSON separators. AWS identity is `eventID`, Okta is `uuid`, and GitHub is `_document_id`. GCP uses `[logName, insertId, timestamp]` to distinguish repeated insert IDs in different streams. Osquery has no universal event ID, so its identity is the complete result record. Reordered object keys preserve IDs; changed osquery collection metadata changes IDs. Use `normalize(envelope).id` to locate contributing records. Retain the original batch for evidence lookup.

## Field mappings and supported semantics

### AWS CloudTrail

`eventTime`, `eventName`, `userIdentity.arn`, and `sourceIPAddress` map to timestamp, action, user, and source IP. Asset uses `requestParameters.name` when present, otherwise `recipientAccountId`. API calls without `errorCode` map to success; calls with an error map to failure. `ConsoleLogin` becomes authentication/login and uses `responseElements.ConsoleLogin`, since console failure is not reliably represented by `errorCode`. Cloud service DNS callers have unknown IP scope. This adapter does not resolve role sessions to human users or enumerate every resource in an API call. See the [CloudTrail record reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) and [IAM sign-in examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).

### GCP Audit Logs

The adapter requires a Cloud Logging entry with an AuditLog `protoPayload.@type`. It maps `timestamp`, `protoPayload.methodName`, `authenticationInfo.principalEmail`, `resourceName`, and `requestMetadata.callerIp`. Missing or zero `status.code` maps to success; nonzero integer codes map to failure. Redacted `private` and `gce-internal-ip` callers have unknown IP scope. Missing principal emails remain absent. This mapping targets ordinary completed API records; it does not join long-running operation start/completion entries. See [AuditLog fields](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog) and [Cloud Logging audit entry structure](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs).

### Okta System Log

`published` is event time, `actor.alternateId` (falling back to actor ID) is user, and `client.ipAddress` is source IP. Asset is the envelope tenant. Only `user.session.start` becomes login; SSO, MFA, reset, and policy actions preserve `eventType`. Only `SUCCESS` and `FAILURE` map to completed outcomes. Other outcomes remain unknown, preventing policy ALLOW/DENY or CHALLENGE from counting as completed logins. Actor and client IP are required by the authentication schema; system events without them are rejected. See the [System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/), [query examples](https://developer.okta.com/docs/reference/system-log-query/), and [event catalog](https://developer.okta.com/docs/reference/api/event-types/).

### Linux and macOS osquery

These adapters accept event-format `added` results with `hostIdentifier`, `name`, and `columns`. Use query names `process_events` and `socket_events` on Linux, and `es_process_events` on macOS. Query names are operator-defined, so configure those exact names. Event time comes from `columns.time` in epoch seconds, independently of logger `unixTime`. PID accepts numeric strings or integers. Paths come from `columns.path`; macOS usernames come from `columns.username`. Linux UID values are not silently translated into usernames.

Example query projections are `SELECT *, time FROM process_events`, `SELECT *, time FROM socket_events`, and `SELECT *, time FROM es_process_events`. Enable the corresponding event publisher when collecting live logs; the pipeline itself requires no osquery installation.

Linux process events become process_start. Only successful socket `connect` events become network_connect; bind, failed, or in-progress sockets become network_observe and cannot complete egress correlation. macOS `exec` becomes process_start; `fork` and `exit` become process_observe. Modern macOS network events are outside this adapter's scope. Snapshot process rows are not execution evidence and are rejected. See [osquery logging](https://osquery.readthedocs.io/en/stable/deployment/logging/), [platform support and socket outcomes](https://github.com/osquery/osquery/blob/master/docs/wiki/deployment/process-auditing.md), and the [EndpointSecurity table schema](https://github.com/osquery/osquery/blob/master/specs/darwin/es_process_events.table).

### GitHub organization audit logs

`@timestamp` is epoch milliseconds; `action`, `actor`, and optional `actor_ip` map directly. Asset is `repo`, falling back to `org`. Outcome stays unknown because audit records have no shared success/failure field. The sample visibility rule detects any `repo.access` event; it does not claim every visibility change makes a repository public. Actor IP availability depends on export settings; missing addresses remain unknown. See the [audit API examples](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization) and [audit action definitions](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization).

## Scope

Adapters validate fields needed by the common schema. The complete parsed source record, including command-line and request bodies, is retained in `Event.original_json` and excluded from serialized output. Selected original fields and a fingerprint are carried in alert evidence. They do not implement complete vendor schemas, cross-provider identity resolution, or unrestricted field-expression rules. Risk arithmetic, window boundaries, and input limits are unchanged. Alerts add structured evidence; ingestion now distinguishes conflicting IDs and rejects duplicate JSON object keys. No dependencies or infrastructure were added.

## Provenance contract

All adapters use `Event.from_record`. The `provenance` summary is immutable and preserves original strings without trimming or case conversion. Missing source values remain null; absence is never replaced with an invented successful outcome. `Event.original_json` stores the complete parsed native record, or the complete generic record, as immutable text. It is excluded from model dumps, JSON serialization, and representation.

| Source | `record_id` | Original `action` | Original `event_type` | Original `outcome` |
| --- | --- | --- | --- | --- |
| Generic | `id` | `action` | `type` | `outcome` |
| AWS | `eventID` | `eventName` | `eventType` | `responseElements.ConsoleLogin`, otherwise `errorCode` |
| GCP | `insertId` | `protoPayload.methodName` | `protoPayload.@type` | `protoPayload.status.code` |
| Okta | `uuid` | `eventType` | `eventType` | `outcome.result` |
| GitHub | `_document_id` | `action` | null | null |
| osquery | `columns.eid` when present | `columns.event_type`, otherwise `columns.action`, otherwise top-level `action` | Query `name` | `columns.status` |

For Linux process events, the original action is `added` and the original event type is `process_events`; the normalized action is `process_start`. Socket records retain `connect` or `bind`. macOS retains `exec`, `fork`, or `exit`. The full snapshot preserves other context such as osquery's outer `added` action, original timestamp strings, actor identifiers, and unselected fields.

`record_sha256` hashes `json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")`. It is a content fingerprint, independent of the existing event-ID algorithm. Reordered object keys have the same fingerprint; changed source fields have a different fingerprint. Record IDs and alert IDs remain stable under the existing algorithms. When a batch repeats an event ID with changed content, the later record is rejected with `conflicting_event_id`; exact content repeats use `duplicate_event_id`. Retain the input batch to inspect either occurrence.

Each alert adds an `evidence` array in contributing-event order, containing `event_id`, `source`, `tenant`, `timestamp`, normalized `action`/`outcome`, and `provenance`. Directly constructed Python Events without source data produce null provenance. Fingerprints do not prove source authenticity or preserve exact file bytes. Collectors remain responsible for trusted tenant routing and original-log retention.
