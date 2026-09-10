"""Deterministic enrichment, rule evaluation, and event-time correlation."""

import hashlib
import json
from collections import deque
from collections.abc import Iterable
from datetime import timedelta
from ipaddress import ip_network
from typing import Literal

from security_event_pipeline.models import (
    Alert,
    Config,
    EnrichedEvent,
    Event,
    Evidence,
    IPAddress,
    Rule,
    Severity,
)


def process_name(path: str | None) -> str:
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()


class Pipeline:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.networks = tuple(ip_network(network) for network in config.internal_networks)

    def scope(self, address: IPAddress | None) -> Literal["internal", "external", "unknown"]:
        if address is None:
            return "unknown"
        return "internal" if any(address in network for network in self.networks) else "external"

    def enrich(self, event: Event) -> EnrichedEvent:
        return EnrichedEvent(
            event=event,
            privileged_user=event.user in self.config.privileged_users,
            sensitive_asset=event.asset in self.config.sensitive_assets,
            source_scope=self.scope(event.source_ip),
            destination_scope=self.scope(event.destination_ip),
        )

    def run(self, events: Iterable[Event]) -> list[Alert]:
        ordered = sorted(events, key=lambda event: event.timestamp)
        if len({event.id for event in ordered}) != len(ordered):
            raise ValueError("pipeline requires unique event IDs")
        alerts: list[Alert] = []
        failures: dict[tuple[str, str, str | None, str, str | None], deque[EnrichedEvent]] = {}
        processes: dict[tuple[str, str, str | None, str], EnrichedEvent] = {}
        policy = self.config.correlation
        suspicious = {name.casefold() for name in policy.suspicious_processes}
        for event in ordered:
            enriched = self.enrich(event)
            for rule in self.config.rules:
                if matches(rule, enriched):
                    alerts.append(
                        make_alert(
                            "rule:" + rule.id,
                            rule.title,
                            rule.severity,
                            rule.risk,
                            [enriched],
                            f"Matched configured rule {rule.id}: {event.type}/{event.action}.",
                        )
                    )
            if not policy.enabled:
                continue
            if event.type == "authentication" and event.action == "login":
                key = (event.source, event.tenant, event.user, str(event.source_ip), event.asset)
                history = failures.setdefault(key, deque(maxlen=policy.failed_login_threshold))
                while history and event.timestamp - history[0].event.timestamp > policy.window:
                    history.popleft()
                if event.outcome == "failure":
                    history.append(enriched)
                elif event.outcome == "success":
                    if (
                        len(history) >= policy.failed_login_threshold
                        and history[-1].event.timestamp < event.timestamp
                    ):
                        alerts.append(
                            make_alert(
                                "correlation:login-recovery",
                                "Repeated failed logins followed by success",
                                "high",
                                65,
                                [*history, enriched],
                                f"At least {policy.failed_login_threshold} failures followed by success "
                                f"for the same user, source IP, and asset within {policy.window_seconds}s.",
                            )
                        )
                    history.clear()
            if event.type == "endpoint" and event.process_id:
                process_key = (event.source, event.tenant, event.asset, event.process_id)
                if event.action == "process_start":
                    # Any new start invalidates prior attribution; a failed start cannot seed it.
                    processes.pop(process_key, None)
                    if event.outcome != "failure" and process_name(event.process) in suspicious:
                        processes[process_key] = enriched
                elif (
                    event.action == "network_connect"
                    and event.outcome != "failure"
                    and enriched.destination_scope == "external"
                ):
                    start = processes.get(process_key)
                    if (
                        start
                        and timedelta(0) < event.timestamp - start.event.timestamp <= policy.window
                    ):
                        alerts.append(
                            make_alert(
                                "correlation:process-egress",
                                "Suspicious process followed by outbound connection",
                                "high",
                                70,
                                [start, enriched],
                                f"Suspicious executable connected outside configured internal networks on "
                                f"the same host and process ID within {policy.window_seconds}s.",
                            )
                        )
                        del processes[process_key]
        return alerts


def matches(rule: Rule, enriched: EnrichedEvent) -> bool:
    event = enriched.event
    return (
        rule.enabled
        and event.type == rule.event_type
        and (rule.source is None or event.source == rule.source)
        and event.action == rule.action
        and (rule.outcome is None or event.outcome == rule.outcome)
        and (
            not rule.process_names
            or process_name(event.process) in {name.casefold() for name in rule.process_names}
        )
        and (not rule.privileged_only or enriched.privileged_user)
        and (not rule.external_destination_only or enriched.destination_scope == "external")
    )


def make_alert(
    rule_id: str,
    title: str,
    severity: Severity,
    base_risk: int,
    events: list[EnrichedEvent],
    reason: str,
) -> Alert:
    ids = tuple(item.event.id for item in events)
    privileged = any(item.privileged_user for item in events)
    sensitive = any(item.sensitive_asset for item in events)
    risk = min(100, base_risk + 15 * privileged + 10 * sensitive)
    digest = hashlib.sha256(json.dumps([rule_id, ids]).encode()).hexdigest()[:24]
    return Alert(
        id=digest,
        rule_id=rule_id,
        title=title,
        severity=severity,
        risk_score=risk,
        contributing_events=ids,
        evidence=tuple(
            Evidence(
                event_id=item.event.id,
                source=item.event.source,
                tenant=item.event.tenant,
                timestamp=item.event.timestamp,
                action=item.event.action,
                outcome=item.event.outcome,
                provenance=item.event.provenance,
            )
            for item in events
        ),
        timestamp=events[-1].event.timestamp,
        reason=f"{reason} Risk: base {base_risk}, privileged +{15 * privileged}, sensitive +{10 * sensitive} (capped at 100).",
    )
