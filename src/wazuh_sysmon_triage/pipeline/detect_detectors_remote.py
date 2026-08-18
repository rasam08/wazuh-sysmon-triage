from __future__ import annotations

from collections.abc import Iterable

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.findings import RemoteActivityLead

from .detect_types import RULE_METADATA


def _detect_remote_activity(leads: Iterable[RemoteActivityLead]) -> list[Alert]:
    alerts: list[Alert] = []
    for lead in leads:
        alert_type = (
            "remote_logon_followed_by_service_install"
            if lead.action_event_id == 4697
            else "remote_logon_followed_by_scheduled_task"
        )
        metadata = RULE_METADATA[alert_type]
        tags = ["remote-logon", lead.action_type]
        if lead.source_host_key:
            tags.append(f"source-host:{lead.source_host_key}")
        alerts.append(
            Alert(
                rule_id=metadata["rule_id"],
                rule_name=metadata["rule_name"],
                primary_event_id=metadata["primary_event_id"],
                utc_time=lead.action_at,
                alert_type=alert_type,
                category="remote_activity_behavior",
                finding_kind="hypothesis",
                evidence_strength=lead.evidence_strength,
                reason=lead.reason,
                host_key=lead.target_host_key,
                image=lead.action_resource,
                command_line=lead.action_details,
                source_host_key=lead.source_host_key,
                source_ip=lead.source_ip,
                source_port=lead.source_port,
                process_guid="",
                tags=tags,
                evidence_refs=lead.evidence_refs,
            )
        )
    return alerts
