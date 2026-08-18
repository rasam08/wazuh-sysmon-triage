from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from wazuh_sysmon_triage.models.findings import EvidenceStrength
from wazuh_sysmon_triage.models.sysmon import (
    RemoteLogonEvent,
    ScheduledTaskCreatedEvent,
    ServiceInstallEvent,
)
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.detect import detect_alerts
from wazuh_sysmon_triage.pipeline.normalize import normalize_data_with_report
from wazuh_sysmon_triage.pipeline.pivot import assign_alert_ids, build_pivot_bundles
from wazuh_sysmon_triage.pipeline.remote_activity import correlate_remote_activity


def _fixture_hits() -> list[dict]:
    path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "incident_004_remote_service_task"
        / "raw_hits.ndjson"
    )
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_native_windows_evidence_reconstructs_bounded_remote_activity() -> None:
    events, report = normalize_data_with_report(_fixture_hits(), collect_dropped=True)

    assert report.dropped_count == 0
    assert sum(isinstance(event, RemoteLogonEvent) for event in events) == 1
    assert sum(isinstance(event, ServiceInstallEvent) for event in events) == 1
    assert sum(isinstance(event, ScheduledTaskCreatedEvent) for event in events) == 1

    correlation = correlate_data(events)
    assert len(correlation["authentication_activity"]) == 1
    assert len(correlation["service_install_activity"]) == 1
    assert len(correlation["scheduled_task_activity"]) == 1
    leads = correlation["remote_activity_leads"]
    assert len(leads) == 2
    source_host = next(event.host_key for event in events if event.agent_id == "101")
    assert all(lead.source_host_key == source_host for lead in leads)
    assert all(lead.source_host_resolution == "exact_agent_ip" for lead in leads)
    assert all(lead.evidence_strength is EvidenceStrength.STRONG for lead in leads)
    assert all("not proof of malicious lateral movement" in lead.reason for lead in leads)

    alerts = assign_alert_ids(detect_alerts(events))
    assert {alert.alert_type for alert in alerts} == {
        "remote_logon_followed_by_service_install",
        "remote_logon_followed_by_scheduled_task",
    }
    assert all(alert.finding_kind == "hypothesis" for alert in alerts)
    assert all(alert.process_guid == "" for alert in alerts)

    bundles = build_pivot_bundles(alerts, events)
    assert len(bundles) == 2
    assert all(bundle["counts"]["authentication_events"] == 1 for bundle in bundles)
    assert all(bundle["counts"]["service_installs"] == 1 for bundle in bundles)
    assert all(bundle["counts"]["scheduled_task_creations"] == 1 for bundle in bundles)


def test_account_only_join_is_circumstantial_and_time_bounded() -> None:
    events, _report = normalize_data_with_report(_fixture_hits())
    logon = next(event for event in events if isinstance(event, RemoteLogonEvent))
    service = next(event for event in events if isinstance(event, ServiceInstallEvent))
    mismatched_logon_id = service.model_copy(update={"subject_logon_id": "0x999"})

    leads = correlate_remote_activity([logon, mismatched_logon_id])
    assert len(leads) == 1
    assert leads[0].evidence_strength is EvidenceStrength.CIRCUMSTANTIAL
    assert "account names match" in leads[0].reason

    too_late = mismatched_logon_id.model_copy(
        update={"timestamp": logon.timestamp + timedelta(minutes=16)}
    )
    assert correlate_remote_activity([logon, too_late]) == []


def test_unmatched_or_interactive_logon_does_not_create_remote_lead() -> None:
    events, _report = normalize_data_with_report(_fixture_hits())
    logon = next(event for event in events if isinstance(event, RemoteLogonEvent))
    service = next(event for event in events if isinstance(event, ServiceInstallEvent))

    interactive = logon.model_copy(update={"logon_type": 2})
    assert correlate_remote_activity([interactive, service]) == []

    unrelated = service.model_copy(
        update={
            "subject_logon_id": "0x999",
            "subject_user_name": "different.user",
            "user": "CORP\\different.user",
        }
    )
    assert correlate_remote_activity([logon, unrelated]) == []

    sentinel_ids = service.model_copy(
        update={
            "subject_logon_id": "0x0",
            "subject_user_name": "different.user",
            "user": "CORP\\different.user",
        }
    )
    sentinel_logon = logon.model_copy(
        update={"target_logon_id": "0x0", "target_user_name": "another.user"}
    )
    assert correlate_remote_activity([sentinel_logon, sentinel_ids]) == []


def test_native_security_event_requires_authoritative_provider() -> None:
    hit = _fixture_hits()[0]
    hit["_source"]["data"]["win"]["system"]["providerName"] = "Unexpected-Provider"

    events, report = normalize_data_with_report([hit], collect_dropped=True)

    assert events == []
    assert report.dropped_by_reason == {"unexpected_provider_windows_security": 1}
