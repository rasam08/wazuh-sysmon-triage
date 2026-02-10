from datetime import UTC, datetime

from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
)
from wazuh_sysmon_triage.pipeline.correlate import correlate_data


def test_correlate_data_process_chain_and_artifact() -> None:
    parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{PARENT}",
        process_id=100,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks.exe /create",
        user="HOST\\user",
    )
    child = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{CHILD}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
        parent_process_guid="{PARENT}",
        parent_process_id=100,
        parent_image="C:\\Windows\\System32\\schtasks.exe",
    )
    file_event = FileCreateEvent(
        event_id=11,
        timestamp=datetime(2024, 1, 1, 0, 2, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{CHILD}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        target_filename="C:\\ProgramData\\lab_demo.ps1",
        creation_utc_time=datetime(2024, 1, 1, 0, 1, 59, tzinfo=UTC),
        user="HOST\\user",
    )

    result = correlate_data([parent, child, file_event])
    summary = result["summary"]

    assert len(result["nodes"]) == 2
    assert len(result["edges"]) == 1
    assert result["edges"][0].parent_guid == "{PARENT}"
    assert result["edges"][0].child_guid == "{CHILD}"

    assert len(result["artifacts"]) == 1
    artifact = result["artifacts"][0]
    assert artifact.path == "c:\\programdata\\lab_demo.ps1"
    assert artifact.confidence.value == "HIGH"
    assert artifact.reason == "Interpreter process or encoded/scripted command"

    assert any("schtasks.exe -> powershell.exe" in bullet for bullet in summary.narrative_bullets)
    assert any("Suspicious script write" in bullet for bullet in summary.narrative_bullets)


def test_correlate_tags_and_network_activity() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{GUID}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
    )
    net = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{GUID}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        destination_ip="8.8.8.8",
        destination_port=4444,
        protocol="tcp",
    )

    result = correlate_data([process, net])
    node = result["nodes"][0]
    assert "attack.t1059" in node.tags
    assert "suspicious.encoding" in node.tags

    network = result["network_activity"][0]
    assert network["suspicious"] is True
    assert "public_ip" in network["reason"]
    assert "uncommon_port" in network["reason"]
