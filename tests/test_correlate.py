from datetime import UTC, datetime

from wazuh_sysmon_triage.models.findings import EvidenceStrength
from wazuh_sysmon_triage.models.sysmon import (
    DnsQueryEvent,
    FileCreateEvent,
    FileDeleteEvent,
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    ProcessTerminateEvent,
    RegistryEvent,
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
    assert artifact.path == "C:\\ProgramData\\lab_demo.ps1"
    assert artifact.relationship_strength is EvidenceStrength.DETERMINISTIC
    assert artifact.reason == "Sysmon EID 11 ProcessGuid identifies the creating process"

    assert any("schtasks.exe -> powershell.exe" in bullet for bullet in summary.narrative_bullets)
    assert any("Script-like file created" in bullet for bullet in summary.narrative_bullets)


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
    assert node.tags == []

    network = result["network_activity"][0]
    assert network["observations"] == [
        "public_destination",
        "uncommon_destination_port",
    ]
    assert "suspicious" not in network


def test_network_context_reports_observations_without_a_verdict() -> None:
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{GUID-2}",
        process_id=210,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
    )
    web_net = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{GUID-2}",
        process_id=210,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
    )

    network = correlate_data([process, web_net])["network_activity"][0]

    assert network["destination_class"] == "public"
    assert network["observations"] == ["public_destination"]
    assert "suspicious" not in network


def test_correlate_links_parent_guid_when_events_arrive_out_of_order() -> None:
    child = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{CHILD-OOO}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        user="HOST\\user",
        parent_process_guid="{PARENT-OOO}",
        parent_process_id=100,
        parent_image="C:\\Windows\\System32\\schtasks.exe",
    )
    parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{PARENT-OOO}",
        process_id=100,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks.exe /create",
        user="HOST\\user",
    )

    result = correlate_data([child, parent])
    edges = result["edges"]
    assert len(edges) == 1
    assert edges[0].parent_guid == "{PARENT-OOO}"
    assert edges[0].child_guid == "{CHILD-OOO}"
    assert edges[0].reason == "Sysmon EID 1 ParentProcessGuid references ProcessGuid"
    assert edges[0].relationship_strength is EvidenceStrength.DETERMINISTIC


def test_process_guids_are_scoped_to_the_host() -> None:
    host_a_parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="001",
        agent_name="host-a-agent",
        computer="HOST-A",
        process_guid="{SHARED-PARENT}",
        process_id=100,
        image="C:\\Windows\\System32\\cmd.exe",
    )
    host_b_parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 1, tzinfo=UTC),
        agent_id="002",
        agent_name="host-b-agent",
        computer="HOST-B",
        process_guid="{SHARED-PARENT}",
        process_id=100,
        image="C:\\Windows\\System32\\services.exe",
    )
    host_b_child = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 2, tzinfo=UTC),
        agent_id="002",
        agent_name="host-b-agent",
        computer="HOST-B",
        process_guid="{HOST-B-CHILD}",
        process_id=200,
        image="C:\\Windows\\System32\\whoami.exe",
        parent_process_guid="{SHARED-PARENT}",
        parent_process_id=100,
    )

    result = correlate_data([host_a_parent, host_b_child, host_b_parent])

    assert len(result["nodes"]) == 3
    assert len(result["edges"]) == 1
    edge = result["edges"][0]
    assert edge.host_key == host_b_parent.host_key
    assert edge.host_key != host_a_parent.host_key
    assert edge.parent_guid == "{SHARED-PARENT}"
    assert edge.child_guid == "{HOST-B-CHILD}"


def test_later_process_create_enriches_an_earlier_seen_network_node() -> None:
    network = NetworkConnectEvent(
        event_id=3,
        timestamp=datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{ORDER-INDEPENDENT}",
        process_id=321,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        destination_ip="8.8.8.8",
        destination_port=443,
    )
    process = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{ORDER-INDEPENDENT}",
        process_id=321,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile -Command Get-Process",
        user="HOST-A\\analyst",
        hashes="SHA256=abcd",
        integrity_level="High",
    )

    node = correlate_data([network, process])["nodes"][0]

    assert node.cmdline == "powershell.exe -NoProfile -Command Get-Process"
    assert node.user == "HOST-A\\analyst"
    assert node.hashes == "SHA256=abcd"
    assert node.integrity_level == "High"
    assert node.created_at == process.timestamp
    assert node.first_seen == process.timestamp
    assert node.last_seen == network.timestamp


def test_missing_guid_parent_is_explicitly_unresolved() -> None:
    child = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{ORPHAN}",
        process_id=200,
        image="C:\\Windows\\System32\\cmd.exe",
        parent_process_guid="{NOT-COLLECTED}",
        parent_process_id=100,
    )

    result = correlate_data([child])

    assert result["edges"] == []
    assert len(result["unresolved_relationships"]) == 1
    unresolved = result["unresolved_relationships"][0]
    assert unresolved["parent_guid"] == "{NOT-COLLECTED}"
    assert unresolved["relationship_strength"] == "unresolved"


def test_pid_reuse_does_not_create_an_ambiguous_parent_edge() -> None:
    first_parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PID-ONE}",
        process_id=100,
        image="C:\\Windows\\System32\\cmd.exe",
    )
    second_parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 30, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PID-TWO}",
        process_id=100,
        image="C:\\Windows\\System32\\services.exe",
    )
    child = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 1, 0, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PID-CHILD}",
        process_id=200,
        image="C:\\Windows\\System32\\whoami.exe",
        parent_process_id=100,
    )

    result = correlate_data([child, first_parent, second_parent])

    assert result["edges"] == []
    assert len(result["unresolved_relationships"]) == 1
    unresolved = result["unresolved_relationships"][0]
    assert unresolved["reason"] == "Multiple bounded same-host PID candidates"
    assert unresolved["candidate_parent_guids"] == ["{PID-ONE}", "{PID-TWO}"]


def test_single_bounded_pid_parent_is_marked_circumstantial() -> None:
    parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PID-PARENT}",
        process_id=100,
        image="C:\\Windows\\System32\\cmd.exe",
    )
    child = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 5, 0, tzinfo=UTC),
        agent_id="999",
        computer="HOST-A",
        process_guid="{PID-CHILD}",
        process_id=200,
        image="C:\\Windows\\System32\\whoami.exe",
        parent_process_id=100,
    )

    result = correlate_data([parent, child])

    assert len(result["edges"]) == 1
    assert result["edges"][0].relationship_strength is EvidenceStrength.CIRCUMSTANTIAL


def test_p1_endpoint_evidence_is_process_scoped_and_preserved() -> None:
    ts = datetime(2024, 1, 1, tzinfo=UTC)
    process = ProcessCreateEvent(
        timestamp=ts,
        agent_id="001",
        computer="HOST-A",
        process_guid="{SOURCE}",
        process_id=4242,
        image="C:\\Tools\\reader.exe",
        command_line="reader.exe --inspect",
    )
    registry = RegistryEvent(
        event_id=13,
        timestamp=ts,
        agent_id="001",
        computer="HOST-A",
        process_guid="{SOURCE}",
        process_id=4242,
        image=process.image,
        registry_event_type="SetValue",
        target_object="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        details="C:\\Users\\alice\\update.exe",
    )
    dns = DnsQueryEvent(
        timestamp=ts,
        agent_id="001",
        computer="HOST-A",
        process_guid="{SOURCE}",
        process_id=4242,
        image=process.image,
        query_name="payload.example",
        query_status="0",
        query_results="203.0.113.10",
    )
    access = ProcessAccessEvent(
        timestamp=ts,
        agent_id="001",
        computer="HOST-A",
        process_guid="{SOURCE}",
        process_id=4242,
        image=process.image,
        target_process_guid="{LSASS}",
        target_process_id=500,
        target_image="C:\\Windows\\System32\\lsass.exe",
        granted_access="0x1010",
    )

    result = correlate_data([access, dns, registry, process])

    source = next(node for node in result["nodes"] if node.guid == "{SOURCE}")
    target = next(node for node in result["nodes"] if node.guid == "{LSASS}")
    assert source.synthetic is False
    assert source.cmdline == "reader.exe --inspect"
    assert target.synthetic is True
    assert result["registry_activity"][0]["relationship_strength"] == "deterministic"
    assert result["dns_activity"][0]["query_name"] == "payload.example"
    assert result["process_access_activity"][0]["target_process_guid"] == "{LSASS}"


def test_p1_same_guid_on_another_host_does_not_enrich_source_process() -> None:
    ts = datetime(2024, 1, 1, tzinfo=UTC)
    other_host = ProcessCreateEvent(
        timestamp=ts,
        agent_id="002",
        computer="HOST-B",
        process_guid="{SHARED}",
        process_id=99,
        image="C:\\Wrong\\other.exe",
        command_line="other.exe --wrong-host",
    )
    dns = DnsQueryEvent(
        timestamp=ts,
        agent_id="001",
        computer="HOST-A",
        process_guid="{SHARED}",
        process_id=99,
        image="C:\\Right\\source.exe",
        query_name="host-a.example",
    )

    result = correlate_data([other_host, dns])
    host_a = next(node for node in result["nodes"] if node.host_key == dns.host_key)

    assert host_a.image == "C:\\Right\\source.exe"
    assert host_a.cmdline is None
    assert len(result["nodes"]) == 2


def test_p2_lifecycle_and_file_deletion_are_process_scoped() -> None:
    start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 0, 1, tzinfo=UTC)
    process = ProcessCreateEvent(
        timestamp=start,
        agent_id="001",
        computer="HOST-A",
        process_guid="{LIFECYCLE}",
        process_id=42,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c cleanup.cmd",
    )
    deletion = FileDeleteEvent(
        event_id=23,
        timestamp=end,
        agent_id="001",
        computer="HOST-A",
        process_guid="{LIFECYCLE}",
        process_id=42,
        image=process.image,
        target_filename="C:\\Temp\\stage.tmp",
        hashes="SHA256=abcd",
        archived="true",
    )
    termination = ProcessTerminateEvent(
        timestamp=end,
        agent_id="001",
        computer="HOST-A",
        process_guid="{LIFECYCLE}",
        process_id=42,
        image=process.image,
    )

    result = correlate_data([termination, deletion, process])

    node = result["nodes"][0]
    assert node.synthetic is False
    assert node.created_at == start
    assert node.terminated_at == end
    assert result["file_delete_activity"][0]["target_filename"].endswith("stage.tmp")
    assert result["file_delete_activity"][0]["relationship_strength"] == "deterministic"
    assert result["process_termination_activity"][0]["process_guid"] == "{LIFECYCLE}"


def test_activity_only_process_node_is_marked_synthetic() -> None:
    termination = ProcessTerminateEvent(
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        agent_id="001",
        computer="HOST-A",
        process_guid="{MISSING-CREATE}",
        process_id=42,
        image="C:\\Windows\\System32\\cmd.exe",
    )

    result = correlate_data([termination])

    assert result["nodes"][0].synthetic is True
    assert result["nodes"][0].terminated_at == termination.timestamp
