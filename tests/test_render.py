from datetime import UTC, datetime

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import FileCreateEvent, ProcessCreateEvent
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.detect import detect_alerts, filter_alerts
from wazuh_sysmon_triage.pipeline.pivot import assign_alert_ids, build_pivot_bundles
from wazuh_sysmon_triage.pipeline.render import (
    render_alert_bundles,
    render_alerts_csv,
    render_process_tree,
    render_report,
    render_timeline,
)


def _build_events():
    parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        rule_id="92203",
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
        rule_id="92204",
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
        rule_id="92205",
        process_guid="{CHILD}",
        process_id=200,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        target_filename="C:\\ProgramData\\lab_demo.ps1",
        creation_utc_time=datetime(2024, 1, 1, 0, 1, 59, tzinfo=UTC),
        user="HOST\\user",
    )
    return [parent, child, file_event]


def test_render_outputs(tmp_path) -> None:
    events = _build_events()
    correlate_result = correlate_data(events)
    alerts = filter_alerts(detect_alerts(events))
    assign_alert_ids(alerts)
    bundles = build_pivot_bundles(alerts, events)

    render_timeline(events, str(tmp_path))
    render_process_tree(correlate_result, str(tmp_path))
    render_alerts_csv(alerts, str(tmp_path))
    render_alert_bundles(bundles, str(tmp_path))
    render_report(
        {
            **correlate_result,
            "events": events,
            "alerts": alerts,
            "query": {"agent_id": "999", "start": "2024-01-01T00:00:00Z"},
        },
        str(tmp_path),
    )

    timeline_path = tmp_path / "timeline.csv"
    process_path = tmp_path / "process_tree.json"
    alerts_path = tmp_path / "alerts.csv"
    report_path = tmp_path / "report.md"
    bundle_path = tmp_path / "alert_A001_bundle.json"

    assert timeline_path.exists()
    assert process_path.exists()
    assert alerts_path.exists()
    assert report_path.exists()
    assert bundle_path.exists()

    timeline_text = timeline_path.read_text(encoding="utf-8")
    header = timeline_text.splitlines()[0]
    assert (
        header
        == "ts,wazuh_timestamp,indexed_at,event_id,host_key,process_guid,process_id,image,command_line,parent_process_guid,parent_image,target_filename,user,source_ip,source_port,destination_ip,destination_port,rule_id,rule_level,agent_name,agent_id,source_index,source_document_id,record_id,raw_digest,parse_warnings,registry_event_type,target_object,details,new_name,query_name,query_status,query_results,target_process_guid,target_process_id,target_image,granted_access,call_trace,event_type,hashes,is_executable,archived,logon_type,target_user_name,target_domain_name,target_logon_id,workstation_name,process_name,logon_process_name,authentication_package_name,elevated_token,restricted_admin_mode,subject_user_name,subject_domain_name,subject_logon_id,service_name,service_file_name,service_type,service_start_type,service_account,task_name,task_content,client_process_id,parent_process_id"
    )
    assert "schtasks.exe" in timeline_text
    assert "lab_demo.ps1" in timeline_text

    process_text = process_path.read_text(encoding="utf-8")
    process_json = __import__("json").loads(process_text)
    assert set(process_json.keys()) >= {"agent", "time_range", "nodes", "edges", "artifacts"}
    assert process_json["schema_version"] == OUTPUT_SCHEMA_VERSION

    alerts_text = alerts_path.read_text(encoding="utf-8")
    assert (
        "alert_id,utc_time,alert_type,category,finding_kind,evidence_strength,reason,host_key,image,command_line,parent_image,destination_ip,destination_port,process_guid,evidence_refs,tags,source_host_key,source_ip,source_port"
        in alerts_text
    )
    assert "scheduled_task_create" in alerts_text

    report_text = report_path.read_text(encoding="utf-8")
    assert "Incident Summary" in report_text
    assert "92203" in report_text
    assert "schtasks.exe -> powershell.exe" in report_text
    assert "Schema version" in report_text
    assert "## Observed evidence summary" in report_text
    assert "## Behavior findings" in report_text
    assert "## Wazuh Pivot Queries" in report_text
    assert "## Observed process chains" in report_text
    assert "## Observed file activity" in report_text
    assert "## ATT&CK metadata from source rules" in report_text
    assert "## Network activity" in report_text
    assert "## DNS activity" in report_text
    assert "## Registry activity" in report_text
    assert "## Process access activity" in report_text
    assert "## Notes" in report_text


def test_process_tree_deterministic_ordering(tmp_path) -> None:
    events = _build_events()
    correlate_result = correlate_data(events)

    render_process_tree(correlate_result, str(tmp_path))
    first = (tmp_path / "process_tree.json").read_text(encoding="utf-8")

    render_process_tree(correlate_result, str(tmp_path))
    second = (tmp_path / "process_tree.json").read_text(encoding="utf-8")

    assert first == second


def test_bundle_suppression_context_includes_allowlist_refs() -> None:
    anchor = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{GUID-A}",
        process_id=100,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA",
        parent_image="C:\\Windows\\explorer.exe",
        user="HOST\\user",
    )
    sibling_allowlisted = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC),
        agent_id="999",
        agent_name="agent-test",
        process_guid="{GUID-B}",
        process_id=101,
        image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        command_line="chrome.exe --type=renderer",
        parent_process_guid="{GUID-A}",
        parent_process_id=100,
        parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        user="HOST\\user",
    )

    alert = Alert(
        alert_id="A001",
        utc_time=anchor.timestamp,
        alert_type="powershell_encoded_or_download_pattern",
        reason="test",
        host_key=anchor.host_key,
        image=anchor.image,
        command_line=anchor.command_line,
        parent_image=anchor.parent_image,
        process_guid=anchor.process_guid,
        tags=["batcave"],
        primary_event_id=1,
    )

    bundles = build_pivot_bundles(
        [alert],
        [anchor, sibling_allowlisted],
        allowlist_basenames=["chrome.exe"],
    )
    assert bundles
    assert bundles[0]["schema_version"] == OUTPUT_SCHEMA_VERSION
    context = bundles[0]["suppression_context"]
    assert context["suppressed_related_event_count"] >= 1
    assert "allowlist:chrome.exe" in context["matched_rules"]


def test_render_report_escapes_markdown_cells(tmp_path) -> None:
    events = _build_events()
    correlate_result = correlate_data(events)
    alert = Alert(
        alert_id="A001",
        utc_time=datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC),
        alert_type="powershell_encoded_or_download_pattern",
        reason="line1|line2\nline3",
        host_key=events[1].host_key,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc aQBlAHgA | more",
        process_guid="{CHILD}",
        tags=["x|y"],
    )

    render_report(
        {
            **correlate_result,
            "events": events,
            "alerts": [alert],
            "query": {"agent_id": "999"},
        },
        str(tmp_path),
    )

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "line1\\|line2 line3" in report_text
    assert "powershell.exe -enc aQBlAHgA \\| more" in report_text
