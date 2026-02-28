from datetime import UTC, datetime

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import FileCreateEvent, ProcessCreateEvent
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
    alerts = filter_alerts(detect_alerts(events), min_score=0)
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
        == "ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id"
    )
    assert "schtasks.exe" in timeline_text
    assert "lab_demo.ps1" in timeline_text

    process_text = process_path.read_text(encoding="utf-8")
    process_json = __import__("json").loads(process_text)
    assert set(process_json.keys()) >= {"agent", "time_range", "nodes", "edges", "artifacts"}
    assert process_json["schema_version"] == "1.1.0"

    alerts_text = alerts_path.read_text(encoding="utf-8")
    assert (
        "utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags"
        in alerts_text
    )
    assert "persistence_schtasks_create" in alerts_text

    report_text = report_path.read_text(encoding="utf-8")
    assert "Incident Summary" in report_text
    assert "92203" in report_text
    assert "schtasks.exe -> powershell.exe" in report_text
    assert "Schema version" in report_text
    assert "## Executive summary" in report_text
    assert "## Alerts" in report_text
    assert "### Queue summary" in report_text
    assert "## Wazuh Pivot Queries" in report_text
    assert "## Observed process chains" in report_text
    assert "## Artifacts & IOCs" in report_text
    assert "## Detections" in report_text
    assert "## Network activity" in report_text
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
        score=95,
        alert_type="powershell_obfuscation",
        reason="test",
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
    assert bundles[0]["schema_version"] == "1.1.0"
    context = bundles[0]["suppression_context"]
    assert context["suppressed_related_event_count"] >= 1
    assert "allowlist:chrome.exe" in context["matched_rules"]


def test_render_report_escapes_markdown_cells(tmp_path) -> None:
    events = _build_events()
    correlate_result = correlate_data(events)
    alert = Alert(
        alert_id="A001",
        utc_time=datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC),
        score=90,
        alert_type="powershell_obfuscation",
        reason="line1|line2\nline3",
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
