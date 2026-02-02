from datetime import UTC, datetime

from wazuh_sysmon_triage.models.sysmon import FileCreateEvent, ProcessCreateEvent
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.render import (
    render_process_tree,
    render_report,
    render_timeline,
)


def _build_events():
    parent = ProcessCreateEvent(
        event_id=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        agent_id="010",
        agent_name="anon",
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
        agent_id="010",
        agent_name="anon",
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
        agent_id="010",
        agent_name="anon",
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

    render_timeline(events, str(tmp_path))
    render_process_tree(correlate_result, str(tmp_path))
    render_report(
        {
            **correlate_result,
            "events": events,
            "query": {"agent_id": "010", "start": "2024-01-01T00:00:00Z"},
        },
        str(tmp_path),
    )

    timeline_path = tmp_path / "timeline.csv"
    process_path = tmp_path / "process_tree.json"
    report_path = tmp_path / "report.md"

    assert timeline_path.exists()
    assert process_path.exists()
    assert report_path.exists()

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

    report_text = report_path.read_text(encoding="utf-8")
    assert "Incident Summary" in report_text
    assert "92203" in report_text
    assert "schtasks.exe -> powershell.exe" in report_text
    assert "## Executive summary" in report_text
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
