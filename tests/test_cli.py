import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

import wazuh_sysmon_triage.cli as cli
from wazuh_sysmon_triage.pipeline.fetch import FetchResult

runner = CliRunner()


def _single_case_dir(base: Path) -> Path:
    dirs = [entry for entry in base.iterdir() if entry.is_dir()]
    assert len(dirs) == 1
    return dirs[0]


def test_fetch_requires_start_end() -> None:
    result = runner.invoke(cli.app, ["fetch"])
    assert result.exit_code == 2


def test_fetch_requires_agent() -> None:
    result = runner.invoke(
        cli.app,
        [
            "fetch",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "dummy-password",
        ],
    )
    assert result.exit_code == 2


def test_fetch_dry_run_query_without_opensearch_creds() -> None:
    result = runner.invoke(
        cli.app,
        [
            "fetch",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--agent-name",
            "anon",
            "--dry-run-query",
        ],
    )
    assert result.exit_code == 0
    payload_start = result.stdout.find("{")
    payload = json.loads(result.stdout[payload_start:])
    assert payload["mode"] == "fetch"
    assert payload["query"]["query"]["bool"]["filter"]


def test_run_requires_agent() -> None:
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "dummy-password",
        ],
    )
    assert result.exit_code == 2


def test_run_requires_opensearch_creds() -> None:
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--agent-id",
            "999",
        ],
        env={
            "WAZUH_OS_HOST": "",
            "WAZUH_OS_USER": "",
            "WAZUH_OS_PASSWORD": "",
        },
    )
    assert result.exit_code == 2


def test_run_case_id_outputs(tmp_path, monkeypatch) -> None:
    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def close(self) -> None:
            return None

    def dummy_fetch(*args, **kwargs):
        return FetchResult(hits=[], truncated=False, reason=None, fetched_count=0)

    monkeypatch.setattr(cli, "OpenSearchClient", DummyClient)
    monkeypatch.setattr(cli, "fetch_sysmon_events", dummy_fetch)

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--event-id",
            "1",
            "--event-id",
            "3",
            "--event-id",
            "11",
            "--agent-id",
            "999",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "dummy-password",
            "--out-dir",
            str(out_dir),
            "--case-id",
            "INCIDENT-001",
        ],
    )

    assert result.exit_code == 0

    case_dir = out_dir / "INCIDENT-001"
    assert (case_dir / "timeline.csv").exists()
    assert (case_dir / "process_tree.json").exists()
    assert (case_dir / "alerts.csv").exists()
    assert (case_dir / "report.md").exists()
    assert (case_dir / "query.json").exists()
    assert (case_dir / "stats.json").exists()

    query = json.loads((case_dir / "query.json").read_text(encoding="utf-8"))
    eid_should = query["query"]["bool"]["filter"][2]["bool"]["should"]
    assert {"terms": {"data.win.system.eventID": [1, 3, 11]}} in eid_should

    report_text = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "Case ID" in report_text


def test_run_offline_ndjson(tmp_path) -> None:
    sample_path = (
        Path(__file__).resolve().parents[1] / "samples" / "incident_001" / "raw_hits.ndjson"
    )

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--log-file",
            str(out_dir / "run.log.ndjson"),
        ],
    )

    assert result.exit_code == 0

    case_dir = _single_case_dir(out_dir)

    process_tree = (case_dir / "process_tree.json").read_text(encoding="utf-8")
    assert "schtasks.exe" in process_tree
    assert "powershell.exe" in process_tree

    report_text = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "Artifacts & IOCs" in report_text
    assert "## Alerts" in report_text

    alerts_text = (case_dir / "alerts.csv").read_text(encoding="utf-8")
    assert (
        "utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags"
        in alerts_text
    )

    artifacts_text = (case_dir / "process_tree.json").read_text(encoding="utf-8")
    assert "lab_demo.ps1" in artifacts_text
    assert "HIGH" in artifacts_text

    log_path = case_dir / "run.log.ndjson"
    explicit_log_path = out_dir / "run.log.ndjson"
    assert log_path.exists() or explicit_log_path.exists()
    use_log_path = log_path if log_path.exists() else explicit_log_path
    lines = [line for line in use_log_path.read_text(encoding="utf-8").splitlines() if line]
    assert lines
    import json

    parsed = [json.loads(line) for line in lines]
    stages = {entry.get("stage") for entry in parsed}
    assert "fetch" in stages
    assert "normalize" in stages
    assert "correlate" in stages
    assert "render" in stages

    metadata = json.loads((case_dir / "run_metadata.json").read_text(encoding="utf-8"))
    assert metadata["schema_version"] == "1.1.0"
    for key in [
        "fetch_duration_ms",
        "normalize_duration_ms",
        "correlate_duration_ms",
        "detect_duration_ms",
        "render_duration_ms",
        "total_duration_ms",
    ]:
        assert key in metadata
        assert metadata[key] >= 0

    stats = json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))
    assert stats["schema_version"] == "1.1.0"
    assert "network_connect" in stats["events_by_type"]
    assert "events_per_second" in stats


def test_run_offline_truncation(tmp_path) -> None:
    sample_path = tmp_path / "many.ndjson"
    lines = []
    for idx in range(5):
        lines.append(
            json.dumps(
                {
                    "_source": {
                        "@timestamp": "2024-01-01T00:00:00Z",
                        "agent": {"id": "999", "name": "agent-test"},
                        "rule": {"id": "92203", "description": "Sysmon Process Create"},
                        "data": {
                            "win": {
                                "system": {"eventID": "1"},
                                "eventdata": {
                                    "ProcessGuid": f"{{GUID-{idx}}}",
                                    "ProcessId": 100 + idx,
                                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                                    "CommandLine": "schtasks.exe /create",
                                    "User": "HOST-A\\user",
                                },
                            }
                        },
                    }
                }
            )
        )
    sample_path.write_text("\n".join(lines), encoding="utf-8")

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--max-events",
            "2",
        ],
    )
    assert result.exit_code == 0

    case_dir = _single_case_dir(out_dir)
    report_text = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "WARNING: Results truncated due to max-events guardrail" in report_text


def test_rebase_scenario_gym_hits_to_now() -> None:
    hits = [
        {
            "_source": {
                "@timestamp": "2024-01-01T00:00:00Z",
                "data": {
                    "win": {
                        "eventdata": {
                            "CreationUtcTime": "2024-01-01T00:00:05Z",
                        }
                    }
                },
            }
        },
        {
            "_source": {
                "@timestamp": "2024-01-01T00:00:10Z",
                "data": {
                    "win": {
                        "eventdata": {
                            "UtcTime": "2024-01-01T00:00:10Z",
                        }
                    }
                },
            }
        },
    ]

    rebased, shifted_fields = cli._rebase_scenario_gym_hits_to_now(hits)

    assert rebased is True
    assert shifted_fields >= 4

    first_ts = cli._parse_iso_ts(hits[0]["_source"]["@timestamp"])
    second_ts = cli._parse_iso_ts(hits[1]["_source"]["@timestamp"])
    creation_ts = cli._parse_iso_ts(
        hits[0]["_source"]["data"]["win"]["eventdata"]["CreationUtcTime"]
    )

    assert first_ts is not None
    assert second_ts is not None
    assert creation_ts is not None

    now = datetime.now(tz=UTC)
    assert abs((now - first_ts).total_seconds()) < 10
    assert int((second_ts - first_ts).total_seconds()) == 10
    assert int((creation_ts - first_ts).total_seconds()) == 5


def test_run_offline_truncation_fails(tmp_path) -> None:
    sample_path = tmp_path / "many.ndjson"
    lines = []
    for idx in range(3):
        lines.append(
            json.dumps(
                {
                    "_source": {
                        "@timestamp": "2024-01-01T00:00:00Z",
                        "agent": {"id": "999", "name": "agent-test"},
                        "rule": {"id": "92203", "description": "Sysmon Process Create"},
                        "data": {
                            "win": {
                                "system": {"eventID": "1"},
                                "eventdata": {
                                    "ProcessGuid": f"{{GUID-{idx}}}",
                                    "ProcessId": 100 + idx,
                                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                                    "CommandLine": "schtasks.exe /create",
                                    "User": "HOST-A\\user",
                                },
                            }
                        },
                    }
                }
            )
        )
    sample_path.write_text("\n".join(lines), encoding="utf-8")

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--max-events",
            "1",
            "--fail-on-truncation",
        ],
    )
    assert result.exit_code == 4


def test_run_config_alert_precedence(tmp_path) -> None:
    scenario_path = tmp_path / "scenario.ndjson"
    scenario_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "_source": {
                            "@timestamp": "2024-01-01T00:00:00Z",
                            "agent": {"id": "999", "name": "agent-test"},
                            "rule": {"id": "92203", "description": "Sysmon Process Create"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "1"},
                                    "eventdata": {
                                        "ProcessGuid": "{M}",
                                        "ProcessId": 333,
                                        "Image": "C:\\Users\\user\\AppData\\Roaming\\mshta.exe",
                                        "CommandLine": "mshta.exe http://test/payload.hta",
                                        "ParentImage": "C:\\Windows\\explorer.exe",
                                        "User": "HOST\\user",
                                    },
                                }
                            },
                        }
                    }
                ),
                json.dumps(
                    {
                        "_source": {
                            "@timestamp": "2024-01-01T00:00:02Z",
                            "agent": {"id": "999", "name": "agent-test"},
                            "rule": {"id": "92206", "description": "Sysmon Network Connect"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "3"},
                                    "eventdata": {
                                        "ProcessGuid": "{M}",
                                        "ProcessId": 333,
                                        "Image": "C:\\Users\\user\\AppData\\Roaming\\mshta.exe",
                                        "DestinationIp": "8.8.8.8",
                                        "DestinationPort": "443",
                                        "Protocol": "tcp",
                                    },
                                }
                            },
                        }
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "min_alert_score: 95",
                "alert_allowlist_basenames:",
                "  - mshta.exe",
            ]
        ),
        encoding="utf-8",
    )

    out_a = tmp_path / "out_a"
    result_a = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(scenario_path),
            "--out-dir",
            str(out_a),
            "--config",
            str(config_path),
        ],
    )
    assert result_a.exit_code == 0
    alerts_a = (_single_case_dir(out_a) / "alerts.csv").read_text(encoding="utf-8").splitlines()
    assert len(alerts_a) == 1

    out_b = tmp_path / "out_b"
    result_b = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(scenario_path),
            "--out-dir",
            str(out_b),
            "--config",
            str(config_path),
            "--allowlist-image",
            "chrome.exe",
            "--min-alert-score",
            "70",
        ],
    )
    assert result_b.exit_code == 0
    alerts_b = (_single_case_dir(out_b) / "alerts.csv").read_text(encoding="utf-8")
    assert "lolbin_outbound" in alerts_b


def test_parse_last_duration_and_window_precedence() -> None:
    assert cli._parse_last_duration("15m").total_seconds() == 900
    assert cli._parse_last_duration("2h").total_seconds() == 7200
    assert cli._parse_last_duration("7d").total_seconds() == 604800

    now = datetime(2026, 2, 19, 12, 0, 0, tzinfo=UTC)
    start, end = cli._resolve_time_window(None, None, "2h", False, False, now=now)
    assert start == "2026-02-19T10:00:00Z"
    assert end == "2026-02-19T12:00:00Z"

    start, end = cli._resolve_time_window(
        "2026-02-18T00:00:00Z",
        "2026-02-18T01:00:00Z",
        "24h",
        False,
        False,
        now=now,
    )
    assert start == "2026-02-18T00:00:00Z"
    assert end == "2026-02-18T01:00:00Z"


def test_profile_merging_with_cli_override(tmp_path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "\n".join(
            [
                "agent_name: base-agent",
                "profiles:",
                "  soc:",
                "    agent_name: profile-agent",
                "    min_alert_score: 88",
                "    alerts_only: true",
                "    print_stats: true",
            ]
        ),
        encoding="utf-8",
    )

    resolved = cli._resolve_config(
        str(cfg),
        "soc",
        None,
        None,
        None,
        "cli-agent",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        70,
        None,
        None,
        None,
        None,
        None,
    )
    assert resolved["agent_name"] == "cli-agent"
    assert resolved["min_alert_score"] == 70
    assert resolved["alerts_only"] is True
    assert resolved["print_stats"] is True


def test_lab_profile_defaults_verify_tls_off(tmp_path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("profiles:\n  lab:\n    agent_name: lab-agent\n", encoding="utf-8")

    resolved = cli._resolve_config(
        str(cfg),
        "lab",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert resolved["verify_tls"] is False


def test_verify_tls_env_override(monkeypatch) -> None:
    monkeypatch.setenv("WAZUH_OS_VERIFY_TLS", "false")
    resolved = cli._resolve_config(
        None,
        "soc",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert resolved["verify_tls"] is False


def test_config_password_ignored_in_favor_of_env(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "\n".join(
            [
                "host: https://indexer:9920",
                "user: admin",
                "pass: inline-secret",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("WAZUH_OS_PASSWORD", raising=False)
    resolved = cli._resolve_config(
        str(cfg),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert resolved["password"] is None

    monkeypatch.setenv("WAZUH_OS_PASSWORD", "env-secret")
    resolved_env = cli._resolve_config(
        str(cfg),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert resolved_env["password"] == "env-secret"


def test_live_dry_run_warns_on_inline_config_password(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "\n".join(
            [
                "host: https://indexer:9920",
                "user: admin",
                "pass: inline-secret",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WAZUH_OS_PASSWORD", "env-secret")
    out_dir = tmp_path / "out"

    result = runner.invoke(
        cli.app,
        [
            "live",
            "--dry-run-query",
            "--agent-name",
            "anon",
            "--last",
            "2h",
            "--case-id",
            "warn-inline-pass",
            "--out-dir",
            str(out_dir),
            "--config",
            str(cfg),
        ],
    )
    assert result.exit_code == 0
    assert "Inline password detected in config" in result.stdout


def test_offline_run_writes_telemetry_summary(tmp_path) -> None:
    sample_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "scenario_gym"
        / "encoded_powershell.ndjson"
    )
    out_dir = tmp_path / "telemetry-out"
    case_id = "telemetry-case"

    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--case-id",
            case_id,
        ],
    )
    assert result.exit_code == 0

    summary_path = out_dir / "telemetry_summary.json"
    history_path = out_dir / "telemetry_history.ndjson"
    assert summary_path.exists()
    assert history_path.exists()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total_runs"] >= 1
    assert summary["successful_runs"] >= 1
    assert "fetch" in summary["stage_latency_percentiles"]

    history_rows = [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(row.get("case_id") == case_id for row in history_rows)


def test_live_and_offline_commands(tmp_path) -> None:
    sample_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "scenario_gym"
        / "encoded_powershell.ndjson"
    )
    out_offline = tmp_path / "offline"
    offline = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_offline),
            "--case-id",
            "encoded",
        ],
    )
    assert offline.exit_code == 0
    assert (out_offline / "encoded" / "alerts.csv").exists()

    live = runner.invoke(cli.app, ["live", "--last", "2h"])
    assert live.exit_code in {0, 2, 3}


def test_offline_queue_filter_excludes_non_matching_queues(tmp_path) -> None:
    sample_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "scenario_gym"
        / "encoded_powershell.ndjson"
    )
    out_dir = tmp_path / "queue-filter"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "queue-filter",
            "--queue",
            "soc_policy",
            "--min-alert-score",
            "0",
        ],
    )
    assert result.exit_code == 0

    alerts_lines = (out_dir / "alerts.csv").read_text(encoding="utf-8").splitlines()
    assert len(alerts_lines) == 1


def test_live_window_defaults_and_today_override(monkeypatch, tmp_path) -> None:
    captured: dict[str, str] = {}

    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def close(self) -> None:
            return None

    def dummy_fetch(*args, **kwargs):
        captured["start"] = kwargs["start_dt"]
        captured["end"] = kwargs["end_dt"]
        return FetchResult(hits=[], truncated=False, reason=None, fetched_count=0)

    monkeypatch.setattr(cli, "OpenSearchClient", DummyClient)
    monkeypatch.setattr(cli, "fetch_sysmon_events", dummy_fetch)

    out_dir = tmp_path / "live-default"
    default_live = runner.invoke(
        cli.app,
        [
            "live",
            "--agent-name",
            "anon",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "dummy-password",
            "--out-dir",
            str(out_dir),
            "--case-id",
            "live-default",
        ],
    )
    assert default_live.exit_code == 0

    start_default = datetime.fromisoformat(captured["start"].replace("Z", "+00:00"))
    end_default = datetime.fromisoformat(captured["end"].replace("Z", "+00:00"))
    assert (end_default - start_default).total_seconds() == 7200

    out_today = tmp_path / "live-today"
    today_live = runner.invoke(
        cli.app,
        [
            "live",
            "--today",
            "--agent-name",
            "anon",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "dummy-password",
            "--out-dir",
            str(out_today),
            "--case-id",
            "live-today",
        ],
    )
    assert today_live.exit_code == 0

    start_today = datetime.fromisoformat(captured["start"].replace("Z", "+00:00"))
    end_today = datetime.fromisoformat(captured["end"].replace("Z", "+00:00"))
    assert start_today.hour == 0
    assert start_today.minute == 0
    assert start_today.second == 0
    assert start_today <= end_today


def test_live_dry_run_query_without_opensearch_creds(tmp_path) -> None:
    out_dir = tmp_path / "dry-live"
    result = runner.invoke(
        cli.app,
        [
            "live",
            "--dry-run-query",
            "--agent-name",
            "anon",
            "--last",
            "2h",
            "--out-dir",
            str(out_dir),
            "--case-id",
            "dry-live",
        ],
    )
    assert result.exit_code == 0
    payload_start = result.stdout.find("{")
    payload = json.loads(result.stdout[payload_start:])
    assert payload["mode"] == "live"
    assert payload["schema_version"] == "1.1.0"
    assert payload["query"]["query"]["bool"]["filter"]


def test_offline_dry_run_query_does_not_require_input_file(tmp_path) -> None:
    out_dir = tmp_path / "dry-offline"
    missing_input = tmp_path / "missing.ndjson"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--dry-run-query",
            "--input-ndjson",
            str(missing_input),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "dry-offline",
        ],
    )
    assert result.exit_code == 0
    payload_start = result.stdout.find("{")
    payload = json.loads(result.stdout[payload_start:])
    assert payload["mode"] == "offline"
    assert payload["query"]["input_ndjson"] == str(missing_input)


def test_offline_quarantine_and_invalid_timestamp_stats(tmp_path) -> None:
    sample_path = tmp_path / "mixed.ndjson"
    sample_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "_source": {
                            "@timestamp": "2024-01-01T00:00:00Z",
                            "agent": {"id": "999", "name": "agent-test"},
                            "rule": {"id": "92203", "description": "Sysmon Process Create"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "1"},
                                    "eventdata": {
                                        "ProcessGuid": "{GOOD}",
                                        "ProcessId": 100,
                                        "Image": "C:\\Windows\\System32\\schtasks.exe",
                                        "CommandLine": "schtasks.exe /create",
                                        "User": "HOST-A\\user",
                                    },
                                }
                            },
                        }
                    }
                ),
                json.dumps(
                    {
                        "_source": {
                            "@timestamp": "invalid",
                            "agent": {"id": "999", "name": "agent-test"},
                            "rule": {"id": "92206", "description": "Sysmon Network Connect"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "3"},
                                    "eventdata": {
                                        "UtcTime": "invalid",
                                        "ProcessGuid": "{BAD}",
                                        "ProcessId": 200,
                                        "Image": "C:\\Users\\alice\\AppData\\Roaming\\mshta.exe",
                                        "DestinationIp": "10.1.2.3",
                                        "DestinationPort": "443",
                                    },
                                }
                            },
                        }
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "quarantine"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "quarantine-case",
            "--quarantine-drops",
        ],
    )
    assert result.exit_code == 0

    case_dir = out_dir / "quarantine-case"
    quarantine_path = case_dir / "quarantine.ndjson"
    assert quarantine_path.exists()
    quarantine_rows = [
        json.loads(line)
        for line in quarantine_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert quarantine_rows
    assert quarantine_rows[0]["reason"] == "invalid_timestamp"

    stats = json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))
    assert stats["invalid_timestamp_count"] == 1
    assert stats["invalid_timestamp_by_eid"] == {"3": 1}


def test_offline_explain_alert_output(tmp_path) -> None:
    sample_path = tmp_path / "explain.ndjson"
    sample_path.write_text(
        json.dumps(
            {
                "_source": {
                    "@timestamp": "2024-01-01T00:00:00Z",
                    "agent": {"id": "999", "name": "agent-test"},
                    "rule": {"id": "92203", "description": "Sysmon Process Create"},
                    "data": {
                        "win": {
                            "system": {"eventID": "1"},
                            "eventdata": {
                                "ProcessGuid": "{EXP}",
                                "ProcessId": 400,
                                "Image": "C:\\Windows\\System32\\schtasks.exe",
                                "CommandLine": 'schtasks.exe /Create /TN updater-random123 /TR "powershell -nop"',
                                "User": "HOST\\user",
                            },
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "explain-out"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "explain-case",
            "--explain-alert",
            "A001",
        ],
    )
    assert result.exit_code == 0
    assert "[explain] A001" in result.stdout
    assert "contributors=primary_rule:" in result.stdout


def test_offline_sanitize_redacts_internal_ip_and_user(tmp_path) -> None:
    sample_path = tmp_path / "sanitize.ndjson"
    sample_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "_source": {
                            "@timestamp": "2024-01-01T00:00:00Z",
                            "agent": {"id": "999", "name": "agent-test"},
                            "rule": {"id": "92203", "description": "Sysmon Process Create"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "1"},
                                    "eventdata": {
                                        "ProcessGuid": "{SAN}",
                                        "ProcessId": 333,
                                        "Image": "C:\\Users\\alice\\AppData\\Roaming\\mshta.exe",
                                        "CommandLine": "mshta.exe C:\\Users\\alice\\AppData\\Roaming\\payload.hta",
                                        "ParentImage": "C:\\Windows\\explorer.exe",
                                        "User": "HOST\\alice",
                                    },
                                }
                            },
                        }
                    }
                ),
                json.dumps(
                    {
                        "_source": {
                            "@timestamp": "2024-01-01T00:00:02Z",
                            "agent": {"id": "999", "name": "agent-test"},
                            "rule": {"id": "92206", "description": "Sysmon Network Connect"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "3"},
                                    "eventdata": {
                                        "ProcessGuid": "{SAN}",
                                        "ProcessId": 333,
                                        "Image": "C:\\Users\\alice\\AppData\\Roaming\\mshta.exe",
                                        "DestinationIp": "10.10.10.10",
                                        "DestinationPort": "443",
                                        "Protocol": "tcp",
                                    },
                                }
                            },
                        }
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "sanitize-out"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "sanitize-case",
            "--sanitize",
        ],
    )
    assert result.exit_code == 0

    case_dir = out_dir / "sanitize-case"
    primary_artifacts = [
        case_dir / "report.md",
        case_dir / "alerts.csv",
        case_dir / "process_tree.json",
        case_dir / "timeline.csv",
    ]
    primary_artifacts.extend(sorted(case_dir.glob("alert_*_bundle.json")))

    corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in primary_artifacts if path.exists()
    )
    forbidden_tokens = [
        "10.10.10.10",
        "HOST\\alice",
        "C:\\Users\\alice\\",
        "alice\\AppData\\Roaming",
    ]
    for token in forbidden_tokens:
        assert token not in corpus

    assert "internal-ip-001" in corpus
    assert "HOST\\user001" in corpus
