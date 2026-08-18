import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

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
from wazuh_sysmon_triage.pipeline.normalize import normalize_data, normalize_data_with_report


@pytest.fixture()
def eid1_hit() -> dict:
    return {
        "_index": "wazuh-alerts-4.x-2024.01.01",
        "_id": "doc-eid1",
        "_source": {
            "@timestamp": "2024-01-01T00:00:01Z",
            "timestamp": "2024-01-01T00:00:02Z",
            "agent": {"id": "999", "name": "agent-test", "ip": "192.0.2.5"},
            "rule": {
                "id": "100001",
                "level": 12,
                "description": "Sysmon Process Create",
                "groups": ["sysmon", "windows"],
                "mitre": {
                    "id": ["T1059.003", "T1105"],
                    "tactic": ["Execution", "Command and Control"],
                },
            },
            "data": {
                "win": {
                    "system": {
                        "eventID": "1",
                        "computer": "HOST-A",
                        "channel": "Microsoft-Windows-Sysmon/Operational",
                        "eventRecordID": "12345",
                        "providerName": "Microsoft-Windows-Sysmon",
                    },
                    "eventdata": {
                        "UtcTime": "2024-01-01T00:00:00Z",
                        "ProcessGuid": "{GUID-A}",
                        "ProcessId": "4242",
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                        "CommandLine": "cmd.exe /c whoami",
                        "CurrentDirectory": "C:\\Windows\\System32",
                        "User": "HOST-A\\user",
                        "ParentProcessGuid": "{GUID-P}",
                        "ParentProcessId": 300,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "ParentCommandLine": "explorer.exe",
                        "Hashes": "SHA256=abcd",
                        "IntegrityLevel": "High",
                    },
                }
            },
        },
    }


@pytest.fixture()
def eid11_hit() -> dict:
    return {
        "_source": {
            "@timestamp": "2024-01-01T00:10:00Z",
            "agent": {"id": "999", "name": "agent-test"},
            "rule": {"id": "100002", "description": "Sysmon File Create"},
            "data": {
                "win": {
                    "system": {"eventID": 11, "computer": "HOST-A"},
                    "eventdata": {
                        "utcTime": "2024-01-01T00:09:59Z",
                        "processGuid": "{GUID-B}",
                        "processId": 9001,
                        "image": "C:\\Windows\\System32\\notepad.exe",
                        "targetFilename": "C:\\Temp\\test.txt",
                        "creationUtcTime": "2024-01-01T00:09:58Z",
                        "user": "HOST-A\\user",
                    },
                }
            },
        }
    }


@pytest.fixture()
def eid3_hit() -> dict:
    return {
        "_source": {
            "@timestamp": "2024-01-01T00:05:00Z",
            "agent": {"id": "999", "name": "agent-test"},
            "rule": {"id": "92206", "description": "Sysmon Network Connect"},
            "data": {
                "win": {
                    "system": {"eventID": 3, "computer": "HOST-A"},
                    "eventdata": {
                        "ProcessGuid": "{CHILD}",
                        "ProcessId": 200,
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "DestinationIp": "8.8.8.8",
                        "DestinationPort": "443",
                        "DestinationHostname": "dns.google",
                        "SourceIp": "192.0.2.5",
                        "SourcePort": "51515",
                        "SourceHostname": "HOST-A",
                        "Protocol": "tcp",
                        "Initiated": "true",
                        "User": "HOST-A\\user",
                    },
                }
            },
        }
    }


def test_normalize_data(eid1_hit: dict, eid11_hit: dict, eid3_hit: dict) -> None:
    results = normalize_data([eid11_hit, eid1_hit, eid3_hit])
    assert len(results) == 3
    assert isinstance(results[0], ProcessCreateEvent)
    assert isinstance(results[1], NetworkConnectEvent)
    assert isinstance(results[2], FileCreateEvent)

    assert results[0].process_id == 4242
    assert results[0].agent_id == "999"
    assert results[0].mitre_techniques == ["T1059.003", "T1105"]
    assert results[0].timestamp == datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    assert results[0].wazuh_timestamp == datetime(2024, 1, 1, 0, 0, 2, tzinfo=UTC)
    assert results[0].indexed_at == datetime(2024, 1, 1, 0, 0, 1, tzinfo=UTC)
    assert results[0].rule_level == 12
    assert results[0].rule_groups == ["sysmon", "windows"]
    assert results[0].provider == "Microsoft-Windows-Sysmon"
    assert results[0].host_key == "agent:999|computer:host-a"
    assert results[0].source_ref.source_type == "opensearch_hit"
    assert results[0].source_ref.index == "wazuh-alerts-4.x-2024.01.01"
    assert results[0].source_ref.document_id == "doc-eid1"
    assert len(results[0].source_ref.raw_digest or "") == 64

    assert results[1].destination_ip == "8.8.8.8"
    assert results[1].destination_port == 443
    assert results[1].destination_hostname == "dns.google"
    assert results[1].source_ip == "192.0.2.5"
    assert results[1].source_port == 51515
    assert results[1].source_hostname == "HOST-A"
    assert results[1].initiated is True
    assert results[1].user == "HOST-A\\user"

    assert results[2].target_filename == "C:\\Temp\\test.txt"
    assert results[2].creation_utc_time == datetime(2024, 1, 1, 0, 9, 58, tzinfo=UTC)


def test_normalize_invalid_timestamp_is_dropped() -> None:
    bad_hit = deepcopy(
        {
            "_source": {
                "@timestamp": "not-a-date",
                "agent": {"id": "999", "name": "agent-test"},
                "rule": {"id": "100001", "description": "Sysmon Process Create"},
                "data": {
                    "win": {
                        "system": {"eventID": "1"},
                        "eventdata": {
                            "UtcTime": "invalid",
                            "ProcessGuid": "{GUID-BAD}",
                            "ProcessId": "1234",
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                        },
                    }
                },
            }
        }
    )

    results = normalize_data([bad_hit])
    assert results == []


def test_normalize_report_invalid_timestamp_by_eid() -> None:
    hit_invalid_eid1 = {
        "_source": {
            "@timestamp": "invalid",
            "agent": {"id": "999", "name": "agent-test"},
            "rule": {"id": "100001", "description": "Sysmon Process Create"},
            "data": {
                "win": {
                    "system": {"eventID": "1"},
                    "eventdata": {
                        "UtcTime": "invalid",
                        "ProcessGuid": "{GUID-1}",
                        "ProcessId": "1234",
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                    },
                }
            },
        }
    }
    hit_invalid_eid3 = {
        "_source": {
            "@timestamp": "invalid",
            "agent": {"id": "999", "name": "agent-test"},
            "rule": {"id": "92206", "description": "Sysmon Network Connect"},
            "data": {
                "win": {
                    "system": {"eventID": "3"},
                    "eventdata": {
                        "UtcTime": "invalid",
                        "ProcessGuid": "{GUID-3}",
                        "ProcessId": "200",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "DestinationIp": "8.8.8.8",
                        "DestinationPort": "443",
                    },
                }
            },
        }
    }

    events, report = normalize_data_with_report([hit_invalid_eid1, hit_invalid_eid3])
    assert events == []
    assert report.invalid_timestamp_count == 2
    assert report.invalid_timestamp_by_eid == {"1": 1, "3": 1}


def test_native_wazuh_json_is_normalized_with_digest_provenance() -> None:
    raw_event = {
        "timestamp": "2024-01-01T00:00:02Z",
        "agent": {"id": "999", "name": "agent-test"},
        "rule": {
            "id": "100001",
            "level": 10,
            "groups": ["sysmon"],
            "mitre": {"id": ["T1059.001"]},
        },
        "data": {
            "win": {
                "system": {
                    "eventID": "1",
                    "computer": "HOST-A",
                    "eventRecordID": "9000",
                },
                "eventdata": {
                    "UtcTime": "2024-01-01T00:00:00Z",
                    "ProcessGuid": "{NATIVE}",
                    "ProcessId": "42",
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                },
            }
        },
    }

    events = normalize_data([raw_event])

    assert len(events) == 1
    event = events[0]
    assert event.mitre_techniques == ["T1059.001"]
    assert event.source_ref.source_type == "wazuh_json"
    assert event.source_ref.record_id == "9000"
    assert len(event.source_ref.raw_digest or "") == 64


def test_invalid_sysmon_time_falls_back_but_remains_visible() -> None:
    hit = {
        "_source": {
            "timestamp": "2024-01-01T00:00:02Z",
            "@timestamp": "2024-01-01T00:00:03Z",
            "agent": {"id": "999"},
            "rule": {"id": "100001"},
            "data": {
                "win": {
                    "system": {"eventID": "1", "computer": "HOST-A"},
                    "eventdata": {
                        "UtcTime": "not-a-time",
                        "ProcessGuid": "{FALLBACK}",
                        "ProcessId": "42",
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                    },
                }
            },
        }
    }

    events = normalize_data([hit])

    assert len(events) == 1
    assert events[0].timestamp == datetime(2024, 1, 1, 0, 0, 2, tzinfo=UTC)
    assert events[0].parse_warnings == ["invalid_sysmon_utc_time"]


def test_unsupported_event_ids_are_counted_explicitly() -> None:
    hit = {
        "_source": {
            "@timestamp": "2024-01-01T00:00:00Z",
            "agent": {"id": "999"},
            "rule": {"id": "100013"},
            "data": {
                "win": {
                    "system": {"eventID": "7", "computer": "HOST-A"},
                    "eventdata": {},
                }
            },
        }
    }

    events, report = normalize_data_with_report([hit], collect_dropped=True)

    assert events == []
    assert report.dropped_count == 1
    assert report.unsupported_count == 1
    assert report.unsupported_by_eid == {"7": 1}
    assert report.dropped_events[0]["reason"] == "unsupported_event_id"


def test_normalize_p1_registry_process_access_and_dns() -> None:
    def hit(event_id: int, eventdata: dict, second: int) -> dict:
        return {
            "_index": "wazuh-alerts-p1",
            "_id": f"p1-{event_id}",
            "_source": {
                "@timestamp": f"2024-01-01T00:00:{second:02d}Z",
                "agent": {"id": "001", "name": "host-a"},
                "rule": {"id": f"sysmon-{event_id}", "level": 8},
                "data": {
                    "win": {
                        "system": {"eventID": str(event_id), "computer": "HOST-A"},
                        "eventdata": {
                            "UtcTime": f"2024-01-01T00:00:{second:02d}Z",
                            **eventdata,
                        },
                    }
                },
            },
        }

    registry_hit = hit(
        13,
        {
            "ProcessGuid": "{SOURCE}",
            "ProcessId": "4242",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "EventType": "SetValue",
            "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\alice\\update.exe",
            "User": "HOST-A\\alice",
        },
        1,
    )
    access_hit = hit(
        10,
        {
            "SourceProcessGUID": "{SOURCE}",
            "SourceProcessId": "4242",
            "SourceThreadId": "77",
            "SourceImage": "C:\\Tools\\reader.exe",
            "TargetProcessGUID": "{LSASS}",
            "TargetProcessId": "500",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+123",
            "SourceUser": "HOST-A\\alice",
            "TargetUser": "NT AUTHORITY\\SYSTEM",
        },
        2,
    )
    dns_hit = hit(
        22,
        {
            "ProcessGuid": "{SOURCE}",
            "ProcessId": "4242",
            "Image": "C:\\Tools\\reader.exe",
            "QueryName": "payload.example",
            "QueryStatus": "0",
            "QueryResults": "type: 5 target.example;::ffff:203.0.113.10;",
            "User": "HOST-A\\alice",
        },
        3,
    )

    events = normalize_data([dns_hit, access_hit, registry_hit])

    assert isinstance(events[0], RegistryEvent)
    assert events[0].target_object.endswith("Run\\Updater")
    assert isinstance(events[1], ProcessAccessEvent)
    assert events[1].process_guid == "{SOURCE}"
    assert events[1].target_process_guid == "{LSASS}"
    assert events[1].source_thread_id == 77
    assert isinstance(events[2], DnsQueryEvent)
    assert events[2].query_name == "payload.example"
    assert all(event.host_key == "agent:001|computer:host-a" for event in events)


def test_normalize_p2_process_termination_and_file_deletion() -> None:
    fixture = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "incident_003_file_cleanup"
        / "raw_hits.ndjson"
    )
    hits = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines()]

    events = normalize_data(hits)

    deletion = next(event for event in events if isinstance(event, FileDeleteEvent))
    termination = next(event for event in events if isinstance(event, ProcessTerminateEvent))
    assert deletion.event_id == 23
    assert deletion.target_filename.endswith("stage.tmp")
    assert deletion.hashes == "SHA256=" + ("2" * 64)
    assert deletion.is_executable == "false"
    assert deletion.archived == "true"
    assert termination.process_guid == "{CLEANUP-CMD}"
    assert termination.process_id == 6100
