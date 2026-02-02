from datetime import datetime, timezone

import pytest

from wazuh_sysmon_triage.models.sysmon import FileCreateEvent, NetworkConnectEvent, ProcessCreateEvent
from wazuh_sysmon_triage.pipeline.normalize import normalize_data


@pytest.fixture()
def eid1_hit() -> dict:
    return {
        "_source": {
            "@timestamp": "2024-01-01T00:00:01Z",
            "agent": {"id": "010", "name": "anon", "ip": "10.0.0.5"},
            "rule": {"id": "100001", "description": "Sysmon Process Create", "mitre": ["T1059"]},
            "data": {
                "win": {
                    "system": {
                        "eventID": "1",
                        "computer": "HOST-A",
                        "channel": "Microsoft-Windows-Sysmon/Operational",
                        "eventRecordID": "12345",
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
        }
    }


@pytest.fixture()
def eid11_hit() -> dict:
    return {
        "_source": {
            "@timestamp": "2024-01-01T00:10:00Z",
            "agent": {"id": "010", "name": "anon"},
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
            "agent": {"id": "010", "name": "anon"},
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
                        "Protocol": "tcp",
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
    assert results[0].agent_id == "010"
    assert results[0].mitre_techniques == ["T1059"]
    assert results[0].timestamp == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    assert results[1].destination_ip == "8.8.8.8"
    assert results[1].destination_port == 443

    assert results[2].target_filename == "C:\\Temp\\test.txt"
    assert results[2].creation_utc_time == datetime(2024, 1, 1, 0, 9, 58, tzinfo=timezone.utc)