from __future__ import annotations

from typing import Any, TypedDict


class WazuhAgent(TypedDict, total=False):
    id: str
    name: str
    ip: str


class WazuhRule(TypedDict, total=False):
    id: str | int
    level: int
    description: str
    groups: list[str]
    mitre: dict[str, Any] | list[str] | str


class WinSystem(TypedDict, total=False):
    eventID: str | int
    computer: str
    providerName: str
    timeCreated: str


class WinEventData(TypedDict, total=False):
    ProcessGuid: str
    ProcessId: str | int
    Image: str
    CommandLine: str
    User: str
    ParentProcessGuid: str
    ParentProcessId: str | int
    ParentImage: str
    TargetFilename: str
    IsExecutable: str | bool
    Archived: str | bool
    UtcTime: str
    CreationUtcTime: str
    CurrentDirectory: str
    ParentCommandLine: str
    Hashes: str
    IntegrityLevel: str
    SourceIp: str
    SourcePort: str | int
    SourceHostname: str
    DestinationIp: str
    DestinationPort: str | int
    DestinationHostname: str
    Protocol: str
    Initiated: str | bool
    EventType: str
    TargetObject: str
    Details: str
    NewName: str
    QueryName: str
    QueryStatus: str | int
    QueryResults: str
    SourceProcessGUID: str
    SourceProcessId: str | int
    SourceThreadId: str | int
    SourceImage: str
    TargetProcessGUID: str
    TargetProcessId: str | int
    TargetImage: str
    GrantedAccess: str
    CallTrace: str
    SourceUser: str
    TargetUser: str


class WazuhWinData(TypedDict, total=False):
    system: WinSystem
    eventdata: WinEventData


class WazuhData(TypedDict, total=False):
    win: WazuhWinData


WazuhAlertSource = TypedDict(
    "WazuhAlertSource",
    {
        "agent": WazuhAgent,
        "rule": WazuhRule,
        "data": WazuhData,
        "@timestamp": str,
        "timestamp": str,
    },
    total=False,
)


class RawHit(TypedDict, total=False):
    _source: WazuhAlertSource
    _id: str
    _index: str
    _score: float
    fields: dict[str, Any]
    sort: list[Any]
