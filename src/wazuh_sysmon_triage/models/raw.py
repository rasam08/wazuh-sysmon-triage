from __future__ import annotations

from typing import Any, Dict, List, TypedDict


class WazuhAgent(TypedDict, total=False):
    id: str
    name: str
    ip: str


class WazuhRule(TypedDict, total=False):
    id: str | int
    level: int
    description: str
    groups: List[str]


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
    },
    total=False,
)


class RawHit(TypedDict, total=False):
    _source: WazuhAlertSource
    _id: str
    _index: str
    _score: float
    fields: Dict[str, Any]