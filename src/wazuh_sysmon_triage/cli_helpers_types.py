from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypedDict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.pipeline.detect import DetectionRunResult
from wazuh_sysmon_triage.pipeline.ndjson import InputQualityReport
from wazuh_sysmon_triage.pipeline.normalize import NormalizeReport


class TruncationInfo(TypedDict):
    truncated: bool
    reason: str | None


@dataclass
class FetchStageResult:
    hits: list[RawHit]
    truncation: TruncationInfo
    duration_ms: int
    input_quality: InputQualityReport | None = None


@dataclass
class NormalizeStageResult:
    events: list[SysmonEvent]
    report: NormalizeReport
    counts_by_eid: dict[str, int]
    duration_ms: int


@dataclass
class CorrelateStageResult:
    correlation: dict[str, Any]
    duration_ms: int


@dataclass
class DetectStageResult:
    detection_result: DetectionRunResult
    all_alerts: list[Alert]
    alerts: list[Alert]
    pivot_bundles: list[dict[str, Any]]
    duration_ms: int
