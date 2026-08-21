from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from wazuh_sysmon_triage.corpus import (  # noqa: E402
    ACCEPTANCE_SCENARIOS,
    ACCEPTANCE_SEED,
    iter_mixed_hits,
    iter_scenario_lines,
)

KNOWN_FINDINGS = [
    "powershell_encoded_or_download_pattern",
    "powershell_reflection_or_native_api_pattern",
    "scheduled_task_create",
    "registry_persistence_location_modified",
    "lsass_process_access",
    "remote_logon_followed_by_service_install",
    "remote_logon_followed_by_scheduled_task",
    "lolbin_outbound",
    "user_writable_path_outbound",
]

SCENARIO_DOCS = {
    "benign_admin_powershell": (
        "Benign administrative PowerShell",
        "Ordinary interactive PowerShell with routine process and network context. "
        "It is here to prove that normal administration does not become a local finding.",
    ),
    "benign_software_installation": (
        "Benign software installation",
        "A normal installer creates expected process, service, and maintenance activity. "
        "Approval context is outside the telemetry, but the fixture must not invent a threat.",
    ),
    "benign_rmm_remote_maintenance": (
        "Benign remote maintenance",
        "A network logon followed by service creation represents legitimate remote support. "
        "The expected output is a reviewable hypothesis, never a maliciousness verdict.",
    ),
    "powershell_download_execute": (
        "PowerShell download and execution",
        "PowerShell download behavior is joined to file, network, and child-process evidence. "
        "The fixture checks the stronger correlated finding and its source references.",
    ),
    "lsass_access_with_context": (
        "LSASS access with context",
        "A recorded Sysmon process-access event targets LSASS while preserving the source "
        "process. The result is an evidence-backed lead, not proof of credential theft.",
    ),
    "registry_runkey_persistence": (
        "Run-key registry change",
        "A process modifies a Windows Run key. The expected finding keeps the exact registry "
        "target and originating process without claiming the referenced file is malicious.",
    ),
    "remote_service_and_task": (
        "Remote service and scheduled task",
        "Out-of-order multi-host logon, service, and scheduled-task records exercise exact "
        "session relationships and bounded remote-activity leads.",
    ),
    "degraded_telemetry": (
        "Degraded telemetry",
        "Malformed, unsupported, duplicated, invalid-time, out-of-order, and missing-parent "
        "records prove that collection gaps stay visible without destroying the usable case.",
    ),
    "noisy_workstation": (
        "Noisy workstation",
        "Deterministic browser, Defender, Office, developer-tool, update, and background "
        "activity surrounds one injected PowerShell chain to test noise accounting at scale.",
    ),
}


def _finding(
    finding_type: str,
    *,
    kind: str,
    strength: str,
) -> dict[str, str]:
    return {
        "type": finding_type,
        "finding_kind": kind,
        "evidence_strength": strength,
    }


def _manifest(name: str, *, noisy_events: int) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "scenario": name,
        "provenance": "synthetic",
        "required_findings": [],
        "forbidden_findings": ["malicious_verdict"],
        "expected_unknowns": ["operator intent is not established by endpoint telemetry"],
        "minimum_process_edges": 0,
        "minimum_unresolved_relationships": 0,
        "expected_counts": {
            "input_records": 0,
            "selected_records": 0,
            "omitted_records": 0,
            "input_rejected": 0,
            "normalize_dropped": 0,
            "unsupported": 0,
        },
    }

    if name == "benign_admin_powershell":
        manifest["forbidden_findings"] += KNOWN_FINDINGS
        manifest["expected_counts"].update(input_records=2, selected_records=2)
    elif name == "benign_software_installation":
        manifest["forbidden_findings"] += KNOWN_FINDINGS
        manifest["expected_unknowns"] = [
            "software approval is external to the collected evidence"
        ]
        manifest["expected_counts"].update(input_records=3, selected_records=3)
    elif name == "benign_rmm_remote_maintenance":
        manifest["required_findings"] = [
            _finding(
                "remote_logon_followed_by_service_install",
                kind="hypothesis",
                strength="strong",
            )
        ]
        manifest["forbidden_findings"] += [
            "remote_logon_followed_by_scheduled_task",
            "malicious_lateral_movement",
        ]
        manifest["expected_unknowns"] = [
            "authorization and maintenance-ticket context are not present"
        ]
        manifest["expected_counts"].update(input_records=3, selected_records=3)
    elif name == "powershell_download_execute":
        manifest["required_findings"] = [
            _finding(
                "powershell_encoded_or_download_pattern",
                kind="correlated_pattern",
                strength="strong",
            )
        ]
        manifest["expected_unknowns"] = ["downloaded content was not collected"]
        manifest["expected_counts"].update(input_records=5, selected_records=5)
        manifest["minimum_process_edges"] = 1
    elif name == "lsass_access_with_context":
        manifest["required_findings"] = [
            _finding(
                "lsass_process_access",
                kind="correlated_pattern",
                strength="deterministic",
            )
        ]
        manifest["expected_unknowns"] = [
            "process access is not proof that credentials were extracted"
        ]
        manifest["expected_counts"].update(input_records=2, selected_records=2)
    elif name == "registry_runkey_persistence":
        manifest["required_findings"] = [
            _finding(
                "registry_persistence_location_modified",
                kind="correlated_pattern",
                strength="deterministic",
            )
        ]
        manifest["expected_unknowns"] = ["the referenced executable content was not collected"]
        manifest["expected_counts"].update(input_records=2, selected_records=2)
    elif name == "remote_service_and_task":
        manifest["required_findings"] = [
            _finding(
                "remote_logon_followed_by_service_install",
                kind="hypothesis",
                strength="strong",
            ),
            _finding(
                "remote_logon_followed_by_scheduled_task",
                kind="hypothesis",
                strength="strong",
            ),
        ]
        manifest["forbidden_findings"] += ["malicious_lateral_movement"]
        manifest["expected_unknowns"] = [
            "the sequence is a scoping lead and does not establish malicious movement"
        ]
        manifest["expected_counts"].update(input_records=4, selected_records=4)
    elif name == "degraded_telemetry":
        manifest["forbidden_findings"] += KNOWN_FINDINGS
        manifest["expected_unknowns"] = [
            "parent process is unresolved",
            "one input line was syntactically malformed",
        ]
        manifest["expected_counts"].update(
            input_records=5,
            selected_records=4,
            input_rejected=1,
            normalize_dropped=2,
            unsupported=1,
        )
        manifest["minimum_unresolved_relationships"] = 1
        manifest["order_invariant"] = True
    elif name == "noisy_workstation":
        manifest["required_findings"] = [
            _finding(
                "powershell_encoded_or_download_pattern",
                kind="correlated_pattern",
                strength="strong",
            )
        ]
        manifest["expected_unknowns"] = [
            "background endpoint noise does not establish intent for the injected chain"
        ]
        manifest["expected_counts"].update(
            input_records=noisy_events,
            selected_records=noisy_events,
        )
        manifest["generator"] = {
            "seed": ACCEPTANCE_SEED,
            "event_count": noisy_events,
            "event_mix": ["process", "network", "dns", "file"],
            "injected_chain": "powershell_download_execute",
        }
    else:
        raise ValueError(f"Unknown scenario: {name}")

    manifest["forbidden_findings"] = sorted(set(manifest["forbidden_findings"]))
    return manifest


def generate_corpus(
    output_root: Path,
    *,
    noisy_events: int = 5000,
    include_noisy_raw: bool = False,
) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    for name in ACCEPTANCE_SCENARIOS:
        scenario_dir = output_root / name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        manifest = _manifest(name, noisy_events=noisy_events)
        (scenario_dir / "expected.yaml").write_text(
            yaml.safe_dump(manifest, sort_keys=False),
            encoding="utf-8",
        )
        generated_note = (
            "`raw_hits.ndjson` is generated on demand and intentionally not committed at scale."
            if name == "noisy_workstation" and not include_noisy_raw
            else "`raw_hits.ndjson` is a deterministic checked-in synthetic fixture."
        )
        title, summary = SCENARIO_DOCS[name]
        (scenario_dir / "README.md").write_text(
            f"# {title}\n\n"
            f"{summary}\n\n"
            "All identities and records are synthetic; there are no production credentials "
            "or organization-specific names in this scenario.\n\n"
            f"{generated_note} See `expected.yaml` for the machine-checked conclusions.\n",
            encoding="utf-8",
        )

        raw_path = scenario_dir / "raw_hits.ndjson"
        if name == "noisy_workstation":
            if include_noisy_raw:
                with raw_path.open("wb") as handle:
                    for hit in iter_mixed_hits(noisy_events, seed=ACCEPTANCE_SEED):
                        handle.write(
                            json.dumps(hit, sort_keys=True, separators=(",", ":")).encode(
                                "utf-8"
                            )
                            + b"\n"
                        )
            elif raw_path.exists():
                raw_path.unlink()
            continue

        with raw_path.open("wb") as handle:
            for line in iter_scenario_lines(name):
                handle.write(line)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic acceptance fixtures.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("samples/acceptance"),
        help="Corpus output directory.",
    )
    parser.add_argument("--noisy-events", type=int, default=5000)
    parser.add_argument("--include-noisy-raw", action="store_true")
    args = parser.parse_args()
    if args.noisy_events < 5:
        parser.error("--noisy-events must be at least 5 so the injected chain is complete")
    generate_corpus(
        args.output_root,
        noisy_events=args.noisy_events,
        include_noisy_raw=args.include_noisy_raw,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
