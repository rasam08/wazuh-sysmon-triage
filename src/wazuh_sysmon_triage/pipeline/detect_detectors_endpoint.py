from __future__ import annotations

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import ProcessAccessEvent, ProcessCreateEvent, RegistryEvent
from wazuh_sysmon_triage.windows_paths import windows_basename

from .detect_detectors_process import _base_alert

REGISTRY_PERSISTENCE_LOCATIONS: tuple[tuple[str, str], ...] = (
    (r"\software\microsoft\windows\currentversion\runonce", "RunOnce key"),
    (r"\software\microsoft\windows\currentversion\run", "Run key"),
    (r"\software\microsoft\windows nt\currentversion\winlogon\shell", "Winlogon Shell"),
    (
        r"\software\microsoft\windows nt\currentversion\winlogon\userinit",
        "Winlogon Userinit",
    ),
    (
        r"\software\microsoft\windows nt\currentversion\windows\appinit_dlls",
        "AppInit DLLs",
    ),
    (r"\software\microsoft\windows nt\currentversion\image file execution options", "IFEO"),
    (r"\system\currentcontrolset\services", "service configuration"),
)


def _persistence_location(target_object: str) -> str | None:
    target = target_object.replace("/", "\\").lower()
    for marker, label in REGISTRY_PERSISTENCE_LOCATIONS:
        if marker not in target:
            continue
        if label == "service configuration" and not target.endswith(
            (r"\imagepath", r"\servicedll")
        ):
            continue
        if label == "IFEO" and not target.endswith(r"\debugger"):
            continue
        return label
    return None


def _detect_registry_persistence(
    event: RegistryEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    location = _persistence_location(event.target_object)
    if location is None:
        return None

    observed = [
        f"location={location}",
        f"event_type={event.registry_event_type}",
        f"target={event.target_object}",
    ]
    if event.details:
        observed.append(f"details={event.details}")
    if event.new_name:
        observed.append(f"new_name={event.new_name}")

    return _base_alert(
        event=event,
        alert_type="registry_persistence_location_modified",
        reason="Registry persistence location modified: " + "; ".join(observed),
        category="persistence_behavior",
        tags=["persistence", "registry", f"location:{location.lower().replace(' ', '_')}"],
        finding_kind="correlated_pattern" if process_create else "observed_pattern",
        evidence_events=[process_create] if process_create else [],
        command_line=process_create.command_line if process_create else None,
        parent_image=process_create.parent_image if process_create else None,
    )


def _detect_lsass_access(
    event: ProcessAccessEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    if windows_basename(event.target_image) != "lsass.exe":
        return None

    reason = (
        "Sysmon recorded process access to LSASS: "
        f"source={event.image}; target={event.target_image}; "
        f"granted_access={event.granted_access}. "
        "This is an investigation lead, not proof of credential theft."
    )
    return _base_alert(
        event=event,
        alert_type="lsass_process_access",
        reason=reason,
        category="credential_access_behavior",
        tags=["process-access", "target:lsass"],
        finding_kind="correlated_pattern" if process_create else "observed_pattern",
        evidence_events=[process_create] if process_create else [],
        command_line=process_create.command_line if process_create else None,
        parent_image=process_create.parent_image if process_create else None,
    )
