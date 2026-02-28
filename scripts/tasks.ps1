param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("test", "build", "smoke-live", "smoke-offline", "release-gate")]
    [string]$Task,
    [string]$OutDir = ".\out",
    [string]$CaseId = "task-smoke"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-PythonExe {
    $candidates = @(
        ".\.venv\Scripts\python.exe",
        ".\.venv-5\Scripts\python.exe",
        ".\.venv-2\Scripts\python.exe",
        ".\.venv-1\Scripts\python.exe",
        "python"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -eq "python" -or (Test-Path $candidate)) {
            return $candidate
        }
    }
    return "python"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot
$env:PYTHONPATH = (Join-Path $repoRoot "src")
$pythonExe = Resolve-PythonExe

switch ($Task) {
    "test" {
        & $pythonExe -m pytest -q
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        npm --prefix ui run test -- --run
        exit $LASTEXITCODE
    }
    "build" {
        npm --prefix ui run build
        exit $LASTEXITCODE
    }
    "smoke-live" {
        & $pythonExe -m wazuh_sysmon_triage live --dry-run-query --profile soc --agent-name anon --last 2h --case-id "$CaseId-live" --out-dir $OutDir
        exit $LASTEXITCODE
    }
    "smoke-offline" {
        & $pythonExe -m wazuh_sysmon_triage offline --input-ndjson "samples/scenario_gym/encoded_powershell.ndjson" --case-id "$CaseId-offline" --out-dir $OutDir
        exit $LASTEXITCODE
    }
    "release-gate" {
        & (Join-Path $PSScriptRoot "release_gate.ps1")
        exit $LASTEXITCODE
    }
}
