param(
    [string]$Profile = "soc",
    [string]$OutDir = ".tmp_release_gate_out",
    [string]$CaseId = "release-gate-probe"
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

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    Write-Host "[gate] $Name"
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Release gate failed at step: $Name (exit=$LASTEXITCODE)"
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot
$env:PYTHONPATH = (Join-Path $repoRoot "src")

$pythonExe = Resolve-PythonExe
$configPath = if (Test-Path ".\config.local.yaml") { ".\config.local.yaml" } elseif (Test-Path ".\config.example.yaml") { ".\config.example.yaml" } else { $null }

Invoke-Step -Name "Python schema compatibility test" -Action { & $pythonExe -m pytest -q tests/test_schema_compat.py }
Invoke-Step -Name "Python tests" -Action { & $pythonExe -m pytest -q }
Invoke-Step -Name "UI server contract test" -Action { npm --prefix ui run test -- --run src/test/server-contract.test.ts }
Invoke-Step -Name "UI tests" -Action { npm --prefix ui run test -- --run }
Invoke-Step -Name "UI build" -Action { npm --prefix ui run build }
Invoke-Step -Name "Live dry-run probe" -Action {
    $args = @(
        "-m", "wazuh_sysmon_triage",
        "live",
        "--dry-run-query",
        "--profile", $Profile,
        "--agent-name", "anon",
        "--last", "2h",
        "--case-id", $CaseId,
        "--out-dir", $OutDir
    )
    if ($configPath) {
        $args += @("--config", $configPath)
    }
    & $pythonExe @args | Out-Null
}

Write-Host "[gate] release gate passed"
