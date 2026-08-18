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
    $existingCandidates = @()
    foreach ($candidate in $candidates) {
        if ($candidate -eq "python" -or (Test-Path $candidate)) {
            $existingCandidates += $candidate
        }
    }

    foreach ($candidate in $existingCandidates) {
        try {
            & $candidate -c "import pytest" 1>$null 2>$null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
            continue
        }
    }

    if ($existingCandidates.Count -gt 0) {
        return $existingCandidates[0]
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

Invoke-Step -Name "Output contract tests" -Action { & $pythonExe -m pytest -q tests/test_render.py tests/test_config.py }
Invoke-Step -Name "Python tests" -Action { & $pythonExe -m pytest -q }
Invoke-Step -Name "Documentation links" -Action { & $pythonExe scripts/check_markdown_links.py }
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
