[CmdletBinding()]
param(
    [int]$Port = 4173,
    [int]$TunnelPort = 9920,
    [switch]$SkipBuild,
    [switch]$SkipTunnelCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-CommandAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' is not available in PATH."
    }
}

function Get-RequiredEnv {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Missing required environment variable '$Name'. Set it in this shell before launching UI."
    }
    return $value.Trim()
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$Host,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMs = 1500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($Host, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.Close()
            return $false
        }
        $client.EndConnect($connect)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Assert-PortAvailable {
    param([Parameter(Mandatory = $true)][int]$Port)

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    } catch {
        $owner = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($owner) {
            $processName = "PID $($owner.OwningProcess)"
            $process = Get-Process -Id $owner.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                $processName = "$($process.ProcessName) (PID $($owner.OwningProcess))"
            }
            throw "Port $Port is already in use by $processName. Stop that process or pass -Port."
        }
        throw "Port $Port is already in use. Stop the existing listener or pass -Port."
    } finally {
        try {
            $listener.Stop()
        } catch {
            # no-op
        }
    }
}

Assert-CommandAvailable -Name "node"
Assert-CommandAvailable -Name "npm"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

$wazuhHostRaw = Get-RequiredEnv -Name "WAZUH_OS_HOST"
[void](Get-RequiredEnv -Name "WAZUH_OS_USER")
[void](Get-RequiredEnv -Name "WAZUH_OS_PASSWORD")

try {
    $wazuhHost = [System.Uri]$wazuhHostRaw
} catch {
    throw "WAZUH_OS_HOST must be a valid URL (example: https://127.0.0.1:9920)."
}
if ($wazuhHost.Scheme -ne "http" -and $wazuhHost.Scheme -ne "https") {
    throw "WAZUH_OS_HOST must use http or https."
}

if (-not $SkipTunnelCheck) {
    $hostLooksLocal = $wazuhHost.Host -in @("127.0.0.1", "localhost", "::1")
    if ($hostLooksLocal -or $wazuhHost.Port -eq $TunnelPort) {
        if (-not (Test-TcpPort -Host "127.0.0.1" -Port $TunnelPort)) {
            throw "Tunnel/indexer port $TunnelPort is unreachable on 127.0.0.1. Start SSH tunnel first (ssh -N -L $TunnelPort`:localhost:$TunnelPort <user>@<server>)."
        }
    }
}

Assert-PortAvailable -Port $Port

if (-not (Test-Path ".\config.local.yaml") -and (Test-Path ".\config.yaml")) {
    Write-Warning "Found config.yaml but not config.local.yaml. CLI auto-load favors config.local.yaml."
}

if (-not (Test-Path ".\ui\node_modules")) {
    Write-Host "[ui-live] Installing UI dependencies (npm ci)..."
    npm --prefix ui ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if (-not $SkipBuild) {
    Write-Host "[ui-live] Building UI bundle..."
    npm --prefix ui run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$env:PORT = "$Port"
$env:BIND_HOST = "127.0.0.1"
$env:PUBLIC_BIND = "false"
$env:PYTHONPATH = (Join-Path $repoRoot "src")
if ([string]::IsNullOrWhiteSpace($env:TRIAGE_ASYNC_RUNS_ENABLED)) {
    $env:TRIAGE_ASYNC_RUNS_ENABLED = "true"
}

Write-Host "[ui-live] Starting standalone UI server at http://127.0.0.1:$Port"
Write-Host "[ui-live] TRIAGE_ASYNC_RUNS_ENABLED=$($env:TRIAGE_ASYNC_RUNS_ENABLED)"
npm --prefix ui start
exit $LASTEXITCODE
