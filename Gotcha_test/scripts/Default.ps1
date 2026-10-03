#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Gotcha lab — restore settings saved by Optimization.ps1

.DESCRIPTION
    Reads GotchaNetTune-state.json and reverts:
    - Power plan (best-effort parse of previous scheme GUID)
    - NIC advanced properties
    - NIC power management note (re-enable AllowComputerToTurnOff if saved)
    - IPv6 binding
    - Defender realtime monitoring
    Does not remove Defender exclusions automatically (safe default).

.NOTES
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\Default.ps1
#>

[CmdletBinding()]
param(
    [string]$StateFile = "",
    [switch]$RemoveDefenderExclusion
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $StateFile) {
    $StateFile = Join-Path $ScriptDir "GotchaNetTune-state.json"
}

function Write-Info($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[~] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[!] $msg" -ForegroundColor Red }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Run as Administrator."
    exit 1
}

Write-Host "============================================================" -ForegroundColor White
Write-Host " Gotcha network settings restore" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

if (-not (Test-Path $StateFile)) {
    Write-Err "State file not found: $StateFile"
    Write-Info "Run Optimization.ps1 first."
    exit 1
}

try {
    $state = Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Err "Cannot parse state file: $_"
    exit 1
}

$adapterName = $state.AdapterName
Write-Info "State from: $($state.Timestamp)"
Write-Info "Adapter: $adapterName"

$nic = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
if (-not $nic) {
    Write-Warn "Adapter '$adapterName' not found — will still try power plan / Defender"
}

# --- Power plan ---
if ($state.PowerPlan) {
    Write-Info "Restore power plan"
    # powercfg /getactivescheme output contains GUID in parentheses or as bare GUID
    if ($state.PowerPlan -match "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})") {
        $guid = $Matches[1]
        powercfg /setactive $guid 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Power plan restored: $guid"
        } else {
            Write-Warn "Could not activate scheme $guid — set Balanced manually"
            powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e 2>$null
        }
    } else {
        Write-Warn "No GUID in saved power plan; activating Balanced"
        powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e 2>$null
    }
}

# --- Advanced properties ---
if ($nic -and $state.AdvancedProps) {
    Write-Info "Restore advanced NIC properties"
    foreach ($item in $state.AdvancedProps) {
        $dn  = $item.DisplayName
        $old = $item.OldValue
        if (-not $dn -or $null -eq $old) { continue }
        try {
            Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName $dn -DisplayValue $old -ErrorAction Stop
            Write-Ok "$dn -> $old"
        } catch {
            Write-Warn "Cannot restore $dn : $_"
        }
    }
}

# --- NIC power management (re-enable allow turn off if we only disabled) ---
if ($nic) {
    try {
        Enable-NetAdapterPowerManagement -Name $adapterName -ErrorAction SilentlyContinue
        Write-Ok "NIC power management re-enabled (OS defaults)"
    } catch {
        Write-Warn "NIC power management restore: $_"
    }
}

# --- IPv6 ---
if ($nic -and $null -ne $state.IPv6Binding) {
    try {
        if ($state.IPv6Binding -eq $true) {
            Enable-NetAdapterBinding -Name $adapterName -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            Write-Ok "IPv6 binding enabled"
        }
    } catch {
        Write-Warn "IPv6 restore: $_"
    }
}

# --- Defender realtime ---
if ($null -ne $state.DefenderRealtime) {
    Write-Info "Defender realtime"
    try {
        if ($state.DefenderRealtime -eq $true) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Ok "Realtime monitoring enabled"
        }
    } catch {
        Write-Warn "Defender restore failed (policy?): $_"
    }
}

if ($RemoveDefenderExclusion -and $state.DefenderExclusion) {
    try {
        Remove-MpPreference -ExclusionPath $state.DefenderExclusion -ErrorAction SilentlyContinue
        Write-Ok "Removed exclusion: $($state.DefenderExclusion)"
    } catch {
        Write-Warn "Exclusion remove: $_"
    }
}

Write-Host ""
Write-Ok "Restore finished. Reboot if NIC still behaves oddly."
Write-Host ""
