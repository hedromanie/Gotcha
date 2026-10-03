#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Gotcha lab — prepare Windows 10/11 for high-rate packet TX (WinDivert / Npcap).

.DESCRIPTION
    - High Performance power plan
    - Disable NIC power saving
    - Tune common advanced NIC properties (best-effort by DisplayName)
    - Optional: Defender exclusion + disable realtime scanning
    - Start npcap service if present
    Saves previous state to GotchaNetTune-state.json for Default.ps1

.NOTES
    Run from elevated PowerShell:
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\Optimization.ps1
      .\Optimization.ps1 -AdapterName "Ethernet"
      .\Optimization.ps1 -SkipDefender
#>

[CmdletBinding()]
param(
    [string]$AdapterName = "",
    [switch]$SkipDefender,
    [switch]$SkipPowerPlan,
    [string]$StateFile = ""
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

# --- Admin ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Run as Administrator."
    exit 1
}

Write-Host "============================================================" -ForegroundColor White
Write-Host " Gotcha network TX optimization" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

# --- Pick adapter ---
$adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Wi-?Fi|Wireless|802\.11" })

if (-not $adapters -or $adapters.Count -eq 0) {
    Write-Warn "No Up Ethernet adapters found; trying any physical Up adapter..."
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" })
}

if ($AdapterName) {
    $nic = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
    if (-not $nic) {
        Write-Err "Adapter '$AdapterName' not found."
        Get-NetAdapter -Physical | Format-Table Name, Status, LinkSpeed, InterfaceDescription
        exit 1
    }
} elseif ($adapters.Count -eq 1) {
    $nic = $adapters[0]
} elseif ($adapters.Count -gt 1) {
    Write-Info "Multiple adapters Up:"
    $i = 0
    foreach ($a in $adapters) {
        Write-Host ("  [{0}] {1}  {2}  {3}" -f $i, $a.Name, $a.LinkSpeed, $a.InterfaceDescription)
        $i++
    }
    $choice = Read-Host "Select index (default 0)"
    if ($choice -eq "") { $choice = 0 }
    $nic = $adapters[[int]$choice]
} else {
    Write-Err "No suitable network adapter found."
    exit 1
}

Write-Ok "Using adapter: $($nic.Name) ($($nic.InterfaceDescription))"

$state = [ordered]@{
    Timestamp     = (Get-Date).ToString("o")
    AdapterName   = $nic.Name
    PowerPlan     = $null
    PowerPlanRestored = $null
    NicPowerMgmt  = $null
    AdvancedProps = @()
    DefenderRealtime = $null
    DefenderExclusion = $null
    IPv6Binding   = $null
}

# --- Power plan ---
if (-not $SkipPowerPlan) {
    Write-Info "Power plan -> High Performance"
    try {
        $active = powercfg /getactivescheme
        $state.PowerPlan = "$active"
        # High Performance GUID (built-in)
        $hp = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        powercfg /setactive $hp 2>$null
        if ($LASTEXITCODE -ne 0) {
            # Ultimate Performance if present
            powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null | Out-Null
            powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
        }
        Write-Ok "High Performance (or best available) active"
    } catch {
        Write-Warn "Power plan change failed: $_"
    }
}

# --- NIC power management ---
Write-Info "Disable NIC power management"
try {
    $pm = Get-NetAdapterPowerManagement -Name $nic.Name -ErrorAction SilentlyContinue
    if ($pm) {
        $state.NicPowerMgmt = @{
            AllowComputerToTurnOffDevice = "$($pm.AllowComputerToTurnOffDevice)"
        }
    }
    Disable-NetAdapterPowerManagement -Name $nic.Name -ErrorAction SilentlyContinue
    Write-Ok "Power management disabled on $($nic.Name)"
} catch {
    Write-Warn "NIC power management: $_"
}

# --- Advanced properties (best-effort) ---
# Map: regex against DisplayName -> desired DisplayValue
$desired = @(
    @{ Pattern = "Interrupt Moderation$";           Value = "Disabled" },
    @{ Pattern = "Interrupt Moderation Rate";       Value = "Off" },
    @{ Pattern = "Flow Control";                    Value = "Disabled" },
    @{ Pattern = "Energy Efficient Ethernet";       Value = "Disabled" },
    @{ Pattern = "Green Ethernet";                  Value = "Disabled" },
    @{ Pattern = "Ultra Low Power Mode";            Value = "Disabled" },
    @{ Pattern = "Power Saving Mode";               Value = "Disabled" },
    @{ Pattern = "Selective Suspend";               Value = "Disabled" },
    @{ Pattern = "Large Send Offload.*IPv4";        Value = "Disabled" },
    @{ Pattern = "Large Send Offload.*IPv6";        Value = "Disabled" },
    @{ Pattern = "Recv Segment Coalescing";         Value = "Disabled" },
    @{ Pattern = "Receive Segment Coalescing";      Value = "Disabled" },
    @{ Pattern = "ARP Offload";                     Value = "Disabled" },
    @{ Pattern = "NS Offload";                      Value = "Disabled" },
    @{ Pattern = "IPv4 Checksum Offload";           Value = "Rx & Tx Enabled" },  # keep if useful; skip if fails
    @{ Pattern = "Receive Buffers";                 Value = $null },  # max — set below
    @{ Pattern = "Transmit Buffers";                Value = $null }
)

Write-Info "Tuning advanced NIC properties (skip if name not found)"
try {
    $props = Get-NetAdapterAdvancedProperty -Name $nic.Name -ErrorAction Stop
} catch {
    $props = @()
    Write-Warn "Cannot read advanced properties: $_"
}

foreach ($prop in $props) {
    $dn = $prop.DisplayName
    if (-not $dn) { continue }

    foreach ($rule in $desired) {
        if ($dn -notmatch $rule.Pattern) { continue }

        $target = $rule.Value
        # Buffers: pick maximum valid value if possible
        if ($dn -match "Receive Buffers|Transmit Buffers") {
            try {
                $valid = $prop.ValidDisplayValues
                if ($valid -and $valid.Count -gt 0) {
                    $nums = $valid | Where-Object { $_ -match "^\d+$" } | ForEach-Object { [int]$_ }
                    if ($nums) { $target = [string](($nums | Measure-Object -Maximum).Maximum) }
                }
            } catch { }
            if (-not $target) { continue }
        }

        if (-not $target) { continue }
        if ("$($prop.DisplayValue)" -eq $target) {
            Write-Host "    [=] $dn already $target"
            continue
        }

        $state.AdvancedProps += [ordered]@{
            DisplayName  = $dn
            RegistryKeyword = $prop.RegistryKeyword
            OldValue     = "$($prop.DisplayValue)"
            NewValue     = $target
        }

        try {
            Set-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName $dn -DisplayValue $target -ErrorAction Stop
            Write-Ok "$dn -> $target"
        } catch {
            Write-Warn "Skip $dn : $_"
            # remove last state entry if failed
            if ($state.AdvancedProps.Count -gt 0) {
                $state.AdvancedProps = @($state.AdvancedProps | Select-Object -SkipLast 1)
            }
        }
        break
    }
}

# --- Optional: disable IPv6 binding on this adapter (lab only) ---
try {
    $v6 = Get-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    if ($v6) {
        $state.IPv6Binding = [bool]$v6.Enabled
        if ($v6.Enabled) {
            Disable-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            Write-Ok "IPv6 binding disabled on $($nic.Name) (lab)"
        }
    }
} catch {
    Write-Warn "IPv6 binding: $_"
}

# --- Defender ---
if (-not $SkipDefender) {
    Write-Info "Windows Defender tweaks"
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $state.DefenderRealtime = -not [bool]$mp.DisableRealtimeMonitoring

        $gotchaRoot = Split-Path $ScriptDir -Parent
        if (-not (Test-Path $gotchaRoot)) { $gotchaRoot = $ScriptDir }
        Add-MpPreference -ExclusionPath $gotchaRoot -ErrorAction SilentlyContinue
        $state.DefenderExclusion = $gotchaRoot
        Write-Ok "Exclusion path: $gotchaRoot"

        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Write-Ok "Realtime monitoring disabled (temporary; policy may re-enable)"
    } catch {
        Write-Warn "Defender changes failed (policy/Tamper Protection?): $_"
    }
} else {
    Write-Info "SkipDefender: no AV changes"
}

# --- npcap service ---
Write-Info "Npcap service"
foreach ($svcName in @("npcap", "npf")) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Running") {
            try {
                Start-Service $svcName -ErrorAction Stop
                Write-Ok "Service $svcName started"
            } catch {
                Write-Warn "Cannot start $svcName : $_"
            }
        } else {
            Write-Ok "Service $svcName already Running"
        }
    }
}

# --- Save state ---
try {
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8
    Write-Ok "State saved: $StateFile"
} catch {
    Write-Warn "Could not save state file: $_"
}

Write-Host ""
Write-Ok "Done. Reboot recommended after first NIC property change."
Write-Info "Restore with: .\Default.ps1"
Write-Host ""
