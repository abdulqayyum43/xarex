#Requires -Version 5.1
<#
.SYNOPSIS
    Phantom Probe — Windows Installer

.DESCRIPTION
    Installs the Phantom Probe as a Windows service on the local machine.
    Downloads the probe binary from your Cloud Brain instance, creates
    the configuration file, and registers a Windows service set to
    automatic start.

    The installer is idempotent — safe to re-run to upgrade or reconfigure.

.PARAMETER CloudBrainUrl
    URL of the Cloud Brain (e.g. https://cloud.example.com).
    If not specified, the installer will prompt interactively.

.PARAMETER OrgId
    Organisation ID from the Phantom dashboard.
    If not specified, the installer will prompt interactively.

.PARAMETER ProbeId
    Optional custom Probe ID. Defaults to "probe-<hostname>".

.EXAMPLE
    .\install-windows.ps1
    .\install-windows.ps1 -CloudBrainUrl https://cloud.example.com -OrgId abc123

.NOTES
    Requires: PowerShell 5.1+, Windows 10/Server 2016 or later, Administrator privileges.
    Version: 1.0.0
#>
[CmdletBinding()]
param(
    [string]$CloudBrainUrl = "",
    [string]$OrgId         = "",
    [string]$ProbeId       = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────
$PhantomVersion = "1.0.0"
$InstallDir     = "C:\Program Files\Phantom"
$BinaryPath     = "$InstallDir\phantom-probe.exe"
$ConfPath       = "$InstallDir\phantom.conf"
$ServiceName    = "PhantomProbe"
$ServiceDisplay = "Phantom Probe"
$ServiceDesc    = "Phantom autonomous penetration testing probe agent"
$LogFile        = "$env:TEMP\phantom-probe-install.log"

# ── Colour helpers ─────────────────────────────────────────────────────────────
function Write-Step   { param([string]$msg) Write-Host "`n━━━ $msg ━━━" -ForegroundColor Cyan }
function Write-Info   { param([string]$msg) Write-Host "[INFO]  $msg" -ForegroundColor Gray; Add-Content $LogFile "[$(Get-Date -f 'u')] INFO  $msg" }
function Write-Ok     { param([string]$msg) Write-Host "[ OK ]  $msg" -ForegroundColor Green; Add-Content $LogFile "[$(Get-Date -f 'u')] OK    $msg" }
function Write-Warn   { param([string]$msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; Add-Content $LogFile "[$(Get-Date -f 'u')] WARN  $msg" }
function Write-Err    { param([string]$msg) Write-Host "[ERR ]  $msg" -ForegroundColor Red; Add-Content $LogFile "[$(Get-Date -f 'u')] ERR   $msg" }
function Abort        { param([string]$msg) Write-Err $msg; exit 1 }

# ── Banner ────────────────────────────────────────────────────────────────────
"" | Out-Null
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        Phantom Probe — Windows Installer             ║" -ForegroundColor Cyan
Write-Host "║                    v$PhantomVersion                            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Add-Content $LogFile "=== Phantom Probe Installer v$PhantomVersion — $(Get-Date -f 'u') ==="

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 1 — Checking Administrator Privileges"
# ═════════════════════════════════════════════════════════════════════════════

$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Abort "This installer must be run as Administrator. Right-click PowerShell and choose 'Run as Administrator'."
}
Write-Ok "Running as Administrator."

# Check Windows version
$OsVer = [System.Environment]::OSVersion.Version
if ($OsVer.Major -lt 10) {
    Write-Warn "Windows version $($OsVer.ToString()) detected. Windows 10 / Server 2016 or later is recommended."
} else {
    Write-Ok "OS: $(([System.Environment]::OSVersion.VersionString))"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 2 — Configuration"
# ═════════════════════════════════════════════════════════════════════════════

function Prompt-IfEmpty {
    param([string]$Varname, [string]$PromptText, [string]$Default = "", [switch]$IsSecret)
    $current = (Get-Variable -Name $Varname -Scope Script -ErrorAction SilentlyContinue).Value
    if (-not [string]::IsNullOrWhiteSpace($current)) {
        if (-not $IsSecret) { Write-Info "$Varname = $current (from parameter)" }
        else { Write-Info "$Varname already set (from parameter)" }
        return
    }

    $displayPrompt = $PromptText
    if (-not [string]::IsNullOrEmpty($Default)) { $displayPrompt += " [$Default]" }
    $displayPrompt += ": "

    while ($true) {
        if ($IsSecret) {
            $secureStr = Read-Host $displayPrompt -AsSecureString
            $value = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStr))
        } else {
            $value = Read-Host $displayPrompt
        }
        if ([string]::IsNullOrWhiteSpace($value) -and -not [string]::IsNullOrEmpty($Default)) {
            $value = $Default
        }
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            Set-Variable -Name $Varname -Value $value -Scope Script
            break
        }
        Write-Warn "Value cannot be empty. Please try again."
    }
}

Prompt-IfEmpty -Varname CloudBrainUrl -PromptText "Cloud Brain URL (e.g. https://cloud.example.com)"
Prompt-IfEmpty -Varname OrgId         -PromptText "Organisation ID"

if ([string]::IsNullOrWhiteSpace($ProbeId)) {
    $ProbeId = "probe-$($env:COMPUTERNAME.ToLower())"
}
Write-Info "Probe ID: $ProbeId"

# Clean up URL
$CloudBrainUrl = $CloudBrainUrl.TrimEnd('/')

# Parse gRPC host/port
$GrpcHost = $CloudBrainUrl -replace 'https?://', '' -split ':' | Select-Object -First 1
$GrpcPort = 50051

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 3 — Connectivity Check"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Testing connectivity to ${GrpcHost}:${GrpcPort}..."
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $connect = $tcp.BeginConnect($GrpcHost, $GrpcPort, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne(5000, $false)
    if ($wait -and $tcp.Connected) {
        $tcp.EndConnect($connect)
        Write-Ok "Port $GrpcPort reachable on $GrpcHost."
    } else {
        Write-Warn "Cannot reach ${GrpcHost}:${GrpcPort}. Ensure port 50051 is open and Cloud Brain is running."
    }
    $tcp.Close()
} catch {
    Write-Warn "Connectivity check failed: $_"
}

# HTTP health check
try {
    $response = Invoke-WebRequest -Uri "$CloudBrainUrl/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    if ($response.StatusCode -eq 200) { Write-Ok "Cloud Brain HTTP health check passed." }
} catch {
    Write-Warn "Cloud Brain HTTP health check failed. Proceeding anyway."
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 4 — Creating Installation Directory"
# ═════════════════════════════════════════════════════════════════════════════

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Ok "Created $InstallDir"
} else {
    Write-Info "$InstallDir already exists."
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 5 — Downloading Probe Binary"
# ═════════════════════════════════════════════════════════════════════════════

$DownloadUrl = "$CloudBrainUrl/download/phantom-probe.exe"
$TempBinary  = "$InstallDir\phantom-probe.exe.tmp"

Write-Info "Downloading from $DownloadUrl..."
try {
    # Use TLS 1.2+
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadUrl, $TempBinary)
    Move-Item -Path $TempBinary -Destination $BinaryPath -Force
    Write-Ok "Binary downloaded to $BinaryPath"
} catch {
    if (Test-Path $BinaryPath) {
        Write-Warn "Download failed: $_"
        Write-Warn "Using existing binary at $BinaryPath"
    } else {
        Abort "Download failed and no existing binary found.`nURL: $DownloadUrl`nError: $_"
    }
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 6 — Writing Configuration"
# ═════════════════════════════════════════════════════════════════════════════

$ConfContent = @"
# Phantom Probe Configuration
# Generated by install-windows.ps1 on $(Get-Date -f 'u')

CLOUD_BRAIN_ADDR=${GrpcHost}:${GrpcPort}
ORG_ID=$OrgId
PROBE_ID=$ProbeId
LOG_LEVEL=info
GRPC_TLS=false
"@

Set-Content -Path $ConfPath -Value $ConfContent -Encoding UTF8

# Restrict config file permissions to SYSTEM and Administrators only
$acl = Get-Acl $ConfPath
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow")
$acl.AddAccessRule($rule)
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow")
$acl.AddAccessRule($rule2)
Set-Acl $ConfPath $acl

Write-Ok "Configuration written to $ConfPath"

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 7 — Registering Windows Service"
# ═════════════════════════════════════════════════════════════════════════════

# Build the service command — read conf file and pass as env vars to the binary
$ServiceBinaryPath = "`"$BinaryPath`" --config `"$ConfPath`""

# Check for NSSM (preferred — supports log rotation and richer service config)
$NssmPath = (Get-Command nssm.exe -ErrorAction SilentlyContinue)?.Source
if ($NssmPath) {
    Write-Info "NSSM found at $NssmPath. Using NSSM for service registration."

    # Remove existing service if present
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Removing existing service '$ServiceName'..."
        & $NssmPath stop  $ServiceName | Out-Null
        & $NssmPath remove $ServiceName confirm | Out-Null
    }

    & $NssmPath install $ServiceName $BinaryPath "--config" $ConfPath
    & $NssmPath set $ServiceName Description $ServiceDesc
    & $NssmPath set $ServiceName DisplayName $ServiceDisplay
    & $NssmPath set $ServiceName Start SERVICE_AUTO_START
    & $NssmPath set $ServiceName AppStdout "$InstallDir\phantom-probe.log"
    & $NssmPath set $ServiceName AppStderr "$InstallDir\phantom-probe-error.log"
    & $NssmPath set $ServiceName AppRotateFiles 1
    & $NssmPath set $ServiceName AppRotateOnline 1
    & $NssmPath set $ServiceName AppRotateBytes 10485760  # 10 MB
    Write-Ok "Service registered via NSSM."

} else {
    Write-Info "NSSM not found. Using sc.exe for service registration."

    # Remove existing service
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Stopping and removing existing service '$ServiceName'..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Register with sc.exe
    $scResult = & sc.exe create $ServiceName `
        binPath= $ServiceBinaryPath `
        DisplayName= $ServiceDisplay `
        start= auto `
        obj= LocalSystem
    if ($LASTEXITCODE -ne 0) { Abort "sc.exe create failed: $scResult" }

    # Set description
    & sc.exe description $ServiceName $ServiceDesc | Out-Null

    # Configure failure recovery — restart after 10s, up to 3 times
    & sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

    Write-Ok "Service registered via sc.exe."
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 8 — Starting Service"
# ═════════════════════════════════════════════════════════════════════════════

Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-Ok "Service '$ServiceName' is running."
} else {
    Write-Warn "Service '$ServiceName' status: $($svc.Status). Check Windows Event Log for details."
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Step 9 — Verifying Probe Connection"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Waiting for probe to register with Cloud Brain..."
$MaxWait = 60
$Interval = 5
$Elapsed = 0
$Connected = $false

while ($Elapsed -lt $MaxWait) {
    Start-Sleep -Seconds $Interval
    $Elapsed += $Interval

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc.Status -ne "Running") {
        Write-Err "Service stopped unexpectedly after ${Elapsed}s."
        break
    }

    try {
        $r = Invoke-WebRequest -Uri "$CloudBrainUrl/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            $Connected = $true
            break
        }
    } catch {}
}

if ($Connected) {
    Write-Ok "Probe service is running and Cloud Brain is reachable."
} else {
    Write-Warn "Could not confirm probe registration within ${MaxWait}s."
    Write-Warn "Check Windows Event Viewer > Application logs for 'PhantomProbe'."
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Step "Installation Complete"
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║        Phantom Probe installed successfully!             ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Probe details:" -ForegroundColor White
Write-Host "  Probe ID     : $ProbeId"
Write-Host "  Cloud Brain  : $CloudBrainUrl"
Write-Host "  gRPC Addr    : ${GrpcHost}:${GrpcPort}"
Write-Host "  Install dir  : $InstallDir"
Write-Host "  Config file  : $ConfPath"
Write-Host "  Service name : $ServiceName"
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor White
Write-Host "  Get-Service PhantomProbe                  # Check service status"
Write-Host "  Restart-Service PhantomProbe              # Restart the probe"
Write-Host "  Stop-Service PhantomProbe                 # Stop the probe"
Write-Host "  Get-EventLog -LogName Application -Source PhantomProbe -Newest 50"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Log in to your Phantom dashboard at $CloudBrainUrl"
Write-Host "  2. Navigate to the Probes page — '$ProbeId' should appear online."
Write-Host "  3. Create a new scan and select this probe."
Write-Host ""
Write-Host "Install log: $LogFile"
Write-Host ""
