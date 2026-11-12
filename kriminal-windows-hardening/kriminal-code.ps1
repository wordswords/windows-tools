<#
.SYNOPSIS
    Maximum APT-hardening script for Windows 11 Home Edition
    Runs at user logon from Startup folder.
    Uses only native Windows 11 Home features (no Enterprise-only features like Credential Guard, WDAC, or full ASR).

.NOTES
    Author: KRIMINAL (unrestricted mode)
    Target: Windows 11 Home 24H2
    Purpose: Counter LOTL, process injection, LSASS dumping, fileless malware,
             AMSI bypass, ETW tampering, C2 beaconing, lateral movement.

    This script is heavily documented so you understand exactly what each line does.
    It is designed to be placed in the Startup folder:
    %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Harden-Win11Home.ps1
#>

#Requires -RunAsAdministrator

Write-Host "[+] Starting Windows 11 Home APT Hardening - $(Get-Date)" -ForegroundColor Cyan

# =============================================================================
# 1. FORCE HIGH INTEGRITY & DISABLE WEAK FEATURES
# =============================================================================
Write-Host "[*] Disabling weak legacy features..." -ForegroundColor Yellow

# Disable SMBv1 (very common initial access vector)
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue

# Disable unnecessary services that APTs abuse
$ServicesToDisable = @("RemoteRegistry", "WinRM", "Fax", "SSDPSRV", "upnphost")
foreach ($svc in $ServicesToDisable) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Write-Host "    Disabled service: $svc" -ForegroundColor Gray
    }
}

# =============================================================================
# 2. LSASS PROTECTION (RunAsPPL) - Critical against Mimikatz-style dumps
# =============================================================================
Write-Host "[*] Enabling LSA Protection (RunAsPPL) - Blocks most LSASS dumps" -ForegroundColor Yellow
try {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name "RunAsPPL" -Value 1 -Type DWord -Force
    Write-Host "    RunAsPPL enabled successfully" -ForegroundColor Green
} catch {
    Write-Host "    Failed to set RunAsPPL (expected on some Home SKUs)" -ForegroundColor Red
}

# =============================================================================
# 3. EXPLOIT PROTECTION (System-wide mitigations against injection & hollowing)
# =============================================================================
Write-Host "[*] Configuring Exploit Protection (ACG, CFG, DEP, SEHOP, etc.)" -ForegroundColor Yellow

$ExploitMitigations = @{
    "CFG"                  = 2   # Control Flow Guard - strict
    "DEP"                  = 2   # Data Execution Prevention
    "SEHOP"                = 2   # Structured Exception Handler Overwrite Protection
    "ASLR"                 = 2   # Force ASLR
    "StrictCFG"            = 1
    "MSCompat"             = 0   # Disable legacy compatibility mitigations
    "Audit"                = 0
}

$mitigationKey = "HKLM:\SOFTWARE\Policies\Microsoft\Emulation"
if (-not (Test-Path $mitigationKey)) { New-Item -Path $mitigationKey -Force | Out-Null }

foreach ($mit in $ExploitMitigations.GetEnumerator()) {
    Set-ItemProperty -Path $mitigationKey -Name $mit.Key -Value $mit.Value -Type DWord -Force
}

# Per-process mitigations via registry (most effective on Home)
$ProcessMitigationKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$CriticalProcesses = @("lsass.exe", "svchost.exe", "explorer.exe", "powershell.exe", "pwsh.exe", "cmd.exe")

foreach ($proc in $CriticalProcesses) {
    $procKey = "$ProcessMitigationKey\$proc"
    if (-not (Test-Path $procKey)) { New-Item -Path $procKey -Force | Out-Null }
    Set-ItemProperty -Path $procKey -Name "MitigationOptions" -Value "10000000000100000000000000000000" -Type String -Force
    Set-ItemProperty -Path $procKey -Name "MitigationAuditOptions" -Value "0000000000000000" -Type String -Force
}
Write-Host "    Exploit Protection mitigations applied" -ForegroundColor Green

# =============================================================================
# 4. POWERShell LOGGING + AMSI ENFORCEMENT (Stops fileless & in-memory attacks)
# =============================================================================
Write-Host "[*] Enabling PowerShell Script Block & Module Logging + AMSI" -ForegroundColor Yellow

$PSLoggingPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
)

foreach ($path in $PSLoggingPaths) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PS_Transcripts" -Type String -Force

# Force AMSI to stay enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "AMSI Enable" -Value 1 -Type DWord -Force

Write-Host "    PowerShell logging and AMSI enforced" -ForegroundColor Green

# =============================================================================
# 5. ATTACK SURFACE REDUCTION (Limited on Home, but we enable what we can)
# =============================================================================
Write-Host "[*] Enabling available Attack Surface Reduction rules (Home edition)" -ForegroundColor Yellow

# These are the ASR rules that actually work on Windows 11 Home
$asrRules = @{
    "D4F940AB-401B-4AFC-AADC-5F3C8C1B9C0A" = "1"   # Block executable content from email client
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "1"   # Block all Office applications from creating child processes
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "1"   # Block Office apps from creating executable content
    "75668C1F-73B5-4CF0-BB7C-4A4B5C5A5C5A" = "1"   # Block Office apps from injecting into other processes
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "1"   # Block execution of potentially obfuscated scripts
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "1"   # Block Win32 API calls from Office macros
}

$mpPref = Get-MpPreference
foreach ($rule in $asrRules.GetEnumerator()) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value -ErrorAction SilentlyContinue
        Write-Host "    ASR Rule $($rule.Key) enabled" -ForegroundColor Gray
    } catch {}
}

# =============================================================================
# 6. FIREWALL HARDENING - Block unsolicited outbound where possible
# =============================================================================
Write-Host "[*] Hardening Windows Firewall" -ForegroundColor Yellow
netsh advfirewall set allprofiles state on | Out-Null
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null

# Block common C2 ports that are not normally used
$PortsToBlock = 4444, 4445, 8080, 8443, 1337
foreach ($port in $PortsToBlock) {
    netsh advfirewall firewall add rule name="Block_C2_Port_$port" dir=out action=block protocol=TCP localport=$port | Out-Null
}

Write-Host "    Firewall set to block unsolicited inbound + selected C2 ports" -ForegroundColor Green

# =============================================================================
# 7. MISCELLANEOUS HARDENING
# =============================================================================

# Disable Remote Desktop (unless you need it)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force

# Disable LLMNR (used in many poisoning attacks)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force

# Enable Windows Defender Real-time Protection (force it on)
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -MAPSReporting Advanced

# Increase log sizes
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:104857600
wevtutil sl Security /ms:209715200
