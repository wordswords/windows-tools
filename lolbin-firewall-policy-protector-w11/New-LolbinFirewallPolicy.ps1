#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a production-oriented Windows Firewall deployment script that
    blocks outbound internet traffic for 39 common Living-off-the-Land
    binaries (LOLBins).

.DESCRIPTION
    New-LolbinFirewallPolicy is a side-effect-free GENERATOR. It never touches
    a firewall, requires no elevation, and never contacts a domain controller.
    It validates your configuration and writes a self-contained deployment
    script (Deploy-LolbinFirewallPolicy.ps1) with an embedded JSON manifest
    (base64-encoded data; a human-readable copy is emitted alongside).

    Run the generated script on a target machine (or against a domain GPO) to
    apply the policy. The generated script:

      - Creates outbound BLOCK rules scoped by default to RemoteAddress
        'Internet' (the set of destinations TO BLOCK). Windows Network
        Isolation classifies destinations: intranet address space (AD
        sites/subnets, the GPO 'Private network ranges for apps' setting,
        and the local subnet) counts as private; everything else is
        'Internet'. Classification MUST be validated per environment.
      - Reconciles idempotently: deterministic rule names in a dedicated
        namespace, ownership markers, drift repair (program path, scope,
        profile, protocol, enabled state), stale owned rules are removed only
        AFTER successful reconciliation of desired rules.
      - Targets the local PersistentStore or a domain GPO (batched
        Open-NetGPO / -GPOSession / Save-NetGPO, or direct -PolicyStore).
      - Backs up owned rules (versioned schema) before mutation - a failed
        backup is fatal. -RestoreFromBackup recreates the SAVED
        configuration (scope, enabled state, profile included), which is
        distinct from -RemoveOnly (deletes our rules).
      - Handles errors per operation, continues on failure, writes a CSV
        change report, and exits 0 (success) / 1 (partial failure) / 2
        (fatal).

    References:
      - New-NetFirewallRule: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
      - GPO sessions: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line
      - Network isolation ('Internet' keyword): https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/isolating-apps-on-your-network
      - Set-NetFirewallRule: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule
      - LOLBAS project: https://lolbas-project.github.io/

.NOTES
    Limitations of path-based firewall rules (documented in the generated
    script and README):
      - Renamed or copied binaries are not contained.
      - Child processes are only contained if they are themselves blocked.
      - Brokered/service-mediated transfers are not contained (e.g. a rule
        on bitsadmin.exe does not block transfers performed by the BITS
        service in svchost.exe).
      - Effective enforcement (Network Isolation classification, profile
        merge states, IPv6) must be validated on real Windows hosts - this
        is a production-oriented candidate requiring a Windows pilot.

.PARAMETER OutputPath
    Path of the generated deployment script.

.PARAMETER PolicyName
    Namespace prefix for all rules (also used as the rule Group). Must match
    [A-Za-z0-9._-]. Default 'LOLBAS-Block-Outbound'.

.PARAMETER RemoteAddress
    The set of destinations TO BLOCK. Default @('Internet'). Accepts firewall
    keywords (Internet, Intranet, LocalSubnet, ...) or explicit IPv4/IPv6
    addresses, subnets, or ranges. NOTE: supplying intranet CIDRs here BLOCKS
    those destinations - it does not subtract them from the Internet scope.

.PARAMETER BinaryPaths
    Hashtable mapping a binary name to one or more program path templates
    (env-var style like '%SystemRoot%\System32\certutil.exe' or literal
    absolute paths). Overrides the catalog default for that binary. Unknown
    names are rejected (typo guard).

.PARAMETER AdditionalBinaries
    Full program paths to append beyond the catalog (e.g. javaw.exe,
    AppInstaller.exe under WindowsApps).

.PARAMETER ExcludeBinaries
    Binary names to EXCLUDE from the policy. Primary mechanism for
    environments where certain administrative tools must keep outbound
    internet access (ssh, mstsc, wmic...). Exclusions are recorded in the
    manifest for audit.

.PARAMETER NoWow64
    Skip 32-bit path variants.

.PARAMETER IncludePowerShell7
    Add %ProgramFiles%\PowerShell\7\pwsh.exe.

.PARAMETER PassThru
    Emit the manifest objects as output.

.EXAMPLE
    .\New-LolbinFirewallPolicy.ps1
    Generates .\Deploy-LolbinFirewallPolicy.ps1 with all defaults.

.EXAMPLE
    .\New-LolbinFirewallPolicy.ps1 -PolicyName 'ACME-Lolbin-Block' -ExcludeBinaries 'ssh.exe','mstsc.exe'
    Generates a policy that leaves OpenSSH and RDP outbound-capable for admins.

.EXAMPLE
    .\New-LolbinFirewallPolicy.ps1 -BinaryPaths @{ 'certutil.exe' = 'D:\Tools\certutil.exe' } -AdditionalBinaries 'C:\Java\bin\javaw.exe'
    Override a path and add a non-catalog binary.

.OUTPUTS
    System.IO.FileInfo for the generated script (and manifest objects with -PassThru).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) 'Deploy-LolbinFirewallPolicy.ps1'),

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$PolicyName = 'LOLBAS-Block-Outbound',

    [string[]]$RemoteAddress = @('Internet'),

    [hashtable]$BinaryPaths,

    [string[]]$AdditionalBinaries,

    [string[]]$ExcludeBinaries,

    [switch]$NoWow64,

    [switch]$IncludePowerShell7,

    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GeneratorVersion = '1.1.0'

# ---------------------------------------------------------------------------
# Catalog: 39 distinct LOLBin executable names with their REAL Windows
# locations (PowerShell under WindowsPowerShell\v1.0, WMIC under wbem,
# .NET tools under Microsoft.NET\Framework[64]\v4.0.30319, OpenSSH under
# System32\OpenSSH). Path templates are env-var strings so they resolve on
# each TARGET machine at rule evaluation time. Binaries absent from a
# machine simply never match their rule (inert rule).
# ---------------------------------------------------------------------------
$Catalog = @(
    # --- Download / transfer primitives ------------------------------------
    @{ Name='certutil.exe';  Category='Download';   AdminSensitive=$false; Note='Certificate tool; -urlcache/-verifyctl can download and exfiltrate files' }
    @{ Name='bitsadmin.exe'; Category='Download';   AdminSensitive=$false; Note='BITS admin tool (note: does not contain transfers made by the BITS service itself)' }
    @{ Name='curl.exe';      Category='Download';   AdminSensitive=$false; Note='Modern Windows ships curl.exe; direct download/upload primitive' }
    @{ Name='tar.exe';       Category='Download';   AdminSensitive=$false; Note='bsdtar; supports remote URL fetch (http, ftp, sftp)' }
    @{ Name='ftp.exe';       Category='Download';   AdminSensitive=$false; Note='Legacy FTP client (removed in recent builds; rule stays inert)' }
    @{ Name='tftp.exe';      Category='Download';   AdminSensitive=$false; Note='Legacy TFTP client (removed in recent builds; rule stays inert)' }

    # --- Script / HTML application hosts -----------------------------------
    @{ Name='mshta.exe';        Category='ScriptHost'; AdminSensitive=$false; Note='HTML Application host; executes inline VBScript/JScript' }
    @{ Name='wscript.exe';      Category='ScriptHost'; AdminSensitive=$false; Note='Windows Script Host (GUI); executes .vbs/.js' }
    @{ Name='cscript.exe';      Category='ScriptHost'; AdminSensitive=$false; Note='Windows Script Host (console); executes .vbs/.js' }
    @{ Name='powershell.exe';   Category='ScriptHost'; AdminSensitive=$false; Note='Windows PowerShell console; network via .NET/WebClient' }
    @{ Name='powershell_ise.exe'; Category='ScriptHost'; AdminSensitive=$false; Note='Windows PowerShell ISE; same .NET networking as console host' }

    # --- Code execution via COM / installers -------------------------------
    @{ Name='regsvr32.exe'; Category='CodeExec'; AdminSensitive=$false; Note='COM registration; /i:http... remote script execution' }
    @{ Name='rundll32.exe'; Category='CodeExec'; AdminSensitive=$false; Note='Generic DLL entry-point executor (e.g. javascript: URLs)' }
    @{ Name='msiexec.exe';  Category='CodeExec'; AdminSensitive=$false; Note='Windows Installer; can install from URL sources' }
    @{ Name='installutil.exe'; Category='CodeExec'; AdminSensitive=$false; Note='.NET installer utility; executes arbitrary C# installers' }
    @{ Name='regasm.exe';  Category='CodeExec'; AdminSensitive=$false; Note='.NET assembly registration; executes installer classes' }
    @{ Name='regsvcs.exe'; Category='CodeExec'; AdminSensitive=$false; Note='.NET COM+ registration; executes installer classes' }
    @{ Name='msbuild.exe'; Category='CodeExec'; AdminSensitive=$false; Note='Build engine; inline tasks execute arbitrary code' }

    # --- Remote administration (likely admin-required in many orgs) ----------
    @{ Name='wmic.exe';      Category='RemoteAdmin'; AdminSensitive=$true; Note='WMI command line; remote /node: operations' }
    @{ Name='mstsc.exe';     Category='RemoteAdmin'; AdminSensitive=$true; Note='Remote Desktop client' }
    @{ Name='schtasks.exe';  Category='RemoteAdmin'; AdminSensitive=$true; Note='Task scheduler; /S remote host task creation' }
    @{ Name='sc.exe';       Category='RemoteAdmin'; AdminSensitive=$true; Note='Service control; \\remote operations' }
    @{ Name='net.exe';      Category='RemoteAdmin'; AdminSensitive=$true; Note='net use / domain ops over SMB' }
    @{ Name='net1.exe';     Category='RemoteAdmin'; AdminSensitive=$true; Note='net.exe runtime helper; same SMB exposure' }
    @{ Name='nltest.exe';   Category='RemoteAdmin'; AdminSensitive=$true; Note='DC locator / domain enumeration' }
    @{ Name='reg.exe';      Category='RemoteAdmin'; AdminSensitive=$true; Note='Registry tool; \\remote\HKLM queries over SMB' }
    @{ Name='iscsicli.exe'; Category='RemoteAdmin'; AdminSensitive=$true; Note='iSCSI command line; remote storage attach' }

    # --- OpenSSH client (only 64-bit on modern Windows) ----------------------
    @{ Name='ssh.exe';         Category='OpenSSH'; AdminSensitive=$true; Wow64=$false; Note='OpenSSH client; located under System32\OpenSSH' }
    @{ Name='scp.exe';         Category='OpenSSH'; AdminSensitive=$true; Wow64=$false; Note='OpenSSH copy' }
    @{ Name='sftp.exe';        Category='OpenSSH'; AdminSensitive=$true; Wow64=$false; Note='OpenSSH SFTP' }
    @{ Name='ssh-keyscan.exe'; Category='OpenSSH'; AdminSensitive=$false; Wow64=$false; Note='OpenSSH key scanning (recon primitive)' }

    # --- Misc LOLBAS ---------------------------------------------------------
    @{ Name='xwizard.exe';    Category='Misc'; AdminSensitive=$false; Note='Extensible wizard; network-capable class' }
    @{ Name='msdt.exe';      Category='Misc'; AdminSensitive=$false; Note='Diagnostics (Follina); can run remote diagnostics paths' }
    @{ Name='hh.exe';        Category='Misc'; AdminSensitive=$false; Note='HTML Help; can retrieve remote compiled help' }
    @{ Name='rasautou.exe';  Category='Misc'; AdminSensitive=$false; Note='Remote Access AutoDial; download capability' }
    @{ Name='stordiag.exe';  Category='Misc'; AdminSensitive=$false; Note='Storage diagnostics; collects traces/uploads' }
    @{ Name='presentationhost.exe'; Category='Misc'; AdminSensitive=$false; Note='XBAP host; downloads .xbap applications' }
    @{ Name='certreq.exe';   Category='Misc'; AdminSensitive=$false; Note='Certificate request; submits to remote CAs' }
    @{ Name='devicecredentialdeployment.exe'; Category='Misc'; AdminSensitive=$false; Note='Workplace join; network enrollment' }
)

# Per-binary path templates (defaults). Env-var strings resolve on the target.
$script:DefaultPaths = @{
    'powershell.exe'         = @('%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe', '%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe')
    'powershell_ise.exe'    = @('%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell_ise.exe', '%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe')
    'wmic.exe'              = @('%SystemRoot%\System32\wbem\wmic.exe', '%SystemRoot%\SysWOW64\wbem\wmic.exe')
    'installutil.exe'       = @('%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\installutil.exe', '%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\installutil.exe')
    'regasm.exe'            = @('%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\regasm.exe', '%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\regasm.exe')
    'regsvcs.exe'           = @('%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe', '%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe')
    'msbuild.exe'           = @('%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe', '%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe')
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function ConvertTo-RuleNameSuffix {
    param([string]$ProgramPath)
    $p = $ProgramPath -replace '%[^%]*%', '' -replace '\.[A-Za-z0-9]+$', ''
    if ($p -match 'Microsoft.NET\\Framework64') { return 'NET64' }
    if ($p -match 'Microsoft.NET\\Framework')   { return 'NET32' }
    if ($p -match 'SysWOW64\\WindowsPowerShell') { return 'Wow64PS' }
    if ($p -match 'System32\\WindowsPowerShell') { return 'Sys32PS' }
    if ($p -match 'SysWOW64\\wbem')              { return 'Wow64WBEM' }
    if ($p -match 'System32\\wbem')              { return 'Sys32WBEM' }
    if ($p -match 'System32\\OpenSSH')           { return 'OpenSSH' }
    if ($p -match 'SysWOW64')                    { return 'Wow64' }
    if ($p -match 'System32')                    { return 'Sys32' }
    if ($p -match 'PowerShell\\7')               { return 'PS7' }
    $s = ($p -replace '[^A-Za-z0-9]+', '-').Trim('-')
    if ($s.Length -gt 48) { $s = $s.Substring($s.Length - 48) }
    if (-not $s) { $s = 'Custom' }
    return $s
}

function Test-ProgramPathTemplate {
    param([string]$Path)
    if ($Path -match '[<>"|]') { return $false }
    if ($Path -match '^%[^%]+%\\') { return $true }
    if ($Path -match '^[A-Za-z]:\\') { return $true }
    return $false
}

$ipv4Octet = '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
$ipv4 = "{0}\.{0}\.{0}\.{0}" -f $ipv4Octet
$allowedKeywords = @('Any','LocalSubnet','DNS','DHCP','WINS','DefaultGateway','Internet','Intranet','IntranetRemoteAccess','PlayToDevice','CaptivePortal')
foreach ($ra in $RemoteAddress) {
    $isKeyword = $allowedKeywords -contains $ra -or $ra -match '^(LocalSubnet|DNS|DHCP|WINS|Intranet|Internet|IntranetRemoteAccess)[46]$'
    $isAddress = $ra -match "^$ipv4(/(3[0-2]|[12]?\d))?$" -or
                  $ra -match "^$ipv4-$ipv4$" -or
                  $ra -match '^[0-9a-fA-F:]{2,}(/[0-9]{1,3})?-[0-9a-fA-F:]{2,}(/[0-9]{1,3})?$'
    if (-not ($isKeyword -or $isAddress)) {
        throw "Invalid RemoteAddress entry '$ra'. Use a supported keyword ($($allowedKeywords -join ', ')) or a valid IPv4/IPv6 address, subnet or range."
    }
}

# Typo guard: unknown -BinaryPaths keys are rejected
if ($BinaryPaths) {
    $known = $Catalog | ForEach-Object { $_.Name }
    foreach ($k in @($BinaryPaths.Keys)) {
        if ($k -notin $known) {
            throw "Unknown -BinaryPaths key '$k' (not in catalog; catalog names: $($known -join ', '))."
        }
    }
}

# ---------------------------------------------------------------------------
# Build the desired rule set
# ---------------------------------------------------------------------------
$rules = [System.Collections.Generic.List[object]]::new()
$seenNames = @{}

foreach ($bin in $Catalog) {
    if ($ExcludeBinaries -and $ExcludeBinaries -contains $bin.Name) { continue }

    $paths = [System.Collections.Generic.List[string]]::new()
    if ($BinaryPaths -and $BinaryPaths.ContainsKey($bin.Name)) {
        $override = $BinaryPaths[$bin.Name]
        if ($override -is [array]) { $paths.AddRange([string[]]$override) } else { $paths.Add([string]$override) }
    }
    elseif ($script:DefaultPaths.ContainsKey($bin.Name)) {
        $paths.AddRange([string[]]$script:DefaultPaths[$bin.Name])
    }
    elseif ($bin.Name -in @('ssh.exe','scp.exe','sftp.exe','ssh-keyscan.exe')) {
        $paths.Add('%SystemRoot%\System32\OpenSSH\' + $bin.Name)
    }
    else {
        $paths.Add('%SystemRoot%\System32\' + $bin.Name)
        if (-not $NoWow64) { $paths.Add('%SystemRoot%\SysWOW64\' + $bin.Name) }
    }

    foreach ($p in $paths) {
        if (-not (Test-ProgramPathTemplate -Path $p)) {
            throw "Invalid program path template '$p' for $($bin.Name). Use an absolute drive path or an env-var template such as '%SystemRoot%\System32\<name>'."
        }
        $suffix = ConvertTo-RuleNameSuffix -ProgramPath $p
        $ruleName = '{0}-{1}-{2}' -f $PolicyName, $bin.Name, $suffix
        if ($seenNames.ContainsKey($ruleName)) {
            throw "Duplicate rule name generated: '$ruleName'. Ensure -BinaryPaths overrides do not map to identical name suffixes."
        }
        $seenNames[$ruleName] = $true
        $rules.Add([pscustomobject]@{
            name          = $ruleName
            displayName   = "Block outbound internet - $($bin.Name) ($suffix)"
            program       = $p
            binary        = $bin.Name
            category      = $bin.Category
            adminSensitive = $bin.AdminSensitive
            description   = "LOLBAS outbound internet block. $($bin.Note). Managed by New-LolbinFirewallPolicy v$GeneratorVersion; do not edit manually."
        })
    }
}

if ($IncludePowerShell7) {
    foreach ($p in @('%ProgramFiles%\PowerShell\7\pwsh.exe')) {
        $suffix = ConvertTo-RuleNameSuffix -ProgramPath $p
        $ruleName = '{0}-pwsh.exe-{1}' -f $PolicyName, $suffix
        if (-not $seenNames.ContainsKey($ruleName)) {
            $seenNames[$ruleName] = $true
            $rules.Add([pscustomobject]@{
                name          = $ruleName
                displayName   = "Block outbound internet - pwsh.exe ($suffix)"
                program       = $p
                binary        = 'pwsh.exe'
                category      = 'ScriptHost'
                adminSensitive = $false
                description   = "LOLBAS outbound internet block. PowerShell 7 (install-dependent path). Managed by New-LolbinFirewallPolicy v$GeneratorVersion; do not edit manually."
            })
        }
    }
}

foreach ($p in ($AdditionalBinaries | Where-Object { $_ })) {
    if (-not (Test-ProgramPathTemplate -Path $p)) {
        throw "Invalid -AdditionalBinaries path '$p'. Use an absolute drive path or an env-var template."
    }
    $fileName = [System.IO.Path]::GetFileName($p)
    $suffix = ConvertTo-RuleNameSuffix -ProgramPath $p
    $ruleName = '{0}-{1}-{2}' -f $PolicyName, $fileName, $suffix
    if ($seenNames.ContainsKey($ruleName)) {
        throw "Duplicate rule name generated: '$ruleName' (AdditionalBinaries)."
    }
    $seenNames[$ruleName] = $true
    $rules.Add([pscustomobject]@{
        name          = $ruleName
        displayName   = "Block outbound internet - $fileName ($suffix)"
        program       = $p
        binary        = $fileName
        category      = 'Custom'
        adminSensitive = $false
        description   = "LOLBAS outbound internet block (custom addition). Managed by New-LolbinFirewallPolicy v$GeneratorVersion; do not edit manually."
    })
}

# Record exclusions (audit trail for admin-required environments)
$exclusionRecords = @()
if ($ExcludeBinaries) {
    $known = $Catalog | ForEach-Object { $_.Name }
    foreach ($ex in $ExcludeBinaries) {
        if ($ex -notin $known) {
            Write-Warning "Excluded binary '$ex' is not in the catalog (typo?); it was never going to be blocked."
        }
        $entry = $Catalog | Where-Object { $_.Name -eq $ex }
        $reason = 'Administrator requirement'
        if ($entry -and $entry.AdminSensitive) { $reason = 'Administrator requirement (catalog flags this tool as admin-sensitive)' }
        $exclusionRecords += [pscustomobject]@{ name = $ex; reason = $reason }
    }
}

# Minimum coverage: 30+ DISTINCT executable identities (not rule count)
$distinctBinaries = @($rules | ForEach-Object { $_.binary } | Sort-Object -Unique)
if ($distinctBinaries.Count -lt 30) {
    throw ("The generated policy covers only {0} distinct binaries; at least 30 are required. Check -ExcludeBinaries." -f $distinctBinaries.Count)
}

$manifest = [pscustomobject]@{
    manifestVersion = 2
    generator       = "New-LolbinFirewallPolicy v$GeneratorVersion"
    generatedUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    policyName      = $PolicyName
    remoteAddress   = @($RemoteAddress)
    exclusions      = $exclusionRecords
    rules           = $rules.ToArray()
}

$manifestJson = $manifest | ConvertTo-Json -Depth 5
$manifestB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($manifestJson))

# ---------------------------------------------------------------------------
# Deployment script template. All configuration travels as base64 JSON data;
# no user input is ever interpolated into code, and the generated script
# contains no Invoke-Expression.
# ---------------------------------------------------------------------------
$template = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys outbound internet block rules for Living-off-the-Land binaries
    (LOLBins). Generated by New-LolbinFirewallPolicy - do not hand-edit the
    embedded manifest; regenerate instead.

.DESCRIPTION
    Idempotent reconciliation of LOLBin outbound block rules against a target
    policy store (local PersistentStore or a domain GPO).

    Targeting:
      -Target Local       local PersistentStore (requires elevation)
      -Target GPO         domain GPO via -GpoTarget 'domain.fqdn\GPO Name'
                          (default: batched Open-NetGPO/-GPOSession/Save-NetGPO;
                           -UseGpoSession:$false writes via -PolicyStore directly)

    Operations:
      (default)           reconcile to the embedded manifest
      -RemoveOnly         remove ONLY rules in this policy's namespace
      -RestoreFromBackup  recreate the SAVED owned-rule configuration from a
                          backup JSON (preserves scope/enabled state/profile) -
                          distinct from RemoveOnly, which deletes our rules

    Behaviour notes:
      - Ordinary allow rules cannot override matching explicit block rules.
        Exceptions must be modelled at GENERATION time (-ExcludeBinaries on
        New-LolbinFirewallPolicy) or by changing the RemoteAddress scope.
      - RemoteAddress is the set of destinations TO BLOCK. The default is the
        'Internet' keyword: Windows Network Isolation classifies destinations
        (intranet = AD sites/subnets + GPO 'Private network ranges for apps'
        + local subnet; everything else is Internet). CLASSIFICATION MUST BE
        VALIDATED in your environment, and intranet destinations are only
        preserved insofar as that classification is correct.
      - A rule on an executable does not contain service/broker-mediated
        transfers (e.g. bitsadmin.exe rules do not block BITS service
        transfers), renamed/copied binaries, or unlisted child processes.
      - If the local store is targeted while 'Apply local firewall rules' is
        disabled (AllowLocalFirewallRules = False on any active profile),
        locally created rules are silently ignored - this script warns.
      - GPO sessions load and save the ENTIRE GPO: run during a change window;
        concurrent edits by other administrators are overwritten on save. If
        any operation fails during a GPO session, Save-NetGPO is skipped and
        nothing is persisted. If Save-NetGPO itself throws, the outcome is
        UNCERTAIN and must be verified manually.
      - Stale owned rules are removed only AFTER desired rules reconcile
        successfully; if any operation fails, stale removal is deferred to
        the next run.

    Exit codes: 0 = success, 1 = partial failure, 2 = fatal.

    References:
      - New-NetFirewallRule: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
      - Firewall + GPO command line: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line
      - Network isolation: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/isolating-apps-on-your-network
      - Set-NetFirewallRule: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule
      - Profile local-rule merge: https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Local','GPO')]
    [string]$Target = 'Local',

    # GPO target as 'domain.fqdn\GPO Name' (required when -Target GPO)
    [string]$GpoTarget,

    # Batched GPO session (recommended). $false writes each change directly.
    [bool]$UseGpoSession = $true,

    # Optional deploy-time override of the destination scope for every rule
    [string[]]$RemoteAddressOverride,

    # Create rules in Disabled state (staged rollout; enable via Set-NetFirewallRule -Group <policy> -Enabled True)
    [switch]$DisableRules,

    # Remove only this policy's rules; no reconcile
    [switch]$RemoveOnly,

    # Restore the owned-rule configuration captured in a backup JSON
    [string]$RestoreFromBackup,

    # Where to write the pre-change backup of owned rules (must differ from RestoreFromBackup)
    [string]$BackupPath,

    # CSV change report
    [string]$ReportPath,

    # Optional transcript log
    [string]$TranscriptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Embedded manifest (data only - parsed, never evaluated)
# ---------------------------------------------------------------------------
$ManifestB64 = '__MANIFEST_B64__'
$Manifest = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ManifestB64)) | ConvertFrom-Json
$PolicyPrefix = '{0}-' -f $Manifest.policyName
$Failures = [System.Collections.Generic.List[string]]::new()
$Changes = [System.Collections.Generic.List[object]]::new()
$Fatal = $false

function Write-Info  { param([string]$m) Write-Host "[INFO ] $m" }
function Write-Warn2 { param([string]$m) Write-Warning $m }
function Add-Change  { param([string]$op,[string]$name,[string]$status,[string]$err='') $script:Changes.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('s'); Operation=$op; RuleName=$name; Status=$status; Error=$err }) }
function Add-Fail    { param([string]$m) $script:Failures.Add($m); Write-Warning $m }

if ($TranscriptPath) {
    try { Start-Transcript -Path $TranscriptPath -Append | Out-Null } catch { Write-Warn2 "Transcript could not be started: $_" }
}

try {
    # -----------------------------------------------------------------------
    # Preflight
    # -----------------------------------------------------------------------
    if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw 'NetSecurity module not available on this system.'
    }
    $IsWin = $false
    if (Test-Path variable:IsWindows) { $IsWin = [bool]$IsWindows }
    elseif (($PSVersionTable.PSEdition -eq 'Desktop') -and ($env:OS -eq 'Windows_NT')) { $IsWin = $true }
    if ($Target -eq 'Local' -and $IsWin -and -not $RemoveOnly) {
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                     ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $elevated) { throw 'Local deployment requires an elevated PowerShell session.' }
    }
    if ($Target -eq 'GPO') {
        if (-not $GpoTarget -or $GpoTarget -notmatch '\\') {
            throw "-GpoTarget is required for GPO deployment and must look like 'domain.fqdn\\GPO Name'."
        }
    }
    if ($Target -eq 'Local' -and $IsWin -and -not $RemoveOnly) {
        try {
            $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
            $ignored = @($profiles | Where-Object { $_.AllowLocalFirewallRules -eq $false })
            if ($ignored.Count -gt 0) {
                Write-Warn2 ("Profiles with local rule merge disabled: {0}. Locally created rules are IGNORED on those profiles. " -f ($ignored.Name -join ', ') +
                             "Deploy via -Target GPO instead, or enable 'Apply local firewall rules'.")
            }
        } catch { Add-Fail "Could not inspect firewall profiles (non-fatal): $_" }
    }

    # -----------------------------------------------------------------------
    # Store resolution
    # -----------------------------------------------------------------------
    $GpoSession = $null
    $Store = @{}
    if ($Target -eq 'GPO' -and $UseGpoSession) {
        try { $GpoSession = Open-NetGPO -PolicyStore $GpoTarget } catch { throw "Open-NetGPO failed for '$GpoTarget': $_" }
        $Store = @{ GPOSession = $GpoSession }
        Write-Info "GPO session opened for '$GpoTarget'."
    }
    elseif ($Target -eq 'GPO') {
        $Store = @{ PolicyStore = $GpoTarget }
    }
    else {
        $Store = @{ PolicyStore = 'PersistentStore' }
    }

    # -----------------------------------------------------------------------
    # Desired state FIRST (so the pre-change backup can never clobber the
    # restore input, and restore input is validated before any mutation).
    # -----------------------------------------------------------------------
    if ($RestoreFromBackup) {
        if (-not (Test-Path $RestoreFromBackup)) { throw "Backup file not found: '$RestoreFromBackup'." }
        $backupDoc = Get-Content -LiteralPath $RestoreFromBackup -Raw | ConvertFrom-Json
        if (-not $backupDoc.schemaVersion -or $backupDoc.schemaVersion -ne 2) {
            throw "Unsupported backup schema (expected schemaVersion 2): '$RestoreFromBackup'."
        }
        $desired = @()
        foreach ($rec in @($backupDoc.rules)) {
            if ($rec.name -notlike "$($PolicyPrefix)*") { throw "Backup contains non-owned rule '$($rec.name)'; refusing to restore outside our namespace." }
            if (-not $rec.program -or -not $rec.remoteAddress) { throw "Backup record '$($rec.name)' is missing program/remoteAddress; refusing." }
            $desired += [pscustomobject]@{
                name = $rec.name; displayName = $rec.displayName; description = $rec.description
                program = $rec.program; remoteAddress = @($rec.remoteAddress)
                enabled = if ($null -ne $rec.enabled) { "$($rec.enabled)" } else { 'True' }
                profile = if ($rec.profile) { "$($rec.profile)" } else { 'Any' }
                direction = if ($rec.direction) { "$($rec.direction)" } else { 'Outbound' }
                action = if ($rec.action) { "$($rec.action)" } else { 'Block' }
                protocol = if ($rec.protocol) { "$($rec.protocol)" } else { 'Any' }
            }
        }
        Write-Info "Desired state: RESTORE from '$RestoreFromBackup' ($($desired.Count) rules, saved configuration)."
    }
    elseif ($RemoveOnly) {
        $desired = @()
        Write-Info 'Desired state: EMPTY (RemoveOnly).'
    }
    else {
        $enabledDefault = if ($DisableRules) { 'False' } else { 'True' }
        $scopeDefault = if ($RemoteAddressOverride) { @($RemoteAddressOverride) } else { @($Manifest.remoteAddress) }
        $desired = @(foreach ($r in @($Manifest.rules)) {
            [pscustomobject]@{
                name = $r.name; displayName = $r.displayName; description = $r.description
                program = $r.program; remoteAddress = $scopeDefault
                enabled = $enabledDefault; profile = 'Any'; direction = 'Outbound'; action = 'Block'; protocol = 'Any'
            }
        })
        Write-Info "Desired state: embedded manifest ($($desired.Count) rules)."
    }

    # -----------------------------------------------------------------------
    # Backup owned rules before mutation. A FAILED BACKUP IS FATAL.
    # -----------------------------------------------------------------------
    if (-not $BackupPath) {
        $BackupPath = Join-Path (Get-Location) ("{0}-backup-{1:yyyyMMdd-HHmmss}.json" -f $Manifest.policyName, (Get-Date))
    }
    if ($RestoreFromBackup) {
        $bp = [System.IO.Path]::GetFullPath($BackupPath)
        $rp = [System.IO.Path]::GetFullPath($RestoreFromBackup)
        if ($bp -eq $rp) { throw 'BackupPath must differ from RestoreFromBackup (refusing to overwrite recovery data).' }
    }
    function Get-OwnedRulesRaw {
        Get-NetFirewallRule @Store -ErrorAction Stop | Where-Object { $_.Name -like "$($script:PolicyPrefix)*" }
    }
    $ownedAll = @(Get-OwnedRulesRaw)
    # Ownership marker: our prefix PLUS our group or our generator signature.
    # Prefixed rules that lack the marker are foreign - warned, never touched.
    $ours = @($ownedAll | Where-Object { ("$($_.Group)" -eq $Manifest.policyName) -or ("$($_.Description)" -match 'New-LolbinFirewallPolicy') })
    $foreign = @($ownedAll | Where-Object { ("$($_.Group)" -ne $Manifest.policyName) -and ("$($_.Description)" -notmatch 'New-LolbinFirewallPolicy') })
    if ($foreign.Count -gt 0) {
        Write-Warn2 ("{0} prefixed rule(s) lack our ownership marker and will NOT be touched: {1}" -f $foreign.Count, (($foreign | ForEach-Object { $_.Name }) -join ', '))
    }
    Write-Info "Owned rules currently in store: $($ours.Count) ours, $($foreign.Count) foreign-prefixed (untouched)."

    if ($ours.Count -gt 0) {
        try {
            $backupRules = foreach ($r in $ours) {
                $af = Get-NetFirewallApplicationFilter @Store -AssociatedNetFirewallRule $r -ErrorAction Stop
                $adf = Get-NetFirewallAddressFilter @Store -AssociatedNetFirewallRule $r -ErrorAction Stop
                $pf = Get-NetFirewallPortFilter @Store -AssociatedNetFirewallRule $r -ErrorAction Stop
                [pscustomobject]@{
                    name = $r.Name; displayName = $r.DisplayName; description = $r.Description; group = $r.Group
                    program = $af.Program; remoteAddress = @($adf.RemoteAddress)
                    enabled = [string]$r.Enabled; profile = [string]$r.Profile; direction = [string]$r.Direction; action = [string]$r.Action
                    protocol = [string]$pf.Protocol
                }
            }
            $backupDoc = [pscustomobject]@{
                schemaVersion = 2
                policyName    = $Manifest.policyName
                capturedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                rules         = @($backupRules)
            }
            $backupDoc | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupPath -Encoding UTF8
            Write-Info "Backup of $($backupRules.Count) owned rules written to '$BackupPath'."
        }
        catch { throw "Pre-change backup FAILED - aborting without mutation: $_" }
    }

    # -----------------------------------------------------------------------
    # Reconciliation phase 1: create/update desired rules.
    # -----------------------------------------------------------------------
    $ownedMap = @{}
    foreach ($o in $ours) { $ownedMap[$o.Name] = $o }
    foreach ($d in $desired) {
        if ($PSCmdlet.ShouldProcess($d.name, "Ensure outbound block rule for $($d.program)")) {
            if ($ownedMap.ContainsKey($d.name)) {
                $existing = $ownedMap[$d.name]
                $af = $null; $adf = $null; $pf = $null
                try { $af = Get-NetFirewallApplicationFilter @Store -AssociatedNetFirewallRule $existing -ErrorAction Stop } catch { }
                try { $adf = Get-NetFirewallAddressFilter @Store -AssociatedNetFirewallRule $existing -ErrorAction Stop } catch { }
                try { $pf = Get-NetFirewallPortFilter @Store -AssociatedNetFirewallRule $existing -ErrorAction Stop } catch { }
                $drift = @()
                # Unreadable filters count as drift (cannot verify sync).
                if (-not $af -or ("$($af.Program)" -ne "$($d.program)")) { $drift += 'Program' }
                if (-not $adf -or (@($adf.RemoteAddress) -join ';') -ne ($d.remoteAddress -join ';')) { $drift += 'RemoteAddress' }
                if (-not $pf -or ("$($pf.Protocol)" -ne "$($d.protocol)")) { $drift += 'Protocol' }
                if ("$($existing.Action)" -ne "$($d.action)") { $drift += 'Action' }
                if ("$($existing.Direction)" -ne "$($d.direction)") { $drift += 'Direction' }
                if ("$($existing.Enabled)" -ne "$($d.enabled)") { $drift += 'Enabled' }
                if ("$($existing.Profile)" -ne "$($d.profile)") { $drift += 'Profile' }
                if ($drift.Count -eq 0) {
                    Add-Change -op 'Verify' -name $d.name -status 'InSync'
                    continue
                }
                try {
                    # NOTE: -Name selects the rule; -NewDisplayName/-Program/-RemoteAddress
                    # etc. are setters. -Group/-DisplayName would be SELECTORS here.
                    Set-NetFirewallRule @Store -Name $d.name -Action $d.action -Direction $d.direction `
                        -Enabled $d.enabled -Profile $d.profile -Protocol $d.protocol `
                        -NewDisplayName $d.displayName -Description $d.description `
                        -Program $d.program -RemoteAddress $d.remoteAddress -ErrorAction Stop
                    Add-Change -op 'Update' -name $d.name -status ("Updated (" + ($drift -join ',') + ')')
                } catch { Add-Change -op 'Update' -name $d.name -status 'Failed' -err "$_"; Add-Fail "Update '$($d.name)' failed: $_" }
            }
            else {
                try {
                    New-NetFirewallRule @Store -Name $d.name -DisplayName $d.displayName -Description $d.description `
                        -Group $Manifest.policyName -Enabled $d.enabled -Profile $d.profile -Direction $d.direction `
                        -Action $d.action -Program $d.program -RemoteAddress $d.remoteAddress -Protocol $d.protocol -ErrorAction Stop | Out-Null
                    Add-Change -op 'Create' -name $d.name -status 'Created'
                } catch { Add-Change -op 'Create' -name $d.name -status 'Failed' -err "$_"; Add-Fail "Create '$($d.name)' failed: $_" }
            }
        }
    }

    # -----------------------------------------------------------------------
    # Reconciliation phase 2: remove stale owned rules - ONLY after a fully
    # successful phase 1 (a failed replacement must not remove the previous
    # protection; stale removal is retried on the next run).
    # -----------------------------------------------------------------------
    $desiredNames = @{}
    foreach ($d in $desired) { $desiredNames[$d.name] = $true }
    if ($Failures.Count -gt 0) {
        if (@($ours | Where-Object { -not $desiredNames.ContainsKey($_.Name) }).Count -gt 0) {
            Add-Fail 'Reconciliation had failures - stale owned rules were NOT removed (deferred to next run).'
        }
    }
    else {
        foreach ($o in $ours) {
            if (-not $desiredNames.ContainsKey($o.Name)) {
                if ($PSCmdlet.ShouldProcess($o.Name, 'Remove stale owned rule')) {
                    try {
                        Remove-NetFirewallRule @Store -Name $o.Name -ErrorAction Stop
                        Add-Change -op 'Remove' -name $o.Name -status 'Removed'
                    } catch { Add-Change -op 'Remove' -name $o.Name -status 'Failed' -err "$_"; Add-Fail "Remove '$($o.Name)' failed: $_" }
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # GPO save. If staging had failures, Save is SKIPPED (nothing persisted).
    # If Save itself throws, the outcome is UNCERTAIN - verify manually.
    # -----------------------------------------------------------------------
    if ($GpoSession) {
        if ($Failures.Count -eq 0) {
            if (@($Changes).Count -eq 0) {
                Write-Info 'No changes were made - Save-NetGPO skipped (nothing to save).'
            }
            else {
                try { Save-NetGPO -GPOSession $GpoSession; Write-Info "GPO '$GpoTarget' saved." }
                catch { Add-Fail "Save-NetGPO FAILED - the persisted state of the GPO is UNCERTAIN; verify manually: $_" }
            }
        }
        else {
            Add-Fail 'GPO session had failures - Save-NetGPO skipped; no changes were persisted to the GPO.'
        }
    }
}
catch {
    $Fatal = $true
    Add-Fail "FATAL: $_"
}
finally {
    if ($TranscriptPath) { try { Stop-Transcript | Out-Null } catch {} }
}

# ---------------------------------------------------------------------------
# Report + summary + exit code (0 success / 1 partial / 2 fatal)
# ---------------------------------------------------------------------------
if ($ReportPath) {
    try {
        $Changes | Export-Csv -Path $ReportPath -NoTypeInformation -Append:$false
        Write-Info "Change report written to '$ReportPath'."
    } catch { Add-Fail "Report write failed: $_" }
}

Write-Host ''
Write-Info ("Summary: created={0} updated={1} removed={2} in-sync={3} failed={4}" -f `
    @($Changes | Where-Object { $_.Operation -eq 'Create' -and $_.Status -eq 'Created' }).Count, `
    @($Changes | Where-Object { $_.Operation -eq 'Update' -and $_.Status -like 'Updated*' }).Count, `
    @($Changes | Where-Object { $_.Operation -eq 'Remove' -and $_.Status -eq 'Removed' }).Count, `
    @($Changes | Where-Object { $_.Status -eq 'InSync' }).Count, `
    @($Changes | Where-Object { $_.Status -eq 'Failed' }).Count)
if ($Manifest.exclusions.Count -gt 0) {
    Write-Host ('Excluded binaries (not blocked): ' + (($Manifest.exclusions | ForEach-Object { $_.name }) -join ', '))
}

if ($Fatal) { exit 2 }
if ($Failures.Count -gt 0) { exit 1 }
exit 0
'@

$scriptText = $template.Replace('__MANIFEST_B64__', $manifestB64)

# ---------------------------------------------------------------------------
# Validate that the generated script parses before writing anything out
# ---------------------------------------------------------------------------
$tokens = $null; $parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count -gt 0) {
    throw ("Generated script failed to parse: " + (($parseErrors | ForEach-Object { "{0} ({1})" -f $_.Message, $_.Extent.StartLineNumber }) -join '; '))
}

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Human-readable copy of the manifest for review/audit (written after the
# directory exists)
$manifestJson | Set-Content -Path ("$OutputPath.manifest.json") -Encoding UTF8
$scriptText | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ("Generated '{0}'" -f $OutputPath)
Write-Host ("  Policy namespace  : {0}" -f $PolicyName)
Write-Host ("  Distinct binaries : {0}" -f $distinctBinaries.Count)
Write-Host ("  Block rules        : {0}  (blocking {1})" -f $rules.Count, ($RemoteAddress -join ', '))
Write-Host ("  Excluded binaries : {0}" -f ($(if ($ExcludeBinaries) { $ExcludeBinaries -join ', ' } else { '(none)' })))
Write-Host ''
Write-Host 'Next steps:'
Write-Host ("  Local :  .\{0} -Target Local" -f (Split-Path -Leaf $OutputPath))
Write-Host ("  GPO   :  .\{0} -Target GPO -GpoTarget 'domain.fqdn\GPO Name'" -f (Split-Path -Leaf $OutputPath))
Write-Host ("  Remove:  .\{0} -RemoveOnly   (or -RestoreFromBackup <backup.json>)" -f (Split-Path -Leaf $OutputPath))

if ($PassThru) { $manifest }
