# Test harness: exercises Deploy-LolbinFirewallPolicy.ps1 against mocked
# NetSecurity cmdlets (see MockNetSecurity.ps1). Each deploy invocation runs
# in a child pwsh process so exit codes are real.
param(
    [string]$GeneratorPath = (Join-Path $PSScriptRoot '..\New-LolbinFirewallPolicy.ps1'),
    [string]$WorkDir = (Join-Path $PSScriptRoot 'out')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$pwsh = 'pwsh-preview'
$deploy = Join-Path $WorkDir 'Deploy-LolbinFirewallPolicy.ps1'
$mock = Join-Path $PSScriptRoot 'MockNetSecurity.ps1'
$runDeploy = Join-Path $PSScriptRoot 'Run-Deploy.ps1'
$statePath = Join-Path $WorkDir 'mock-state.json'
$backupPath = Join-Path $WorkDir 'backup.json'
$reportPath = Join-Path $WorkDir 'report.csv'

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

$env:MOCK_STATE = $statePath

$script:Results = [System.Collections.Generic.List[object]]::new()
function Assert-True {
    param([bool]$Condition, [string]$Name, [string]$Detail = '')
    $script:Results.Add([pscustomobject]@{ Name = $Name; Pass = $Condition; Detail = $Detail })
    if (-not $Condition) { Write-Host "  FAIL: $Name $Detail" -ForegroundColor Red }
}

function Reset-State {
    if (Test-Path $statePath) { Remove-Item -Force $statePath }
    Remove-Item Env:\MOCK_FAIL_NEW -ErrorAction SilentlyContinue
}

function Get-State {
    if (-not (Test-Path $statePath)) { return $null }
    return (Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable)
}

function Get-Rules {
    param([string]$Key = 'main::PersistentStore')
    $state = Get-State
    if (-not $state -or -not $state['stores'].ContainsKey($Key)) { return @() }
    return @($state['stores'][$Key])
}

function New-RuleRecord {
    param([string]$Name, [string]$Program = 'C:\x.exe', [string]$Group = 'LOLBAS-Block-Outbound',
          [string]$Description = 'Managed by New-LolbinFirewallPolicy v1.1.0; do not edit manually.',
          [string]$Enabled = 'True', $RemoteAddress = @('Internet'), [string]$Protocol = 'Any')
    @{ Name = $Name; DisplayName = "d-$Name"; Description = $Description; Group = $Group
       Enabled = $Enabled; Profile = 'Any'; Direction = 'Outbound'; Action = 'Block'
       _program = $Program; _remoteAddress = @($RemoteAddress); _protocol = $Protocol }
}

function Set-StateRules {
    param([string]$Key, $Rules)
    $state = if (Test-Path $statePath) { Get-State } else { @{ stores = @{} } }
    $state['stores'][$Key] = @($Rules)
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
}

function Invoke-Deploy {
    param([string]$DeployPath = $deploy, [string[]]$Arguments = @())
    $argsFile = Join-Path $WorkDir ('args-' + [guid]::NewGuid().ToString('N') + '.json')
    $Arguments | ConvertTo-Json | Set-Content -LiteralPath $argsFile -Encoding UTF8
    & $pwsh -NoProfile -File $runDeploy -MockPath $mock -DeployPath $DeployPath -ArgsFile $argsFile 2>&1 |
        ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $WorkDir 'last-deploy-log.txt')
    return $LASTEXITCODE
}

function Invoke-Generator {
    param([string[]]$Arguments = @())
    $argsFile = Join-Path $WorkDir ('gargs-' + [guid]::NewGuid().ToString('N') + '.json')
    $Arguments | ConvertTo-Json | Set-Content -LiteralPath $argsFile -Encoding UTF8
    & $pwsh -NoProfile -File $runDeploy -MockPath $mock -DeployPath $GeneratorPath -ArgsFile $argsFile 2>&1 |
        ForEach-Object { "$_" } | Set-Content -LiteralPath (Join-Path $WorkDir 'last-generator-log.txt')
    return $LASTEXITCODE
}

$manifestDoc = $null
function Get-ManifestRuleCount {
    if (-not $manifestDoc) { $script:manifestDoc = Get-Content -LiteralPath "$deploy.manifest.json" -Raw | ConvertFrom-Json }
    return @($manifestDoc.rules).Count
}

# ---------------------------------------------------------------------------
Write-Host '== T1: generator produces a parseable deployment script' -ForegroundColor Cyan
$code = Invoke-Generator -Arguments @('-OutputPath', $deploy)
Assert-True ($code -eq 0) 'T1 generator exit code 0' "code=$code"
Assert-True (Test-Path $deploy) 'T1 deployment script written'
$expectedRules = Get-ManifestRuleCount
$manifestBinaries = @((Get-Content -LiteralPath "$deploy.manifest.json" -Raw | ConvertFrom-Json).rules | ForEach-Object { $_.binary } | Sort-Object -Unique)
Assert-True ($manifestBinaries.Count -ge 30) 'T1 manifest covers 30+ distinct binaries' "count=$($manifestBinaries.Count)"
Assert-True ($expectedRules -gt $manifestBinaries.Count) 'T1 rule count exceeds binary count (path variants)'

Write-Host '== T2: first local apply creates all rules' -ForegroundColor Cyan
Reset-State
$code = Invoke-Deploy -Arguments @('-Target', 'Local', '-ReportPath', $reportPath)
Assert-True ($code -eq 0) 'T2 apply exit code 0' "code=$code"
Assert-True (@(Get-Rules).Count -eq $expectedRules) 'T2 all rules created' "expected=$expectedRules actual=$(@(Get-Rules).Count)"
Assert-True (Test-Path $reportPath) 'T2 CSV report written'

Write-Host '== T3: second apply is idempotent (in-sync, no duplicates)' -ForegroundColor Cyan
$before = (Get-Rules | Sort-Object { $_['Name'] } | ConvertTo-Json -Depth 5)
$code = Invoke-Deploy -Arguments @('-Target', 'Local', '-BackupPath', $backupPath)
Assert-True ($code -eq 0) 'T3 second apply exit code 0' "code=$code"
$after = (Get-Rules | Sort-Object { $_['Name'] } | ConvertTo-Json -Depth 5)
Assert-True ($before -eq $after) 'T3 rule set unchanged after re-apply'
Assert-True (@(Get-Rules).Count -eq $expectedRules) 'T3 no duplicate rules'
Assert-True (Test-Path $backupPath) 'T3 pre-change backup written'

Write-Host '== T4: drifted rule is repaired (program via application filter)' -ForegroundColor Cyan
$state = Get-State
$driftName = 'LOLBAS-Block-Outbound-certutil.exe-Sys32'
$rule = @($state['stores']['main::PersistentStore'] | Where-Object { $_['Name'] -eq $driftName })[0]
$rule['_program'] = 'C:\evil\certutil.exe'
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
$code = Invoke-Deploy -Arguments @('-Target', 'Local')
Assert-True ($code -eq 0) 'T4 drift repair exit code 0' "code=$code"
$fixed = @(Get-Rules | Where-Object { $_['Name'] -eq $driftName })
Assert-True ($fixed[0]['_program'] -eq '%SystemRoot%\System32\certutil.exe') 'T4 program restored from manifest' "actual=$($fixed[0]['_program'])"

Write-Host '== T5: excluded binary removes its managed rule (admin exception)' -ForegroundColor Cyan
$deployNoSsh = Join-Path $WorkDir 'Deploy-NoSsh.ps1'
$code = Invoke-Generator -Arguments @('-OutputPath', $deployNoSsh, '-ExcludeBinaries', 'ssh.exe')
Assert-True ($code -eq 0) 'T5 regeneration exit code 0' "code=$code"
$code = Invoke-Deploy -DeployPath $deployNoSsh -Arguments @('-Target', 'Local')
Assert-True ($code -eq 0) 'T5 no-ssh apply exit code 0' "code=$code"
$sshRules = @(Get-Rules | Where-Object { $_['Name'] -like '*ssh.exe*' })
Assert-True ($sshRules.Count -eq 0) 'T5 ssh.exe rules removed after exclusion'
Assert-True (@(Get-Rules).Count -eq ($expectedRules - 1)) 'T5 other rules intact' "expected=$(($expectedRules - 1)) actual=$(@(Get-Rules).Count)"

Write-Host '== T6: RemoveOnly removes only owned rules' -ForegroundColor Cyan
$code = Invoke-Deploy -Arguments @('-RemoveOnly')
Assert-True ($code -eq 0) 'T6 RemoveOnly exit code 0' "code=$code"
Assert-True (@(Get-Rules).Count -eq 0) 'T6 all owned rules removed'

Write-Host '== T7: RestoreFromBackup restores previous owned configuration' -ForegroundColor Cyan
$code = Invoke-Deploy -Arguments @('-RestoreFromBackup', $backupPath)
Assert-True ($code -eq 0) 'T7 restore exit code 0' "code=$code"
Assert-True (@(Get-Rules).Count -eq $expectedRules) 'T7 all rules restored from backup' "expected=$expectedRules actual=$(@(Get-Rules).Count)"

Write-Host '== T8: GPO session deployment commits on success' -ForegroundColor Cyan
Reset-State
$code = Invoke-Deploy -Arguments @('-Target', 'GPO', '-GpoTarget', 'test.local\FW-LOLBAS')
Assert-True ($code -eq 0) 'T8 GPO apply exit code 0' "code=$code"
$gpoRules = @(Get-Rules -Key 'main::test.local\FW-LOLBAS')
Assert-True ($gpoRules.Count -eq $expectedRules) 'T8 rules committed to GPO store' "expected=$expectedRules actual=$($gpoRules.Count)"

Write-Host '== T9: GPO session with a failure saves NOTHING' -ForegroundColor Cyan
Reset-State
$env:MOCK_FAIL_NEW = 'LOLBAS-Block-Outbound-mshta.exe-Sys32'
$code = Invoke-Deploy -Arguments @('-Target', 'GPO', '-GpoTarget', 'test.local\FW-LOLBAS')
Assert-True ($code -eq 1) 'T9 GPO apply exit code 1 (partial failure)' "code=$code"
$gpoRules = @(Get-Rules -Key 'main::test.local\FW-LOLBAS')
Assert-True ($gpoRules.Count -eq 0) 'T9 nothing persisted to GPO on failure' "actual=$($gpoRules.Count)"
Remove-Item Env:\MOCK_FAIL_NEW -ErrorAction SilentlyContinue

Write-Host '== T10: -WhatIf makes no changes (local)' -ForegroundColor Cyan
Reset-State
$code = Invoke-Deploy -Arguments @('-Target', 'Local', '-WhatIf')
Assert-True ($code -eq 0) 'T10 WhatIf exit code 0' "code=$code"
Assert-True (@(Get-Rules).Count -eq 0) 'T10 no rules created under WhatIf'

Write-Host '== T11: paths with spaces and apostrophes survive the round trip' -ForegroundColor Cyan
$deployCustom = Join-Path $WorkDir 'Deploy-Custom.ps1'
$oddPath = 'C:\Program Files\Joe''s Tools\tool.exe'
$code = Invoke-Generator -Arguments @('-OutputPath', $deployCustom, '-AdditionalBinaries', $oddPath)
Assert-True ($code -eq 0) 'T11 generator exit code 0' "code=$code"
Reset-State
$code = Invoke-Deploy -DeployPath $deployCustom -Arguments @('-Target', 'Local')
Assert-True ($code -eq 0) 'T11 custom apply exit code 0' "code=$code"
$odd = @(Get-Rules | Where-Object { $_['_program'] -eq $oddPath })
Assert-True ($odd.Count -eq 1) 'T11 odd path rule created with exact program path'

Write-Host '== T12: generator rejects invalid configuration' -ForegroundColor Cyan
$code = Invoke-Generator -Arguments @('-OutputPath', (Join-Path $WorkDir 'bad.ps1'), '-RemoteAddress', 'NotAKeyword!!')
Assert-True ($code -ne 0) 'T12 invalid RemoteAddress rejected' "code=$code"
$code = Invoke-Generator -Arguments @('-OutputPath', (Join-Path $WorkDir 'bad2.ps1'), '-AdditionalBinaries', 'relative\no-colon.exe')
Assert-True ($code -ne 0) 'T12 invalid path template rejected' "code=$code"
# Hashtable argument cannot travel through the flat args file - use a temp script
$gbad3 = Join-Path $WorkDir 'gbad3.ps1'
@"
param([string]`$GeneratorPath)
& `$GeneratorPath -OutputPath 'bad3.ps1' -BinaryPaths @{ 'notacatalog.exe' = 'C:\x.exe' }
exit `$LASTEXITCODE
"@ | Set-Content -LiteralPath $gbad3 -Encoding UTF8
& $pwsh -NoProfile -File $gbad3 -GeneratorPath $GeneratorPath | Out-Null
$code = $LASTEXITCODE
Assert-True ($code -ne 0) 'T12 unknown BinaryPaths key rejected' "code=$code"

Write-Host '== T13: restore preserves SAVED configuration (scope/enabled), not manifest defaults' -ForegroundColor Cyan
Reset-State
$code = Invoke-Deploy -Arguments @('-Target', 'Local')
Assert-True ($code -eq 0) 'T13 baseline apply exit code 0' "code=$code"
# Drift one rule: disable it and change its scope; then capture that state as a backup
$state = Get-State
$t13Name = 'LOLBAS-Block-Outbound-tar.exe-Sys32'
$rule = @($state['stores']['main::PersistentStore'] | Where-Object { $_['Name'] -eq $t13Name })[0]
$rule['Enabled'] = 'False'
$rule['_remoteAddress'] = @('203.0.113.0/24')
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
$driftBackup = Join-Path $WorkDir 't13-backup.json'
$code = Invoke-Deploy -Arguments @('-Target', 'Local', '-BackupPath', $driftBackup)
Assert-True ($code -eq 0) 'T13 drifted-state backup + repair exit code 0' "code=$code"
$code = Invoke-Deploy -Arguments @('-RemoveOnly')
Assert-True ($code -eq 0) 'T13 RemoveOnly exit code 0' "code=$code"
$code = Invoke-Deploy -Arguments @('-RestoreFromBackup', $driftBackup)
Assert-True ($code -eq 0) 'T13 restore exit code 0' "code=$code"
$restored = @(Get-Rules | Where-Object { $_['Name'] -eq $t13Name })
Assert-True ($restored.Count -eq 1) 'T13 rule restored'
Assert-True ($restored[0]['Enabled'] -eq 'False') 'T13 restored rule keeps SAVED enabled state' "actual=$($restored[0]['Enabled'])"
Assert-True (($restored[0]['_remoteAddress'] -join ';') -eq '203.0.113.0/24') 'T13 restored rule keeps SAVED remote scope'

Write-Host '== T14: failed replacement does NOT remove stale protection (deferred removal)' -ForegroundColor Cyan
Reset-State
$staleName = 'LOLBAS-Block-Outbound-oldtool.exe-Sys32'
Set-StateRules -Key 'main::PersistentStore' -Rules @(New-RuleRecord -Name $staleName)
$env:MOCK_FAIL_NEW = 'LOLBAS-Block-Outbound-mshta.exe-Sys32'
$code = Invoke-Deploy -Arguments @('-Target', 'Local')
Assert-True ($code -eq 1) 'T14 partial failure exit code 1' "code=$code"
Assert-True (@(Get-Rules | Where-Object { $_['Name'] -eq $staleName }).Count -eq 1) 'T14 stale rule retained after failure'
Remove-Item Env:\MOCK_FAIL_NEW -ErrorAction SilentlyContinue
$code = Invoke-Deploy -Arguments @('-Target', 'Local')
Assert-True ($code -eq 0) 'T14 clean rerun exit code 0' "code=$code"
Assert-True (@(Get-Rules | Where-Object { $_['Name'] -eq $staleName }).Count -eq 0) 'T14 stale rule removed on successful rerun'

Write-Host '== T15: prefixed rules without our ownership marker are never touched' -ForegroundColor Cyan
Reset-State
$foreignName = 'LOLBAS-Block-Outbound-foreign.exe-Sys32'
Set-StateRules -Key 'main::PersistentStore' -Rules @(New-RuleRecord -Name $foreignName -Group 'SomeOtherPolicy' -Description 'unrelated rule')
$code = Invoke-Deploy -Arguments @('-Target', 'Local')
Assert-True ($code -eq 0) 'T15 apply exit code 0' "code=$code"
$foreign = @(Get-Rules | Where-Object { $_['Name'] -eq $foreignName })
Assert-True ($foreign.Count -eq 1) 'T15 foreign prefixed rule untouched'
Assert-True (@(Get-Rules).Count -eq ($expectedRules + 1)) 'T15 desired rules created alongside foreign rule'

Write-Host '== T16: GPO session preserves unrelated GPO content, removes stale owned' -ForegroundColor Cyan
Reset-State
$gpoKey = 'main::test.local\FW-LOLBAS'
$unrelated = New-RuleRecord -Name 'SomeOther-Rule' -Group 'Other' -Description 'unrelated'
$staleGpo = New-RuleRecord -Name 'LOLBAS-Block-Outbound-oldgpo.exe-Sys32'
Set-StateRules -Key $gpoKey -Rules @($unrelated, $staleGpo)
$code = Invoke-Deploy -Arguments @('-Target', 'GPO', '-GpoTarget', 'test.local\FW-LOLBAS')
Assert-True ($code -eq 0) 'T16 GPO apply exit code 0' "code=$code"
$gpoRules = @(Get-Rules -Key $gpoKey)
Assert-True (@($gpoRules | Where-Object { $_['Name'] -eq 'SomeOther-Rule' }).Count -eq 1) 'T16 unrelated GPO content preserved'
Assert-True (@($gpoRules | Where-Object { $_['Name'] -eq 'LOLBAS-Block-Outbound-oldgpo.exe-Sys32' }).Count -eq 0) 'T16 stale owned GPO rule removed'
Assert-True (@($gpoRules | Where-Object { $_['Group'] -eq 'LOLBAS-Block-Outbound' }).Count -eq $expectedRules) 'T16 desired rules committed'

Write-Host '== T17: GPO -WhatIf saves nothing' -ForegroundColor Cyan
$before = (Get-Rules -Key $gpoKey | Sort-Object { $_['Name'] } | ConvertTo-Json -Depth 5)
$code = Invoke-Deploy -Arguments @('-Target', 'GPO', '-GpoTarget', 'test.local\FW-LOLBAS', '-WhatIf')
Assert-True ($code -eq 0) 'T17 GPO WhatIf exit code 0' "code=$code"
$after = (Get-Rules -Key $gpoKey | Sort-Object { $_['Name'] } | ConvertTo-Json -Depth 5)
Assert-True ($before -eq $after) 'T17 committed GPO content unchanged under WhatIf'

Write-Host '== T18: fatal errors exit with code 2' -ForegroundColor Cyan
$code = Invoke-Deploy -Arguments @('-Target', 'GPO')   # missing -GpoTarget
Assert-True ($code -eq 2) 'T18 fatal error exit code 2' "code=$code"
$code = Invoke-Deploy -Arguments @('-Target', 'Local', '-RestoreFromBackup', (Join-Path $WorkDir 'does-not-exist.json'))
Assert-True ($code -eq 2) 'T18 missing backup file exit code 2' "code=$code"

# ---------------------------------------------------------------------------
$failed = @($script:Results | Where-Object { -not $_.Pass })
$passed = @($script:Results | Where-Object { $_.Pass })
Write-Host ''
Write-Host ("RESULTS: {0} passed, {1} failed" -f $passed.Count, $failed.Count) -ForegroundColor $(if ($failed.Count) {'Red'} else {'Green'})
$script:Results | Format-Table -AutoSize
if ($failed.Count) { exit 1 }
exit 0
