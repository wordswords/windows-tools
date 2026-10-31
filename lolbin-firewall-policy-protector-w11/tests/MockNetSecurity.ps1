# Mock NetSecurity cmdlets for testing Deploy-LolbinFirewallPolicy.ps1 on
# non-Windows hosts. Mirrors the REAL API shape:
#   - Program lives on the application filter (NOT on the rule object)
#   - RemoteAddress on the address filter, Protocol on the port filter
#   - Open-NetGPO copies committed GPO content into the session; Save-NetGPO
#     replaces the committed content with the session content (whole-GPO save)
# State is persisted to disk on every mutation so `exit` never loses data.
#   $env:MOCK_STATE   - path of the JSON state file
#   $env:MOCK_FAIL_NEW - rule Name for which New-NetFirewallRule throws
# Requires PowerShell 7+ (ConvertFrom-Json -AsHashtable) - test infrastructure only.
$global:MockStatePath = if ($env:MOCK_STATE) { $env:MOCK_STATE } else { Join-Path $env:TEMP 'mock-firewall-state.json' }

function Get-MockState {
    if (Test-Path $global:MockStatePath) {
        $s = Get-Content -LiteralPath $global:MockStatePath -Raw | ConvertFrom-Json -AsHashtable
        if (-not $s.ContainsKey('stores')) { $s['stores'] = @{} }
        return $s
    }
    return @{ stores = @{} }
}

function Set-MockState {
    param($State)
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $global:MockStatePath -Encoding UTF8
}

function Get-MockStoreKey {
    param($PolicyStore, $GPOSession)
    if ($GPOSession) { return "staging::$GPOSession" }
    if ($PolicyStore) { return "main::$PolicyStore" }
    return 'main::PersistentStore'
}

function Get-MockRulesArray {
    param($State, $Key)
    if (-not $State['stores'].ContainsKey($Key)) { $State['stores'][$Key] = @() }
    return $State['stores'][$Key]
}

function New-NetFirewallRule {
    [CmdletBinding()]
    param([string]$Name, [string]$DisplayName, [string]$Description, [string]$Group,
          [string]$Enabled, [string]$Profile, [string]$Direction, [string]$Action,
          [string]$Program, $RemoteAddress, [string]$Protocol,
          [string]$PolicyStore, [string]$GPOSession)
    if ($env:MOCK_FAIL_NEW -eq $Name) { throw "MOCK FAILURE for rule $Name" }
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $record = @{
        Name = $Name; DisplayName = $DisplayName; Description = $Description; Group = $Group
        Enabled = "$Enabled"; Profile = "$Profile"; Direction = "$Direction"; Action = "$Action"
        _program = $Program; _remoteAddress = @($RemoteAddress); _protocol = "$Protocol"
    }
    $state['stores'][$key] = @(Get-MockRulesArray -State $state -Key $key | Where-Object { $_['Name'] -ne $Name }) + @($record)
    Set-MockState -State $state
}

function Get-NetFirewallRule {
    [CmdletBinding()]
    param([string]$Name, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $all = Get-MockRulesArray -State $state -Key $key
    if ($Name) { return @($all | Where-Object { $_['Name'] -eq $Name }) }
    return @($all)
}

function Remove-NetFirewallRule {
    [CmdletBinding()]
    param([string]$Name, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    if ($state['stores'].ContainsKey($key)) {
        $state['stores'][$key] = @($state['stores'][$key] | Where-Object { $_['Name'] -ne $Name })
        Set-MockState -State $state
    }
}

function Set-NetFirewallRule {
    [CmdletBinding()]
    param([string]$Name, [string]$NewDisplayName, [string]$Description, [string]$Group,
          [string]$Enabled, [string]$Direction, [string]$Action, [string]$Profile,
          [string]$Program, $RemoteAddress, [string]$Protocol,
          [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $rules = Get-MockRulesArray -State $state -Key $key
    $r = @($rules | Where-Object { $_['Name'] -eq $Name })
    if ($r.Count -eq 0) { throw "Set-NetFirewallRule: rule '$Name' not found" }
    $r = $r[0]
    if ($PSBoundParameters.ContainsKey('NewDisplayName'))  { $r['DisplayName'] = $NewDisplayName }
    if ($PSBoundParameters.ContainsKey('Description'))     { $r['Description'] = $Description }
    if ($PSBoundParameters.ContainsKey('Group'))           { $r['Group'] = $Group }
    if ($PSBoundParameters.ContainsKey('Enabled'))          { $r['Enabled'] = "$Enabled" }
    if ($PSBoundParameters.ContainsKey('Direction'))       { $r['Direction'] = "$Direction" }
    if ($PSBoundParameters.ContainsKey('Action'))          { $r['Action'] = "$Action" }
    if ($PSBoundParameters.ContainsKey('Profile'))          { $r['Profile'] = "$Profile" }
    if ($PSBoundParameters.ContainsKey('Program'))         { $r['_program'] = $Program }
    if ($PSBoundParameters.ContainsKey('RemoteAddress'))   { $r['_remoteAddress'] = @($RemoteAddress) }
    if ($PSBoundParameters.ContainsKey('Protocol'))        { $r['_protocol'] = "$Protocol" }
    Set-MockState -State $state
}

function Get-NetFirewallApplicationFilter {
    [CmdletBinding()]
    param($AssociatedNetFirewallRule, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $rules = Get-MockRulesArray -State $state -Key $key
    $rule = @($rules | Where-Object { $_['Name'] -eq $AssociatedNetFirewallRule.Name })
    if ($rule.Count -eq 0) { return $null }
    return @{ Program = $rule[0]['_program'] }
}

function Set-NetFirewallApplicationFilter {
    [CmdletBinding()]
    param($AssociatedNetFirewallRule, [string]$Program, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $rules = Get-MockRulesArray -State $state -Key $key
    $rule = @($rules | Where-Object { $_['Name'] -eq $AssociatedNetFirewallRule.Name })
    if ($rule.Count -eq 0) { throw "Set-NetFirewallApplicationFilter: rule not found" }
    $rule[0]['_program'] = $Program
    Set-MockState -State $state
}

function Get-NetFirewallAddressFilter {
    [CmdletBinding()]
    param($AssociatedNetFirewallRule, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $rules = Get-MockRulesArray -State $state -Key $key
    $rule = @($rules | Where-Object { $_['Name'] -eq $AssociatedNetFirewallRule.Name })
    if ($rule.Count -eq 0) { return $null }
    return @{ RemoteAddress = @($rule[0]['_remoteAddress']) }
}

function Set-NetFirewallAddressFilter {
    [CmdletBinding()]
    param($AssociatedNetFirewallRule, $RemoteAddress, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $rules = Get-MockRulesArray -State $state -Key $key
    $rule = @($rules | Where-Object { $_['Name'] -eq $AssociatedNetFirewallRule.Name })
    if ($rule.Count -eq 0) { throw "Set-NetFirewallAddressFilter: rule not found" }
    $rule[0]['_remoteAddress'] = @($RemoteAddress)
    Set-MockState -State $state
}

function Get-NetFirewallPortFilter {
    [CmdletBinding()]
    param($AssociatedNetFirewallRule, [string]$PolicyStore, [string]$GPOSession)
    $state = Get-MockState
    $key = Get-MockStoreKey -PolicyStore $PolicyStore -GPOSession $GPOSession
    $rules = Get-MockRulesArray -State $state -Key $key
    $rule = @($rules | Where-Object { $_['Name'] -eq $AssociatedNetFirewallRule.Name })
    if ($rule.Count -eq 0) { return $null }
    return @{ Protocol = $rule[0]['_protocol'] }
}

function Get-NetFirewallProfile {
    [CmdletBinding()]
    param([string]$PolicyStore)
    return @(
        [pscustomobject]@{ Name='Domain';  AllowLocalFirewallRules=$true }
        [pscustomobject]@{ Name='Private'; AllowLocalFirewallRules=$true }
        [pscustomobject]@{ Name='Public';  AllowLocalFirewallRules=$true }
    )
}

function Open-NetGPO {
    [CmdletBinding()]
    param([string]$PolicyStore)
    # The session starts as a COPY of the committed GPO content.
    $state = Get-MockState
    $mainKey = "main::$PolicyStore"
    $sessionKey = "session-for::$PolicyStore"
    $committed = if ($state['stores'].ContainsKey($mainKey)) { $state['stores'][$mainKey] } else { @() }
    $copy = @()
    foreach ($r in $committed) { $copy += $r.Clone() }
    # The staging store the rule cmdlets address via -GPOSession <token>
    $state['stores']["staging::$sessionKey"] = $copy
    Set-MockState -State $state
    return "session-for::$PolicyStore"
}

function Save-NetGPO {
    [CmdletBinding()]
    param([string]$GPOSession)
    # Whole-GPO save: the committed content is REPLACED by the session content.
    $state = Get-MockState
    $gpoName = $GPOSession -replace '^session-for::', ''
    $sessionKey = "staging::$GPOSession"
    if (-not $state['stores'].ContainsKey($sessionKey)) { return }
    $state['stores']["main::$gpoName"] = $state['stores'][$sessionKey]
    $state['stores'].Remove($sessionKey) | Out-Null
    Set-MockState -State $state
}
