# LOLBin Outbound Firewall Policy Generator

A PowerShell generator (`New-LolbinFirewallPolicy.ps1`) that emits a
production-oriented Windows Firewall deployment script blocking **outbound
internet traffic for 39 common Living-off-the-Land binaries (LOLBins)** —
`certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`, `curl`, `tar`,
`ssh`, `wmic`, `msiexec`, `msbuild`, and more (74 rules by default,
including SysWOW64 and OpenSSH path variants).

The generator is **side-effect free**: no elevation, no firewall changes, no
domain contact. It validates your configuration and writes a self-contained
deployment script plus a human-readable JSON manifest for review.

The output is a production-oriented **candidate** that has been exercised
against a mock of the NetSecurity API (see "Testing"). Mocked testing cannot
substantiate real enforcement on Windows — pilot it on representative hosts
before fleet-wide rollout.

## Files

| File | Purpose |
|---|---|
| `New-LolbinFirewallPolicy.ps1` | The generator (run this first) |
| `Deploy-LolbinFirewallPolicy.ps1` | Example generated deployment script |
| `Deploy-LolbinFirewallPolicy.ps1.manifest.json` | Example generated manifest (human-readable) |
| `tests/TestRunner.ps1` | Mock-based test harness (55 assertions, 18 scenarios) |

## Quick start

```powershell
# 1. Generate (no admin rights needed)
.\New-LolbinFirewallPolicy.ps1

# 2. Review the manifest
Get-Content .\Deploy-LolbinFirewallPolicy.ps1.manifest.json

# 3a. Deploy locally (elevated PowerShell required)
.\Deploy-LolbinFirewallPolicy.ps1 -Target Local

# 3b. Deploy into a domain GPO (recommended; batched session)
.\Deploy-LolbinFirewallPolicy.ps1 -Target GPO -GpoTarget 'corp.example.com\Firewall-LOLBAS-Block'

# Rollback options
.\Deploy-LolbinFirewallPolicy.ps1 -RemoveOnly                     # remove only this policy's rules
.\Deploy-LolbinFirewallPolicy.ps1 -RestoreFromBackup <backup.json> # restore previous owned config
```

## Generator parameters

| Parameter | Default | Notes |
|---|---|---|
| `-OutputPath` | `.\Deploy-LolbinFirewallPolicy.ps1` | Where to write the deployment script |
| `-PolicyName` | `LOLBAS-Block-Outbound` | Rule namespace/Group; must match `[A-Za-z0-9._-]+` |
| `-RemoteAddress` | `Internet` | Destination scope (see "Scope semantics" below) |
| `-BinaryPaths` | *(catalog defaults)* | Hashtable: `@{ 'certutil.exe' = 'D:\Tools\certutil.exe' }` overrides paths; env-var templates supported |
| `-AdditionalBinaries` | *(none)* | Extra full paths, e.g. `javaw.exe`, `AppInstaller.exe` |
| `-ExcludeBinaries` | *(none)* | Binaries to leave unblocked (admin exceptions) |
| `-NoWow64` | off | Skip 32-bit path variants |
| `-IncludePowerShell7` | off | Add `%ProgramFiles%\PowerShell\7\pwsh.exe` |
| `-PassThru` | off | Emit manifest objects to the pipeline |

## Deployment script parameters

| Parameter | Default | Notes |
|---|---|---|
| `-Target` | `Local` | `Local` (PersistentStore, elevation required) or `GPO` |
| `-GpoTarget` | — | `'domain.fqdn\GPO Name'` (required for `-Target GPO`) |
| `-UseGpoSession` | `$true` | Batched `Open-NetGPO`/`Save-NetGPO`; `$false` writes via `-PolicyStore` directly |
| `-RemoteAddressOverride` | — | Deploy-time destination scope override |
| `-DisableRules` | off | Create rules disabled for staged rollout, then enable with `Set-NetFirewallRule -Group LOLBAS-Block-Outbound -Enabled True` |
| `-RemoveOnly` | off | Remove only this policy's rules |
| `-RestoreFromBackup` | — | Recreate the owned-rule configuration from a backup JSON |
| `-BackupPath` | timestamped file in CWD | Pre-change backup of owned rules |
| `-ReportPath` | — | CSV change report |
| `-TranscriptPath` | — | Optional transcript |
| `-WhatIf` | — | Genuine `-WhatIf` (no changes) |

## Scope semantics: what "Internet" means

`RemoteAddress` is the set of destinations the rules **block** — it is not
an exception list. Supplying intranet CIDRs there *blocks* those ranges; it
does not subtract them from the block. The default block rules use
`RemoteAddress = 'Internet'`. Windows Network Isolation classifies each
destination: the intranet address space (Active Directory sites and subnets,
the GPO "Private network ranges for apps" setting, and the local subnet)
counts as private; everything else is Internet ([Microsoft network isolation
guidance](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/isolating-apps-on-your-network)).
Consequences:

- **Do not assume domain management traffic is automatically preserved.** If
  your intranet ranges are not classified correctly on the target hosts, the
  block will be too broad or too narrow — validate the Network Isolation
  configuration (`Computer Configuration > Policies > Administrative
  Templates > Network > Network Isolation > Private network ranges for
  apps`, plus AD sites/subnets) during the pilot.
- For a scope you control explicitly, regenerate with your own CIDR list of
  destinations to block: `-RemoteAddress '203.0.113.0/24','2001:db8::/32'`
  (or `Any` for a total outbound block — aggressive; test first).

## Exceptions for admin-required environments

With Windows Firewall, **ordinary allow rules cannot override a matching
explicit block rule**, so an allow rule cannot carve exceptions out of these
blocks. Supported patterns:

1. **Exclude the binary** (recommended): regenerate with
   `-ExcludeBinaries 'ssh.exe','mstsc.exe'`. Exclusions are recorded in the
   manifest for audit. Removing an exclusion and re-deploying automatically
   re-creates the block.
2. **Scope the destination**: regenerate with `-RemoteAddress` set to the
   specific destinations you want blocked, so management destinations are
   never matched by the rules.
3. **Per-role GPOs**: deploy differently-scoped policies to different OUs
   (e.g. a server-management OU that excludes `wmic`/`mstsc`, a workstation
   OU that blocks everything).
4. **Staged rollout**: `-DisableRules` creates the rules disabled; enable
   per pilot group.

## GPO deployment notes

- The recommended path is the batched GPO session (`Open-NetGPO` →
  cmdlets with `-GPOSession` → `Save-NetGPO`), which is Microsoft's
  documented workflow for scripting firewall rules into a domain GPO
  ([Windows Firewall command-line management](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line)).
- In batched GPO-session mode, a pre-save rule-operation failure prevents
  the script from calling `Save-NetGPO` at all (verified by test as "save
  skipped after pre-save failure"). A failure of the save itself has an
  **uncertain outcome** and is reported as such. Local deployment and direct
  `-PolicyStore` mode (with `-UseGpoSession:$false`) can leave partial
  changes.
- The session loads and saves the *entire* GPO: run during a change window,
  because concurrent edits by other administrators are overwritten on save.
- The deployment script never creates or links the GPO itself — create it in
  GPMC, then target it with `-GpoTarget`.

## Rollback fidelity and reconciliation guarantees

- **`-RestoreFromBackup` recreates the SAVED configuration**, not the
  manifest defaults: scope (RemoteAddress), enabled state, profile, and
  protocol of each backed-up rule are restored as they were. This lets you
  roll back to a state that included manual tweaks.
- **Stale-rule removal is deferred on failure**: rules from a previous
  deployment of this policy that no longer appear in the manifest are only
  removed after a run with zero failures. If any rule create/update fails,
  the stale rules are deliberately retained (existing protection stays in
  place) and removed on the next clean run.
- **Ownership safety**: only rules matching this policy's prefix AND
  group/description markers are modified or removed. Foreign rules that
  merely share the name prefix are warned about and left untouched.
- A failed backup is **fatal** (exit code 2): the script refuses to make
  changes it cannot roll back. A `Save-NetGPO` exception is reported as
  "outcome UNCERTAIN" because the GPO may or may not have been written.

## Preflight warnings

- **Local rule merge**: if any active profile has "Apply local firewall
  rules" disabled (`AllowLocalFirewallRules = False`), locally created rules
  are silently ignored ([Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile)).
  The deployment script warns and suggests GPO deployment. Note that local
  Group Policy (gpedit) firewall rules still apply in that state.
- **Profiles**: rules are created with `-Profile Any` (Domain, Private,
  Public).

## Limitations (by design of path-based firewall rules)

- Renamed or copied binaries are **not** contained.
- Child processes are only contained if they are themselves on the block
  list (e.g. `powershell` spawned by `mshta` is blocked; a signed LOLBin
  not in the catalog is not).
- Brokered network operations (e.g. downloads initiated through Explorer
  or the shell) are not contained by program-path rules.
- **BITS service caveat**: the `bitsadmin.exe` rule blocks the *tool*; file
  transfers performed by the BITS service itself (e.g. on behalf of Windows
  Update or other applications) are not affected by it.
- Rules for binaries absent from a machine (e.g. `ftp.exe` on current
  builds, or `pwsh.exe` when PowerShell 7 is not installed) are inert, not
  errors.
- Blocking `certutil`/`MpCmdRun`-style binaries can break legitimate
  operational flows (certificate enrollment, AV signature updates) —
  evaluate exclusions per environment.

## Testing

The harness mocks the NetSecurity cmdlets (mocked state persists to disk,
so real exit codes are exercised in child processes):

```powershell
pwsh -NoProfile -File tests/TestRunner.ps1
```

Coverage: generator parse/manifest content, first apply, idempotent re-apply,
drift repair (program/protocol/scope/profile), exclusion removal,
`-RemoveOnly`, backup restore (preserving the SAVED configuration),
restore-fidelity, GPO session commit (unrelated GPO content preserved, stale
owned rules removed), GPO save skipped after pre-save failure, GPO `-WhatIf`,
failed-replacement retention of stale protection, foreign prefixed rules
untouched, paths with spaces/apostrophes, invalid-input rejection, and fatal
exit codes. **55 assertions across 18 scenarios, all passing** (verified on
PowerShell 7.7.0-preview.5 on Linux against the mock; no stable PowerShell
or Windows PowerShell validation is claimed). Genuine enforcement (including IPv6 classification and
profile merge states) must still be validated on real Windows hosts — that
is a stated limitation of mocked testing; treat the deliverable as a
production-oriented candidate requiring a Windows pilot.

## References

- [New-NetFirewallRule (NetSecurity)](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
- [Manage Windows Firewall with the command line (GPO sessions)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line)
- [Isolating apps on your network (Network Isolation / 'Internet' keyword)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/isolating-apps-on-your-network)
- [Set-NetFirewallProfile (AllowLocalFirewallRules)](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile)
- [Set-NetFirewallRule (selector vs setter parameters)](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule)
- [LOLBAS project](https://lolbas-project.github.io/)
