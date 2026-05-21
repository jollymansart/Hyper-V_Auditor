# HyperVInventory-CSVHealth

**Version:** 1.0.0
**Part of:** HyperV Inventory Report suite
**Author:** Michael George
**Last updated:** 2026-04-10

Cluster Shared Volume health auditing module providing filter driver enumeration, CSV redirection state analysis, VM lock diagnostics, and compliance reporting.

## Key design principles

- **Read-only.** This module never changes cluster state. Remediation is produced as PowerShell script text that must be reviewed and executed manually.
- **PS 5.1 compatible.** ASCII only, no non-ASCII characters, no PS 7+ syntax.
- **Cross-domain aware.** Kerberos/Negotiate authentication fallback for multi-domain environments (ohdc.com, overheaddoor.com, creative.com).
- **Runspace parallelization** for multi-node queries (consistent with the rest of the suite).
- **External knowledge base.** Filter driver classification lives in `CSVFilterKnowledgeBase.json`, not in code — update without editing the module.
- **Excel output** via EPPlus, matching suite conventions.

## Installation

1. Copy all four files to the suite module directory:
   ```
   HyperVInventory-CSVHealth.psd1
   HyperVInventory-CSVHealth.psm1
   CSVFilterKnowledgeBase.json
   README-CSVHealth.md
   ```
   Typical location: `\\rictx-script-p2\Script_Dev\Powershell\Modules\HyperVInventory-CSVHealth\`

2. Import the module:
   ```powershell
   Import-Module \\rictx-script-p2\Script_Dev\Powershell\Modules\HyperVInventory-CSVHealth
   ```

3. Verify:
   ```powershell
   Get-Command -Module HyperVInventory-CSVHealth
   ```

## Public functions

### Get-CSVFilterDrivers

Enumerates file system minifilter drivers attached to a Cluster Shared Volume and classifies each as OK, INCOMPATIBLE, or UNKNOWN against the knowledge base.

```powershell
Get-CSVFilterDrivers -CSVName HV-Nimble4
Get-CSVFilterDrivers -CSVName HV-Nimble4 | Where-Object Classification -eq 'INCOMPATIBLE'
```

### Get-CSVRedirectionState

Reports per-node CSV redirection state including `FileSystemRedirectedIOReason` and `BlockRedirectedIOReason`. Flags non-healthy states.

```powershell
Get-CSVRedirectionState
Get-CSVRedirectionState -CSVName HV-Nimble4 | Where-Object Healthy -eq $false
```

### Get-CSVHealthSummary

One-shot cluster-wide CSV health sweep that composes the two primitives above into a single per-CSV health report. This is the function to call from the inventory suite runner.

```powershell
Get-CSVHealthSummary
Get-CSVHealthSummary -Cluster RICTX-UCS-CLS | Where-Object Health -ne 'Healthy'
```

Output per CSV includes:
- Overall `Health` (Healthy/Warning/Critical)
- Filter driver counts and details
- Per-node state information
- Human-readable issue summary

### Test-CSVFilterCompliance

Thin pass/fail wrapper for scheduled compliance checks. Returns a compliance result object.

```powershell
$c = Test-CSVFilterCompliance
if (-not $c.Compliant) { Send-MailMessage ... }

# Strict mode: Warning state also fails
$c = Test-CSVFilterCompliance -FailOnWarning
```

### Get-VMLockDiagnostic

Comprehensive VM lock / start failure diagnostic with automatic root cause classification. Generates remediation script text (never executes). Module function version of the `Invoke-VMLockDiagnostic` v1.1 standalone script.

```powershell
$diag = Get-VMLockDiagnostic -VMName RICTX-GDTMON-P1 -IncludeRemediationScript
$diag.Classification      # KernelModeStuckLock / OrphanedCheckpoint / etc.
$diag.PrimaryCause
$diag.RemediationScript | Out-File C:\Temp\fix-gdtmon.ps1
# Review C:\Temp\fix-gdtmon.ps1 carefully before executing
```

**Classifications:**

| Classification | Meaning | Remediation |
|---|---|---|
| `KernelModeStuckLock` | Stuck kernel file reference; user-mode tools blind | Drain + reboot specific node + manual merge |
| `UserModeHandleLock` | Handle visible via handle.exe / SMB | Kill specific process on specific node |
| `OrphanedVMWPProcess` | Ghost vmwp.exe for non-running VM | Kill ghost process |
| `OrphanedCheckpoint` | AVHDX without snapshot, no active lock | Safe manual merge |
| `IncompatibleFilterDriver` | CVDLP or similar detected | Cluster-wide filter remediation |
| `ActiveBackupJob` | CommVault running + files present | Wait or kill CommCell job |
| `Unknown` | Insufficient evidence | Escalate with full report |

### Export-CSVHealthReport

Exports a CSV health summary to a multi-sheet Excel workbook (Summary, Filters, NodeStates, Violations, Metadata) with color-coded health indicators.

```powershell
Export-CSVHealthReport
Get-CSVHealthSummary | Export-CSVHealthReport -OutputPath C:\Reports\csv-health.xlsx
```

Default output: `\\rictx-script-p2\LOG\Hyper-V\CSVHealth_<cluster>_<timestamp>.xlsx`

## Knowledge base maintenance

`CSVFilterKnowledgeBase.json` classifies file system filter drivers. To extend coverage without editing the module:

```json
{
    "incompatible": {
        "<DriverName>": {
            "vendor": "Vendor Name",
            "product": "Product description",
            "severity": "High|Medium|Low",
            "remediation": "Actionable remediation guidance",
            "reference": "Optional incident or doc reference"
        }
    },
    "compatible": [
        "<DriverName1>",
        "<DriverName2>"
    ]
}
```

After updating the JSON, reload the module (or restart the session). The next `Get-CSVFilterDrivers` call will pick up the new classifications.

**Workflow for handling an UNKNOWN filter in the field:**

1. `Get-CSVHealthSummary` reports an unknown filter
2. Research the driver name (vendor documentation, `sigcheck.exe <driver>.sys`)
3. Determine whether it's CSV-compatible
4. Add to `CSVFilterKnowledgeBase.json` in the appropriate section
5. Next scan reflects the new classification

## Integration with the HyperV Inventory Report suite

To include CSV health in the weekly inventory report, add to the suite runner:

```powershell
Import-Module HyperVInventory-CSVHealth

$csvHealth = Get-CSVHealthSummary -Cluster $TargetCluster
$csvHealth | Export-CSVHealthReport -OutputPath $SuiteOutputPath

$compliance = Test-CSVFilterCompliance
if (-not $compliance.Compliant) {
    # Add to the suite's Executive Summary alerts
    $SuiteAlerts += "CSV compliance failure: $($compliance.Violations.Count) violation(s)"
}
```

## Scheduled compliance monitoring

Add a scheduled task that runs every 6 hours:

```powershell
Import-Module HyperVInventory-CSVHealth

$compliance = Test-CSVFilterCompliance -FailOnWarning
if (-not $compliance.Compliant) {
    $body = @"
CSV Compliance Failure on $($compliance.Cluster)

Violations: $($compliance.Violations.Count)
Critical: $($compliance.CriticalCount)
Warning:  $($compliance.WarningCount)

$($compliance.Violations | Format-Table CSVName, Health, Issues -AutoSize | Out-String)
"@
    Send-MailMessage -From 'hypervmon@ohdc.com' `
        -To 'infra-team@ohdc.com' `
        -Subject "[CSV Health] Compliance violation on $($compliance.Cluster)" `
        -Body $body `
        -SmtpServer 'mail.overheaddoor.com'
}
```

## Incident investigation workflow

When a VM fails to start with sharing violation (0x80070020):

```powershell
# 1. Run the diagnostic
$diag = Get-VMLockDiagnostic -VMName <VM> -IncludeRemediationScript

# 2. Review classification
$diag | Format-List Classification, Confidence, PrimaryCause, ContributingFactors

# 3. Review evidence
$diag.Evidence | Format-List

# 4. Review generated remediation script
$diag.RemediationScript

# 5. Save for audit trail
$diag | ConvertTo-Json -Depth 8 | Out-File "\\rictx-script-p2\LOG\Hyper-V\diag-$(Get-Date -Format yyyyMMdd-HHmm).json"

# 6. Execute remediation manually after review
```

## Troubleshooting the module itself

**EPPlus not found:** `Export-CSVHealthReport` requires EPPlus. Install via `Install-Package EPPlus` or drop `EPPlus.dll` into the module folder.

**handle.exe missing:** `Get-VMLockDiagnostic` uses handle.exe for user-mode handle enumeration if present. Deploy to nodes via:
```powershell
Invoke-Command -ComputerName $nodes {
    Invoke-WebRequest 'https://live.sysinternals.com/handle64.exe' `
        -OutFile 'C:\Windows\System32\handle.exe'
}
```

**Runspace timeouts:** Increase `-ThrottleLimit` or check node WinRM health with `Test-WSMan`.

**Cross-domain authentication failures:** The module falls back from Kerberos to Negotiate automatically. If both fail, verify trust relationships and WinRM service state.

## Version history

| Version | Date | Notes |
|---------|------|-------|
| 1.0.0   | 2026-04-10 | Initial release. Derived from investigation of RICTX-UCS-CLS CVDLP incident. |

## Related resources

- Parent suite: HyperV Inventory Report suite (v3.10.x range)
- Standalone tool: `Invoke-VMLockDiagnostic.ps1` v1.1 (becomes a thin wrapper around `Get-VMLockDiagnostic`)
- Incident documentation: `RICTX-GDTMON-P1_Troubleshooting.md` / `.docx`
