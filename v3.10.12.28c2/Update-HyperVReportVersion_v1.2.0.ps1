Function Update-HyperVReportVersion
{

<#
.SYNOPSIS
    Updates the HyperV Inventory Report version number across all files in a release folder.

.DESCRIPTION
    Walks a release folder and updates the version string in every file that carries
    one. One command, one new version, everything bumped consistently:

      1. All .psd1 manifests -> ModuleVersion = 'X.Y.Z'
      2. All .psm1 modules   -> header "Version: X.Y.Z" or "Version = 'X.Y.Z'"
      3. HyperVInventory.psm1 orchestrator -> version string
      4. Run_Report.ps1                    -> Hyper-V Inventory Report vX.Y.Z log line
      5. Config-OHDC.psd1 (optional)       -> ReportVersion = 'X.Y.Z' if present
      6. Master plan .md files (optional)  -> "Current production: vX.Y.Z" line

    What it does NOT touch:
      - ReleaseNotes fields in .psd1 files (preserved so history isn't blown away)
      - Anything inside XML/HTML comments that aren't version declarations
      - Historical CHANGELOG files
      - Any line where the version appears inside a URL or file path

    Safety features:
      - -WhatIf support: previews every change
      - -Backup: writes <file>.bak before overwriting
      - Summary report at end: count per file type, count of lines changed
      - Preserves file encoding (UTF-8 with BOM if original had one)

.PARAMETER Path
    Root folder of the release tree (e.g. v3.10.10). All .psd1 / .psm1 / .ps1 / .md
    files below this path are candidates.

.PARAMETER NewVersion
    Target version string in 'Major.Minor.Patch' format (e.g. 3.10.11).

.PARAMETER Backup
    If present, writes <file>.bak copies of every file that gets modified.

.PARAMETER IncludeMasterPlan
    If present, updates the "Current production: vX.Y.Z" line in any
    HyperV-Report-Master-Plan_*.md files found. Default OFF to avoid
    accidentally bumping historical plan snapshots.

.EXAMPLE
    .\Update-HyperVReportVersion.ps1 -Path '\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\v3.10.10' -NewVersion '3.10.10' -WhatIf

    Preview changes without writing anything.

.EXAMPLE
    .\Update-HyperVReportVersion.ps1 -Path 'C:\temp\v3.10.11' -NewVersion '3.10.11' -Backup

    Apply changes, writing .bak files for safety.

.NOTES
    Author: Michael George (with Claude)
    Version: 1.0.0
    Date: 2026-04-11
    PS Compat: 5.1+
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$NewVersion,

    [switch]$Backup,

    [switch]$IncludeMasterPlan
)

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Path does not exist or is not a directory: $Path"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " HyperV Report Version Bumper" -ForegroundColor Cyan
Write-Host " Target version: $NewVersion" -ForegroundColor Cyan
Write-Host " Root folder   : $Path" -ForegroundColor Cyan
Write-Host " Mode          : $(if ($WhatIfPreference) { 'WhatIf (preview)' } else { 'APPLY' })" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$stats = @{
    PSD1    = 0
    PSM1    = 0
    PS1     = 0
    MD      = 0
    Linked  = 0
    Skipped = 0
}

# Patterns that we replace the RHS of with the new version.
# Key = regex to match; Value = replacement template (use {V} for version).
$patterns = @(
    # [0] .psd1 ModuleVersion = 'X.Y.Z'
    @{ Pattern = "(ModuleVersion\s*=\s*')(\d+\.\d+\.\d+)(')";           Replace = "`${1}$NewVersion`${3}";                     Label = 'ModuleVersion' },
    # [1] .psm1 header: "Version: X.Y.Z" or "Version: X.Y.Z-SuffixName"
    @{ Pattern = "(Version\s*:\s*)(\d+\.\d+\.\d+)(-[A-Za-z]+)?";         Replace = "`${1}$NewVersion`${3}";                     Label = 'Version header' },
    # [2] .psm1 top-of-file "# Version: X.Y.Z" comment
    @{ Pattern = "(#\s*Version\s+)(\d+\.\d+\.\d+)";                      Replace = "`${1}$NewVersion";                          Label = '# Version comment' },
    # [3] Run_Report.ps1 log banner: "Hyper-V Inventory Report vX.Y.Z" (literal, rare)
    @{ Pattern = "(Hyper-V Inventory Report v)(\d+\.\d+\.\d+)";          Replace = "`${1}$NewVersion";                          Label = 'Log banner' },
    # [4] Config-*.psd1: Version = 'X.Y.Z' (master config version -- the one Run_Report.ps1 reads at runtime)
    @{ Pattern = "(\bVersion\s*=\s*')(\d+\.\d+\.\d+)(')";                Replace = "`${1}$NewVersion`${3}";                     Label = 'Config Version key' },
    # [5] Legacy ReportVersion key (kept for backwards compatibility if any file still uses it)
    @{ Pattern = "(ReportVersion\s*=\s*')(\d+\.\d+\.\d+)(')";            Replace = "`${1}$NewVersion`${3}";                     Label = 'ReportVersion' },
    # [6] PowerShell variable assignment with double quotes:
    #     $script:ModuleVersion = "X.Y.Z"  (used in HyperVInventory.psm1 orchestrator)
    #     $global:ModuleVersion = "X.Y.Z"
    #     $ReportVersion = "X.Y.Z"
    #     This is the line that emits the runtime "Hyper-V Inventory Report vX.Y.Z" banner via Write-HVLog.
    #     NOTE: In PowerShell single-quoted strings, \ is literal (not escape).
    #     So \$ matches a literal $ character, and \d matches a literal d -- but
    #     .NET regex inside [regex]::Replace treats \ as escape. Single-quoted
    #     strings in PS pass through literally to .NET, so \$ = regex escaped $.
    @{ Pattern = '(\$(?:script:|global:|local:|private:)?(?:Module|Report|Script)?Version\s*=\s*")(\d+\.\d+\.\d+)(")'; Replace = "`${1}$NewVersion`${3}"; Label = '$script:ModuleVersion variable' },
    # [7] Orchestrator ExpectedVersion in the $subModules array:
    #     ExpectedVersion = "X.Y.Z"  (each module entry has one)
    #     These must be bumped whenever the suite version changes, otherwise
    #     the orchestrator warns "loaded vX, expected vY" for every module.
    @{ Pattern = '(ExpectedVersion\s*=\s*")(\d+\.\d+\.\d+)(")'; Replace = "`${1}$NewVersion`${3}"; Label = 'ExpectedVersion' }
)

# Optional: master plan "Current production: vX.Y.Z"
$masterPlanPattern = @{ Pattern = "(Current production:\s*v)(\d+\.\d+\.\d+)"; Replace = "`${1}$NewVersion"; Label = 'Master plan header' }

# File-type filter -> which patterns apply
$fileHandlers = @{
    '.psd1' = @(0, 4, 5)    # ModuleVersion + Config Version key + legacy ReportVersion
    '.psm1' = @(1, 2, 6, 7) # Version: header + # Version comment + $script:ModuleVersion + ExpectedVersion
    '.ps1'  = @(3, 6)       # Log banner (literal) + $script:ModuleVersion variable
}

$files = Get-ChildItem -LiteralPath $Path -Recurse -File -Include *.psd1,*.psm1,*.ps1,*.md |
    Where-Object { $_.FullName -notmatch '\\OLD\\|\\\.bak\\' }

Write-Host "Scanning $($files.Count) candidate files..." -ForegroundColor White
Write-Host ""

foreach ($f in $files) {
    $ext = $f.Extension.ToLower()

    # Determine which patterns to apply
    $applyIdx = @()
    if ($ext -eq '.md') {
        if (-not $IncludeMasterPlan) { $stats.Skipped++; continue }
        if ($f.Name -notmatch 'Master-Plan') { $stats.Skipped++; continue }
        $patternsToTry = @($masterPlanPattern)
    }
    else {
        if (-not $fileHandlers.ContainsKey($ext)) { $stats.Skipped++; continue }
        $patternsToTry = $fileHandlers[$ext] | ForEach-Object { $patterns[$_] }
    }

    # Read content preserving encoding
    $content = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
    $original = $content
    $changedLabels = @()

    foreach ($p in $patternsToTry) {
        if ($content -match $p.Pattern) {
            $newContent = [regex]::Replace($content, $p.Pattern, $p.Replace)
            if ($newContent -ne $content) {
                $content = $newContent
                $changedLabels += $p.Label
            }
        }
    }

    if ($content -eq $original) { continue }

    # Summary per file
    $relative = $f.FullName.Substring($Path.Length).TrimStart('\','/')
    Write-Host "  [$ext] $relative" -ForegroundColor Yellow
    foreach ($lbl in $changedLabels) { Write-Host "        -> $lbl" -ForegroundColor Gray }

    if ($PSCmdlet.ShouldProcess($f.FullName, "Update version to $NewVersion")) {
        if ($Backup) {
            Copy-Item -LiteralPath $f.FullName -Destination "$($f.FullName).bak" -Force
        }
        Set-Content -LiteralPath $f.FullName -Value $content -Encoding UTF8 -NoNewline
    }

    switch ($ext) {
        '.psd1' { $stats.PSD1++ }
        '.psm1' { $stats.PSM1++ }
        '.ps1'  { $stats.PS1++ }
        '.md'   { $stats.MD++ }
    }
    $stats.Linked += $changedLabels.Count
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  .psd1 files updated: $($stats.PSD1)"
Write-Host "  .psm1 files updated: $($stats.PSM1)"
Write-Host "  .ps1  files updated: $($stats.PS1)"
Write-Host "  .md   files updated: $($stats.MD)"
Write-Host "  Version strings replaced: $($stats.Linked)"
Write-Host "  Files skipped (no version): $($stats.Skipped)"
Write-Host ""
if ($WhatIfPreference) {
    Write-Host "  NO CHANGES WRITTEN (WhatIf mode). Re-run without -WhatIf to apply." -ForegroundColor Yellow
} else {
    Write-Host "  Version bump complete." -ForegroundColor Green
    if ($Backup) { Write-Host "  Backups written as <filename>.bak alongside each modified file." -ForegroundColor Green }
}
Write-Host "============================================================" -ForegroundColor Cyan
}

