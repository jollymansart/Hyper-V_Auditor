<#
.SYNOPSIS
    CR112: Synchronize a deployed Config-OHDC.psd1 against the public Config.psd1 template.
    Identifies keys present in the template but missing from your live config, and optionally
    appends them with their default values and comments from the template.

.DESCRIPTION
    The HyperV Inventory Report adds new config keys with each release. When you
    deploy a new version over an existing config file, the live config does not
    automatically gain the new keys -- it continues working with built-in defaults,
    but you lose visibility and tunability of new features.

    This script compares your live config against Config.psd1 (the public template)
    and:
      1. Reports every key in the template that is missing from your live config
      2. Shows the default value and inline comment from the template for each key
      3. Optionally appends the missing keys to your live config as commented-out
         blocks (preserving your existing values, never overwriting them)

    Run this after every version upgrade. Safe to run repeatedly -- it only adds,
    never removes or modifies existing keys.

.PARAMETER LiveConfig
    Path to your deployed config file (e.g. Config-OHDC.psd1).
    Defaults to Config-OHDC.psd1 in the same folder as this script.

.PARAMETER TemplateConfig
    Path to the public template (Config.psd1).
    Defaults to Config.psd1 in the same folder as this script.

.PARAMETER Apply
    When specified, appends the missing keys to the live config file as
    commented-out blocks with their template default values.
    Without -Apply, this script is read-only (report only).

.PARAMETER BackupFirst
    When -Apply is specified, creates a .bak backup of the live config
    before modifying it. Default: $true.

.EXAMPLE
    # Report only -- see what's missing
    .\Migrate-Config.ps1

.EXAMPLE
    # Apply missing keys as commented-out blocks
    .\Migrate-Config.ps1 -Apply

.EXAMPLE
    # Apply to a specific config path
    .\Migrate-Config.ps1 -LiveConfig "\\server\share\Config-OHDC.psd1" -Apply
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$LiveConfig     = '',
    [string]$TemplateConfig = '',
    [switch]$Apply,
    [bool]$BackupFirst = $true
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $LiveConfig)     { $LiveConfig     = Join-Path $scriptDir 'Config-OHDC.psd1' }
if (-not $TemplateConfig) { $TemplateConfig = Join-Path $scriptDir 'Config.psd1' }

Write-Host ""
Write-Host "===== CR112: Config Migration Utility =====" -ForegroundColor Cyan
Write-Host "  Live config:     $LiveConfig" -ForegroundColor Gray
Write-Host "  Template:        $TemplateConfig" -ForegroundColor Gray
Write-Host "  Mode:            $(if ($Apply) { 'APPLY (will modify live config)' } else { 'REPORT ONLY (read-only)' })" -ForegroundColor $(if ($Apply) { 'Yellow' } else { 'Gray' })
Write-Host ""

# Validate paths
foreach ($p in @($LiveConfig, $TemplateConfig)) {
    if (-not (Test-Path $p)) {
        Write-Host "  [ERROR] File not found: $p" -ForegroundColor Red
        exit 1
    }
}

# Parse both files -- extract key names
function Get-ConfigKeys {
    param([string]$Path)
    $keys = [System.Collections.Generic.List[string]]::new()
    $content = Get-Content $Path
    foreach ($line in $content) {
        if ($line -match '^\s{2,4}([A-Za-z]\w+)\s*=') {
            $key = $matches[1]
            if (-not $keys.Contains($key)) { $keys.Add($key) }
        }
    }
    return $keys
}

# Parse template -- extract key + raw lines (key + comment block above it + value line)
function Get-TemplateBlocks {
    param([string]$Path)
    $blocks  = [ordered]@{}
    $content = Get-Content $Path
    $buffer  = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $content.Count; $i++) {
        $line = $content[$i]

        # Accumulate comment/blank lines as preamble for next key
        if ($line -match '^\s*#' -or $line -match '^\s*$') {
            $buffer.Add($line)
            continue
        }

        # Key line
        if ($line -match '^\s{2,4}([A-Za-z]\w+)\s*=') {
            $key = $matches[1]
            $block = [System.Collections.Generic.List[string]]::new()
            foreach ($bl in $buffer) { $block.Add($bl) }
            $block.Add($line)
            $blocks[$key] = $block
            $buffer.Clear()
            continue
        }

        # Anything else (nested values, closing braces) -- absorb into buffer
        $buffer.Add($line)
    }

    return $blocks
}

$liveKeys     = Get-ConfigKeys -Path $LiveConfig
$templateKeys = Get-ConfigKeys -Path $TemplateConfig
$templateBlocks = Get-TemplateBlocks -Path $TemplateConfig

$missingKeys = @($templateKeys | Where-Object { -not $liveKeys.Contains($_) })
$extraKeys   = @($liveKeys | Where-Object { -not $templateKeys.Contains($_) })

Write-Host "  Template keys:   $($templateKeys.Count)" -ForegroundColor Gray
Write-Host "  Live config keys:$($liveKeys.Count)" -ForegroundColor Gray
Write-Host ""

if ($missingKeys.Count -eq 0) {
    Write-Host "  [OK] No missing keys -- your config is up to date with the template." -ForegroundColor Green
}
else {
    Write-Host "  [!] Missing from live config ($($missingKeys.Count) keys):" -ForegroundColor Yellow
    foreach ($k in $missingKeys) {
        $block = $templateBlocks[$k]
        $valueLine = if ($block) { ($block | Where-Object { $_ -match "^\s{2,4}$k\s*=" }) } else { $null }
        $defaultVal = if ($valueLine) { ($valueLine -split '=', 2)[1].Trim().TrimEnd(',') } else { '(unknown)' }
        Write-Host "    - $k  (template default: $defaultVal)" -ForegroundColor Yellow
    }
}

Write-Host ""

if ($extraKeys.Count -gt 0) {
    Write-Host "  [INFO] Keys in live config not in template ($($extraKeys.Count)) -- OHDC-specific or deprecated:" -ForegroundColor DarkGray
    foreach ($k in $extraKeys) { Write-Host "    + $k" -ForegroundColor DarkGray }
    Write-Host ""
}

# Apply mode -- append missing keys as commented-out blocks
if ($Apply -and $missingKeys.Count -gt 0) {
    if ($BackupFirst) {
        $bakPath = "$LiveConfig.$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"
        if ($PSCmdlet.ShouldProcess($LiveConfig, "Backup to $bakPath")) {
            Copy-Item -Path $LiveConfig -Destination $bakPath -Force
            Write-Host "  [OK] Backup created: $bakPath" -ForegroundColor Green
        }
    }

    $appendLines = [System.Collections.Generic.List[string]]::new()
    $appendLines.Add("")
    $appendLines.Add("    # =========================================================================")
    $appendLines.Add("    # Keys added by Migrate-Config.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $appendLines.Add("    # These are the template defaults -- uncomment and adjust as needed.")
    $appendLines.Add("    # =========================================================================")

    foreach ($k in $missingKeys) {
        $block = $templateBlocks[$k]
        if ($block) {
            $appendLines.Add("")
            foreach ($bl in $block) {
                # Comment out value lines, keep comment lines as-is
                if ($bl -match "^\s{2,4}$k\s*=") {
                    $appendLines.Add("    # $($bl.Trim())")
                }
                else {
                    $appendLines.Add($bl)
                }
            }
        }
        else {
            $appendLines.Add("    # $k = (see Config.psd1 for default)")
        }
    }

    # Insert before closing brace of the hashtable
    $liveContent = Get-Content $LiveConfig
    $lastBrace = $liveContent.Count - 1
    $closingBracePattern = '^\}'
    for ($i = $liveContent.Count - 1; $i -ge 0; $i--) {
        if ($liveContent[$i] -match $closingBracePattern) { $lastBrace = $i; break }
    }

    $newContent = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $lastBrace; $i++) { $newContent.Add($liveContent[$i]) }
    foreach ($al in $appendLines) { $newContent.Add($al) }
    $newContent.Add($liveContent[$lastBrace])  # closing brace

    if ($PSCmdlet.ShouldProcess($LiveConfig, "Append $($missingKeys.Count) missing keys (commented out)")) {
        Set-Content -Path $LiveConfig -Value $newContent -Encoding UTF8
        Write-Host "  [OK] $($missingKeys.Count) missing key block(s) appended to $LiveConfig (commented out)." -ForegroundColor Green
        Write-Host "       Review the additions at the bottom of the file and uncomment/adjust as needed." -ForegroundColor Yellow
    }
}
elseif ($Apply -and $missingKeys.Count -eq 0) {
    Write-Host "  [OK] Nothing to apply -- config is already up to date." -ForegroundColor Green
}
elseif (-not $Apply -and $missingKeys.Count -gt 0) {
    Write-Host "  Run with -Apply to append the missing keys (commented-out) to your live config." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "===== Done =====" -ForegroundColor Cyan
