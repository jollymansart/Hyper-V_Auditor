# HyperVInventory.psm1
# Hyper-V Inventory Report - Main Orchestrator
# Version: 3.10.12.12

$script:ModuleVersion = "3.10.12.26"

# Determine module root
if ($PSScriptRoot) {
    $modulesFolder = Join-Path $PSScriptRoot "Modules"
}
else {
    $modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $modulesFolder = Join-Path $modulePath "Modules"
}

# Sub-module definitions with expected versions
$subModules = @(
    @{ Name = "HyperVInventory-Core";          PSM1 = "HyperVInventory-Core.psm1";          PSD1 = "HyperVInventory-Core.psd1";          ExpectedVersion = "3.10.12" }
    @{ Name = "HyperVInventory-Cluster";       PSM1 = "HyperVInventory-Cluster.psm1";       PSD1 = "HyperVInventory-Cluster.psd1";       ExpectedVersion = "3.10.12" }
    @{ Name = "HyperVInventory-Security";      PSM1 = "HyperVInventory-Security.psm1";      PSD1 = "HyperVInventory-Security.psd1";      ExpectedVersion = "3.10.12" }
    @{ Name = "HyperVInventory-OS";            PSM1 = "HyperVInventory-OS.psm1";            PSD1 = "HyperVInventory-OS.psd1";            ExpectedVersion = "3.10.12" }   # CR4: InstallState, CR5: Local-Builtin
    @{ Name = "HyperVInventory-Storage";       PSM1 = "HyperVInventory-Storage.psm1";       PSD1 = "HyperVInventory-Storage.psd1";       ExpectedVersion = "3.10.12" }
    @{ Name = "HyperVInventory-Analysis";      PSM1 = "HyperVInventory-Analysis.psm1";      PSD1 = "HyperVInventory-Analysis.psd1";      ExpectedVersion = "3.10.12" }
    @{ Name = "HyperVInventory-Export";        PSM1 = "HyperVInventory-Export.psm1";        PSD1 = "HyperVInventory-Export.psd1";        ExpectedVersion = "3.10.12" }   # CR3-CR8 all changes
    @{ Name = "HyperVInventory-ADAuth";        PSM1 = "HyperVInventory-ADAuth.psm1";        PSD1 = "HyperVInventory-ADAuth.psd1";        ExpectedVersion = "3.10.12" }
    @{ Name = "HyperVInventory-LiveMigration"; PSM1 = "HyperVInventory-LiveMigration.psm1"; PSD1 = "HyperVInventory-LiveMigration.psd1"; ExpectedVersion = "3.10.12" }   # CR1 auth detection (read-only, no change needed)
    @{ Name = "HyperVInventory-S2D";           PSM1 = "HyperVInventory-S2D.psm1";           PSD1 = "HyperVInventory-S2D.psd1";           ExpectedVersion = "3.10.12" }   # CR2: new S2D audit module
    @{ Name = "HyperVInventory-ResourceMetering"; PSM1 = "HyperVInventory-ResourceMetering.psm1"; PSD1 = "HyperVInventory-ResourceMetering.psd1"; ExpectedVersion = "3.10.12" }   # S8d: VM resource metering + IOPS
    @{ Name = "HyperVInventory-TLS";             PSM1 = "HyperVInventory-TLS.psm1";             PSD1 = "HyperVInventory-TLS.psd1";             ExpectedVersion = "3.10.12" }   # S8e: TLS / Secure Channel compliance audit
    @{ Name = "HyperVInventory-VMActivity";      PSM1 = "HyperVInventory-VMActivity.psm1";      PSD1 = "HyperVInventory-VMActivity.psd1";      ExpectedVersion = "3.10.12" }   # S14: VM Activity Audit
    @{ Name = "HyperVInventory-SCCM";            PSM1 = "HyperVInventory-SCCM.psm1";            PSD1 = "HyperVInventory-SCCM.psd1";            ExpectedVersion = "3.10.12" }   # S9: SCCM Client Status Integration
    @{ Name = "HyperVInventory-LAPS";            PSM1 = "HyperVInventory-LAPS.psm1";            PSD1 = "HyperVInventory-LAPS.psd1";            ExpectedVersion = "3.10.12" }  # v3.10.11 CR102+CR103: LAPS Audit + Unified Backend
    @{ Name = "HyperVInventory-Permissions";     PSM1 = "HyperVInventory-Permissions.psm1";     PSD1 = "HyperVInventory-Permissions.psd1";     ExpectedVersion = "3.10.12" }  # v3.10.12 OPEN-60: Permission Audit (local groups + user rights)
    @{ Name = "HyperVInventory-VHDChain";        PSM1 = "HyperVInventory-VHDChain.psm1";        PSD1 = "HyperVInventory-VHDChain.psd1";        ExpectedVersion = "3.10.12" }  # v3.10.12 CR105: VHD parent chain visibility
    @{ Name = "HyperVInventory-Remediation";     PSM1 = "HyperVInventory-Remediation.psm1";     PSD1 = "HyperVInventory-Remediation.psd1";     ExpectedVersion = "3.10.12" }  # v3.10.12 CR106: Dynamic per-VM remediation script generation
    @{ Name = "HyperVInventory-Cyphers";         PSM1 = "HyperVInventory-Cyphers.psm1";         PSD1 = "HyperVInventory-Cyphers.psd1";         ExpectedVersion = "3.10.12" }  # v3.10.12.27 OPEN-68: Cipher / Kerberos encryption-type audit
)

Write-Verbose "Loading HyperV Inventory v$script:ModuleVersion modules from: $modulesFolder"

$versionMismatches = @()
foreach ($mod in $subModules) {
    $psm1Path = Join-Path $modulesFolder $mod.PSM1
    $psd1Path = if ($mod.PSD1) { Join-Path $modulesFolder $mod.PSD1 } else { $null }
    
    # Prefer PSD1 manifest if it exists -- but fall back to PSM1 if manifest
    # loads with 0 ExportedCommands. Confirmed PS 5.1 bug: certain modules load via
    # PSD1 (Manifest mode) with 0 exports despite correct FunctionsToExport. PSM1-direct
    # import reliably produces full ExportedCommands. Diagnostic confirmed 2026-05-13.
    $usedManifest = $false
    if ($psd1Path -and (Test-Path $psd1Path)) {
        Import-Module $psd1Path -Force -Global -ErrorAction Stop -WarningAction SilentlyContinue
        $loaded = Get-Module | Where-Object { $_.Path -and $_.Path.StartsWith($modulesFolder) -and $_.Name -eq $mod.Name } | Select-Object -First 1
        if (-not $loaded) { $loaded = Get-Module $mod.Name | Where-Object { $_.Path -like "*$($mod.PSM1)*" } | Select-Object -First 1 }

        # If PSD1 loaded but ExportedCommands is empty, fall back to PSM1 direct import
        if ($loaded -and $loaded.ExportedCommands.Count -eq 0 -and (Test-Path $psm1Path)) {
            Write-Warning "  [PSM1-FALLBACK] $($mod.Name): PSD1 import produced 0 exports -- retrying with PSM1 direct"
            Remove-Module $mod.Name -Force -ErrorAction SilentlyContinue
            Import-Module $psm1Path -Force -Global -ErrorAction Stop -WarningAction SilentlyContinue
            $loaded = Get-Module | Where-Object { $_.Path -and $_.Path.StartsWith($modulesFolder) -and $_.Name -eq $mod.Name } | Select-Object -First 1
            if (-not $loaded) { $loaded = Get-Module $mod.Name | Where-Object { $_.Path -like "*$($mod.PSM1)*" } | Select-Object -First 1 }
        } else {
            $usedManifest = $true
        }

        $loadedVer = if ($loaded) { $loaded.Version.ToString() } else { 'Unknown' }
        Write-Verbose "  [OK] $($mod.Name) v$loadedVer $(if ($usedManifest) { '(manifest)' } else { '(psm1-fallback)' })"

        # Version check only when loaded via manifest (PSM1 has no embedded version)
        if ($usedManifest -and $loadedVer -ne $mod.ExpectedVersion) {
            $versionMismatches += "$($mod.Name): loaded v$loadedVer, expected v$($mod.ExpectedVersion)"
        }
    }
    elseif (Test-Path $psm1Path) {
        # Fallback to bare PSM1 (no version tracking -- used for S2D module and future modules without manifests)
        Import-Module $psm1Path -Force -Global -ErrorAction Stop -WarningAction SilentlyContinue
        Write-Verbose "  [OK] $($mod.Name) (no manifest - version untracked)"
    }
    else {
        # Optional modules (S2D) are allowed to be missing -- skip with a warning
        if ($mod.PSM1 -like '*S2D*' -or $mod.PSM1 -like '*ResourceMetering*' -or $mod.PSM1 -like '*TLS*' -or $mod.PSM1 -like '*VMActivity*' -or $mod.PSM1 -like '*SCCM*' -or $mod.PSM1 -like '*Cyphers*') {
            Write-Warning "  [SKIP] Optional module not found: $psm1Path -- S2D audit will be skipped."
        }
        else {
            throw "Required module not found: $psm1Path"
        }
    }
}

if ($versionMismatches.Count -gt 0) {
    Write-Warning "Module version mismatches detected:"
    foreach ($mm in $versionMismatches) { Write-Warning "  $mm" }
    Write-Warning "Deploy all files from the same v$script:ModuleVersion package to fix."
}

Write-Verbose "All modules loaded successfully (v$script:ModuleVersion)"

    # v3.10.12.18 FIX: Capture VHDChain and Remediation function references directly from
    # the module's ExportedCommands at import time. This bypasses PS 5.1 scope issues where
    # Get-Command cannot find functions imported with -Global from inside a module body.
    # The FunctionInfo objects are stored as script-level variables and called via & operator.
    # v3.10.12.20: Three-tier function capture bypassing PS 5.1 scope/registration issues.
    # Tier1: ExportedCommands (normal). Tier2: Get-Command session. Tier3: dot-source PSM1.
    $global:HVI_fnVHDChainCollection  = $null
    $global:HVI_fnVHDChainRecommend   = $null
    $global:HVI_fnVMRemediationScript = $null
    $global:HVI_fnKCDRemediationScript = $null   # OPEN-61: set after module load, used in Export
    $global:HVI_fnKCDRemediationIndex  = $null   # OPEN-61: set after module load, used in Export

    # VHDChain Tier1
    $vhdMod = Get-Module -Name 'HyperVInventory-VHDChain'
    if ($vhdMod -and $vhdMod.ExportedCommands.ContainsKey('Invoke-VHDChainCollection')) {
        $global:HVI_fnVHDChainCollection = $vhdMod.ExportedCommands['Invoke-VHDChainCollection']
        $global:HVI_fnVHDChainRecommend  = $vhdMod.ExportedCommands['Get-VHDChainRecommendation']
        Write-Host "[v3.10.12.20] VHDChain captured (Tier1-ExportedCommands)" -ForegroundColor DarkCyan
    }
    # VHDChain Tier2
    if (-not $global:HVI_fnVHDChainCollection) {
        $gc = Get-Command -Name 'Invoke-VHDChainCollection' -ErrorAction SilentlyContinue
        if ($gc) {
            $global:HVI_fnVHDChainCollection = $gc
            $global:HVI_fnVHDChainRecommend  = Get-Command -Name 'Get-VHDChainRecommendation' -ErrorAction SilentlyContinue
            Write-Host "[v3.10.12.20] VHDChain captured (Tier2-GetCommand)" -ForegroundColor DarkCyan
        }
    }
    # VHDChain Tier3: dot-source directly -- always works, bypasses module machinery
    if (-not $global:HVI_fnVHDChainCollection) {
        $vhdPsm1 = Join-Path $modulesFolder 'HyperVInventory-VHDChain.psm1'
        if (Test-Path $vhdPsm1) {
            Write-Warning "[v3.10.12.20] VHDChain all tiers failed -- dot-sourcing PSM1 directly"
            try {
                . $vhdPsm1
                $gc = Get-Command -Name 'Invoke-VHDChainCollection' -ErrorAction SilentlyContinue
                if ($gc) {
                    $global:HVI_fnVHDChainCollection = $gc
                    $global:HVI_fnVHDChainRecommend  = Get-Command -Name 'Get-VHDChainRecommendation' -ErrorAction SilentlyContinue
                    Write-Host "[v3.10.12.20] VHDChain captured (Tier3-DotSource)" -ForegroundColor Green
                }
            } catch { Write-Warning "[v3.10.12.20] VHDChain dot-source failed: $($_.Exception.Message)" }
        }
    }
    if (-not $global:HVI_fnVHDChainCollection) {
        Write-Warning "[v3.10.12.20] VHDChain: all capture tiers failed -- Step 5t will be skipped"
    }

    # Remediation Tier1
    $remMod = Get-Module -Name 'HyperVInventory-Remediation'
    if ($remMod -and $remMod.ExportedCommands.ContainsKey('New-VMRemediationScript')) {
        $global:HVI_fnVMRemediationScript = $remMod.ExportedCommands['New-VMRemediationScript']
    }
    # Remediation Tier2
    if (-not $global:HVI_fnVMRemediationScript) {
        $gc = Get-Command -Name 'New-VMRemediationScript' -ErrorAction SilentlyContinue
        if ($gc) { $global:HVI_fnVMRemediationScript = $gc }
    }
    # Remediation Tier3
    if (-not $global:HVI_fnVMRemediationScript) {
        $remPsm1 = Join-Path $modulesFolder 'HyperVInventory-Remediation.psm1'
        if (Test-Path $remPsm1) {
            try { . $remPsm1; $gc = Get-Command 'New-VMRemediationScript' -EA SilentlyContinue; if ($gc) { $global:HVI_fnVMRemediationScript = $gc } }
            catch { Write-Warning "[v3.10.12.20] Remediation dot-source failed: $($_.Exception.Message)" }
        }
    }

    # OPEN-61 Part B: KCD remediation function capture -- MUST be inside Invoke-HyperVInventory.
    # Module-scope capture fails because: (a) $modulesFolder is undefined at module load time,
    # (b) Write-HVLog doesn't exist yet, (c) Get-Command can't see PSM1-fallback dot-sourced functions
    # until after the module load is complete. Running here guarantees all three are available.
    $global:HVI_fnKCDRemediationScript = $null
    $global:HVI_fnKCDRemediationIndex  = $null
    # Tier 1: ExportedCommands (works if Remediation loaded as a proper module)
    $remMod2 = Get-Module -Name 'HyperVInventory-Remediation'
    if ($remMod2 -and $remMod2.ExportedCommands.ContainsKey('New-KCDRemediationScript')) {
        $global:HVI_fnKCDRemediationScript = $remMod2.ExportedCommands['New-KCDRemediationScript']
        $global:HVI_fnKCDRemediationIndex  = $remMod2.ExportedCommands['New-KCDRemediationIndex']
    }
    # Tier 2: Get-Command (works if PSM1-fallback dot-sourced into global/script scope)
    if (-not $global:HVI_fnKCDRemediationScript) {
        $gc = Get-Command -Name 'New-KCDRemediationScript' -ErrorAction SilentlyContinue
        if ($gc) {
            $global:HVI_fnKCDRemediationScript = $gc
            $global:HVI_fnKCDRemediationIndex  = Get-Command -Name 'New-KCDRemediationIndex' -ErrorAction SilentlyContinue
        }
    }
    # Tier 3: dot-source the PSM1 directly -- $modulesFolder is now set
    if (-not $global:HVI_fnKCDRemediationScript) {
        $remPsm1_kcd = Join-Path $modulesFolder 'HyperVInventory-Remediation.psm1'
        if (Test-Path $remPsm1_kcd) {
            try {
                . $remPsm1_kcd
                $gc = Get-Command 'New-KCDRemediationScript' -ErrorAction SilentlyContinue
                if ($gc) {
                    $global:HVI_fnKCDRemediationScript = $gc
                    $global:HVI_fnKCDRemediationIndex  = Get-Command 'New-KCDRemediationIndex' -ErrorAction SilentlyContinue
                }
            }
            catch { Write-HVLog "  OPEN-61: KCD Remediation dot-source failed -- $($_.Exception.Message)" -Level Warning }
        }
    }
    if ($global:HVI_fnKCDRemediationScript) {
        Write-HVLog "  OPEN-61: KCD remediation functions loaded (New-KCDRemediationScript ready)" -Level Info
    }
    else {
        Write-HVLog "  OPEN-61: KCD remediation functions not available -- KCD scripts will not be generated this run" -Level Warning
    }

<#
.SYNOPSIS
    Comprehensive Hyper-V infrastructure inventory with Excel reporting.

.DESCRIPTION
    v3.1.0 Enhancements:
    - Secure Boot certificate detection (2011 expiring vs 2023 updated)
    - VM lifecycle tracking (HV creation date, AD creation date, first/last seen)
    - Config-driven generic credential support (no hardcoded domain names)
    
    v3.0 Fixes:
    - Background jobs now use Import-Module (not dot-source) for proper function export
    - Fixed parameter name: IncludeApplications (was CollectApplications in Core)
    - Fixed Get-StorageProvisioningAnalysis call (was missing -VMs parameter)
    - Fixed Get-ResourceRecommendations call (was passing unknown -HostData)
    - Auto-creates output directory
    - Consolidated remote collection (single Invoke-Command per host)
    - Cluster detection runs remotely
    - Guest OS via KVP exchange

.PARAMETER OutputPath
    Path where the Excel report will be saved.

.PARAMETER IncludeApplications
    Include installed applications inventory.

.PARAMETER Credential
    PSCredential object for connecting to remote hosts.

.PARAMETER UseCredSSP
    Use CredSSP authentication for multi-hop scenarios.

.PARAMETER MaxConcurrentJobs
    Maximum number of concurrent background jobs. Default: 10.

.PARAMETER HistoryPath
    Path to VM-History.json for lifecycle tracking. Defaults to same directory as OutputPath.
    If the file exists, it is read and merged with current run data.

.EXAMPLE
    Get-HyperVInventory -OutputPath "C:\Reports\HyperV.xlsx"

.EXAMPLE
    $cred = Get-Credential
    Get-HyperVInventory -Credential $cred -UseCredSSP -IncludeApplications
#>
function Get-HyperVInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeApplications,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCredSSP,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrentJobs = 10,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{},
        
        [Parameter(Mandatory=$false)]
        [string]$HistoryPath,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Basic','Intermediate','Advanced','All')]
        [string]$ReportLevel = 'Basic',
        
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeVMPatterns = @(),
        
        # SCCM Integration (v3.2.0 -- Session 6, params defined now)
        [Parameter(Mandatory=$false)]
        [switch]$IncludeSCCM,
        
        [Parameter(Mandatory=$false)]
        [string]$SCCMSiteServer,
        
        [Parameter(Mandatory=$false)]
        [string]$SCCMSiteCode,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('WMI','AdminService','CIM')]
        [string]$SCCMMethod = 'WMI',
        
        # Missing VM dropoff threshold (v3.6.1)
        [Parameter(Mandatory=$false)]
        [int]$MissingVMDropoffDays = 90,
        
        # Guest storage tracking mode (v3.6.1)
        # 'Day' = one snapshot per calendar date (immune to scheduled task drift)
        # 'Hour' = one snapshot per GuestStorageTrackingIntervalHours
        [Parameter(Mandatory=$false)]
        [ValidateSet('Day','Hour','Delta')]
        [string]$GuestStorageTrackingMode = 'Day',
        
        [Parameter(Mandatory=$false)]
        [int]$GuestStorageTrackingIntervalHours = 4,
        
        # Include monthly growth columns in VM-Guest-Storage tab (v3.6.1)
        [Parameter(Mandatory=$false)]
        [bool]$GuestStorageMonthlyColumns = $true,
        
        # Services collection filter (v3.6.1)
        # Controls StartModes collected, exclusion list, and alerting behavior.
        [Parameter(Mandatory=$false)]
        [hashtable]$ServicesFilter = @{},
        
        # Required builtin group members for local admin audit (v3.6.1 - S4-1)
        # Hashtable: GroupName -> array of required member names.
        # Members not in this list are flagged as unauthorized.
        [Parameter(Mandatory=$false)]
        [hashtable]$RequiredBuiltinMembers = @{},

        # AD Authentication Audit (v3.6.1 - S5a)
        # Collects delegation type, SPN status, LAPS status per machine from AD.
        [Parameter(Mandatory=$false)]
        [bool]$IncludeADAuthAudit = $true,

        # Roles and Features collection (v3.6.1 - S5a)
        # Collect installed Windows Roles/Features and .NET versions per VM/host.
        [Parameter(Mandatory=$false)]
        [bool]$IncludeRolesFeatures = $true
    )
    
    $startTime = Get-Date
    
    # Determine output path and CREATE DIRECTORY
    $reportTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    if (-not $OutputPath) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "HyperV-Inventory_$reportTimestamp.xlsx"
    }
    else {
        # If caller provided OutputPath, inject timestamp into the filename
        # e.g. "...\HyperV-Inventory.xlsx" -> "...\HyperV-Inventory_20260217_121756.xlsx"
        $opDir  = Split-Path $OutputPath -Parent
        $opName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
        $opExt  = [System.IO.Path]::GetExtension($OutputPath)
        # Only add timestamp if the filename doesn't already contain one (8+ digits)
        if ($opName -notmatch '\d{8}') {
            $OutputPath = Join-Path $opDir "${opName}_${reportTimestamp}${opExt}"
        }
    }
    
    # Ensure output directory exists (FIX: was not created before)
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        Write-Verbose "Created output directory: $outputDir"
    }
    
    Write-HVLog "===================================================" -Level Info
    Write-HVLog "Hyper-V Inventory Report v$script:ModuleVersion" -Level Info
    Write-HVLog "Report Level: $ReportLevel" -Level Info
    Write-HVLog "Mode: $(if ($IncludeApplications) { 'Comprehensive (with applications)' } else { 'Standard' })" -Level Info
    Write-HVLog "===================================================" -Level Info

    # CR112: Config template key audit.
    # Warns when the loaded config is missing keys defined in the public template.
    # Missing keys use built-in defaults silently -- this surfaces the gap so the
    # operator knows to run Migrate-Config.ps1 and review the new options.
    $cr112KnownKeys = @(
        'ADGroupOU','ADGroupPrefix','AGListenerNames','AppCompliance',
        # NOTE: AppsToRemove and SecurityTools are sub-keys of AppCompliance (not top-level).
        # They are intentionally excluded here -- AppCompliance above covers the parent key.
        'BackupCheckpointStaleDays','BackupVendorPatterns',
        'CAServer','CollectIOPSPerfCounters','CollectionTimeoutSeconds',
        'DebugDumpFailedTabs','DefaultMaxSnapshotAgeDays','EnableCipherAudit',
        'EnableRemediationScripts',
        'EnableResourceMetering','EnableTLSAudit','EfficientIPCredPath',
        'EfficientIPIgnoreSSL','EfficientIPServer','ExcludeHostNames',
        'GuestStorageBufferPct','GuestStorageCriticalPct',
        'GuestStorageTrackingIntervalHours','GuestStorageTrackingMode',
        'GuestStorageWarningPct','IncludeDNSValidation','IncludeDiskFormatAudit',
        'IncludeHardwareInfo','IncludeOfflineDiskCheck','IncludePermissionAudit',
        'IncludeRolesFeatures','IncludeSCCM','IncludeSPNInventoryFull',
        'IncludeVMActivityAudit','IOPSBaselines','IOPSCollectorDaysBack',
        'IOPSCollectorPath','LAPSMode','MaxHostJobParallelism',
        'MaxSnapshotWarningAgeDays','OutputPath','RBACBuiltinGroups',
        'RequiredBuiltinMembers','S2DExcludeClusterNames','S2DOnlyActiveHVClusters',
        'SCCMMethod','SCCMSiteCode','SCCMSiteServer',
        # NOTE: SecurityTools is a sub-key of AppCompliance -- not a top-level config key.
        'SplitRemediationByMachine','StorageRiskCriticalPct','StorageRiskHighPct',
        'StorageRiskMediumPct','StorageRiskMinimumCriticalGB','StorageRiskMinimumWarningGB',
        'TLSAuditIncludeVMs','VMActivityChunkSize','VMActivityDaysBack',
        'VMActivitySeparateFile','VMWinRMConnectTimeoutSec',
        'VHDChainCriticalDepth','VHDChainStaleCheckpointDays',
        'VHDChainWarningDepth'
    )
    if ($config) {
        $missingConfigKeys = @($cr112KnownKeys | Where-Object { -not $config.ContainsKey($_) })
        if ($missingConfigKeys.Count -gt 0) {
            Write-HVLog "CR112: Config is missing $($missingConfigKeys.Count) key(s) from the public template (defaults will be used). Run Migrate-Config.ps1 to sync." -Level Warning
            Write-HVLog "  CR112 missing keys: $($missingConfigKeys -join ', ')" -Level Warning
        }
        else {
            Write-HVLog "CR112: Config key check passed -- all known template keys present." -Level Info
        }
    }

    # OPEN-67: AuditScope derivation -- must be set before Step 5r (Permissions) and Step 5j (TLS).
    # Placed here, immediately after config load, so $includeVMScope is available for the entire run.
    # HostsOnly     = hosts only (classic behavior)
    # HostsAndVMs   = hosts + WinRM into guest VMs (PSDirect fallback on Hyper-V hosts)
    # Full          = HostsAndVMs + future AD computer objects
    $auditScope = 'HostsOnly'
    if ($config -and $config.ContainsKey('AuditScope')) {
        $auditScope = $config.AuditScope
    }
    $includeVMScope = ($auditScope -in @('HostsAndVMs', 'Full'))
    Write-HVLog "  OPEN-67: AuditScope = '$auditScope' (IncludeVMs = $includeVMScope)" -Level Info

    # Step 1: Discover hosts
    Write-HVLog "Step 1: Discovering Hyper-V hosts from Active Directory..." -Level Info
    $allHosts = Get-HyperVHostsFromAD -Config $config
    
    if (-not $allHosts -or $allHosts.Count -eq 0) {
        Write-HVLog "No Hyper-V hosts found in Active Directory" -Level Error
        return
    }
    
    Write-HVLog "Found $($allHosts.Count) potential Hyper-V hosts" -Level Success
    
    # Step 2: Test connectivity
    # v3.8.2: Two-tier auth per credential (Kerberos first, CredSSP fallback), with
    # multi-credential fallback. The winning credential AND auth method are stored on
    # $hostInfo so the background job uses exactly what worked during the connectivity test.
    Write-HVLog "Step 2: Testing connectivity to hosts..." -Level Info
    $accessibleHosts = [System.Collections.Generic.List[object]]::new()
    $unavailableHosts = [System.Collections.Generic.List[object]]::new()
    
    foreach ($hostInfo in $allHosts) {
        $testResult = Test-HyperVHost -ComputerName $hostInfo.FQDN -Credential $Credential -UseCredSSP:$UseCredSSP -DomainCredentials $DomainCredentials
        
        if ($testResult.IsHyperV) {
            # Track which credential AND auth method succeeded for the background job
            $effCred = if ($testResult.CredentialUsed) { $testResult.CredentialUsed } else { $Credential }
            $effAuth = if ($testResult.AuthMethod -eq 'CredSSP') { $true } else { $false }
            $hostInfo | Add-Member -NotePropertyName 'EffectiveCredential' -NotePropertyValue $effCred -Force
            $hostInfo | Add-Member -NotePropertyName 'EffectiveUseCredSSP' -NotePropertyValue $effAuth -Force
            $accessibleHosts.Add($hostInfo)
            # Build informative verbose message
            $authLabel = $testResult.AuthMethod
            $credChanged = $effCred -and $Credential -and $effCred.UserName -ne $Credential.UserName
            if ($credChanged) {
                Write-Verbose "$($hostInfo.FQDN) is accessible (fallback credential: $($effCred.UserName), auth: $authLabel)"
            }
            else {
                Write-Verbose "$($hostInfo.FQDN) is accessible (auth: $authLabel)"
            }
        }
        else {
            $unavailableHosts.Add([PSCustomObject]@{
                HostName        = $hostInfo.HostName
                FQDN            = $hostInfo.FQDN
                OperatingSystem = $hostInfo.OperatingSystem
                LastLogon       = $hostInfo.LastLogon
                Reason          = $testResult.Error
                IsOnline        = $testResult.IsOnline
            })
            Write-HVLog "$($hostInfo.HostName): $($testResult.Error)" -Level Warning
        }
    }
    
    Write-HVLog "Accessible: $($accessibleHosts.Count) / $($allHosts.Count) hosts" -Level Info
    # v3.8.2: Show auth method breakdown
    $krbCount     = @($accessibleHosts | Where-Object { -not $_.EffectiveUseCredSSP }).Count
    $credsspCount = @($accessibleHosts | Where-Object { $_.EffectiveUseCredSSP }).Count
    $fallbackCount = @($accessibleHosts | Where-Object { $_.EffectiveCredential -and $Credential -and $_.EffectiveCredential.UserName -ne $Credential.UserName }).Count
    Write-HVLog "  Auth: $krbCount Kerberos, $credsspCount CredSSP$(if ($fallbackCount -gt 0) { ", $fallbackCount using fallback credential" })" -Level Info
    
    if ($accessibleHosts.Count -eq 0) {
        Write-HVLog "No accessible hosts found. Cannot proceed." -Level Error
        return
    }
    
    # Step 3: Collect inventory
    Write-HVLog "Step 3: Collecting inventory from $($accessibleHosts.Count) hosts..." -Level Info
    
    # v3.10.12.28 OPEN-70: Read CollectionTimeoutSeconds from config; fall back to
    # application-aware defaults (7200s with apps, 300s without).
    # CollectionTimeoutSeconds is the max IDLE time (no new output) before a host
    # job is considered stuck and forcibly killed. Distinct from VMWinRMConnectTimeoutSec
    # which limits per-VM WinRM session establishment.
    if ($config -and $config.ContainsKey('CollectionTimeoutSeconds') -and $config.CollectionTimeoutSeconds -gt 0) {
        $maxIdleTime = [int]$config.CollectionTimeoutSeconds
        Write-HVLog "  Collection idle timeout: ${maxIdleTime}s (from config CollectionTimeoutSeconds)" -Level Info
    }
    else {
        $maxIdleTime = if ($IncludeApplications) { 7200 } else { 300 }
        Write-HVLog "  Collection idle timeout: ${maxIdleTime}s (default)" -Level Info
    }

    # v3.10.12.28 OPEN-70: Per-VM WinRM connect timeout passed to OS collection.
    # Controls New-PSSessionOption -OpenTimeout. A firewall DROP (no response)
    # hangs indefinitely without this; 120s is the default.
    $script:vmWinRMConnectTimeoutSec = 120
    if ($config -and $config.ContainsKey('VMWinRMConnectTimeoutSec') -and $config.VMWinRMConnectTimeoutSec -gt 0) {
        $script:vmWinRMConnectTimeoutSec = [int]$config.VMWinRMConnectTimeoutSec
    }
    Write-HVLog "  VM WinRM connect timeout: $($script:vmWinRMConnectTimeoutSec)s (config: VMWinRMConnectTimeoutSec)" -Level Info

    $script:collectionStartTime = Get-Date   # v3.10.9 CR99: Used by progress indicator
    
    # Create checkpoint directory
    $checkpointDir = Join-Path $env:TEMP "HyperV-Checkpoints-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -Path $checkpointDir -ItemType Directory -Force | Out-Null
    
    # -----------------------------------------------------------------------
    # BUILD MODULE PATHS AND JOB INITIALIZATION
    # FIX: Use Import-Module instead of dot-source for proper Export-ModuleMember
    # -----------------------------------------------------------------------
    if ($PSScriptRoot) {
        $mainModuleDir = $PSScriptRoot
    }
    else {
        $mainModuleDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    $modulesDir = Join-Path $mainModuleDir "Modules"
    
    $subModuleFiles = @(
        "HyperVInventory-Core"
        "HyperVInventory-Cluster"
        "HyperVInventory-Security"
        "HyperVInventory-OS"
        "HyperVInventory-Storage"
    )
    
    # Validate all modules exist and build import lines (prefer PSD1 manifests)
    Write-HVLog "Validating module files for background jobs..." -Level Info
    $importLines = @()
    foreach ($modName in $subModuleFiles) {
        $psd1File = Join-Path $modulesDir "$modName.psd1"
        $psm1File = Join-Path $modulesDir "$modName.psm1"
        if (Test-Path $psm1File) {
            # FIX v3.6.2: Background jobs MUST use .psm1 directly, NOT .psd1 manifest.
            # When a job runs in a new process, the manifest's RootModule path is resolved
            # relative to the job's working directory -- UNC paths fail with
            # "no valid module file was found in any module directory".
            # Loading the .psm1 directly bypasses the manifest indirection entirely.
            Write-Verbose "  [OK] $psm1File (direct psm1 for background job)"
            $importLines += "Import-Module '$psm1File' -Force"
        }
        elseif (Test-Path $psd1File) {
            # Fallback: psm1 missing, try psd1 (unusual, but guard it)
            Write-Verbose "  [OK] $psd1File (manifest fallback -- psm1 not found)"
            $importLines += "Import-Module '$psd1File' -Force"
        }
        else {
            throw "Required module not found: $psm1File"
        }
    }
    Write-HVLog "All modules validated" -Level Success
    
       # FIX (v3.6.1): InitializeDefaultDrives warning suppression.
    # Background jobs from a UNC share cannot map the FileSystem provider during
    # Import-Module, producing: "Attempting to perform the InitializeDefaultDrives
    # operation on the 'FileSystem' provider failed."
    # Bake a Set-Location to a guaranteed-local path as the first line of the job
    # init script. Must use a literal path -- $env:TEMP expands in the UNC outer
    # context and may itself be a network path.
    $initSetLoc = "if (Test-Path 'C:\Windows\Temp') { Set-Location 'C:\Windows\Temp' } elseif (Test-Path 'C:\') { Set-Location 'C:\' }"
    $initScriptText = $initSetLoc + "`r`n" + ($importLines -join "`r`n")
    $jobInitScript = [scriptblock]::Create($initScriptText)
    
    Write-Verbose "Job initialization script:`r`n$initScriptText"
    
    # Job scriptblock
    # FIX: Uses -IncludeApplications (matching Core module parameter name)
    $inventoryScriptBlock = {
        param(
            $ComputerName,
            $Credential,
            $UseCredSSP,
            $IncludeApplications,
            $CheckpointDir,
            $DomainCredentials,
            $ServicesFilter
        )
        
        # FIX (v3.6.1): Set local working dir inside the job scriptblock too.
        # The -InitializationScript Set-Location runs in a separate context; the scriptblock
        # itself also needs a local CWD to avoid InitializeDefaultDrives warnings on UNC paths.
        # FIX (v3.6.2): Suppress WarningPreference for the entire job scope to silence any
        # InitializeDefaultDrives warnings from Import-Module calls inside sub-modules
        # (e.g. Import-Module FailoverClusters called at runtime in HyperVInventory-Cluster.psm1).
        # The warning is cosmetic-only and does not affect functionality.
        $WarningPreference = 'SilentlyContinue'
        try { Set-Location -Path 'C:\Windows\Temp' -ErrorAction SilentlyContinue } catch {}
        if ((Get-Location).Path -like '\\*') {
            try { Set-Location -Path $env:SystemRoot -ErrorAction SilentlyContinue } catch {}
        }

        # FIX: Parameter name matches Get-HyperVHostInventory definition
        $data = Get-HyperVHostInventory `
            -ComputerName $ComputerName `
            -Credential $Credential `
            -UseCredSSP:$UseCredSSP `
            -IncludeApplications:$IncludeApplications `
            -DomainCredentials $DomainCredentials `
            -ServicesFilter $ServicesFilter
        
        # Save checkpoint
        if ($data) {
            $checkpointFile = Join-Path $CheckpointDir "$ComputerName.checkpoint.xml"
            try {
                $checkpointData = @{
                    HostName       = $ComputerName
                    HostInfo       = $data.HostInfo
                    VMs            = $data.VMs
                    ClusterInfo    = $data.ClusterInfo
                    Storage        = $data.Storage
                    HostFirmware   = $data.HostFirmware
                    HostUpdate     = $data.HostUpdate
                    HostReboot     = $data.HostReboot
                    JunctionAlerts = $data.JunctionAlerts
                    JunctionMap    = $data.JunctionMap
                    RebootHistory  = $data.RebootHistory
                    CollectedAt    = Get-Date
                    Phase          = "Complete"
                }
                Export-Clixml -Path $checkpointFile -InputObject $checkpointData -Depth 10 -Force
            }
            catch {
                Write-Warning "Could not save checkpoint for $ComputerName : $_"
            }
        }
        
        return $data
    }
    
    # Start background jobs
    # v3.6.1: Retry support - transient WinRM/network errors retry up to $maxJobRetries times
    $maxJobRetries  = 3    # max attempts per host (1 initial + 2 retries)
    $jobRetryDelay  = 45   # seconds to wait before relaunching a failed job
    $script:jobs        = [System.Collections.Generic.List[object]]::new()  # FIX v3.6.2: script scope so $launchJob scriptblock can write to it
    $script:jobProgress = @{}                                                # FIX v3.6.2: script scope so $launchJob scriptblock can write to it
    $hostInfoMap  = @{}    # FQDN -> hostInfo object (for retry relaunches)
    $completedHosts = [System.Collections.Generic.List[object]]::new()

    # Helper: launch one job and register it
    # v3.8.2: Uses the host's EffectiveCredential AND EffectiveUseCredSSP (set in Step 2)
    # so that each host's background job uses exactly the credential + auth method that
    # succeeded during the connectivity test. Hosts where Kerberos worked won't be
    # forced into CredSSP (which may fail due to delegation policy), and vice versa.
    $launchJob = {
        param($hostInfo, $retryNum)
        $hostCred    = if ($hostInfo.EffectiveCredential)            { $hostInfo.EffectiveCredential }   else { $Credential }
        $hostCredSSP = if ($null -ne $hostInfo.EffectiveUseCredSSP)  { $hostInfo.EffectiveUseCredSSP }   else { $UseCredSSP }
        $j = Start-Job `
            -InitializationScript $jobInitScript `
            -ScriptBlock $inventoryScriptBlock `
            -ArgumentList @(
                $hostInfo.FQDN,
                $hostCred,
                $hostCredSSP,
                $IncludeApplications,
                $checkpointDir,
                $DomainCredentials,
                $ServicesFilter
            )
        $script:jobs.Add($j)
        $script:jobProgress[$j.Id] = @{
            HostName     = $hostInfo.FQDN
            StartTime    = Get-Date
            LastActivity = Get-Date
            Completed    = $false
            RetryCount   = $retryNum
        }
        return $j
    }
    
    foreach ($hostInfo in $accessibleHosts) {
        while ((Get-Job -State Running -ErrorAction SilentlyContinue).Count -ge $MaxConcurrentJobs) {
            Start-Sleep -Milliseconds 500
        }
        $hostInfoMap[$hostInfo.FQDN] = $hostInfo
        & $launchJob $hostInfo 0 | Out-Null
    }
    
    # Monitor jobs
    # FIX v3.6.2: $script:jobs and $script:jobProgress are the authoritative collections (set in $launchJob scriptblock).
    # Alias them to local names so the monitor/harvest code below works without changes.
    $jobs        = $script:jobs
    $jobProgress = $script:jobProgress
    $checkInterval = 30
    $stuckJobs = @()
    
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
        Start-Sleep -Seconds $checkInterval
        
        $runningJobs = @($jobs | Where-Object { $_.State -eq 'Running' })
        $completedCount = @($jobs | Where-Object { $_.State -eq 'Completed' }).Count
        
        # v3.10.9 CR99: Enhanced progress indicator visible on console.
        # Shows elapsed time, completion percentage, and names of still-running hosts
        # so the operator knows the script isn't stalled.
        $totalElapsed = [math]::Round(((Get-Date) - $script:collectionStartTime).TotalMinutes, 1)
        $pctComplete = if ($jobs.Count -gt 0) { [math]::Round(($completedCount / $jobs.Count) * 100) } else { 0 }
        $runningHostNames = @($runningJobs | ForEach-Object {
            $p = $jobProgress[$_.Id]
            if ($p) { ($p.HostName -split '\.')[0] }
        }) -join ', '
        Write-HVLog "Progress: $completedCount/$($jobs.Count) hosts complete ($pctComplete%) | Elapsed: ${totalElapsed}m | Running: $runningHostNames" -Level Info

        # Verbose: show per-host status for each still-running job
        if ($VerbosePreference -ne 'SilentlyContinue') {
            foreach ($rj in $runningJobs) {
                $rp = $jobProgress[$rj.Id]
                $elapsed   = [math]::Round(((Get-Date) - $rp.StartTime).TotalSeconds)
                $idleSec   = [math]::Round(((Get-Date) - $rp.LastActivity).TotalSeconds)
                $jobState  = $rj.State

                # Peek at last output line from the child job (does NOT consume/remove it)
                $lastLine = $null
                if ($rj.ChildJobs.Count -gt 0) {
                    $cj = $rj.ChildJobs[0]
                    # Read any new output but keep it so Receive-Job still gets it later
                    $peek = $cj.Output | Select-Object -Last 1
                    if ($peek) { $lastLine = $peek.ToString().Trim() }
                    if (-not $lastLine -and $cj.Verbose.Count -gt 0) {
                        $lastLine = ($cj.Verbose | Select-Object -Last 1).Message
                    }
                    if (-not $lastLine -and $cj.Progress.Count -gt 0) {
                        $p = $cj.Progress | Select-Object -Last 1
                        $lastLine = "[$($p.Activity)] $($p.StatusDescription)"
                    }
                }
                $lastStr = if ($lastLine) { " | Last: $lastLine" } else { " | (no output)" }
                Write-Verbose "  [$jobState] $($rp.HostName) -- elapsed:${elapsed}s idle:${idleSec}s$lastStr"
            }
        }
        
        foreach ($job in $runningJobs) {
            $progress = $jobProgress[$job.Id]
            
            # Check for output activity
            $hasOutput = ($job.ChildJobs.Count -gt 0) -and (
                $job.ChildJobs[0].Output.Count -gt 0 -or 
                $job.ChildJobs[0].Verbose.Count -gt 0
            )
            
            if ($hasOutput) {
                $progress.LastActivity = Get-Date
            }
            
            # Check idle time
            $idleTime = ((Get-Date) - $progress.LastActivity).TotalSeconds
            
            if ($idleTime -gt $maxIdleTime) {
                # Only mark stuck ONCE per host (avoid duplicate checkpoint recoveries)
                $alreadyStuck = $stuckJobs | Where-Object { $_.HostName -eq $progress.HostName }
                if (-not $alreadyStuck) {
                    # v3.10.12.28 OPEN-70: Kill the job immediately on timeout instead of letting
                    # it block the entire run. A firewall DROP on a VM WinRM connection hangs
                    # indefinitely -- marking stuck but leaving the job running means the report
                    # waits for the outer Wait-Job loop to time out too (effectively forever).
                    # Killing here lets checkpoint recovery proceed right away.
                    $lastMsg = ''
                    try {
                        $lastVerbose = $job.ChildJobs[0].Verbose | Select-Object -Last 1
                        if ($lastVerbose) { $lastMsg = " | Last: $($lastVerbose.Message -replace '\r?\n.*','')" }
                    } catch { }
                    Write-HVLog "Job for $($progress.HostName) idle for $([math]::Round($idleTime))s (limit: ${maxIdleTime}s) -- forcibly stopping.${lastMsg}" -Level Warning
                    Write-HVLog "  Cause is likely a VM WinRM connection hanging (firewall DROP). Check VMWinRMConnectTimeoutSec in config." -Level Warning
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                    $stuckJobs += @{
                        Job      = $job
                        HostName = $progress.HostName
                        IdleTime = $idleTime
                    }
                }
            }
        }
    }
    
    # Handle stuck jobs with checkpoint recovery
    if ($stuckJobs.Count -gt 0) {
        Write-HVLog "Recovering $($stuckJobs.Count) stuck jobs from checkpoints" -Level Warning
        
        foreach ($stuckJob in $stuckJobs) {
            $hostname = $stuckJob.HostName
            $checkpointFile = Join-Path $checkpointDir "$hostname.checkpoint.xml"
            
            if (Test-Path $checkpointFile) {
                try {
                    $recovered = Import-Clixml -Path $checkpointFile
                    $completedHosts.Add(@{
                        HostName    = $hostname
                        HostInfo    = $recovered.HostInfo
                        VMs         = $recovered.VMs
                        ClusterInfo = $recovered.ClusterInfo
                        Storage     = if ($recovered.Storage) { $recovered.Storage } else { @() }
                        HostFirmware = $recovered.HostFirmware
                        HostUpdate  = $recovered.HostUpdate
                        HostReboot  = $recovered.HostReboot
                        JunctionAlerts = if ($recovered.JunctionAlerts) { $recovered.JunctionAlerts } else { @() }
                        JunctionMap = if ($recovered.JunctionMap) { $recovered.JunctionMap } else { @{} }
                        RebootHistory = if ($recovered.RebootHistory) { $recovered.RebootHistory } else { @() }
                    })
                    Write-HVLog "Recovered: $hostname ($($recovered.VMs.Count) VMs)" -Level Success
                }
                catch {
                    Write-HVLog "Failed to recover checkpoint for $hostname : $_" -Level Error
                }
            }
            
            Stop-Job -Job $stuckJob.Job -ErrorAction SilentlyContinue
        }
    }
    
    # Collect results from completed jobs
    # v3.6.1: Hosts that fail with transient WinRM/network errors are retried up to $maxJobRetries times
    $stuckHostNames  = @($stuckJobs | ForEach-Object { $_.HostName })
    $retryQueue      = [System.Collections.Generic.List[hashtable]]::new()
    $successfulHosts = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($job in $jobs) {
        $progress = $jobProgress[$job.Id]
        $hostname = $progress.HostName

        # Skip if already recovered from checkpoint
        if ($stuckHostNames -contains $hostname) {
            $successfulHosts.Add($hostname) | Out-Null
            continue
        }

        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobErrors

        if ($result) {
            $completedHosts.Add($result)
            $duration = ((Get-Date) - $progress.StartTime).TotalSeconds
            Write-Verbose "$hostname completed in $([math]::Round($duration,1))s"
            $successfulHosts.Add($hostname) | Out-Null
        }
        elseif ($jobErrors) {
            # Classify errors - transient WinRM/network errors are retryable
            $retryablePatterns = @('WinRM','cannot complete the operation','network path','RPC',
                                   'timed out','The remote procedure call','connection was forcibly closed')
            $isRetryable = $false
            $errMsg = ''
            foreach ($err in $jobErrors) {
                $errMsg = $err.Exception.Message
                foreach ($pat in $retryablePatterns) {
                    if ($errMsg -like "*$pat*") { $isRetryable = $true; break }
                }
                if ($isRetryable) { break }
            }

            $currentRetry = $progress.RetryCount
            if ($isRetryable -and $currentRetry -lt ($maxJobRetries - 1)) {
                $nextRetry = $currentRetry + 1
                Write-HVLog "  $hostname failed (attempt $($currentRetry+1)/$maxJobRetries) - queued for retry in ${jobRetryDelay}s: $errMsg" -Level Warning
                $retryQueue.Add(@{ HostInfo = $hostInfoMap[$hostname]; RetryNum = $nextRetry })
            }
            else {
                Write-HVLog "Error inventorying $hostname : $errMsg" -Level Error
            }
        }
        else {
            Write-HVLog "$hostname returned no data" -Level Warning
        }
    }

    # Process retry queue - wait then relaunch failed jobs
    while ($retryQueue.Count -gt 0) {
        Write-HVLog "Retrying $($retryQueue.Count) host(s) after ${jobRetryDelay}s delay..." -Level Info
        Start-Sleep -Seconds $jobRetryDelay

        $currentBatch = @($retryQueue)
        $retryQueue.Clear()
        $retryJobs = @()

        foreach ($entry in $currentBatch) {
            while ((Get-Job -State Running -ErrorAction SilentlyContinue).Count -ge $MaxConcurrentJobs) {
                Start-Sleep -Milliseconds 500
            }
            Write-HVLog "  Retry attempt $($entry.RetryNum)/$($maxJobRetries-1): $($entry.HostInfo.FQDN)" -Level Info
            $rj = & $launchJob $entry.HostInfo $entry.RetryNum
            $retryJobs += $rj
        }

        # Wait for this retry batch
        while (($retryJobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
            Start-Sleep -Seconds $checkInterval
            $rc = @($retryJobs | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' }).Count
            $rr = @($retryJobs | Where-Object { $_.State -eq 'Running' }).Count
            Write-HVLog "Retry progress: $rc/$($retryJobs.Count) done, $rr running..." -Level Info
        }

        # Collect retry results
        foreach ($rj in $retryJobs) {
            $progress = $jobProgress[$rj.Id]
            $hostname = $progress.HostName
            $result   = Receive-Job -Job $rj -ErrorAction SilentlyContinue -ErrorVariable rjErrors
            if ($result) {
                $completedHosts.Add($result)
                $duration = ((Get-Date) - $progress.StartTime).TotalSeconds
                Write-HVLog "  Retry succeeded: $hostname ($([math]::Round($duration,1))s)" -Level Success
                $successfulHosts.Add($hostname) | Out-Null
            }
            elseif ($rjErrors) {
                $errMsg       = $rjErrors[0].Exception.Message
                $currentRetry = $progress.RetryCount
                if ($currentRetry -lt ($maxJobRetries - 1)) {
                    $retryQueue.Add(@{ HostInfo = $hostInfoMap[$hostname]; RetryNum = $currentRetry + 1 })
                    Write-HVLog "  $hostname still failing (attempt $($currentRetry+1)/$maxJobRetries) - queued again" -Level Warning
                }
                else {
                    Write-HVLog "  $hostname failed after $maxJobRetries attempts: $errMsg" -Level Error
                }
            }
            else {
                Write-HVLog "  Retry: $hostname returned no data" -Level Warning
            }
        }
        $retryJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }

        # Clean up
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    if (Test-Path $checkpointDir) {
        Remove-Item -Path $checkpointDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Write-HVLog "Inventory collection complete: $($completedHosts.Count) hosts" -Level Success
    
    # Step 4: Discover clusters (host-side data + AD cross-reference)
    Write-HVLog "Step 4: Discovering Hyper-V clusters..." -Level Info
    
    # 4a: Build cluster inventory from HOST-SIDE collected data (primary source)
    $discoveredClusters = @{}
    foreach ($hostData in $completedHosts) {
        if (-not $hostData.ClusterInfo -or -not $hostData.ClusterInfo.ClusterName) { continue }
        $clsName = $hostData.ClusterInfo.ClusterName
        if (-not $discoveredClusters.ContainsKey($clsName)) {
            $discoveredClusters[$clsName] = @{
                ClusterName = $clsName
                Nodes       = [System.Collections.Generic.List[string]]::new()
                NodeStates  = @{}
            }
        }
        $nodeName = $hostData.HostName
        if (-not $nodeName -and $hostData.HostInfo) { $nodeName = $hostData.HostInfo.Host }
        if ($nodeName -and -not $discoveredClusters[$clsName].Nodes.Contains($nodeName)) {
            $discoveredClusters[$clsName].Nodes.Add($nodeName)
            $discoveredClusters[$clsName].NodeStates[$nodeName] = $hostData.ClusterInfo.NodeState
        }
    }
    
    if ($discoveredClusters.Count -gt 0) {
        Write-HVLog "Found $($discoveredClusters.Count) active cluster(s) from host inventory" -Level Success
        foreach ($cls in $discoveredClusters.Values) {
            Write-HVLog "  Cluster: $($cls.ClusterName) ($($cls.Nodes.Count) nodes: $($cls.Nodes -join ', '))" -Level Info
        }
    }
    
    # 4b: Get detailed cluster resources via Invoke-Command on a known node
    foreach ($cls in $discoveredClusters.Values) {
        $targetNode = $cls.Nodes | Select-Object -First 1
        if (-not $targetNode) { continue }
        
        try {
            $invokeParams = @{ ComputerName = $targetNode; ErrorAction = 'Stop' }
            if ($UseCredSSP -and $Credential) {
                $invokeParams['Authentication'] = 'Credssp'
                $invokeParams['Credential'] = $Credential
            }
            elseif ($Credential) {
                $invokeParams['Credential'] = $Credential
            }
            
            $clusterDetail = Invoke-Command @invokeParams -ScriptBlock {
                try {
                    $cluster = Get-Cluster -ErrorAction Stop
                    $nodes = Get-ClusterNode -ErrorAction Stop
                    $resources = Get-ClusterResource -ErrorAction SilentlyContinue
                    $groups = Get-ClusterGroup -ErrorAction SilentlyContinue
                    $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
                    $quorum = Get-ClusterQuorum -ErrorAction SilentlyContinue
                    $networks = Get-ClusterNetwork -ErrorAction SilentlyContinue
                    
                    @{
                        ClusterName  = $cluster.Name
                        ClusterDomain = $cluster.Domain
                        AllNodes     = @($nodes | ForEach-Object { @{ Name = $_.Name; State = $_.State.ToString() } })
                        Resources    = @($resources | ForEach-Object {
                            @{
                                Name         = $_.Name
                                ResourceType = $_.ResourceType.Name
                                OwnerGroup   = $_.OwnerGroup.Name
                                State        = $_.State.ToString()
                                OwnerNode    = $_.OwnerNode.Name
                            }
                        })
                        Groups       = @($groups | ForEach-Object {
                            @{
                                Name       = $_.Name
                                State      = $_.State.ToString()
                                OwnerNode  = $_.OwnerNode.Name
                                GroupType  = $_.GroupType.ToString()
                            }
                        })
                        CSVCount     = if ($csvs) { $csvs.Count } else { 0 }
                        CSVs         = @($csvs | ForEach-Object { @{ Name = $_.Name; State = $_.State.ToString() } })
                        QuorumType   = if ($quorum) { $quorum.QuorumType.ToString() } else { 'Unknown' }
                        QuorumResource = if ($quorum -and $quorum.QuorumResource) { $quorum.QuorumResource.Name } else { 'N/A' }
                        Networks     = @($networks | ForEach-Object { @{ Name = $_.Name; State = $_.State.ToString(); Role = $_.Role.ToString() } })
                    }
                }
                catch { @{ Error = $_.Exception.Message } }
            }
            
            if ($clusterDetail -and -not $clusterDetail.Error) {
                $cls['Detail'] = $clusterDetail
                $cls['AllNodes'] = $clusterDetail.AllNodes
                $cls['Resources'] = $clusterDetail.Resources
                $cls['Groups'] = $clusterDetail.Groups
                $cls['CSVCount'] = $clusterDetail.CSVCount
                $cls['CSVs'] = $clusterDetail.CSVs
                $cls['QuorumType'] = $clusterDetail.QuorumType
                $cls['QuorumResource'] = $clusterDetail.QuorumResource
                $cls['Networks'] = $clusterDetail.Networks
                $cls['Domain'] = $clusterDetail.ClusterDomain
                Write-HVLog "  Cluster $($cls.ClusterName): $($clusterDetail.Resources.Count) resources, $($clusterDetail.Groups.Count) groups, $($clusterDetail.CSVCount) CSVs" -Level Info
            }
            else {
                Write-HVLog "  Cluster $($cls.ClusterName): resource query failed: $($clusterDetail.Error)" -Level Warning
            }
        }
        catch {
            Write-HVLog "  Could not query cluster $($cls.ClusterName) via node $targetNode : $($_.Exception.Message)" -Level Warning
        }
    }
    
    # 4c: AD cross-reference -- find ALL cluster SPN objects, classify against discovered
    $clusters = [System.Collections.Generic.List[object]]::new()
    $discoveredClusterNames = @($discoveredClusters.Keys | ForEach-Object { $_.ToUpper() })
    # Also build a lookup of all resource/group names per cluster
    $resourceToCluster = @{}
    foreach ($cls in $discoveredClusters.Values) {
        if ($cls.Resources) {
            foreach ($r in $cls.Resources) {
                if ($r.Name) { $resourceToCluster[$r.Name.ToUpper()] = $cls.ClusterName }
            }
        }
        if ($cls.Groups) {
            foreach ($g in $cls.Groups) {
                if ($g.Name) { $resourceToCluster[$g.Name.ToUpper()] = $cls.ClusterName }
            }
        }
    }
    
    # Build VM-name-to-host lookup for VM-hosted cluster detection (SCVMM, WAC, SQL VMs)
    $vmNameToHost = @{}
    foreach ($hostData in $completedHosts) {
        if (-not $hostData.VMs) { continue }
        $hvHostName = if ($hostData.HostName) { $hostData.HostName } elseif ($hostData.HostInfo) { $hostData.HostInfo.Host } else { '' }
        foreach ($vm in $hostData.VMs) {
            $vn = if ($vm.VM) { $vm.VM.ToUpper() } else { '' }
            if ($vn) { $vmNameToHost[$vn] = $hvHostName }
        }
    }
    
    try {
        $adParams = @{
            Filter     = {ServicePrincipalName -like "MSClusterVirtualServer/*"}
            Properties = @('ServicePrincipalName', 'CN', 'DNSHostName', 'Description', 'LastLogonDate', 'whenCreated')
            ErrorAction = 'Stop'
        }
        $adClusterObjects = @(Get-ADComputer @adParams)
        
        Write-HVLog "Found $($adClusterObjects.Count) cluster AD objects - classifying..." -Level Info
        
        foreach ($adObj in $adClusterObjects) {
            $objName = $adObj.Name.ToUpper()
            $lastLogon = $adObj.LastLogonDate
            $ageDays = if ($lastLogon) { ((Get-Date) - $lastLogon).Days } else { 9999 }
            
            $clusterEntry = @{
                ClusterName    = $adObj.Name
                Domain         = ($adObj.DNSHostName -split '\.', 2)[1]
                FQDN           = $adObj.DNSHostName
                ClusterType    = 'Unknown'
                ParentCluster  = ''
                Status         = 'Unknown'
                Nodes          = ''
                NodeCount      = 0
                Resources      = ''
                CSVCount       = 0
                QuorumType     = ''
                LastLogon      = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { 'Never' }
                ADObjectAge    = "${ageDays}d"
                ADCreated      = if ($adObj.whenCreated) { $adObj.whenCreated.ToString('yyyy-MM-dd') } else { '' }
                Recommendation = ''
                Error          = ''
            }
            
            # Classify
            if ($discoveredClusterNames -contains $objName) {
                # This is a real active cluster we discovered from hosts
                $cls = $discoveredClusters[$adObj.Name]
                $clusterEntry.ClusterType   = 'HyperV-Cluster'
                $clusterEntry.Status        = 'Active'
                $allNodes = if ($cls.AllNodes) { $cls.AllNodes } else { @() }
                $clusterEntry.Nodes         = ($allNodes | ForEach-Object { "$($_.Name) ($($_.State))" }) -join '; '
                $clusterEntry.NodeCount     = $allNodes.Count
                $clusterEntry.CSVCount      = if ($cls.CSVCount) { $cls.CSVCount } else { 0 }
                $clusterEntry.QuorumType    = if ($cls.QuorumType) { $cls.QuorumType } else { '' }
                $clusterEntry.Resources     = if ($cls.Groups) {
                    ($cls.Groups | Where-Object { $_.Name -ne 'Cluster Group' } | ForEach-Object { "$($_.Name) [$($_.State)]" }) -join '; '
                } else { '' }
                $clusterEntry.Recommendation = ''
            }
            elseif ($resourceToCluster.ContainsKey($objName)) {
                # This AD object matches a cluster resource/group name (Role VNN, AG Listener, etc.)
                $parentName = $resourceToCluster[$objName]
                $clusterEntry.ClusterType   = 'ClusterRole'
                $clusterEntry.ParentCluster = $parentName
                $clusterEntry.Status        = 'Active'
                
                # Try to determine role type from the parent cluster resources
                $parentCls = $discoveredClusters[$parentName]
                $matchingResource = $null
                if ($parentCls.Resources) {
                    $matchingResource = $parentCls.Resources | Where-Object { $_.Name -eq $adObj.Name } | Select-Object -First 1
                }
                $matchingGroup = $null
                if ($parentCls.Groups) {
                    $matchingGroup = $parentCls.Groups | Where-Object { $_.Name -eq $adObj.Name } | Select-Object -First 1
                }
                
                if ($matchingResource -and $matchingResource.ResourceType -match 'SQL|Network Name|IP Address') {
                    $clusterEntry.ClusterType = 'SQL-Listener'
                }
                elseif ($matchingGroup) {
                    $clusterEntry.ClusterType = "ClusterRole ($($matchingGroup.GroupType))"
                    $clusterEntry.Status = $matchingGroup.State
                }
                
                $clusterEntry.Recommendation = ''
            }
            else {
                # Not discovered from hosts -- check if stale, VM-hosted, or external
                if ($ageDays -gt 90) {
                    $clusterEntry.ClusterType   = 'Stale'
                    $clusterEntry.Status        = 'Stale (AD Only)'
                    $clusterEntry.Recommendation = "AD object last active ${ageDays}d ago. Verify and remove if decommissioned."
                }
                elseif ($ageDays -gt 30) {
                    $clusterEntry.ClusterType   = 'Unreachable'
                    $clusterEntry.Status        = 'Not Inventoried'
                    $clusterEntry.Recommendation = "Last logon ${ageDays}d ago. Not on any discovered HV host. Verify status."
                }
                else {
                    # Active but not a HV host cluster
                    # Check 1: Is this CNO a resource/group in a discovered HV cluster?
                    if ($resourceToCluster.ContainsKey($objName)) {
                        $parentCls = $resourceToCluster[$objName]
                        $clusterEntry.ClusterType = 'ClusterRole'
                        $clusterEntry.ParentCluster = $parentCls
                        $clusterEntry.Status = 'Active (Role in HV Cluster)'
                        $clusterEntry.Recommendation = "Cluster role VNN inside $parentCls"
                    }
                    # Check 2: Is this CNO name also a VM name in our inventory? (VM-hosted cluster)
                    elseif ($vmNameToHost.ContainsKey($objName)) {
                        $hvHost = $vmNameToHost[$objName]
                        $clusterEntry.ClusterType = 'VM-Hosted'
                        $clusterEntry.Status = 'Active (VM-Hosted)'
                        $clusterEntry.Recommendation = "CNO matches VM $objName on $hvHost"
                    }
                    else {
                        # Check 3: Try Invoke-Command on CNO to get nodes, then match against VMs
                        $vmHostedOn = ''
                        try {
                            $icParams = @{ ComputerName = $adObj.DNSHostName; ErrorAction = 'Stop' }
                            if ($Credential) { $icParams['Credential'] = $Credential }
                            if ($UseCredSSP -and $Credential) { $icParams['Authentication'] = 'Credssp' }
                            
                            $nodeData = Invoke-Command @icParams -ScriptBlock {
                                try {
                                    $n = Get-ClusterNode -ErrorAction Stop
                                    $g = Get-ClusterGroup -ErrorAction SilentlyContinue
                                    @{
                                        Nodes = @($n | ForEach-Object { @{ Name = $_.Name; State = $_.State.ToString() } })
                                        Groups = @($g | ForEach-Object { @{ Name = $_.Name; State = $_.State.ToString(); GroupType = $_.GroupType.ToString() } })
                                    }
                                }
                                catch { @{ Error = $_.Exception.Message } }
                            }
                            
                            if ($nodeData -and -not $nodeData.Error -and $nodeData.Nodes) {
                                $clusterEntry.Nodes = ($nodeData.Nodes | ForEach-Object { "$($_.Name) ($($_.State))" }) -join '; '
                                $clusterEntry.NodeCount = $nodeData.Nodes.Count
                                if ($nodeData.Groups) {
                                    $clusterEntry.Resources = ($nodeData.Groups | Where-Object { $_.Name -ne 'Cluster Group' } | ForEach-Object { "$($_.Name) [$($_.State)]" }) -join '; '
                                }
                                foreach ($nodeName in @($nodeData.Nodes | ForEach-Object { $_.Name })) {
                                    if ($vmNameToHost.ContainsKey($nodeName.ToUpper())) {
                                        $hvHost = $vmNameToHost[$nodeName.ToUpper()]
                                        $vmHostedOn = if ($vmHostedOn) { "$vmHostedOn; $nodeName->$hvHost" } else { "$nodeName->$hvHost" }
                                    }
                                }
                            }
                        }
                        catch { }
                        
                        if ($vmHostedOn) {
                            $clusterEntry.ClusterType   = 'VM-Hosted'
                            $clusterEntry.Status        = 'Active (VM-Hosted)'
                            $clusterEntry.Recommendation = "Cluster nodes are VMs: $vmHostedOn"
                        }
                        else {
                            $clusterEntry.ClusterType   = 'Non-HyperV'
                            $clusterEntry.Status        = 'Active (Non-HV)'
                            $clusterEntry.Recommendation = "Active cluster not on any HV host. May be SQL-only or app cluster."
                        }
                    }
                }
            }
            
            $clusters.Add([PSCustomObject]$clusterEntry)
        }
    }
    catch {
        Write-HVLog "AD cluster object query failed: $($_.Exception.Message)" -Level Warning
    }
    
    # Summary
    $activeCount   = @($clusters | Where-Object { $_.Status -eq 'Active' }).Count
    $vmHostedCount = @($clusters | Where-Object { $_.ClusterType -eq 'VM-Hosted' }).Count
    $roleCount     = @($clusters | Where-Object { $_.ClusterType -match 'ClusterRole' }).Count
    $staleCount    = @($clusters | Where-Object { $_.ClusterType -eq 'Stale' }).Count
    $nonHVCount    = @($clusters | Where-Object { $_.ClusterType -eq 'Non-HyperV' }).Count
    Write-HVLog "Cluster summary: $activeCount active HV clusters, $vmHostedCount VM-hosted, $roleCount roles, $staleCount stale, $nonHVCount non-HV" -Level Success
    
    if ($clusters.Count -gt 0) {
        Write-HVLog "Found $($clusters.Count) cluster object(s)" -Level Success
    }
    
    # Step 4b: VM Lifecycle - AD whenCreated batch lookup
    Write-HVLog "Step 4b: Enriching VM lifecycle data (AD creation dates)..." -Level Info
    
    $adCreatedLookup = @{}
    $adNameLookup = @{}
    try {
        # Batch query: get ALL AD computer accounts with whenCreated + Name in one call
        $adComputers = Get-ADComputer -Filter * -Properties whenCreated, DNSHostName -ErrorAction Stop
        foreach ($adc in $adComputers) {
            $adCreatedLookup[$adc.Name.ToUpper()] = $adc.whenCreated
            $adNameLookup[$adc.Name.ToUpper()] = $adc.Name
        }
        Write-HVLog "Loaded $($adCreatedLookup.Count) AD computer accounts for lifecycle correlation" -Level Success
    }
    catch {
        Write-HVLog "AD batch query failed (lifecycle will have partial data): $($_.Exception.Message)" -Level Warning
    }
    
    # Apply AD whenCreated + AD Name to all VMs
    foreach ($hostData in $completedHosts) {
        if (-not $hostData.VMs) { continue }
        foreach ($vm in $hostData.VMs) {
            $vmNameUpper = $vm.VM.ToUpper()
            if ($adCreatedLookup.ContainsKey($vmNameUpper)) {
                $vm.AD_WhenCreated = $adCreatedLookup[$vmNameUpper].ToString('o')
                $vm | Add-Member -NotePropertyName 'AD_ComputerName' -NotePropertyValue $adNameLookup[$vmNameUpper] -Force
            }
            else {
                $vm | Add-Member -NotePropertyName 'AD_ComputerName' -NotePropertyValue '' -Force
            }
        }
    }
    
    # Step 4c: VM History - Read/merge/write VM-History.json
    Write-HVLog "Step 4c: Processing VM lifecycle history..." -Level Info
    
    if (-not $HistoryPath) {
        $HistoryPath = Join-Path (Split-Path $OutputPath -Parent) "VM-History.json"
    }
    
    $vmHistory = @{}
    $missingVMs = @()
    $todayISO = (Get-Date).ToString('yyyy-MM-dd')
    
    # Read existing history
    if (Test-Path $HistoryPath) {
        try {
            $rawJson = Get-Content -Path $HistoryPath -Raw -ErrorAction Stop
            $vmHistory = $rawJson | ConvertFrom-Json -ErrorAction Stop
            # ConvertFrom-Json returns PSCustomObject; convert to working hashtable
            $tempHistory = @{}
            foreach ($prop in $vmHistory.PSObject.Properties) {
                $tempHistory[$prop.Name] = $prop.Value
            }
            $vmHistory = $tempHistory
            Write-HVLog "Loaded VM history: $($vmHistory.Count) entries from $HistoryPath" -Level Info
        }
        catch {
            Write-HVLog "Could not read VM history (starting fresh): $($_.Exception.Message)" -Level Warning
            $vmHistory = @{}
        }
    }
    else {
        Write-HVLog "No existing VM history file. Creating new: $HistoryPath" -Level Info
    }
    
    # Build set of current VMs for missing-VM detection (by VMId if available, fallback to name)
    $currentVMIds = @{}
    $currentVMNames = @{}
    foreach ($hostData in $completedHosts) {
        if (-not $hostData.VMs) { continue }
        foreach ($vm in $hostData.VMs) {
            $vmNameKey = $vm.VM.ToUpper()
            $vmIdKey = if ($vm.VMId) { "VMID:$($vm.VMId)" } else { $null }
            $currentVMNames[$vmNameKey] = $true
            if ($vmIdKey) { $currentVMIds[$vmIdKey] = $vmNameKey }
            
            # Prefer VMId key for history, fall back to name
            $histKey = if ($vmIdKey -and $vmHistory.ContainsKey($vmIdKey)) { $vmIdKey }
                       elseif ($vmHistory.ContainsKey($vmNameKey)) { $vmNameKey }
                       elseif ($vmIdKey) { $vmIdKey }
                       else { $vmNameKey }
            
            # Merge into history
            if ($vmHistory.ContainsKey($histKey)) {
                $entry = $vmHistory[$histKey]
                $entry.LastSeen = $todayISO
                if ($vm.VMId -and -not $entry.VMId) { $entry | Add-Member -NotePropertyName 'VMId' -NotePropertyValue $vm.VMId -Force }
                if ($entry.VMName -ne $vm.VM) { $entry | Add-Member -NotePropertyName 'VMName' -NotePropertyValue $vm.VM -Force }
                $hostList = @($entry.Hosts)
                if ($hostList -notcontains $vm.Host) {
                    $hostList += $vm.Host
                    $entry.Hosts = $hostList
                }
                # If old name-keyed entry exists and we now have VMId, migrate to VMId key
                if ($vmIdKey -and $histKey -eq $vmNameKey -and $vmIdKey -ne $vmNameKey) {
                    $vmHistory[$vmIdKey] = $entry
                    $vmHistory.Remove($vmNameKey)
                    $histKey = $vmIdKey
                }
            }
            else {
                $vmHistory[$histKey] = [PSCustomObject]@{
                    VMName    = $vm.VM
                    VMId      = $vm.VMId
                    FirstSeen = $todayISO
                    LastSeen  = $todayISO
                    Hosts     = @($vm.Host)
                }
            }
            
            # Attach history to VM for export
            $histEntry = $vmHistory[$histKey]
            $vm | Add-Member -NotePropertyName 'FirstSeenInReport' -NotePropertyValue $histEntry.FirstSeen -Force
            $vm | Add-Member -NotePropertyName 'LastSeenInReport'  -NotePropertyValue $histEntry.LastSeen -Force
        }
    }
    
    # Identify VMs in history that are NOT in current run
    # v3.6.1: Apply MissingVMDropoffDays - prune entries older than threshold from
    # both the Missing-VMs tab output AND the VM-History.json file.
    $dropoffDays    = if ($MissingVMDropoffDays -gt 0) { $MissingVMDropoffDays } else { [int]::MaxValue }
    $keysToRemove   = [System.Collections.Generic.List[string]]::new()
    
    foreach ($vmKey in @($vmHistory.Keys)) {
        $hist = $vmHistory[$vmKey]
        $isPresent = $false
        if ($vmKey -match '^VMID:' -and $currentVMIds.ContainsKey($vmKey)) { $isPresent = $true }
        elseif ($currentVMNames.ContainsKey($vmKey)) { $isPresent = $true }
        elseif ($hist.VMName -and $currentVMNames.ContainsKey($hist.VMName.ToUpper())) { $isPresent = $true }
        
        if (-not $isPresent) {
            $displayName = if ($hist.VMName) { $hist.VMName } else { $vmKey }
            $lastSeenDate = [datetime]::Parse($hist.LastSeen)
            $daysSince = ((Get-Date) - $lastSeenDate).Days
            
            # Prune entries that have exceeded the dropoff threshold
            if ($daysSince -gt $dropoffDays) {
                $keysToRemove.Add($vmKey)
                Write-Verbose "Pruning from history (${daysSince}d > ${dropoffDays}d dropoff): $displayName"
                continue
            }
            
            # Tiered status labels
            $status = if     ($daysSince -le 7)            { 'Recently Missing' }
                      elseif ($daysSince -le 30)            { 'Extended Absence' }
                      elseif ($daysSince -le $dropoffDays)  { 'Likely Decommissioned' }
                      else                                   { 'Confirmed Gone' }
            
            $missingVMs += [PSCustomObject]@{
                VM                = $displayName
                VMId              = if ($hist.VMId) { $hist.VMId } else { '' }
                FirstSeen         = $hist.FirstSeen
                LastSeen          = $hist.LastSeen
                DaysSinceLastSeen = $daysSince
                PreviousHosts     = ($hist.Hosts -join '; ')
                Status            = $status
                DropoffIn         = "$($dropoffDays - $daysSince)d"
            }
        }
    }
    
    # Prune expired entries from history before saving
    foreach ($key in $keysToRemove) { $vmHistory.Remove($key) }
    if ($keysToRemove.Count -gt 0) {
        Write-HVLog "Pruned $($keysToRemove.Count) expired VM history entries (>${dropoffDays}d absent)" -Level Info
    }
    
    # Write updated history
    try {
        $historyDir = Split-Path $HistoryPath -Parent
        if (-not (Test-Path $historyDir)) {
            New-Item -Path $historyDir -ItemType Directory -Force | Out-Null
        }
        $vmHistory | ConvertTo-Json -Depth 5 | Set-Content -Path $HistoryPath -Force
        Write-HVLog "VM history saved: $($vmHistory.Count) entries ($($missingVMs.Count) missing from current run)" -Level Success
    }
    catch {
        Write-HVLog "Could not save VM history: $($_.Exception.Message)" -Level Warning
    }
    
    # Step 4d: VM Name Exclusion Filter (built-in patterns always apply)
    Write-HVLog "Step 4d: Applying VM name exclusion filters..." -Level Info
    $excludeCount = 0
    foreach ($hostData in $completedHosts) {
        if (-not $hostData.VMs) { continue }
        $filteredVMs = @()
        foreach ($vm in $hostData.VMs) {
            $vmName = $vm.VM
            $exclude = $false
            
            # Built-in exclusions: names starting with _ or ... or -- 
            if ($vmName -match '^\.\.\.' -or $vmName -match '^--' -or $vmName -match '^_') { $exclude = $true }
            # Built-in exclusions: names containing (DO NOT DELETE) or (DO_NOT_DELETE) or ...
            if ($vmName -match '\(DO[_ ]NOT[_ ]DELETE\)' -or ($vmName -match '\.\.\.' -and $vmName -notmatch '^\.\.\.' )) { $exclude = $true }
            
            # Custom exclusion patterns from config/parameter
            if (-not $exclude -and $ExcludeVMPatterns -and $ExcludeVMPatterns.Count -gt 0) {
                foreach ($pattern in $ExcludeVMPatterns) {
                    if ($vmName -like $pattern) { $exclude = $true; break }
                }
            }
            
            if ($exclude) {
                $excludeCount++
                Write-Verbose "Excluding VM: $vmName (matched exclusion pattern)"
            }
            else {
                $filteredVMs += $vm
            }
        }
        $hostData.VMs = $filteredVMs
    }
    if ($excludeCount -gt 0) {
        Write-HVLog "Excluded $excludeCount VMs by name pattern filter" -Level Info
    }
    
    # Step 5: Analysis
    Write-HVLog "Step 5: Running analysis..." -Level Info
    
    $cpuAnalysis = Get-CPUAllocationAnalysis -HostData @($completedHosts)
    
    # FIX: Extract VMs from completedHosts for storage analysis
    $allVMs = @()
    foreach ($h in $completedHosts) {
        if ($h.VMs) {
            foreach ($vm in $h.VMs) {
                # Ensure HostName is on VM for storage analysis
                if (-not $vm.HostName) { $vm.HostName = $h.HostName }
                $allVMs += $vm
            }
        }
    }
    
    # FIX: Pass both -Hosts and -VMs (was only passing -Hosts)
    # v3.9.8 CR69: Configurable storage risk thresholds + minimum GB floor
    $storageAnalysis = $null
    try {
        $storageParams = @{
            Hosts = @($completedHosts)
            VMs   = $allVMs
        }
        if ($config.StorageRiskCriticalPct)      { $storageParams['CriticalPct']      = $config.StorageRiskCriticalPct }
        if ($config.StorageRiskHighPct)           { $storageParams['HighPct']           = $config.StorageRiskHighPct }
        if ($config.StorageRiskMediumPct)         { $storageParams['MediumPct']         = $config.StorageRiskMediumPct }
        if ($config.StorageRiskMinimumCriticalGB) { $storageParams['MinimumCriticalGB'] = $config.StorageRiskMinimumCriticalGB }
        if ($config.StorageRiskMinimumWarningGB)  { $storageParams['MinimumWarningGB']  = $config.StorageRiskMinimumWarningGB }
        $storageAnalysis = Get-StorageProvisioningAnalysis @storageParams
    }
    catch {
        Write-HVLog "Storage analysis skipped (storage data collected remotely): $($_.Exception.Message)" -Level Warning
    }
    
    $complianceCheck = Test-ComplianceStatus -HostData @($completedHosts)
    
    # FIX: Don't pass -HostData (parameter doesn't exist on this function)
    $recommendations = Get-ResourceRecommendations -CPUAnalysis $cpuAnalysis -StorageAnalysis $storageAnalysis
    
    # Step 5b: Guest Storage History - read/merge/write GuestStorage-History.json
    # Tracks per-VM per-drive UsedGB over time for growth rate projection.
    #
    # DAY mode  - one point per calendar date; immune to scheduled task time drift.
    # HOUR mode - one point per GuestStorageTrackingIntervalHours; for multi-run days.
    $modeLabel = if ($GuestStorageTrackingMode -eq 'Hour') {
        "Hour (interval: ${GuestStorageTrackingIntervalHours}h)" } else { 'Day (one per calendar date)' }
    Write-HVLog "Step 5b: Processing VM guest storage history (mode: $modeLabel)..." -Level Info
    
    $guestStorageHistoryPath = Join-Path (Split-Path $HistoryPath -Parent) "GuestStorage-History.json"
    $guestStorageHistory = @{}
    
    if (Test-Path $guestStorageHistoryPath) {
        try {
            $rawGSH = Get-Content -Path $guestStorageHistoryPath -Raw -ErrorAction Stop
            $gshObj = $rawGSH | ConvertFrom-Json -ErrorAction Stop
            foreach ($prop in $gshObj.PSObject.Properties) { $guestStorageHistory[$prop.Name] = $prop.Value }
            Write-HVLog "Loaded guest storage history: $($guestStorageHistory.Count) VM entries" -Level Info
        }
        catch {
            Write-HVLog "Could not read guest storage history (starting fresh): $($_.Exception.Message)" -Level Warning
            $guestStorageHistory = @{}
        }
    }
    
    $nowLocal      = Get-Date
    $nowUtc        = $nowLocal.ToUniversalTime()
    $nowIso        = $nowUtc.ToString('o')
    $nowDateOnly   = $nowLocal.ToString('yyyy-MM-dd')
    $intervalMins  = $GuestStorageTrackingIntervalHours * 60
    $snapshotCount = 0
    $skippedCount  = 0
    
    foreach ($hostData in $completedHosts) {
        if (-not $hostData.VMs) { continue }
        foreach ($vm in $hostData.VMs) {
            if (-not $vm.GuestDisks -or $vm.GuestDisks.Count -eq 0) { continue }
            $vmKey = if ($vm.VMId) { "VMID:$($vm.VMId)" } else { $vm.VM.ToUpper() }
            
            if (-not $guestStorageHistory.ContainsKey($vmKey)) {
                $guestStorageHistory[$vmKey] = [PSCustomObject]@{
                    VMName = $vm.VM; VMId = if ($vm.VMId) { $vm.VMId } else { '' }; Drives = @{} }
            }
            $entry = $guestStorageHistory[$vmKey]
            if ($entry.VMName -ne $vm.VM) {
                $entry | Add-Member -NotePropertyName 'VMName' -NotePropertyValue $vm.VM -Force }
            
            foreach ($disk in $vm.GuestDisks) {
                $driveKey = $disk.DriveLetter
                if ($entry.Drives -isnot [hashtable]) {
                    $drivesHT = @{}
                    foreach ($dp in $entry.Drives.PSObject.Properties) { $drivesHT[$dp.Name] = $dp.Value }
                    $entry | Add-Member -NotePropertyName 'Drives' -NotePropertyValue $drivesHT -Force
                }
                if (-not $entry.Drives.ContainsKey($driveKey)) { $entry.Drives[$driveKey] = @() }
                
                $drivePoints   = @($entry.Drives[$driveKey])
                $shouldRecord  = $true
                $updateInPlace = $false
                
                if ($drivePoints.Count -gt 0) {
                    $lastPoint = $drivePoints | Sort-Object {
                        try { [datetime]::Parse($_.CollectedAt) }
                        catch { try { [datetime]::Parse($_.Date) } catch { [datetime]::MinValue } }
                    } | Select-Object -Last 1
                    
                    if ($GuestStorageTrackingMode -eq 'Day') {
                        $lastDate = if ($lastPoint.Date) { $lastPoint.Date } else { '' }
                        if ($lastDate -eq $nowDateOnly) {
                            $updateInPlace = $true; $shouldRecord = $false; $skippedCount++ }
                    } else {
                        if ($lastPoint.CollectedAt) {
                            try {
                                $elapsedMins = ($nowUtc - [datetime]::Parse($lastPoint.CollectedAt).ToUniversalTime()).TotalMinutes
                                if ($elapsedMins -lt $intervalMins) {
                                    $updateInPlace = $true; $shouldRecord = $false; $skippedCount++ }
                            } catch { }
                        }
                    }
                    if ($updateInPlace -and $lastPoint) {
                        $lastPoint | Add-Member -NotePropertyName 'TotalGB'     -NotePropertyValue $disk.TotalGB -Force
                        $lastPoint | Add-Member -NotePropertyName 'UsedGB'      -NotePropertyValue $disk.UsedGB  -Force
                        $lastPoint | Add-Member -NotePropertyName 'FreeGB'      -NotePropertyValue $disk.FreeGB  -Force
                        $lastPoint | Add-Member -NotePropertyName 'CollectedAt' -NotePropertyValue $nowIso       -Force
                    }
                }
                
                if ($shouldRecord) {
                    $entry.Drives[$driveKey] = @($drivePoints) + @([PSCustomObject]@{
                        Date = $nowDateOnly; CollectedAt = $nowIso
                        TotalGB = $disk.TotalGB; UsedGB = $disk.UsedGB; FreeGB = $disk.FreeGB })
                    $snapshotCount++
                }
                if ($entry.Drives[$driveKey].Count -gt 365) {
                    $entry.Drives[$driveKey] = @($entry.Drives[$driveKey] | Select-Object -Last 365) }
            }
        }
    }
    
    Write-HVLog "Guest storage snapshots: $snapshotCount new, $skippedCount updated in-place (mode: $GuestStorageTrackingMode)" -Level Info
    
    try {
        $histDir = Split-Path $guestStorageHistoryPath -Parent
        if (-not (Test-Path $histDir)) { New-Item -Path $histDir -ItemType Directory -Force | Out-Null }
        $guestStorageHistory | ConvertTo-Json -Depth 10 | Set-Content -Path $guestStorageHistoryPath -Force
        Write-HVLog "Guest storage history saved: $($guestStorageHistory.Count) VM entries -> $guestStorageHistoryPath" -Level Info
    }
    catch { Write-HVLog "Could not save guest storage history: $($_.Exception.Message)" -Level Warning }
    
    # Step 5c: AD Authentication Audit (S5a) -- runs on management host, no WinRM hop needed.
    # Collects delegation type, SPN status, and LAPS state from AD for all VMs and HV hosts.
    # Roles and Features are collected per-machine via the OS module data already in $completedHosts.
    $adAuthData   = @{}
    $featuresData = @{}
    $remIssues    = [System.Collections.Generic.List[PSObject]]::new()   # S5b: always initialized

    if ($IncludeADAuthAudit) {
        Write-HVLog "Step 5c: Running AD Authentication Audit..." -Level Info

        # Build combined computer name list: all VM short names + all host short names
        $allComputerNames = [System.Collections.Generic.List[string]]::new()
        foreach ($h in $completedHosts) {
            $allComputerNames.Add($h.HostName)
            if ($h.VMs) {
                foreach ($vm in $h.VMs) {
                    if ($vm.VM) { $allComputerNames.Add($vm.VM) }
                }
            }
        }
        $uniqueNames = @($allComputerNames | Sort-Object -Unique)

        try {
            $adAuthParams = @{ ComputerNames = $uniqueNames; Credential = $Credential }
            if ($DomainCredentials -and $DomainCredentials.Count -gt 0) {
                $adAuthParams['DomainCredentials'] = $DomainCredentials
            }
            $adAuthData = Invoke-ADAuthCollection @adAuthParams
            Write-HVLog "  AD Auth: $($adAuthData.Count) machines audited from AD" -Level Success

            # Per-domain breakdown
            $adErrCount = @($adAuthData.Values | Where-Object { $_.DelegationType -eq 'ADError' }).Count
            if ($DomainCredentials -and $DomainCredentials.Count -gt 0) {
                foreach ($dom in ($DomainCredentials.Keys | Sort-Object)) {
                    $domCount = @($adAuthData.Values | Where-Object { $_.ADDomain -eq $dom }).Count
                    if ($domCount -gt 0) {
                        Write-HVLog "    $dom : $domCount machine(s) resolved" -Level Info
                    }
                }
            }
            $primCount = @($adAuthData.Values | Where-Object { $_.ADDomain -eq 'primary' }).Count
            if ($primCount -gt 0) { Write-HVLog "    primary domain : $primCount machine(s) resolved" -Level Info }
            if ($adErrCount -gt 0) { Write-HVLog "    $adErrCount machine(s) not found in any domain (appliances/Linux/non-domain)" -Level Info }

            # Count security findings for log
            $critCount = @($adAuthData.Values | Where-Object { $_.DelegationType -eq 'Unconstrained' }).Count
            $missSPN   = @($adAuthData.Values | Where-Object { $_.SpnStatus -eq 'Missing' }).Count
            $noLAPS    = @($adAuthData.Values | Where-Object { $_.LapsVersion -eq 'None' }).Count
            if ($critCount -gt 0) {
                Write-HVLog "  [CRITICAL] $critCount machine(s) with Unconstrained Kerberos Delegation" -Level Warning }
            if ($missSPN -gt 0) {
                Write-HVLog "  $missSPN machine(s) with missing WSMAN SPNs" -Level Info }
            if ($noLAPS -gt 0) {
                Write-HVLog "  $noLAPS machine(s) with no LAPS deployed" -Level Info }
        }
        catch {
            Write-HVLog "  AD Auth collection error: $($_.Exception.Message)" -Level Warning
        }
    }

    if ($IncludeRolesFeatures) {
        Write-HVLog "Step 5c: Collecting Roles and Features data..." -Level Info
        # Roles/Features were collected inside each host's Invoke-Command job in the OS module.
        # Wire them from completedHosts into the featuresData hashtable for the Export module.
        $featCount = 0
        foreach ($h in $completedHosts) {
            # Host-level features
            if ($h.HostFeatures) {
                $featuresData[$h.HostName] = $h.HostFeatures
                $featCount += @($h.HostFeatures).Count
            }
            # VM-level features
            if ($h.VMs) {
                foreach ($vm in $h.VMs) {
                    if ($vm.Features) {
                        $featuresData[$vm.VM] = $vm.Features
                        $featCount += @($vm.Features).Count
                    }
                }
            }
        }
        Write-HVLog "  Roles/Features: $featCount feature entries across $($featuresData.Count) machines" -Level Info
    }

    # Step 5p: LAPS Audit (v3.10.11 CR102+CR103)
    # Queries LAPS metadata for every Windows domain-joined VM. Populates LAPS-Usage tab.
    # Controlled by LAPSMode config key: 'Disabled' (default) / 'Audit' / 'Retrieve'
    $lapsResults = @()
    $lapsMode = if ($config -and $config.LAPSMode) { $config.LAPSMode } else { 'Disabled' }
    if ($lapsMode -ne 'Disabled') {
        Write-HVLog "Step 5p: LAPS Audit (mode: $lapsMode)..." -Level Info
        try {
            # Build the VM list from completed host data -- need GuestComputerName and Domain
            $allVMsForLAPS = @()
            foreach ($h in $completedHosts) {
                if ($h.VMs) {
                    $allVMsForLAPS += $h.VMs
                }
            }
            $lapsResults = Invoke-LAPSAudit -VMs $allVMsForLAPS -Config $config `
                -Credential $Credential -DomainCredentials $DomainCredentials
        }
        catch {
            Write-HVLog "Step 5p: LAPS Audit failed -- $($_.Exception.Message)" -Level Error
            $lapsResults = @()
        }
    }
    else {
        Write-HVLog "Step 5p: LAPS Audit skipped (LAPSMode = Disabled)" -Level Info
    }

    # Step 5q: AD Forest/Domain Topology Collection (v3.10.11 -- AD-Info tab)
    # Queries Get-ADForest + Get-ADDomain + Get-ADDomainController for every
    # configured domain in DomainCredentials. Produces one Forest row + one Domain
    # row per domain. Runs only in Advanced mode (tab is Advanced-only).
    # No config opt-in needed -- runs automatically when DomainCredentials are present.
    $adInfoData = @()
    if ($ReportLevel -eq 'Advanced' -or $ReportLevel -eq 'All') {
        $domainsToQuery = @()
        if ($DomainCredentials -and $DomainCredentials.Count -gt 0) {
            $domainsToQuery = @($DomainCredentials.Keys | Where-Object { $_ -notmatch '_\d+$' })
        }
        if ($domainsToQuery.Count -eq 0 -and $Credential) {
            # Fall back to the primary domain if no explicit DomainCredentials
            try {
                $primaryDomain = (Get-ADDomain -ErrorAction Stop).DNSRoot
                $domainsToQuery = @($primaryDomain)
            }
            catch { $domainsToQuery = @() }
        }

        if ($domainsToQuery.Count -gt 0) {
            Write-HVLog "Step 5q: AD Topology collection ($($domainsToQuery.Count) domain(s))..." -Level Info
            $adInfoRows = [System.Collections.Generic.List[PSObject]]::new()
            $forestsSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($domainFQDN in ($domainsToQuery | Sort-Object)) {
                $cred = if ($DomainCredentials.ContainsKey($domainFQDN)) { $DomainCredentials[$domainFQDN] } else { $Credential }
                $adp       = @{ Server = $domainFQDN; ErrorAction = 'Stop' }
                $adpSilent = @{ Server = $domainFQDN; ErrorAction = 'SilentlyContinue' }
                if ($cred) { $adp['Credential'] = $cred; $adpSilent['Credential'] = $cred }

                try {
                    $domObj    = Get-ADDomain @adp
                    $forestKey = $domObj.Forest.ToLower()

                    # ---- Forest row (once per forest) ----
                    if (-not $forestsSeen.Contains($forestKey)) {
                        $forestsSeen.Add($forestKey) | Out-Null
                        try {
                            $forestObj = Get-ADForest -Identity $domObj.Forest @adp

                            # Detect LAPS schema extensions
                            $lapsSchema = 'None'
                            try {
                                $schemaNC  = $forestObj.Schema
                                $lapsAdp   = $adpSilent.Clone(); $lapsAdp['SearchBase'] = $schemaNC
                                $hasLegacy  = $null -ne (Get-ADObject -Filter { name -eq 'ms-Mcs-AdmPwd'    } @lapsAdp)
                                $hasWinLAPS = $null -ne (Get-ADObject -Filter { name -eq 'msLAPS-Password'  } @lapsAdp)
                                $lapsSchema = if ($hasLegacy -and $hasWinLAPS) { 'Both' }
                                             elseif ($hasWinLAPS) { 'WindowsLAPS-WS2025' }
                                             elseif ($hasLegacy)  { 'LegacyLAPS' }
                                             else                 { 'None' }
                            }
                            catch { $lapsSchema = 'Unknown' }

                            # Schema version
                            $schemaVersion = ''
                            try {
                                $schemaObj = Get-ADObject -Identity $forestObj.Schema -Properties objectVersion @adpSilent
                                $schemaVersion = if ($schemaObj) { "objectVersion=$($schemaObj.objectVersion)" } else { '' }
                            }
                            catch {}

                            $domainList = ($forestObj.Domains | Sort-Object) -join ', '
                            $adInfoRows.Add([PSCustomObject]@{
                                Scope                = 'Forest'
                                Name                 = $forestObj.Name
                                FunctionalLevel      = $forestObj.ForestMode.ToString()
                                SchemaMaster         = $forestObj.SchemaMaster
                                DomainNaming         = $forestObj.DomainNamingMaster
                                PDCEmulator          = ''
                                RIDMaster            = ''
                                InfrastructureMaster = ''
                                LAPSSchemaLevel      = $lapsSchema
                                Notes                = "Domains: $domainList$(if($schemaVersion){'; Schema: '+$schemaVersion})"
                            })
                        }
                        catch {
                            Write-HVLog "  Step 5q: Get-ADForest failed for $domainFQDN -- $($_.Exception.Message)" -Level Warning
                        }
                    }

                    # ---- Domain row ----
                    $dcList = ''
                    try {
                        $dcs = Get-ADDomainController -Filter * @adpSilent
                        $dcList = if ($dcs) { ($dcs | Sort-Object Name | ForEach-Object { $_.Name }) -join ', ' } else { '' }
                    }
                    catch {}

                    $trustList = ''
                    try {
                        $trusts = Get-ADTrust -Filter * @adpSilent
                        $trustList = if ($trusts) { ($trusts | ForEach-Object { "$($_.Name) ($($_.TrustType)/$($_.TrustDirection))" }) -join '; ' } else { 'None' }
                    }
                    catch { $trustList = 'Unable to query' }

                    $siteCount = 0
                    try {
                        $sites = Get-ADReplicationSite -Filter * @adpSilent
                        $siteCount = if ($sites) { @($sites).Count } else { 0 }
                    }
                    catch {}

                    $adInfoRows.Add([PSCustomObject]@{
                        Scope                = 'Domain'
                        Name                 = $domObj.DNSRoot
                        FunctionalLevel      = $domObj.DomainMode.ToString()
                        SchemaMaster         = ''
                        DomainNaming         = ''
                        PDCEmulator          = $domObj.PDCEmulator
                        RIDMaster            = $domObj.RIDMaster
                        InfrastructureMaster = $domObj.InfrastructureMaster
                        LAPSSchemaLevel      = ''
                        Notes                = "DCs: $dcList$(if($siteCount){'; Sites: '+$siteCount}); Trusts: $trustList"
                    })
                    Write-HVLog "  Step 5q: $domainFQDN -- DCs: $(@($dcList -split ', ').Count), Sites: $siteCount" -Level Info
                }
                catch {
                    Write-HVLog "  Step 5q: Failed to query $domainFQDN -- $($_.Exception.Message)" -Level Warning
                }
            }
            $adInfoData = @($adInfoRows)
            Write-HVLog "Step 5q: AD Topology complete -- $($adInfoData.Count) row(s) ($($forestsSeen.Count) forest(s), $($domainsToQuery.Count) domain(s))" -Level Info
        }
        else {
            Write-HVLog "Step 5q: AD Topology skipped (no DomainCredentials configured)" -Level Info
        }
    }
    else {
        Write-HVLog "Step 5q: AD Topology skipped (Advanced report only)" -Level Info
    }

    # Step 5r: Permission Audit (v3.10.12 OPEN-60 -- Permissions-Groups + Permissions-Privileges tabs)
    # Collects local group membership (Get-LocalGroupMember) and user rights assignment
    # (secedit /export) from every reachable Hyper-V host via WinRM.
    # Opt-in: IncludePermissionAudit = $true in config. Default: $false.
    $permissionData = @{ GroupData = @(); PrivilegeData = @() }
    $includePermAudit = if ($config -and $config.ContainsKey('IncludePermissionAudit')) {
        [bool]$config.IncludePermissionAudit
    } else { $false }

    if ($includePermAudit -and ($ReportLevel -eq 'Advanced' -or $ReportLevel -eq 'All')) {
        if (Get-Command -Name 'Invoke-PermissionAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5r: Permission Audit (local groups + user rights + security options)..." -Level Info
            try {
                $permParams = @{
                    Hosts      = $completedHosts
                    Config     = $config
                    Credential = $Credential
                    IncludeVMs = $includeVMScope   # OPEN-67: driven by AuditScope
                    DomainCredentials = $domainCredentials
                }
                $permissionData = Invoke-PermissionAudit @permParams
                $groupCount  = if ($permissionData.GroupData)     { @($permissionData.GroupData).Count }     else { 0 }
                $privCount   = if ($permissionData.PrivilegeData) { @($permissionData.PrivilegeData).Count } else { 0 }
                Write-HVLog "Step 5r: Permission Audit complete -- $groupCount group entries, $privCount privilege entries" -Level Info
            }
            catch {
                Write-HVLog "Step 5r: Permission Audit failed -- $($_.Exception.Message)" -Level Error
                $permissionData = @{ GroupData = @(); PrivilegeData = @() }
            }
        }
        else {
            Write-HVLog "Step 5r: Permission Audit skipped (HyperVInventory-Permissions.psm1 not loaded)" -Level Warning
        }
    }
    elseif ($includePermAudit) {
        Write-HVLog "Step 5r: Permission Audit skipped (Advanced report only)" -Level Info
    }
    else {
        Write-HVLog "Step 5r: Permission Audit skipped (IncludePermissionAudit = `$false in config)" -Level Info
    }

    # Step 5d: Generate Remediation Script (alongside xlsx in output folder)
    $remediationScriptPath = $null
    if ($IncludeADAuthAudit -and $adAuthData.Count -gt 0) {
        Write-HVLog "Step 5d: Generating remediation script..." -Level Info
        try {
            $remScriptName = "HyperV-Remediation_${reportTimestamp}.ps1"
            $remScriptPath = Join-Path $outputDir $remScriptName

            # Build issues list inline from adAuthData (mirrors Export module logic, simplified)
            $remIssues = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($key in $adAuthData.Keys) {
                $ad = $adAuthData[$key]
                if ($ad.DelegationType -eq 'Unconstrained') {
                    $remIssues.Add([PSCustomObject]@{ Severity='Critical'; Computer=$ad.ComputerName; Category='Delegation'; Finding='Unconstrained Kerberos Delegation'; Detail=$ad.DelegationDetail })
                }
                elseif ($ad.DelegationType -eq 'KCD') {
                    $remIssues.Add([PSCustomObject]@{ Severity='Warning'; Computer=$ad.ComputerName; Category='Delegation'; Finding='Traditional KCD configured'; Detail=$ad.DelegationDetail })
                }
                if ($ad.SpnStatus -eq 'Missing') {
                    $remIssues.Add([PSCustomObject]@{ Severity='Warning'; Computer=$ad.ComputerName; Category='SPN'; Finding='WSMAN SPNs missing'; Detail='' })
                }
                elseif ($ad.SpnStatus -like 'Partial*') {
                    $remIssues.Add([PSCustomObject]@{ Severity='Info'; Computer=$ad.ComputerName; Category='SPN'; Finding="WSMAN SPNs incomplete ($($ad.SpnStatus))"; Detail='' })
                }
                if ($ad.LapsVersion -eq 'None') {
                    $remIssues.Add([PSCustomObject]@{ Severity='Warning'; Computer=$ad.ComputerName; Category='LAPS'; Finding='No LAPS detected'; Detail='' })
                }
                elseif ($ad.LapsVersion -eq 'Legacy LAPS') {
                    $remIssues.Add([PSCustomObject]@{ Severity='Warning'; Computer=$ad.ComputerName; Category='LAPS'; Finding='Legacy LAPS -- migrate to Windows LAPS'; Detail='' })
                }
            }
            # WinRM issues from completedHosts
            foreach ($h in $completedHosts) {
                if ($h.VMs) {
                    foreach ($vm in $h.VMs) {
                        if ($vm.OSInfo -and $vm.OSInfo.WinRM_Status -match 'Running|Online' -and
                            (-not $vm.OSInfo.WinRM_HTTPS -or $vm.OSInfo.WinRM_HTTPS -eq $false -or $vm.OSInfo.WinRM_HTTPS -eq 'No')) {
                            $remIssues.Add([PSCustomObject]@{ Severity='Warning'; Computer=$vm.VM; Category='WinRM-Transport'; Finding='WinRM HTTP only'; Detail='' })
                        }
                    }
                }
            }

            $caServer = if ($config -and $config.CAServer) { $config.CAServer } else { '' }

            $splitByMachine = $false
            if ($config -and $config.SplitRemediationByMachine) { $splitByMachine = $true }

            $remPath = New-RemediationScript `
                -ADAuthIssues      $remIssues `
                -OutputPath        $remScriptPath `
                -CAServer          $caServer `
                -ReportTimestamp   $reportTimestamp `
                -NICGatewayIssues  $nicAuditData `
                -SplitByMachine:$splitByMachine `
                -ScriptVersion     $script:ModuleVersion

            if ($remPath) {
                $remediationScriptPath = $remPath
                Write-HVLog "  Remediation script: $remScriptName ($($remIssues.Count) findings)" -Level Success
            }
        }
        catch {
            Write-HVLog "  Remediation script generation failed: $($_.Exception.Message)" -Level Warning
        }
    }

    # Step 5e: Kerberos / NTLM Elimination Mapping (S5c)
    # Three-layer analysis: SPN inventory, double-hop service map, NTLM risk synthesis.
    # SPN audit and NTLM risk are pure AD/in-memory -- zero extra WinRM.
    # Double-hop map adds ONE targeted WinRM call per IIS machine to collect app pool identities.
    $spnAuditResults  = $null
    $doublehopResults = $null
    $ntlmRiskResults  = $null

    if ($IncludeADAuthAudit -and $adAuthData.Count -gt 0) {
        Write-HVLog "Step 5e: Kerberos/NTLM Elimination Mapping..." -Level Info

        # Layer 1: SPN Inventory -- categorize all registered SPNs, detect gaps and duplicates
        try {
            $spnAuditResults = Invoke-SPNAudit -ADAuthData $adAuthData -FeaturesData $featuresData
            $spnMissing   = @($spnAuditResults | Where-Object { $_.Status -like 'Missing*' }).Count
            $spnDuplicate = @($spnAuditResults | Where-Object { $_.Status -eq 'Duplicate' }).Count
            $spnTotal     = @($spnAuditResults | Where-Object { $_.Status -eq 'OK' }).Count
            Write-HVLog "  SPN Inventory: $($spnAuditResults.Count) entries -- $spnMissing missing, $spnDuplicate duplicates, $spnTotal OK" -Level Info
            if ($spnDuplicate -gt 0) {
                Write-HVLog "  [WARNING] $spnDuplicate duplicate SPN(s) detected -- Kerberos auth WILL fail for affected services" -Level Warning
            }
        }
        catch {
            Write-HVLog "  SPN Audit error: $($_.Exception.Message)" -Level Warning
        }

        # Layer 2: Double-hop Map -- services/tasks/IIS pools running under domain accounts
        try {
            $dhParams = @{
                CompletedHosts = @($completedHosts)
                ADAuthData     = $adAuthData
                FeaturesData   = $featuresData
                Credential     = $Credential
            }
            $doublehopResults = Resolve-DoublehopMap @dhParams
            $dhHigh    = @($doublehopResults | Where-Object { $_.NTLMRisk -eq 'High' }).Count
            $dhReview  = @($doublehopResults | Where-Object { $_.NTLMRisk -eq 'Review' }).Count
            $dhIIS     = @($doublehopResults | Where-Object { $_.Source -eq 'IIS-AppPool' }).Count
            Write-HVLog "  DoubleHop Map: $($doublehopResults.Count) domain-account services/tasks -- $dhHigh high-risk, $dhReview review, $dhIIS IIS pools" -Level Info
        }
        catch {
            Write-HVLog "  DoubleHop Map error: $($_.Exception.Message)" -Level Warning
        }

        # Layer 3: NTLM Risk Synthesis -- per-machine risk score with inline remediation commands
        try {
            $ntlmRiskResults = Build-NTLMRiskMap `
                -ADAuthData      $adAuthData `
                -SPNAuditResults $spnAuditResults `
                -DoublehopResults $doublehopResults `
                -FeaturesData    $featuresData

            $ntlmCritical = @($ntlmRiskResults | Where-Object { $_.NTLMRisk -eq 'Critical' }).Count
            $ntlmHigh     = @($ntlmRiskResults | Where-Object { $_.NTLMRisk -eq 'High'     }).Count
            $ntlmMedium   = @($ntlmRiskResults | Where-Object { $_.NTLMRisk -eq 'Medium'   }).Count
            Write-HVLog "  NTLM Risk: $ntlmCritical Critical, $ntlmHigh High, $ntlmMedium Medium across $($ntlmRiskResults.Count) machines" -Level Info
            if ($ntlmCritical -gt 0) {
                Write-HVLog "  [CRITICAL] $ntlmCritical machine(s) require immediate NTLM elimination action" -Level Warning
            }
        }
        catch {
            Write-HVLog "  NTLM Risk synthesis error: $($_.Exception.Message)" -Level Warning
        }
    }

    # Step 5e-2: NTLM Deprecation Readiness Audit (S5e)
    # Collects protocol-layer NTLM config from each host/VM via WinRM.
    $ntlmReadinessResults = $null
    if ($IncludeADAuthAudit) {
        if (Get-Command -Name 'Invoke-NTLMReadinessAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5e-2: NTLM Deprecation Readiness Audit..." -Level Info
            try {
                $ntlmReadinessResults = Invoke-NTLMReadinessAudit `
                    -CompletedHosts     @($completedHosts) `
                    -Credential         $Credential `
                    -DomainCredentials  $DomainCredentials

                $nrBlocked   = @($ntlmReadinessResults | Where-Object { $_.OverallReadiness -eq 'Blocked' }).Count
                $nrNeedsWork = @($ntlmReadinessResults | Where-Object { $_.OverallReadiness -eq 'Needs-Work' }).Count
                $nrReady     = @($ntlmReadinessResults | Where-Object { $_.OverallReadiness -eq 'Ready' }).Count
                Write-HVLog "  NTLM Readiness: $($ntlmReadinessResults.Count) machines -- $nrReady Ready, $nrNeedsWork Needs-Work, $nrBlocked Blocked" -Level Info
                if ($nrBlocked -gt 0) {
                    Write-HVLog "  [WARNING] $nrBlocked machine(s) have blocking NTLM protocol configurations" -Level Warning
                }
            }
            catch {
                Write-HVLog "  NTLM Readiness error: $($_.Exception.Message)" -Level Warning
            }
        }
        else {
            Write-HVLog "Step 5e-2: Invoke-NTLMReadinessAudit not available (ADAuth module may need update)" -Level Warning
        }
    }

    # Step 5e-3: Service Account SPN Audit (S5f)
    # Queries AD for user accounts with SPNs, cross-references against running services.
    $svcAccountSPNResults = $null
    if ($IncludeADAuthAudit -and $adAuthData.Count -gt 0) {
        if (Get-Command -Name 'Invoke-ServiceAccountSPNAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5e-3: Service Account SPN Audit..." -Level Info
            try {
                $svcAccountSPNResults = Invoke-ServiceAccountSPNAudit `
                    -CompletedHosts     @($completedHosts) `
                    -ADAuthData         $adAuthData `
                    -Credential         $Credential `
                    -DomainCredentials  $DomainCredentials

                $saTotal    = @($svcAccountSPNResults).Count
                $saCritical = @($svcAccountSPNResults | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
                $saWarning  = @($svcAccountSPNResults | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
                $saAccounts = @($svcAccountSPNResults | Select-Object -Property AccountName -Unique).Count
                Write-HVLog "  Service Account SPNs: $saTotal entries across $saAccounts accounts -- $saCritical Critical, $saWarning Warning" -Level Info
            }
            catch {
                Write-HVLog "  Service Account SPN Audit error: $($_.Exception.Message)" -Level Warning
            }
        }
        else {
            Write-HVLog "Step 5e-3: Invoke-ServiceAccountSPNAudit not available (ADAuth module may need update)" -Level Warning
        }
    }

    # Step 5e-4: KCD Validation Audit (v3.8.9.2)
    # Validates KCD/RBCD delegation targets: SPN registration, DNS resolution, live migration coverage.
    $kcdValidationResults = $null
    if ($IncludeADAuthAudit -and $adAuthData.Count -gt 0) {
        if (Get-Command -Name 'Invoke-KCDValidationAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5e-4: KCD Validation Audit..." -Level Info
            try {
                $kcdValidationResults = Invoke-KCDValidationAudit `
                    -DomainCredentials  $DomainCredentials `
                    -ADAuthData         @($adAuthData.Values) `
                    -ClusterData        $clusterResults `
                    -HostData           @($completedHosts)

                $kcdTotal    = @($kcdValidationResults).Count
                $kcdCritical = @($kcdValidationResults | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
                $kcdWarning  = @($kcdValidationResults | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
                Write-HVLog "  KCD Validation: $kcdTotal delegation entries -- $kcdCritical Critical, $kcdWarning Warning" -Level Info
            }
            catch {
                Write-HVLog "  KCD Validation Audit error: $($_.Exception.Message)" -Level Warning
            }
        }
        else {
            Write-HVLog "Step 5e-4: Invoke-KCDValidationAudit not available (ADAuth module may need update)" -Level Warning
        }
    }

    # Step 5s: AD-Wide SPN Inventory (v3.10.12 OPEN-66 -- SPN-Inventory-Full tab)
    # Queries ALL computer and user accounts with registered SPNs across every
    # configured domain.  Equivalent to "setspn -L" on every account.  Detects
    # cross-account duplicate SPNs (Kerberos auth failure root cause) and SPNs on
    # disabled/stale accounts.  Zero WinRM hops -- pure AD LDAP queries.
    # Opt-in: IncludeSPNInventoryFull = $true in config.  Advanced report only.
    $spnInventoryFullResults = $null
    $includeSPNFull = if ($config -and $config.ContainsKey('IncludeSPNInventoryFull')) {
        [bool]$config.IncludeSPNInventoryFull
    } else { $false }

    if ($includeSPNFull -and ($ReportLevel -eq 'Advanced' -or $ReportLevel -eq 'All')) {
        if (Get-Command -Name 'Invoke-SPNInventoryFull' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5s: AD-Wide SPN Inventory (OPEN-66)..." -Level Info
            try {
                # Build a HashSet of Hyper-V host names (uppercase short names) for
                # AccountScope tagging ("HyperV" vs "Other") in the results
                $hvHostSet = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase)
                foreach ($h in $completedHosts) {
                    if ($h.HostName) { $hvHostSet.Add($h.HostName.ToUpper()) | Out-Null }
                }

                $spnFullParams = @{
                    DomainCredentials = $DomainCredentials
                    Credential        = $Credential
                    HVHostNames       = $hvHostSet
                    StaleThresholdDays = if ($config -and $config.SPNStaleThresholdDays) {
                                             [int]$config.SPNStaleThresholdDays } else { 90 }
                }
                $spnInventoryFullResults = Invoke-SPNInventoryFull @spnFullParams
                $spnFullCrit  = @($spnInventoryFullResults | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
                $spnFullWarn  = @($spnInventoryFullResults | Where-Object { $_.AlertLevel -eq 'Warning'  }).Count
                $spnFullDupe  = @($spnInventoryFullResults | Where-Object { $_.IsDuplicate -eq $true     }).Count
                Write-HVLog "Step 5s: SPN-Inventory-Full complete -- $(@($spnInventoryFullResults).Count) SPN rows, $spnFullCrit Critical (dupes: $spnFullDupe), $spnFullWarn Warning" -Level Info
                if ($spnFullDupe -gt 0) {
                    Write-HVLog "  [WARNING] $spnFullDupe duplicate SPN registrations detected -- immediate remediation required" -Level Warning
                }
            }
            catch {
                Write-HVLog "Step 5s: SPN-Inventory-Full error -- $($_.Exception.Message)" -Level Error
                $spnInventoryFullResults = $null
            }
        }
        else {
            Write-HVLog "Step 5s: Invoke-SPNInventoryFull not available (ADAuth module may need update)" -Level Warning
        }
    }
    elseif ($includeSPNFull) {
        Write-HVLog "Step 5s: SPN-Inventory-Full skipped (Advanced report only)" -Level Info
    }
    else {
        Write-HVLog "Step 5s: SPN-Inventory-Full skipped (IncludeSPNInventoryFull = `$false in config)" -Level Info
    }

    # Step 5t: VHD Parent Chain Collection (v3.10.12 CR105 -- VHD-Chain tab)
    # Walks the ParentPath chain for every disk on every VM across all hosts.
    # Runs via Invoke-Command on each host -- zero additional management-side WinRM hops.
    # One row per chain link: Active / Checkpoint / Base / Passthrough / BrokenParent / Error.
    # Advanced report only.  No config opt-in required -- always runs when Advanced.
    # Source of truth for AvhdxChainDepth used by vCheckpoint (CR104).
    $vhdChainData = $null
    if ($ReportLevel -eq 'Advanced' -or $ReportLevel -eq 'All') {
        if ($global:HVI_fnVHDChainCollection) {
            Write-HVLog "Step 5t: VHD Parent Chain Collection (CR105)..." -Level Info
            try {
                $vhdChainData = & $global:HVI_fnVHDChainCollection `
                    -CompletedHosts   @($completedHosts) `
                    -Credential       $Credential `
                    -DomainCredentials $DomainCredentials `
                    -Config           $config

                $vhdTotal   = @($vhdChainData).Count
                $vhdCritVM  = @($vhdChainData | Where-Object { $_.ChainLevel -eq 0 -and $_.AlertLevel -eq 'Critical' }).Count
                $vhdWarnVM  = @($vhdChainData | Where-Object { $_.ChainLevel -eq 0 -and $_.AlertLevel -eq 'Warning'  }).Count
                $vhdBroken  = @($vhdChainData | Where-Object { $_.LinkType -eq 'BrokenParent' }).Count
                $vhdDeep    = @($vhdChainData | Where-Object { $_.ChainLevel -eq 0 -and $_.ChainDepth -ge 5 }).Count
                Write-HVLog "Step 5t: VHD-Chain complete -- $vhdTotal links, $vhdCritVM Critical VMs ($vhdDeep depth>=5, $vhdBroken broken), $vhdWarnVM Warning" -Level Info
                if ($vhdBroken -gt 0) {
                    Write-HVLog "  [WARNING] $vhdBroken broken parent path(s) detected -- storage investigation required" -Level Warning
                }
                if ($vhdDeep -gt 0) {
                    Write-HVLog "  [WARNING] $vhdDeep VM(s) with chain depth >= 5 -- likely stuck backup chains" -Level Warning
                }

                # Update AvhdxChainDepth on completedHosts from authoritative chain data
                # so vCheckpoint (CR104) uses the actual file-level depth, not checkpoint count
                $chainDepthByVM = @{}
                foreach ($row in ($vhdChainData | Where-Object { $_.ChainLevel -eq 0 })) {
                    $key = "$($row.Host)|$($row.VMName)"
                    if (-not $chainDepthByVM.ContainsKey($key) -or $row.ChainDepth -gt $chainDepthByVM[$key]) {
                        $chainDepthByVM[$key] = $row.ChainDepth
                    }
                }
                foreach ($hostObj in $completedHosts) {
                    if (-not $hostObj.VMs) { continue }
                    foreach ($vm in $hostObj.VMs) {
                        $vmName = if ($vm.VM) { $vm.VM } elseif ($vm.VMName) { $vm.VMName } else { continue }
                        $key    = "$($hostObj.HostName)|$vmName"
                        if ($chainDepthByVM.ContainsKey($key)) {
                            $vm.AvhdxChainDepth = $chainDepthByVM[$key]
                            $critDepthCfg = if ($config -and $config.VHDChainCriticalDepth) { [int]$config.VHDChainCriticalDepth } else { 5 }
                            $vm.StuckBackupFlag = ($vm.BackupCheckpointCount -gt 0 -and $chainDepthByVM[$key] -ge $critDepthCfg)
                        }
                    }
                }
            }
            catch {
                Write-HVLog "Step 5t: VHD-Chain collection error -- $($_.Exception.Message)" -Level Error
                $vhdChainData = $null
            }
        }
        else {
            Write-HVLog "Step 5t: VHD-Chain skipped (HyperVInventory-VHDChain.psm1 not loaded)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5t: VHD-Chain skipped (Advanced report only)" -Level Info
    }

    # Step 5u: Dynamic Remediation Script Generation (v3.10.12 CR106)
    # Generates per-VM VHD chain merge repair scripts for Critical/Warning VMs.
    # Scripts are written to <OutputFolder>\Remediation\VHDChainMerge\ and NEVER auto-executed.
    # Opt-in: EnableRemediationScripts = $true in config.  Default: $false.
    $vhdChainRemediationResults = @()
    $enableRemediation = if ($config -and $config.ContainsKey('EnableRemediationScripts')) {
        [bool]$config.EnableRemediationScripts
    } else { $false }

    if ($enableRemediation -and $vhdChainData -and @($vhdChainData).Count -gt 0) {
        if ($global:HVI_fnVMRemediationScript) {
            Write-HVLog "Step 5u: VHD Chain Remediation Script Generation (CR106)..." -Level Info
            try {
                $triggerLevels = if ($config -and $config.RemediationTriggerLevels) {
                    @($config.RemediationTriggerLevels)
                } else { @('Critical', 'Warning') }

                $allowlist = if ($config -and $config.RemediationScriptAllowlist) {
                    @($config.RemediationScriptAllowlist)
                } else { @() }

                $remFolder = if ($config -and $config.RemediationScriptFolder) {
                    Join-Path $outputDir $config.RemediationScriptFolder
                } else {
                    Join-Path $outputDir 'Remediation'
                }

                # Find qualifying VMs: ChainLevel=0 rows where AlertLevel is in trigger list
                # or VM is in the explicit allowlist
                $qualifyingVMs = @($vhdChainData |
                    Where-Object { $_.ChainLevel -eq 0 } |
                    Where-Object {
                        $_.AlertLevel -in $triggerLevels -or
                        ($allowlist.Count -gt 0 -and ($allowlist | Where-Object { $_.VMName -like $_ }))
                    } |
                    Select-Object -ExpandProperty VMName -Unique)

                Write-HVLog "  CR106: $($qualifyingVMs.Count) qualifying VMs (trigger: $($triggerLevels -join ','))" -Level Info

                $remResults = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($vmName in $qualifyingVMs) {
                    $vmRows = @($vhdChainData | Where-Object { $_.VMName -eq $vmName })
                    $result = & $global:HVI_fnVMRemediationScript `
                        -VMChainRows       $vmRows `
                        -RemediationFolder $remFolder `
                        -ReportTimestamp   $reportTimestamp `
                        -ReportVersion     $script:ModuleVersion
                    if ($result) { $remResults.Add($result) }
                }

                $vhdChainRemediationResults = @($remResults)

                if ($remResults.Count -gt 0) {
                    $indexPath = New-RemediationIndex `
                        -ScriptResults     @($remResults) `
                        -RemediationFolder $remFolder `
                        -ReportTimestamp   $reportTimestamp
                    $genOK  = @($remResults | Where-Object { $_.GeneratedOK }).Count
                    $genErr = @($remResults | Where-Object { -not $_.GeneratedOK }).Count
                    Write-HVLog "Step 5u: CR106 complete -- $genOK scripts generated, $genErr failures. Folder: $remFolder" -Level Info
                }
            }
            catch {
                Write-HVLog "Step 5u: Remediation script generation error -- $($_.Exception.Message)" -Level Error
            }
        }
        else {
            Write-HVLog "Step 5u: Remediation script generation skipped (HyperVInventory-Remediation.psm1 not loaded)" -Level Warning
        }
    }
    elseif ($enableRemediation) {
        Write-HVLog "Step 5u: Remediation script generation skipped (no VHD-Chain data available)" -Level Info
    }
    else {
        Write-HVLog "Step 5u: Remediation script generation skipped (EnableRemediationScripts = `$false in config)" -Level Info
    }

    # Step 5f: Live Migration Validation + Host NIC Audit + DC GUID Validation (S6)
    # Runs a targeted WinRM call per host -- zero impact on Step 3 job parallelism.
    # Also runs DC GUID collection against all VMs/hosts flagged as domain controllers in ADAuthData.
    $liveMigData      = $null
    $nicAuditData     = $null
    $dcGuidData       = $null
    $liveMigFindings  = $null
    $liveMigRecs      = $null

    Write-HVLog "Step 5f: Live Migration + Host NIC Audit + DC GUID Validation..." -Level Info
    try {
        $liveMigCollection = Invoke-LiveMigrationCollection `
            -CompletedHosts @($completedHosts) `
            -Credential     $Credential `
            -ADAuthData     $adAuthData

        $liveMigData     = $liveMigCollection.LiveMigration
        $nicAuditData    = $liveMigCollection.NICaudit
        $liveMigFindings = $liveMigCollection.Findings
        $liveMigRecs     = $liveMigCollection.Recommendations

        $lmEnabled  = @($liveMigData | Where-Object { $_.LiveMigEnabled -eq $true }).Count
        $lmCredSSP  = @($liveMigData | Where-Object { $_.AuthType -eq 'CredSSP' }).Count
        $nicViolations = @($nicAuditData | Where-Object { $_.GatewayAssessment -like 'VIOLATION*' }).Count
        Write-HVLog "  Live Migration: $($liveMigData.Count) hosts -- $lmEnabled enabled, $lmCredSSP CredSSP (should be 0)" -Level Info
        Write-HVLog "  Host NIC Audit: $($nicAuditData.Count) NIC entries -- $nicViolations gateway violation(s)" -Level Info
        if ($lmCredSSP -gt 0) {
            Write-HVLog "  [WARNING] $lmCredSSP host(s) using CredSSP for live migration -- switch to Kerberos" -Level Warning
        }
        if ($nicViolations -gt 0) {
            Write-HVLog "  [WARNING] $nicViolations NIC(s) have default gateway on non-management interface -- remove and use static routes" -Level Warning
        }

        # Merge live migration findings into compliance issues list
        if ($liveMigFindings -and $liveMigFindings.Count -gt 0 -and $complianceCheck) {
            $complianceCheck += $liveMigFindings
        }
    }
    catch {
        Write-HVLog "  Live Migration collection error: $($_.Exception.Message)" -Level Warning
    }

    # DC GUID validation -- separate pass targeting only DC VMs/hosts
    try {
        $dcGuidData = Invoke-DCGuidValidation `
            -CompletedHosts  @($completedHosts) `
            -ADAuthData      $adAuthData `
            -Credential      $Credential `
            -DomainCredentials $DomainCredentials

        $dcTotal   = @($dcGuidData).Count
        $dcOK      = @($dcGuidData | Where-Object { $_.CNAMEStatus -eq 'OK' }).Count
        $dcFail    = @($dcGuidData | Where-Object { $_.CNAMEStatus -like 'FAIL*' }).Count
        $dcWarn    = @($dcGuidData | Where-Object { $_.CNAMEStatus -like 'WARNING*' }).Count
        Write-HVLog "  DC GUID Validation: $dcTotal DCs -- $dcOK OK, $dcWarn warnings, $dcFail failures" -Level Info
        if ($dcFail -gt 0) {
            Write-HVLog "  [WARNING] $dcFail DC(s) with _msdcs CNAME resolution failures -- Kerberos auth may fail" -Level Warning
        }
    }
    catch {
        Write-HVLog "  DC GUID validation error: $($_.Exception.Message)" -Level Warning
    }

    # Step 5g: VHD-to-Guest Drive Letter Correlation (S7)
    # Pure in-memory analysis -- no additional WinRM calls.
    # Uses host-side VHD ControllerLocation + guest-side Win32_DiskDrive SCSILogicalUnit.
    $vhdDriveMap = $null
    Write-HVLog "Step 5g: Building VHD-to-Guest Drive Letter correlation map..." -Level Info
    try {
        $vhdDriveMap = Build-VHDDriveMap -CompletedHosts @($completedHosts)
        $vhdTotal     = @($vhdDriveMap).Count
        $vhdResolved  = @($vhdDriveMap | Where-Object { $_.CorrelationMethod -ne 'Unresolved' -and $_.CorrelationMethod -ne 'WinRM-Unavailable' -and $_.CorrelationMethod -ne 'Linux/N/A' }).Count
        $vhdUnresolved = @($vhdDriveMap | Where-Object { $_.CorrelationMethod -eq 'Unresolved' }).Count
        Write-HVLog "  VHD-Drive-Map: $vhdTotal VHD rows -- $vhdResolved correlated, $vhdUnresolved unresolved" -Level Info
    }
    catch {
        Write-HVLog "  VHD-Drive-Map build error: $($_.Exception.Message)" -Level Warning
    }

    # Step 5h: S2D Storage Audit (v3.8.0 CR2)
    # Audits Storage Spaces Direct clusters: MHOHCLUHV and any other S2D-enabled clusters.
    $s2dAuditData = @{}
    if ($ReportLevel -in @('Advanced','All')) {
        Write-HVLog "Step 5h: S2D Storage Audit (MHOHCLUHV + other S2D clusters)..." -Level Info
        try {
            # Load S2D module if not already present
            $s2dModulePath = Join-Path (Split-Path $PSScriptRoot) 'HyperVInventory-S2D.psm1'
            if (-not (Split-Path $PSScriptRoot)) {
                $s2dModulePath = Join-Path $PSScriptRoot 'Modules\HyperVInventory-S2D.psm1'
            }
            if (Test-Path $s2dModulePath) {
                Import-Module $s2dModulePath -Force -ErrorAction SilentlyContinue
            }
            if (Get-Command Invoke-S2DAudit -ErrorAction SilentlyContinue) {
                # v3.8.9: Pass S2D filtering parameters from config
                $s2dExclude = @()
                if ($config -and $config.ContainsKey('S2DExcludeClusterNames')) {
                    $s2dExclude = @($config.S2DExcludeClusterNames)
                }
                $s2dOnlyActive = $true
                if ($config -and $config.ContainsKey('S2DOnlyActiveHVClusters')) {
                    $s2dOnlyActive = $config.S2DOnlyActiveHVClusters
                }
                # Build list of active HV host FQDNs from completed hosts
                $activeHVHostList = @($completedHosts | ForEach-Object {
                    if ($_.HostFQDN) { $_.HostFQDN } elseif ($_.HostName) { $_.HostName }
                } | Where-Object { $_ })

                $s2dParams = @{
                    ClusterData             = $clusters
                    Credential              = $Credential
                    S2DExcludeClusterNames  = $s2dExclude
                    S2DOnlyActiveHVClusters = $s2dOnlyActive
                    ActiveHVHosts           = $activeHVHostList
                }
                $s2dAuditData = Invoke-S2DAudit @s2dParams
                $s2dRowCount = if ($s2dAuditData.S2DRows) { @($s2dAuditData.S2DRows).Count } else { 0 }
                Write-HVLog "  S2D Audit complete: $s2dRowCount rows" -Level Info
            }
            else {
                Write-HVLog "  S2D module not found -- skipping S2D audit. Place HyperVInventory-S2D.psm1 in Modules\ folder." -Level Warning
            }
        }
        catch {
            Write-HVLog "  S2D Audit error: $($_.Exception.Message)" -Level Warning
        }
    }

    # Step 5i: VM Resource Metering + IOPS Collection (v3.8.7 Session 8d)
    # Enables VM resource metering, collects Measure-VM with per-VHD HardDiskMetrics,
    # detects physical disks on each host, and generates IOPS recommendations.
    $resourceMeteringData = @{}
    $enableMetering = $true
    if ($config -and $config.ContainsKey('EnableResourceMetering')) {
        $enableMetering = $config.EnableResourceMetering
    }
    $collectPerfCounters = $true
    if ($config -and $config.ContainsKey('CollectIOPSPerfCounters')) {
        $collectPerfCounters = $config.CollectIOPSPerfCounters
    }
    $iopsBaselines = @{}
    if ($config -and $config.ContainsKey('IOPSBaselines')) {
        $iopsBaselines = $config.IOPSBaselines
    }

    if ($enableMetering) {
        Write-HVLog "Step 5i: VM Resource Metering + IOPS Collection..." -Level Info
        try {
            if (Get-Command Invoke-ResourceMeteringCollection -ErrorAction SilentlyContinue) {
                $rmParams = @{
                    HostData            = @($completedHosts)
                    Credential          = $Credential
                    DomainCredentials   = $domainCredentials
                    EnableMetering      = $enableMetering
                    IOPSBaselines       = $iopsBaselines
                    CollectPerfCounters = $collectPerfCounters
                }
                $resourceMeteringData = Invoke-ResourceMeteringCollection @rmParams
                $rmVMCount = if ($resourceMeteringData.VMIOPSSummary) { @($resourceMeteringData.VMIOPSSummary).Count } else { 0 }
                $rmHostCount = if ($resourceMeteringData.HostIOPSSummary) { @($resourceMeteringData.HostIOPSSummary).Count } else { 0 }
                $rmRecoCount = if ($resourceMeteringData.IOPSRecommendations) { @($resourceMeteringData.IOPSRecommendations).Count } else { 0 }
                Write-HVLog "  Resource Metering: $rmVMCount VMs, $rmHostCount hosts, $rmRecoCount recommendations" -Level Info

                # Save history snapshot
                try {
                    $historyDir = Split-Path $HistoryPath -Parent
                    $rmHistoryPath = Join-Path $historyDir 'ResourceMetering-History.json'
                    $rmSnapshot = @{
                        Timestamp   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
                        VMSummary   = @($resourceMeteringData.VMIOPSSummary | ForEach-Object {
                            @{
                                Host = $_.Host; VMName = $_.VMName; IOPS = $_.NormalizedIOPS
                                AvgLatency = $_.AvgLatency; ReadMB = $_.TotalDiskReadMB; WriteMB = $_.TotalDiskWrittenMB
                            }
                        })
                        HostSummary = @($resourceMeteringData.HostIOPSSummary | ForEach-Object {
                            @{
                                Host = $_.Host; TotalIOPS = $_.TotalNormalizedIOPS
                                DiskCount = $_.PhysicalDiskCount; Storage = $_.DetectedStorage
                            }
                        })
                    }
                    # Load existing history, append, save
                    $rmHistory = @()
                    if (Test-Path $rmHistoryPath) {
                        try { $rmHistory = @(Get-Content $rmHistoryPath -Raw | ConvertFrom-Json) } catch { $rmHistory = @() }
                    }
                    $rmHistory += $rmSnapshot
                    # Keep last 365 snapshots (one year at daily runs)
                    if ($rmHistory.Count -gt 365) {
                        $rmHistory = $rmHistory[($rmHistory.Count - 365)..($rmHistory.Count - 1)]
                    }
                    $rmHistory | ConvertTo-Json -Depth 5 -Compress | Set-Content $rmHistoryPath -Encoding UTF8
                    Write-HVLog "  Resource Metering history saved: $($rmHistory.Count) snapshots -> $rmHistoryPath" -Level Info
                }
                catch {
                    Write-HVLog "  Resource Metering history save warning: $($_.Exception.Message)" -Level Warning
                }
            }
            else {
                Write-HVLog "  ResourceMetering module not found -- skipping. Place HyperVInventory-ResourceMetering.psm1 in Modules\ folder." -Level Warning
            }
        }
        catch {
            Write-HVLog "  Resource Metering error: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5i: Resource Metering disabled in config (EnableResourceMetering = false)" -Level Info
    }

    # Step 5i-2: IOPS Collector Data Reader (v3.8.9.2 Session 8d-2)
    # Reads JSON Lines from the standalone Collect-ServerIOPS.ps1 collector output.
    # Produces IOPS-Trends (daily peak/avg/p95) and IOPS-Heatmap (hour-of-day demand curve).
    $iopsCollectorData = $null
    $collectorPath = ''
    if ($config -and $config.ContainsKey('IOPSCollectorPath')) {
        $collectorPath = $config.IOPSCollectorPath
    }
    $collectorDaysBack = 30
    if ($config -and $config.ContainsKey('IOPSCollectorDaysBack')) {
        $collectorDaysBack = $config.IOPSCollectorDaysBack
    }

    if ($collectorPath -and (Test-Path $collectorPath -ErrorAction SilentlyContinue)) {
        if (Get-Command -Name 'Import-IOPSCollectorData' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5i-2: IOPS Collector Data Reader ($collectorPath, ${collectorDaysBack}d)..." -Level Info
            try {
                $iopsCollectorData = Import-IOPSCollectorData `
                    -CollectorPath $collectorPath `
                    -DaysBack      $collectorDaysBack

                $trendCount   = if ($iopsCollectorData.IOPSTrends)  { @($iopsCollectorData.IOPSTrends).Count }  else { 0 }
                $heatmapCount = if ($iopsCollectorData.IOPSHeatmap) { @($iopsCollectorData.IOPSHeatmap).Count } else { 0 }
                Write-HVLog "  IOPS Collector: $trendCount trend rows, $heatmapCount heatmap rows" -Level Info
            }
            catch {
                Write-HVLog "  IOPS Collector reader error: $($_.Exception.Message)" -Level Warning
            }
        }
        else {
            Write-HVLog "Step 5i-2: Import-IOPSCollectorData not available (ResourceMetering module may need update)" -Level Warning
        }
    }
    else {
        if ($collectorPath) {
            Write-HVLog "Step 5i-2: IOPS Collector path not accessible -- $collectorPath" -Level Info
        }
        else {
            Write-HVLog "Step 5i-2: IOPSCollectorPath not configured -- skipping collector data reader" -Level Info
        }
    }

    # Step 5j: TLS / Secure Channel Compliance Audit (v3.9.0 Session 8e)
    # Audits SChannel protocols, .NET Framework TLS, WinHTTP, RDP, LDAP, SMB
    # on every host and Windows VM via WinRM.
    # OPEN-67: IncludeVMs driven by $includeVMScope (set from AuditScope at run start, before Step 1).
    $tlsAuditData = @{}
    $enableTLSAudit = $false
    if ($config -and $config.ContainsKey('EnableTLSAudit')) {
        $enableTLSAudit = $config.EnableTLSAudit
    }
    $tlsIncludeVMs = $true
    if ($config -and $config.ContainsKey('TLSAuditIncludeVMs')) {
        $tlsIncludeVMs = $config.TLSAuditIncludeVMs
    }

    if ($enableTLSAudit) {
        Write-HVLog "Step 5j: TLS / Secure Channel Compliance Audit..." -Level Info
        try {
            if (Get-Command Invoke-TLSComplianceAudit -ErrorAction SilentlyContinue) {
                # Determine output folder for remediation scripts
                $tlsOutputFolder = Split-Path $OutputPath -Parent
                if (-not $tlsOutputFolder) { $tlsOutputFolder = '.' }

                $tlsParams = @{
                    HostData          = @($completedHosts)
                    Credential        = $Credential
                    DomainCredentials = $domainCredentials
                    IncludeVMs        = $includeVMScope   # OPEN-67: driven by AuditScope (overrides TLSAuditIncludeVMs)
                    OutputFolder      = $tlsOutputFolder
                }
                $tlsAuditData = Invoke-TLSComplianceAudit @tlsParams
                $tlsCompCount = if ($tlsAuditData.TLSCompliance) { @($tlsAuditData.TLSCompliance).Count } else { 0 }
                $tlsRecoCount = if ($tlsAuditData.TLSRecommendations) { @($tlsAuditData.TLSRecommendations).Count } else { 0 }
                Write-HVLog "  TLS Audit: $tlsCompCount machines checked, $tlsRecoCount recommendations" -Level Info
            }
            else {
                Write-HVLog "  TLS module not found -- skipping. Place HyperVInventory-TLS.psm1 in Modules\ folder." -Level Warning
            }
        }
        catch {
            Write-HVLog "  TLS Audit error: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5j: TLS Audit disabled in config (EnableTLSAudit = false)" -Level Info
    }

    # Step 5j-3: Cipher / Kerberos Encryption-Type Audit (v3.10.12.27, OPEN-68)
    # Per-machine SCHANNEL/cipher state + AD msDS-SupportedEncryptionTypes,
    # interoperability floor, and DC trust/secure-channel diagnostics.
    # Runtime portion honors $includeVMScope (AuditScope, same flag as TLS);
    # the Kerberos-etype portion is pure AD LDAP and always covers every DC.
    $cipherAuditData = @{}
    $enableCipherAudit = $false
    if ($config -and $config.ContainsKey('EnableCipherAudit')) {
        $enableCipherAudit = $config.EnableCipherAudit
    }

    if ($enableCipherAudit) {
        Write-HVLog "Step 5j-3: Cipher / Kerberos Encryption-Type Audit..." -Level Info
        try {
            if (Get-Command Invoke-CipherEncryptionAudit -ErrorAction SilentlyContinue) {
                $cipherParams = @{
                    HostData          = @($completedHosts)
                    Credential        = $Credential
                    DomainCredentials = $domainCredentials
                    IncludeVMs        = $includeVMScope   # OPEN-67: AuditScope-driven, same as TLS
                }
                $cipherAuditData = Invoke-CipherEncryptionAudit @cipherParams
                $cipherCount = if ($cipherAuditData.CipherAudit) { @($cipherAuditData.CipherAudit).Count } else { 0 }
                $etypeCount  = if ($cipherAuditData.KerberosEtypes) { @($cipherAuditData.KerberosEtypes).Count } else { 0 }
                Write-HVLog "  Cipher Audit: $cipherCount machines, $etypeCount Kerberos-etype rows" -Level Info
            }
            else {
                Write-HVLog "  Cipher module not found -- skipping. Place HyperVInventory-Cyphers.psm1 in Modules\ folder." -Level Warning
            }
        }
        catch {
            Write-HVLog "  Cipher Audit error: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5j-3: Cipher Audit disabled in config (EnableCipherAudit = false)" -Level Info
    }

    # Step 5j-2: DNS Record Validation (v3.9.2 CR57)
    # v3.9.6 CR64: DNS validation is Advanced-only (EfficientIP/AD DNS lookups)
    $dnsValidationData = @{}
    $enableDNSValidation = $false
    if ($config -and $config.ContainsKey('IncludeDNSValidation')) {
        $enableDNSValidation = $config.IncludeDNSValidation
    }
    if ($enableDNSValidation -and $ReportLevel -notin @('Advanced','All')) {
        Write-HVLog "Step 5j-2: DNS Validation skipped (Advanced report only, current level: $ReportLevel)" -Level Info
        $enableDNSValidation = $false
    }

    if ($enableDNSValidation) {
        Write-HVLog "Step 5j-2: DNS Record Validation..." -Level Info
        # Load DNS validation module and EfficientIP module (main thread, not background jobs)
        try {
            $dnsModulePath = Join-Path $modulesDir "HyperVInventory-DNS.psm1"
            if (Test-Path $dnsModulePath) {
                Import-Module $dnsModulePath -Force -ErrorAction SilentlyContinue
            }
            $eipModulePath = Join-Path $modulesDir "EfficientIP-Module.psm1"
            if (Test-Path $eipModulePath) {
                Import-Module $eipModulePath -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-HVLog "  Module loading warning: $($_.Exception.Message)" -Level Warning
        }
        try {
            if (Get-Command Invoke-DNSValidation -ErrorAction SilentlyContinue) {
                $dnsParams = @{
                    HostData          = @($completedHosts)
                    DomainCredentials = $DomainCredentials
                }
                # EfficientIP config from Config-OHDC.psd1
                if ($config.EfficientIPServer) {
                    $dnsParams['EfficientIPConfig'] = @{
                        Server         = $config.EfficientIPServer
                        CredentialPath = if ($config.EfficientIPCredPath) { $config.EfficientIPCredPath } else { '' }
                        IgnoreSSL      = if ($null -ne $config.EfficientIPIgnoreSSL) { $config.EfficientIPIgnoreSSL } else { $true }
                    }
                }
                if ($config.DNSSourceOverride) {
                    $dnsParams['DNSSourceOverride'] = $config.DNSSourceOverride
                }
                $dnsValidationData = Invoke-DNSValidation @dnsParams
            }
            else {
                Write-HVLog "  Invoke-DNSValidation function not found -- ensure HyperVInventory-DNS.psm1 is loaded" -Level Warning
            }
        }
        catch {
            Write-HVLog "  DNS Validation error: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5j-2: DNS Validation disabled in config (IncludeDNSValidation = false)" -Level Info
    }

    # Step 5k: Disk Format / Partition Audit (v3.9.0 Session 8f)
    # Collects filesystem type, AllocationUnitSize, PartitionStyle, UseLargeFRS,
    # ReFS integrity from each host via WinRM.
    $diskFormatData = @()
    $enableDiskFormat = $false
    if ($config -and $config.ContainsKey('IncludeDiskFormatAudit')) {
        $enableDiskFormat = $config.IncludeDiskFormatAudit
    }

    if ($enableDiskFormat) {
        Write-HVLog "Step 5k: Disk Format / Partition Audit..." -Level Info
        try {
            if (Get-Command Invoke-DiskFormatAudit -ErrorAction SilentlyContinue) {
                $dfParams = @{
                    HostData          = @($completedHosts)
                    Credential        = $Credential
                    DomainCredentials = $domainCredentials
                }
                $diskFormatData = @(Invoke-DiskFormatAudit @dfParams)
                Write-HVLog "  Disk Format Audit: $($diskFormatData.Count) volumes across all hosts" -Level Info
            }
            else {
                Write-HVLog "  Invoke-DiskFormatAudit function not found -- ensure HyperVInventory-Storage.psm1 is up to date." -Level Warning
            }
        }
        catch {
            Write-HVLog "  Disk Format Audit error: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5k: Disk Format Audit disabled in config (IncludeDiskFormatAudit = false)" -Level Info
    }

    # Step 5l: RBAC Builtin Group Compliance Audit (v3.8.9 Session 8h)
    $rbacComplianceData = $null
    $rbacConfig = if ($config -and $config.RBACBuiltinGroups) { $config.RBACBuiltinGroups } else { $null }
    if ($rbacConfig -and $rbacConfig.Enabled -eq $true) {
        if (Get-Command -Name 'Invoke-RBACComplianceAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5l: RBAC Builtin Group Compliance Audit..." -Level Info
            try {
                $rbacParams = @{
                    HostData   = @($completedHosts)
                    RBACConfig = $rbacConfig
                }
                # Use primary credential for AD queries
                $primaryCred = $null
                foreach ($dk in $DomainCredentials.Keys) {
                    if ($DomainCredentials[$dk]) { $primaryCred = $DomainCredentials[$dk]; break }
                }
                if ($primaryCred) { $rbacParams['Credential'] = $primaryCred }

                $rbacComplianceData = Invoke-RBACComplianceAudit @rbacParams

                $rbacDetailCount = 0
                $rbacSummaryCount = 0
                if ($rbacComplianceData.RBACCompliance) { $rbacDetailCount = $rbacComplianceData.RBACCompliance.Count }
                if ($rbacComplianceData.RBACSummary) { $rbacSummaryCount = $rbacComplianceData.RBACSummary.Count }
                Write-HVLog "Step 5l: RBAC audit complete -- $rbacDetailCount detail rows, $rbacSummaryCount machine summaries" -Level Info
            }
            catch {
                Write-HVLog "Step 5l: RBAC Compliance Audit failed: $($_.Exception.Message)" -Level Warning
            }
        }
        else {
            Write-HVLog "Step 5l: Invoke-RBACComplianceAudit not available (Security module may need update)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5l: RBAC Compliance Audit disabled in config (RBACBuiltinGroups.Enabled = false or missing)" -Level Info
    }

    # Step 5m: VM Activity Audit (v3.10.2 Session 14)
    $vmActivityData = $null
    $enableVMActivity = $false
    if ($config -and $config.ContainsKey('IncludeVMActivityAudit')) {
        $enableVMActivity = $config.IncludeVMActivityAudit
    }
    if ($enableVMActivity -and $ReportLevel -notin @('Advanced','All')) {
        Write-HVLog "Step 5m: VM Activity Audit skipped (Advanced report only, current level: $ReportLevel)" -Level Info
        $enableVMActivity = $false
    }
    if ($enableVMActivity) {
        if (Get-Command -Name 'Invoke-VMActivityAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5m: VM Activity Audit..." -Level Info
            try {
                $vmActivityDaysBack = if ($config.VMActivityDaysBack) { $config.VMActivityDaysBack } else { 7 }
                $primaryCred = $null
                foreach ($dk in $DomainCredentials.Keys) {
                    if ($DomainCredentials[$dk]) { $primaryCred = $DomainCredentials[$dk]; break }
                }
                $actParams = @{
                    HostData = @($completedHosts)
                    DaysBack = $vmActivityDaysBack
                }
                if ($primaryCred) { $actParams['Credential'] = $primaryCred }
                $vmActivityData = Invoke-VMActivityAudit @actParams
                Write-HVLog "Step 5m: VM Activity Audit complete -- $($vmActivityData.Count) events" -Level Info
            }
            catch {
                Write-HVLog "Step 5m: VM Activity Audit failed: $($_.Exception.Message)" -Level Warning
            }
        }
        else {
            Write-HVLog "Step 5m: Invoke-VMActivityAudit not available (VMActivity module not loaded)" -Level Warning
        }
    }
    else {
        Write-HVLog "Step 5m: VM Activity Audit disabled in config (IncludeVMActivityAudit = false or missing)" -Level Info
    }

    # Step 5n: Offline Disk Aggregation (v3.10.4 CR83)
    # Collects OfflineDiskStatus data from all VMs where the Core module's per-VM
    # WinRM collection succeeded. Builds a flat list of offline disk entries for
    # the VM-Offline-Disks tab and Summary/Exec Summary reporting.
    $offlineDiskData = @()
    $includeOfflineDiskCheck = if ($config -and $null -ne $config.IncludeOfflineDiskCheck) { [bool]$config.IncludeOfflineDiskCheck } else { $true }
    if ($includeOfflineDiskCheck) {
        Write-HVLog "Step 5n: Aggregating Offline Disk data from VM inventory..." -Level Info
        $vmChecked = 0
        $vmWithOffline = 0
        $totalOffline = 0
        foreach ($hostData in $completedHosts) {
            if (-not $hostData.VMs) { continue }
            $hostName = $hostData.HostName
            $clusterName = if ($hostData.ClusterInfo -and $hostData.ClusterInfo.ClusterName) { $hostData.ClusterInfo.ClusterName } else { '' }
            foreach ($vm in $hostData.VMs) {
                if (-not $vm.OfflineDiskStatus) { continue }
                $vmChecked++
                $status = $vm.OfflineDiskStatus
                if ($status.TotalDiskCount -eq -1) { continue }  # Get-Disk failed (e.g. Server 2008 R2)

                # Resolve guest OS name (same priority as DNS-Validation)
                $guestName = ''
                if ($vm.GuestComputerName) { $guestName = $vm.GuestComputerName }
                elseif ($vm.KVPData -and $vm.KVPData.FullyQualifiedDomainName) {
                    $fqdn = $vm.KVPData.FullyQualifiedDomainName
                    $guestName = ($fqdn -split '\.')[0]
                }
                if (-not $guestName) { $guestName = $vm.Name }

                if ($status.OfflineDisks -and $status.OfflineDisks.Count -gt 0) {
                    $vmWithOffline++

                    # v3.10.9 CR97: Detect if this VM has Storage Spaces / is a cluster node.
                    # If both are true, offline disks are likely S2D pooled storage and are
                    # intentionally offline (passive cluster node, quorum witness, pool reserve).
                    $vmHasS2D = [bool]$status.HasStoragePool
                    $vmIsCluster = [bool]$status.IsClusterNode
                    $vmPoolName = if ($status.StoragePoolName) { $status.StoragePoolName } else { '' }

                    foreach ($disk in $status.OfflineDisks) {
                        $totalOffline++
                        $diskNum = $disk.DiskNumber
                        $diskNumStr = if ($null -ne $diskNum) { [string]$diskNum } else { 'N/A' }
                        $diskUniqueId = if ($disk.UniqueId) { $disk.UniqueId } else { '' }

                        # CR97: Classify why the disk is offline
                        $offlineCategory = 'Investigate'
                        if ($vmHasS2D -and $vmIsCluster -and ($null -eq $diskNum)) {
                            # S2D pooled disk on a cluster node -- expected offline on passive node
                            $offlineCategory = 'S2D Pool (expected)'
                        }
                        elseif ($vmHasS2D -and ($null -eq $diskNum)) {
                            $offlineCategory = 'Storage Pool (review)'
                        }
                        elseif ($disk.OfflineReason -eq 'Policy' -and $disk.BusType -eq 'SAS') {
                            $offlineCategory = 'SAN Policy (V2V migration)'
                        }
                        elseif ($disk.OfflineReason -eq 'Policy') {
                            $offlineCategory = 'SAN Policy'
                        }

                        $remediation = @()
                        if ($null -ne $diskNum) {
                            # Standard disk with a number -- use Set-Disk -Number
                            $remediation += "Set-Disk -Number $diskNum -IsOffline `$false"
                            if ($disk.IsReadOnly) {
                                $remediation += "Set-Disk -Number $diskNum -IsReadOnly `$false"
                            }
                        }
                        else {
                            # S2D/pooled disk without a number -- use Get-Disk + UniqueId or FriendlyName
                            $remediation += "# S2D pooled disk (no disk number) -- identify by UniqueId or size"
                            if ($diskUniqueId) {
                                $remediation += "Get-Disk | Where-Object { `$_.UniqueId -eq '$diskUniqueId' } | Set-Disk -IsOffline `$false"
                            }
                            else {
                                $remediation += "Get-Disk | Where-Object { `$_.IsOffline -and `$_.Size -eq $([long]($disk.SizeGB * 1GB)) } | Set-Disk -IsOffline `$false"
                            }
                        }
                        if ($status.SANPolicy -and $status.SANPolicy -ne 'Online All') {
                            $remediation += "Set-StorageSetting -NewDiskPolicy OnlineAll"
                        }

                        $offlineDiskData += [PSCustomObject]@{
                            # v3.10.9 CR91 FIX: VM name is stored as .VM not .Name in the vmInfo hashtable.
                            VMName            = if ($vm.VM) { $vm.VM } elseif ($vm.Name) { $vm.Name } else { '' }
                            Host              = $hostName
                            ClusterName       = $clusterName
                            GuestOSDNSName    = $guestName
                            DiskNumber        = $diskNumStr
                            SizeGB            = $disk.SizeGB
                            PartitionStyle    = $disk.PartitionStyle
                            OperationalStatus = $disk.OperationalStatus
                            HealthStatus      = $disk.HealthStatus
                            IsOffline         = $disk.IsOffline
                            IsReadOnly        = $disk.IsReadOnly
                            OfflineReason     = $disk.OfflineReason
                            BusType           = $disk.BusType
                            SANPolicy         = if ($status.SANPolicy) { $status.SANPolicy } else { 'Unknown' }
                            OfflineCategory   = $offlineCategory
                            HasStoragePool    = $vmHasS2D
                            StoragePoolName   = $vmPoolName
                            TotalGuestDisks   = $status.TotalDiskCount
                            Remediation       = ($remediation -join '; ')
                            DataSource        = 'HYPER-V'
                        }
                    }
                }
            }
        }
        Write-HVLog "Step 5n: Offline Disk aggregation complete -- $vmChecked VMs checked, $vmWithOffline with offline disks, $totalOffline total offline disks" -Level $(if ($vmWithOffline -gt 0) { 'Warning' } else { 'Success' })
    }
    else {
        Write-HVLog "Step 5n: Offline Disk Check disabled in config (IncludeOfflineDiskCheck = false)" -Level Info
    }

    # Step 5o: SCCM Client Status Audit (v3.10.7 Session 9)
    $sccmData = $null
    $enableSCCM = $false
    if ($config -and $config.ContainsKey('IncludeSCCM')) {
        $enableSCCM = $config.IncludeSCCM
    }
    if ($enableSCCM -and $ReportLevel -notin @('Advanced','All')) {
        Write-HVLog "Step 5o: SCCM Client Audit skipped (Advanced report only, current level: $ReportLevel)" -Level Info
        $enableSCCM = $false
    }
    if ($enableSCCM) {
        if (Get-Command -Name 'Invoke-SCCMClientAudit' -ErrorAction SilentlyContinue) {
            Write-HVLog "Step 5o: SCCM Client Audit..." -Level Info
            try {
                $sccmServer   = if ($config.SCCMSiteServer) { $config.SCCMSiteServer } else { '' }
                $sccmSiteCode = if ($config.SCCMSiteCode)   { $config.SCCMSiteCode }   else { '' }
                $sccmMethod   = if ($config.SCCMMethod)     { $config.SCCMMethod }     else { 'WMI' }

                if ($sccmServer -and $sccmSiteCode) {
                    $sccmParams = @{
                        SCCMSiteServer = $sccmServer
                        SCCMSiteCode   = $sccmSiteCode
                        HostData       = @($completedHosts)
                        Method         = $sccmMethod
                    }
                    # Use ohdc.com credential for SCCM (same domain as site server)
                    if ($domainCredentials -and $domainCredentials.ContainsKey('ohdc.com')) {
                        $sccmParams['Credential'] = $domainCredentials['ohdc.com']
                    }
                    elseif ($Credential) {
                        $sccmParams['Credential'] = $Credential
                    }
                    $sccmData = Invoke-SCCMClientAudit @sccmParams
                    if ($sccmData -and $sccmData.ClientData) {
                        Write-HVLog "Step 5o: SCCM Client Audit complete -- $($sccmData.Stats.Total) clients, $($sccmData.Stats.MissingClient) missing, $($sccmData.Stats.MatchedToHV) matched to Hyper-V" -Level Info
                    }
                }
                else {
                    Write-HVLog "Step 5o: SCCM enabled but SCCMSiteServer or SCCMSiteCode not configured" -Level Warning
                }
            }
            catch {
                Write-HVLog "Step 5o: SCCM Client Audit error -- $($_.Exception.Message)" -Level Error
            }
        }
        else {
            Write-HVLog "Step 5o: SCCM module not loaded (HyperVInventory-SCCM.psm1 missing from Modules folder)" -Level Info
        }
    }
    else {
        if (-not $enableSCCM) {
            Write-HVLog "Step 5o: SCCM Client Audit disabled in config (IncludeSCCM = false)" -Level Info
        }
    }

    # Step 6: Export to Excel
    Write-HVLog "Step 6: Exporting to Excel..." -Level Info
    
    # Helper: inject report level into filename
    # e.g. HyperV-Inventory_20260223_130710.xlsx -> HyperV-Inventory_Basic_20260223_130710.xlsx
    function Get-LeveledOutputPath {
        param([string]$BasePath, [string]$Level)
        $dir  = Split-Path $BasePath -Parent
        $name = [System.IO.Path]::GetFileNameWithoutExtension($BasePath)
        $ext  = [System.IO.Path]::GetExtension($BasePath)
        # Insert level before the timestamp portion
        if ($name -match '(.+?)(_\d{8}_\d{6})$') {
            return Join-Path $dir "$($Matches[1])_${Level}$($Matches[2])$ext"
        }
        else {
            return Join-Path $dir "${name}_${Level}$ext"
        }
    }
    
    $baseExportParams = @{
        HostData                        = @($completedHosts)
        ClusterData                     = $clusters
        UnavailableHosts                = @($unavailableHosts)
        CPUAnalysis                     = $cpuAnalysis
        StorageAnalysis                 = $storageAnalysis
        ComplianceIssues                = $complianceCheck
        Recommendations                 = $recommendations
        MissingVMs                      = $missingVMs
        AppCompliance                   = if ($config -and $config.AppCompliance) { $config.AppCompliance } else { $null }
        GuestStorageHistory             = $guestStorageHistory
        GuestStorageMonthlyColumns      = $GuestStorageMonthlyColumns
        ServicesFilter                  = $ServicesFilter
        RequiredBuiltinMembers          = $RequiredBuiltinMembers
        ADAuthData                      = $adAuthData      # S5a: hashtable[computerName -> AD auth posture]
        FeaturesData                    = $featuresData    # S5a: hashtable[computerName -> feature array]
        RemediationScriptPath           = $remediationScriptPath  # S5b: path to generated remediation .ps1
        RemediationIssues               = $remIssues      # S5b: issue list for Remediation-Commands tab
        SPNAuditResults                 = $spnAuditResults    # S5c: SPN inventory (all service classes)
        DoublehopResults                = $doublehopResults   # S5c: domain-account service/task/IIS map
        NTLMRiskResults                 = $ntlmRiskResults    # S5c: per-machine NTLM risk + remediation
        NTLMReadinessData               = $ntlmReadinessResults # S5e: NTLM deprecation readiness (protocol config)
        SvcAccountSPNData               = $svcAccountSPNResults # S5f: service account SPN audit
        KCDValidationData               = $kcdValidationResults # v3.8.9.2: KCD validation audit
        LiveMigData                     = $liveMigData        # S6: live migration config per host
        NICauditData                    = $nicAuditData       # S6: host NIC audit -- gateway/DNS violations
        DCGuidData                      = $dcGuidData         # S6: DC DSA GUID + _msdcs CNAME validation
        VHDDriveMap                     = $vhdDriveMap        # S7: VHD-to-guest drive letter correlation
        S2DAuditData                    = $s2dAuditData       # S8b: S2D storage audit (CR2)
        ResourceMeteringData            = $resourceMeteringData # S8d: VM resource metering + IOPS (CR20)
        IOPSCollectorData               = $iopsCollectorData    # S8d-2: IOPS Collector trends + heatmap
        TLSAuditData                    = $tlsAuditData        # S8e: TLS / Secure Channel compliance (CR27)
        CipherAuditData                 = $cipherAuditData     # v3.10.12.27 OPEN-68: Cipher / Kerberos etype audit
        DNSValidationData               = $dnsValidationData   # v3.9.2 CR57: DNS record validation
        DiskFormatData                  = $diskFormatData      # S8f: Disk Format / Partition Audit (CR30)
        RBACComplianceData              = $rbacComplianceData  # S8h: RBAC Builtin Group Compliance (CR31)
        VMActivityData                  = $vmActivityData      # S14: VM Activity Audit (v3.10.2)
        VMActivitySeparateFile          = if ($config -and $config.VMActivitySeparateFile) { [bool]$config.VMActivitySeparateFile } else { $false }  # v3.10.12.9: Option B separate xlsx
        VMActivityChunkSize             = if ($config -and $config.VMActivityChunkSize) { [int]$config.VMActivityChunkSize } else { 5000 }  # v3.10.12.9: rows per chunk tab
        OfflineDiskData                 = $offlineDiskData     # v3.10.4 CR83: VM Offline Disk Detection
        SCCMData                        = if ($sccmData) { $sccmData.ClientData } else { $null }  # v3.10.7 CR89: SCCM Client Status
        SCCMStats                       = if ($sccmData) { $sccmData.Stats } else { $null }       # v3.10.7 CR89: SCCM summary stats
        LAPSData                        = $lapsResults   # v3.10.11 CR102: LAPS Audit posture data for LAPS-Usage tab
        ADInfoData                      = $adInfoData                  # v3.10.11 Step 5q: AD Forest/Domain topology for AD-Info tab
        SPNInventoryFullData            = $spnInventoryFullResults     # v3.10.12 OPEN-66: AD-wide SPN inventory for SPN-Inventory-Full tab
        PermissionData                  = $permissionData              # v3.10.12 OPEN-60: Local group + privilege audit for Permissions tabs
        VHDChainData                    = $vhdChainData                # v3.10.12 CR105: VHD parent chain data for VHD-Chain tab
        VHDChainRemediationResults      = $vhdChainRemediationResults  # v3.10.12 CR106: remediation script generation results
        AuditScope                      = $auditScope          # OPEN-67: HostsOnly / HostsAndVMs / Full -- drives DataSource+Type columns
        IncludeVMScope                  = $includeVMScope      # OPEN-67: derived bool for tabs that add VM rows
        ScriptVersion                   = $script:ModuleVersion  # suite version for Summary tab
        # v3.8.9.6: Configurable storage thresholds (CR53)
        GuestStorageCriticalPct         = if ($config -and $config.GuestStorageCriticalPct) { [int]$config.GuestStorageCriticalPct } else { 5 }
        GuestStorageWarningPct          = if ($config -and $config.GuestStorageWarningPct)  { [int]$config.GuestStorageWarningPct }  else { 10 }
        GuestStorageBufferPct           = if ($config -and $config.GuestStorageBufferPct)   { [int]$config.GuestStorageBufferPct }   else { 10 }
    }
    
    # v3.10.12.28 OPEN-61: Runtime re-capture of KCD remediation function.
    # The module-body capture (lines ~165-205) runs at IMPORT time, before PS
    # has finished registering all module exports in the session command table.
    # Get-Command can't see PSM1-fallback functions during module loading.
    # At this point (just before export) all modules are fully loaded and
    # the session is fully initialized -- Get-Command works reliably.
    if (-not $global:HVI_fnKCDRemediationScript) {
        Write-HVLog "  OPEN-61: Attempting runtime re-capture of New-KCDRemediationScript..." -Level Info
        # Approach 1: scan all loaded modules for the exported command
        $kcdMod = Get-Module | Where-Object { $_.ExportedCommands -and $_.ExportedCommands.ContainsKey('New-KCDRemediationScript') } | Select-Object -First 1
        if ($kcdMod) {
            $global:HVI_fnKCDRemediationScript = $kcdMod.ExportedCommands['New-KCDRemediationScript']
            $global:HVI_fnKCDRemediationIndex  = if ($kcdMod.ExportedCommands.ContainsKey('New-KCDRemediationIndex')) { $kcdMod.ExportedCommands['New-KCDRemediationIndex'] } else { $null }
            Write-HVLog "  OPEN-61: KCD functions resolved at runtime via ExportedCommands scan ($($kcdMod.Name))" -Level Info
        }
        # Approach 2: Get-Command (works when module is in session scope)
        if (-not $global:HVI_fnKCDRemediationScript) {
            $gc = Get-Command -Name 'New-KCDRemediationScript' -ErrorAction SilentlyContinue
            if ($gc) {
                $global:HVI_fnKCDRemediationScript = $gc
                $global:HVI_fnKCDRemediationIndex  = Get-Command -Name 'New-KCDRemediationIndex' -ErrorAction SilentlyContinue
                Write-HVLog "  OPEN-61: KCD functions resolved at runtime via Get-Command" -Level Info
            }
        }
        # Approach 3: force-import the Remediation PSM1 and retry
        if (-not $global:HVI_fnKCDRemediationScript) {
            $remPsm1rt = Join-Path $modulesFolder 'HyperVInventory-Remediation.psm1'
            if (Test-Path $remPsm1rt) {
                try {
                    Import-Module $remPsm1rt -Force -Global -ErrorAction Stop -WarningAction SilentlyContinue
                    $gc = Get-Command -Name 'New-KCDRemediationScript' -ErrorAction SilentlyContinue
                    if (-not $gc) {
                        $kcdMod2 = Get-Module | Where-Object { $_.ExportedCommands -and $_.ExportedCommands.ContainsKey('New-KCDRemediationScript') } | Select-Object -First 1
                        if ($kcdMod2) { $gc = $kcdMod2.ExportedCommands['New-KCDRemediationScript'] }
                    }
                    if ($gc) {
                        $global:HVI_fnKCDRemediationScript = $gc
                        $global:HVI_fnKCDRemediationIndex  = Get-Command -Name 'New-KCDRemediationIndex' -ErrorAction SilentlyContinue
                        Write-HVLog "  OPEN-61: KCD functions resolved at runtime via forced PSM1 re-import" -Level Info
                    }
                } catch {
                    Write-HVLog "  OPEN-61: Runtime PSM1 re-import failed -- $($_.Exception.Message)" -Level Warning
                }
            }
        }
        if (-not $global:HVI_fnKCDRemediationScript) {
            Write-HVLog "  OPEN-61: All runtime re-capture attempts failed -- KCD scripts will not be generated" -Level Warning
        }
    }

    if ($ReportLevel -eq 'All') {
        # Generate all 3 report levels as separate files
        foreach ($level in @('Basic','Intermediate','Advanced')) {
            $levelPath = Get-LeveledOutputPath -BasePath $OutputPath -Level $level
            Write-HVLog "Exporting $level report: $levelPath" -Level Info
            $exportParams = $baseExportParams.Clone()
            $exportParams['OutputPath'] = $levelPath
            $exportParams['ReportLevel'] = $level
            Export-HyperVInventoryToExcel @exportParams
        }
    }
    else {
        $levelPath = Get-LeveledOutputPath -BasePath $OutputPath -Level $ReportLevel
        $exportParams = $baseExportParams.Clone()
        $exportParams['OutputPath'] = $levelPath
        $exportParams['ReportLevel'] = $ReportLevel
        Export-HyperVInventoryToExcel @exportParams
        $OutputPath = $levelPath
    }
    
    # Summary
    $totalVMs = 0
    $runningVMs = 0
    foreach ($hostData in $completedHosts) {
        if ($hostData.VMs) {
            $totalVMs += $hostData.VMs.Count
            $runningVMs += @($hostData.VMs | Where-Object { $_.Powerstate -eq 'poweredOn' }).Count
        }
    }
    
    Write-HVLog "==================================================" -Level Success
    Write-HVLog "INVENTORY COMPLETE!" -Level Success
    Write-HVLog "Hosts: $($completedHosts.Count) | VMs: $totalVMs | Running: $runningVMs" -Level Info
    Write-HVLog "Clusters: $(if ($clusters) { $clusters.Count } else { 0 })" -Level Info
    if ($missingVMs.Count -gt 0) {
        Write-HVLog "Missing VMs (in history, not current): $($missingVMs.Count)" -Level Warning
        foreach ($mvm in $missingVMs) {
            $mvmName = $mvm.VM
            $mvmHost = $mvm.PreviousHosts
            $mvmLast = $mvm.LastSeen
            Write-HVLog "  Missing: $mvmName (last on $mvmHost, last seen $mvmLast)" -Level Warning
        }
    }
    Write-HVLog "Time: $([math]::Round(((Get-Date) - $startTime).TotalMinutes, 0)) minutes" -Level Info
    Write-HVLog "Report: $OutputPath" -Level Success
    Write-HVLog "History: $HistoryPath" -Level Info
    Write-HVLog "==================================================" -Level Success
    
    # Open output folder
    try { Start-Process (Split-Path $OutputPath) } catch {}
}

Export-ModuleMember -Function Get-HyperVInventory
