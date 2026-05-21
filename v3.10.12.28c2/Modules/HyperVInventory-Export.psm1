<#
.SYNOPSIS
    HyperV Inventory v3.6.1 - Export Module

.DESCRIPTION
    v3.6.1 ENHANCEMENTS (S5a/S5b/S5c):
    - S5a: AD-Auth-Detail tab (Advanced): per-machine Kerberos delegation, SPN, LAPS posture.
           AD-Auth-Issues tab (Advanced): rolled-up Critical/Warning/Info auth findings.
           Roles-Features tab (Intermediate+): installed Windows roles, features, .NET versions.
    - S5b: Remediation-Commands tab (Advanced): index pointing to auto-generated .ps1 script
           covering delegation fixes, SPN registration, WinRM HTTPS enablement, and LAPS.
    - S5c: SPN-Inventory tab (Advanced): all registered SPNs categorized by service class
           with gap detection (missing expected SPNs) and duplicate registration warnings.
           DoubleHop-Map tab (Advanced): domain-account services, scheduled tasks, and IIS
           app pool identities cross-referenced against Kerberos delegation configuration.
           NTLM-Elimination tab (Advanced): per-machine NTLM risk score (Critical/High/
           Medium/Low/OK) with inline setspn and Set-ADComputer remediation commands,
           sorted by priority to guide the NTLM elimination program.

    v3.6.1 ENHANCEMENTS:
    - S4-1: Local-Admins tab (Advanced): per-VM Administrators group membership with
            unauthorized/missing member flagging against RequiredBuiltinMembers config.
    - S4-2: Services collection filtered at source (Auto-start only by default).
            Services-Alerts tab (Intermediate+): stopped Auto-start and non-standard
            service accounts surfaced without the noise of 10K+ rows.
            Services tab chunked to bypass Excel 10K row export limit.
    - S4-3: WinRM-Health tab (Intermediate+): per-VM WinRM status, HTTPS cert expiry,
            CredSSP status, and alert level in a dedicated operational view.
    - S4-4: Summary tab enhanced with sectioned operational dashboard.

.NOTES
    Author: Michael George
    Version: 3.8.6-Export
    Date: March 20, 2026
    Requires: ImportExcel module
#>

#Requires -Version 5.0

function Export-HyperVInventoryToExcel {
    <#
    .SYNOPSIS
        Exports comprehensive inventory to Excel with up to 29 worksheets
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$HostData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [array]$ClusterData,
        
        [Parameter(Mandatory=$false)]
        [array]$CPUAnalysis,
        
        [Parameter(Mandatory=$false)]
        [array]$StorageAnalysis,
        
        [Parameter(Mandatory=$false)]
        [array]$ComplianceIssues,
        
        [Parameter(Mandatory=$false)]
        [array]$Recommendations,
        
        [Parameter(Mandatory=$false)]
        [array]$UnavailableHosts,
        
        [Parameter(Mandatory=$false)]
        [array]$MissingVMs,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Basic','Intermediate','Advanced','All')]
        [string]$ReportLevel = 'Basic',
        
        [Parameter(Mandatory=$false)]
        [hashtable]$AppCompliance,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$GuestStorageHistory,
        
        [Parameter(Mandatory=$false)]
        [bool]$GuestStorageMonthlyColumns = $true,
        
        # Services collection filter (v3.6.1)
        [Parameter(Mandatory=$false)]
        [hashtable]$ServicesFilter = @{},
        
        # Required local group members for admin audit (v3.6.1 - S4-1)
        [Parameter(Mandatory=$false)]
        [hashtable]$RequiredBuiltinMembers = @{},

        # AD Authentication Audit data (v3.6.1 - S5a)
        # Hashtable[ComputerName -> PSCustomObject] from Invoke-ADAuthCollection
        [Parameter(Mandatory=$false)]
        [hashtable]$ADAuthData = @{},

        # Roles and Features data (v3.6.1 - S5a)
        # Hashtable[ComputerName -> feature array] from OS module collection
        [Parameter(Mandatory=$false)]
        [hashtable]$FeaturesData = @{},

        # Remediation script path (v3.6.1 - S5b)
        # Full path to the generated HyperV-Remediation_<timestamp>.ps1
        [Parameter(Mandatory=$false)]
        [string]$RemediationScriptPath = '',

        # Remediation issues list (v3.6.1 - S5b)
        # Issue objects for the Remediation-Commands tab
        [Parameter(Mandatory=$false)]
        [object]$RemediationIssues = $null,

        # SPN Inventory results (v3.6.1 - S5c)
        # List of SPN audit rows from Invoke-SPNAudit
        [Parameter(Mandatory=$false)]
        [object]$SPNAuditResults = $null,

        # Double-hop map results (v3.6.1 - S5c)
        # List of domain-account service/task/IIS rows from Resolve-DoublehopMap
        [Parameter(Mandatory=$false)]
        [object]$DoublehopResults = $null,

        # NTLM Risk synthesis results (v3.6.1 - S5c)
        # List of per-machine NTLM risk rows from Build-NTLMRiskMap
        [Parameter(Mandatory=$false)]
        [object]$NTLMRiskResults = $null,

        # Live Migration config per host (v3.7.0 - S6)
        [Parameter(Mandatory=$false)]
        [object]$LiveMigData = $null,

        # Host NIC Audit results (v3.7.0 - S6)
        # All physical/virtual NIC rows with gateway and DNS violation flags
        [Parameter(Mandatory=$false)]
        [object]$NICauditData = $null,

        # DC DSA GUID + _msdcs CNAME validation (v3.7.0 - S6)
        [Parameter(Mandatory=$false)]
        [object]$DCGuidData = $null,

        # VHD-to-Guest Drive Letter correlation map (v3.7.0 - S7)
        # From Build-VHDDriveMap -- one row per VHD per VM
        [Parameter(Mandatory=$false)]
        [object]$VHDDriveMap = $null,

        # S2D Storage Audit results (v3.8.0 - CR2)
        # Hashtable from Invoke-S2DAudit: keys S2DRows, S2DSummaryRows, S2DFindings
        [Parameter(Mandatory=$false)]
        [hashtable]$S2DAuditData = @{},

        # VM Resource Metering + IOPS data (v3.8.7 - Session 8d)
        # Hashtable from Invoke-ResourceMeteringCollection:
        #   VMIOPSSummary, VMIOPSPerDisk, HostIOPSSummary, IOPSRecommendations
        [Parameter(Mandatory=$false)]
        [hashtable]$ResourceMeteringData = @{},

        # TLS / Secure Channel compliance audit results (v3.9.0 Session 8e)
        #   TLSCompliance, TLSRecommendations
        [Parameter(Mandatory=$false)]
        [hashtable]$TLSAuditData = @{},

        # Cipher / Kerberos Encryption-Type audit results (v3.10.12.27, OPEN-68)
        #   CipherAudit, KerberosEtypes, CipherInterop, CipherDiagnostics, EtypeReference
        [Parameter(Mandatory=$false)]
        [hashtable]$CipherAuditData = @{},

        # v3.9.2: DNS Record Validation (CR57)
        [Parameter(Mandatory=$false)]
        [hashtable]$DNSValidationData = @{},

        # Disk Format / Partition Audit results (v3.9.0 Session 8f)
        [Parameter(Mandatory=$false)]
        [array]$DiskFormatData = @(),

        # RBAC Builtin Group Compliance Audit results (v3.8.9 Session 8h)
        # Hashtable with keys: RBACCompliance (detail rows), RBACSummary (per-machine summary)
        [Parameter(Mandatory=$false)]
        [hashtable]$RBACComplianceData = @{},

        # VM Activity Audit results (v3.10.2 Session 14)
        [Parameter(Mandatory=$false)]
        [array]$VMActivityData = @(),

        # VM Offline Disk Detection results (v3.10.4 CR83)
        [Parameter(Mandatory=$false)]
        [array]$OfflineDiskData = @(),

        # SCCM Client Status data (v3.10.7 CR89 Session 9)
        [Parameter(Mandatory=$false)]
        [array]$SCCMData = @(),

        # SCCM summary statistics (v3.10.7 CR89)
        [Parameter(Mandatory=$false)]
        [hashtable]$SCCMStats = @{},

        # LAPS Audit results (v3.10.11 CR102+CR103)
        # Array of PSCustomObjects from Invoke-LAPSAudit -- one per Windows domain-joined VM
        [Parameter(Mandatory=$false)]
        [array]$LAPSData = @(),

        # v3.10.12.9 CR-VMActivityCrash: Export VM-Activity-Audit to a separate xlsx
        # When $true, VM-Activity-Audit writes to its own file instead of the main
        # workbook. This avoids the EPPlus Save() crash that occurs when adding
        # 14K+ rows with conditional formatting to an already-large (~50 tab) xlsx.
        # The crash corrupts the entire main workbook (all prior tabs are lost).
        # Default: $false (same file). Set $true in config: VMActivitySeparateFile = $true
        [Parameter(Mandatory=$false)]
        [bool]$VMActivitySeparateFile = $false,

        # v3.10.12.9: Configurable chunk size for VM-Activity-Audit tab splitting.
        # Controls max rows per worksheet tab. Lower values reduce EPPlus memory
        # pressure during Save(). Default: 5000. Set in config: VMActivityChunkSize = 5000
        [Parameter(Mandatory=$false)]
        [int]$VMActivityChunkSize = 5000,

        # Permission Audit results (v3.10.12 OPEN-60)
        # Hashtable with GroupData and PrivilegeData arrays from Invoke-PermissionAudit
        [Parameter(Mandatory=$false)]
        [hashtable]$PermissionData = @{},

        # AD Forest/Domain topology data (v3.10.11 Step 5q -- AD-Info tab)
        # Array of PSCustomObjects from the Step 5q AD topology collection.
        # One row per scope level: one Forest row + one Domain row per domain.
        [Parameter(Mandatory=$false)]
        [array]$ADInfoData = @(),

        # AD-wide SPN inventory (v3.10.12 OPEN-66 -- SPN-Inventory-Full tab)
        # Array of PSCustomObjects from Invoke-SPNInventoryFull.
        # One row per SPN per account (computer + user) across all domains.
        # Opt-in: IncludeSPNInventoryFull = $true in config.
        [Parameter(Mandatory=$false)]
        [array]$SPNInventoryFullData = @(),

        # VHD Parent Chain data (v3.10.12 CR105 -- VHD-Chain tab)
        # Array of PSCustomObjects from Invoke-VHDChainCollection.
        # One row per chain link (Active/Checkpoint/Base/Passthrough/BrokenParent/Error).
        [Parameter(Mandatory=$false)]
        [array]$VHDChainData = @(),

        # VHD Chain remediation script generation results (v3.10.12 CR106)
        # Array of result objects from New-VMRemediationScript calls.
        # Used to populate RemediationScriptPath column on VHD-Chain tab and
        # add the script count line to the Executive Summary.
        [Parameter(Mandatory=$false)]
        [array]$VHDChainRemediationResults = @(),

        # NTLM Deprecation Readiness Audit results (v3.8.9 Session 5e)
        [Parameter(Mandatory=$false)]
        [array]$NTLMReadinessData = @(),

        # Service Account SPN Audit results (v3.8.9 Session 5f)
        [Parameter(Mandatory=$false)]
        [array]$SvcAccountSPNData = @(),

        # KCD Validation Audit results (v3.8.9.2)
        [Parameter(Mandatory=$false)]
        [array]$KCDValidationData = @(),

        # IOPS Collector trend + heatmap data (v3.8.9.2 Session 8d-2)
        [Parameter(Mandatory=$false)]
        [hashtable]$IOPSCollectorData = @{},

        # Suite version string for Summary tab (v3.7.2)
        [Parameter(Mandatory=$false)]
        [string]$ScriptVersion = '',

        # OPEN-67: DataSource / Type / Scope expansion (v3.10.12.26)
        # AuditScope drives which tabs include VM rows alongside host rows.
        [Parameter(Mandatory=$false)]
        [string]$AuditScope = 'HostsOnly',

        [Parameter(Mandatory=$false)]
        [bool]$IncludeVMScope = $false,

        # v3.8.9.6: Configurable storage thresholds (CR53)
        # These control VM-Guest-Storage alert levels and Summary tab labels.
        # Host-Storage-Risk thresholds are in the Analysis module (separate config).
        [Parameter(Mandatory=$false)]
        [int]$GuestStorageCriticalPct = 5,

        [Parameter(Mandatory=$false)]
        [int]$GuestStorageWarningPct = 10,

        [Parameter(Mandatory=$false)]
        [int]$GuestStorageBufferPct = 10
    )
    
    Write-HVLog "Exporting inventory to Excel: $OutputPath" -Level Info
    
    try {
        # Ensure output directory exists
        $outputDir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }
        
        # Remove existing file
        if (Test-Path $OutputPath) {
            Remove-Item $OutputPath -Force
        }
        
        # Prepare data collections
        $summary = [System.Collections.Generic.List[object]]::new()
        $vmInfo = [System.Collections.Generic.List[object]]::new()
        $cpuInfo = [System.Collections.Generic.List[object]]::new()
        $memoryInfo = [System.Collections.Generic.List[object]]::new()
        $diskInfo = [System.Collections.Generic.List[object]]::new()
        $networkInfo = [System.Collections.Generic.List[object]]::new()
        $checkpointInfo = [System.Collections.Generic.List[object]]::new()
        $hostInfoList = [System.Collections.Generic.List[object]]::new()
        $integrationInfo = [System.Collections.Generic.List[object]]::new()
        $storageInfo = [System.Collections.Generic.List[object]]::new()
        $vmGuestStorage = [System.Collections.Generic.List[object]]::new()
        $replicationInfo = [System.Collections.Generic.List[object]]::new()
        $dvdInfo = [System.Collections.Generic.List[object]]::new()
        $osInventory = [System.Collections.Generic.List[object]]::new()
        $applicationsWindows = [System.Collections.Generic.List[object]]::new()
        $applicationsLinux = [System.Collections.Generic.List[object]]::new()
        $securityCompliance = [System.Collections.Generic.List[object]]::new()
        $diskAnalysis = [System.Collections.Generic.List[object]]::new()
        $rebootHistory = [System.Collections.Generic.List[object]]::new()
        $vSwitchConfig = [System.Collections.Generic.List[object]]::new()
        $servicesList       = [System.Collections.Generic.List[object]]::new()
        $servicesAlerts     = [System.Collections.Generic.List[object]]::new()
        $localAdminsList    = [System.Collections.Generic.List[object]]::new()
        $localBuiltinList   = [System.Collections.Generic.List[object]]::new()   # v3.8.0 CR5
        $winrmHealth        = [System.Collections.Generic.List[object]]::new()
        $scheduledTasksList = [System.Collections.Generic.List[object]]::new()   # v3.6.1 S4b
        $rolesFeaturesList  = [System.Collections.Generic.List[object]]::new()   # v3.6.1 S5a
        $adAuthDetailList   = [System.Collections.Generic.List[object]]::new()   # v3.6.1 S5a
        $adAuthIssuesList   = [System.Collections.Generic.List[object]]::new()   # v3.6.1 S5a
        $crossDomainAuth    = [System.Collections.Generic.List[object]]::new()   # v3.9.0 CR54
        
        # ReportLevel flags -- must be set BEFORE processing loop (columns are gated on these)
        $isIntermediate = $ReportLevel -in @('Intermediate','Advanced')
        $isAdvanced     = $ReportLevel -eq 'Advanced'
        
        # Process each host
        foreach ($hvHost in $HostData) {
            if ($hvHost.Error) {
                Write-HVLog "Skipping $($hvHost.HostName): $($hvHost.Error)" -Level Warning
                continue
            }
            
            $hostName = $hvHost.HostName
            # Fallback: if HostName was lost during job serialization, get it from HostInfo
            if (-not $hostName -and $hvHost.HostInfo) {
                $hostName = $hvHost.HostInfo.Host
            }
            if (-not $hostName) { $hostName = 'Unknown' }
            
            # Host info
            if ($hvHost.HostInfo) {
                $hostObj = [ordered]@{
                    Host              = $hostName
                    Domain            = $hvHost.HostInfo.Domain
                    State             = $hvHost.HostInfo.State
                    LogicalProcessors = $hvHost.HostInfo.LogicalProcessors
                    MemoryGB          = $hvHost.HostInfo.MemoryGB
                    MemoryAvailableGB = $hvHost.HostInfo.MemoryAvailableGB
                    VMs               = $hvHost.HostInfo.VMs
                    RunningVMs        = $hvHost.HostInfo.RunningVMs
                    ClusterInfo       = if ($hvHost.ClusterInfo) { $hvHost.ClusterInfo.Info } else { "N/A" }
                    HyperVVersion     = $hvHost.HostInfo.HyperVVersion
                }
                
                # Intermediate/Advanced columns (not shown on Basic)
                if ($isIntermediate) {
                    $hostObj['HostType']          = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.HostType } else { "Unknown" }
                    $hostObj['FirmwareType']      = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.FirmwareType } else { "Unknown" }
                    $hostObj['SecureBootEnabled'] = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SecureBootEnabled } else { $false }
                    $hostObj['TPMVersion']        = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.TPMVersion } else { "Unknown" }
                    $hostObj['Manufacturer']      = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.Manufacturer } else { "Unknown" }
                    $hostObj['Model']             = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.Model } else { "Unknown" }
                    # Hardware detail (v3.3.0 - S3-2)
                    $hostObj['SerialNumber']      = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SerialNumber }      else { '' }
                    $hostObj['BIOSVersion']       = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.BIOSVersion }       else { '' }
                    $hostObj['BIOSDate']          = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.BIOSDate }          else { '' }
                    $hostObj['CPUModel']          = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.CPUModel }          else { '' }
                    $hostObj['PhysicalCPUs']      = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.PhysicalProcessors } else { 0 }
                    $hostObj['TotalCores']        = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.TotalCores }        else { 0 }
                    $hostObj['TotalLogicalProcs'] = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.TotalLogicalProcs } else { 0 }
                    $hostObj['HW_MemoryGB']       = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.TotalMemoryGB }     else { 0 }
                    $hostObj['SB_Capable']        = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SB_SecureBootCapable } else { $false }
                    $hostObj['SB_Has2023Certs']   = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SB_Has2023Certs } else { $false }
                    $hostObj['SB_CertCount']      = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SB_CertCount } else { 0 }
                    $hostObj['SB_UpdateRequired'] = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SB_UpdateRequired } else { 'Unknown' }
                    $hostObj['SB_DaysUntilExp']   = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SB_DaysUntilExpiration } else { $null }
                    $hostObj['SB_CertDetails']    = if ($hvHost.HostFirmware) { $hvHost.HostFirmware.SB_CertDetails } else { '' }
                    $hostObj['LastUpdateKB']      = if ($hvHost.HostUpdate) { $hvHost.HostUpdate.LastUpdateKB } else { 'N/A' }
                    $hostObj['LastUpdateDate']    = if ($hvHost.HostUpdate) { $hvHost.HostUpdate.LastUpdateDate } else { 'N/A' }
                    $hostObj['RebootPending']     = if ($hvHost.HostReboot) { $hvHost.HostReboot.RebootPending } else { $false }
                    $hostObj['RebootReasons']     = if ($hvHost.HostReboot -and $hvHost.HostReboot.RebootReasons) { $hvHost.HostReboot.RebootReasons -join '; ' } else { '' }
                    $hostObj['DockerRunning']     = if ($hvHost.HostInfo.DockerRunning) { $true } else { $false }
                    $hostObj['DockerServices']    = $hvHost.HostInfo.DockerServices
                    $hostObj['WSLEnabled']        = if ($hvHost.HostInfo.WSLEnabled) { $true } else { $false }
                    
                    # WinRM / CredSSP / HTTPS configuration (v3.2.9)
                    $hi = $hvHost.HostInfo
                    $hostObj['WinRM_Status']       = if ($hi.WinRM_Status) { $hi.WinRM_Status } else { 'Unknown' }
                    $hostObj['WinRM_StartType']    = if ($hi.WinRM_StartType) { $hi.WinRM_StartType } else { '' }
                    $hostObj['WinRM_Listeners']    = if ($hi.WinRM_Listeners) { $hi.WinRM_Listeners } else { '' }
                    $hostObj['WinRM_HTTPS']        = if ($hi.WinRM_HTTPS_Enabled) { $true } else { $false }
                    $hostObj['WinRM_HTTPS_CertExp']= if ($hi.WinRM_HTTPS_CertExp) { $hi.WinRM_HTTPS_CertExp } else { '' }
                    $hostObj['WinRM_HTTPS_Subject']= if ($hi.WinRM_HTTPS_Subject) { $hi.WinRM_HTTPS_Subject } else { '' }
                    $hostObj['WinRM_HTTPS_Issuer'] = if ($hi.WinRM_HTTPS_Issuer) { $hi.WinRM_HTTPS_Issuer } else { '' }
                    $hostObj['WinRM_AuthKerberos'] = if ($hi.WinRM_AuthKerberos) { $hi.WinRM_AuthKerberos } else { '' }
                    $hostObj['WinRM_AuthCredSSP']  = if ($hi.WinRM_AuthCredSSP) { $hi.WinRM_AuthCredSSP } else { '' }
                    $hostObj['WinRM_AuthNegotiate']= if ($hi.WinRM_AuthNegotiate) { $hi.WinRM_AuthNegotiate } else { '' }
                    $hostObj['WinRM_AllowUnencrypt'] = if ($hi.WinRM_AllowUnencrypted) { $hi.WinRM_AllowUnencrypted } else { '' }
                    $hostObj['CredSSP_Server']     = if ($hi.CredSSP_ServerEnabled) { $hi.CredSSP_ServerEnabled } else { '' }
                    $hostObj['CredSSP_Client']     = if ($hi.CredSSP_ClientConfig) { $hi.CredSSP_ClientConfig } else { '' }
                    $hostObj['WinRM_TrustedHosts'] = if ($hi.WinRM_TrustedHosts) { $hi.WinRM_TrustedHosts } else { '' }
                    $hostObj['WinRM_MaxTimeoutMs'] = if ($hi.WinRM_MaxTimeoutMs) { $hi.WinRM_MaxTimeoutMs } else { '' }
                    $hostObj['WinRM_NetworkDelayMs'] = if ($hi.WinRM_NetworkDelayMs) { $hi.WinRM_NetworkDelayMs } else { '' }
                    $hostObj['WinRM_IdleTimeoutMs']= if ($hi.WinRM_IdleTimeoutMs) { $hi.WinRM_IdleTimeoutMs } else { '' }
                    $hostObj['WinRM_MaxEnvKb']     = if ($hi.WinRM_MaxEnvelopeKb) { $hi.WinRM_MaxEnvelopeKb } else { '' }
                    $hostObj['WinRM_MaxShellsPerUser'] = if ($hi.WinRM_MaxShellsPerUser) { $hi.WinRM_MaxShellsPerUser } else { '' }
                    $hostObj['WinRM_MaxMemPerShellMB'] = if ($hi.WinRM_MaxMemoryPerShellMB) { $hi.WinRM_MaxMemoryPerShellMB } else { '' }
                    
                    # WinRM Recommendation (v3.2.9)
                    $winrmRecs = @()
                    if ($hi.WinRM_Status -ne 'Running') {
                        $winrmRecs += 'WinRM not running - enable with: Enable-PSRemoting -Force'
                    }
                    else {
                        if (-not $hi.WinRM_HTTPS_Enabled) {
                            $winrmRecs += 'No HTTPS listener - configure with: New-WSManInstance winrm/config/Listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{CertificateThumbprint="<thumbprint>"}'
                        }
                        if ($hi.WinRM_HTTPS_CertExp -and $hi.WinRM_HTTPS_CertExp -match '^\d{4}') {
                            try {
                                $expDate = [datetime]::Parse($hi.WinRM_HTTPS_CertExp)
                                $daysLeft = ($expDate - (Get-Date)).Days
                                if ($daysLeft -lt 0) { $winrmRecs += "HTTPS cert EXPIRED ($($hi.WinRM_HTTPS_CertExp))" }
                                elseif ($daysLeft -lt 30) { $winrmRecs += "HTTPS cert expires in ${daysLeft}d" }
                            }
                            catch { }
                        }
                        if ($hi.WinRM_AllowUnencrypted -eq 'true') {
                            $winrmRecs += 'AllowUnencrypted=true is a security risk'
                        }
                        if ($hi.WinRM_AuthBasic -eq 'true') {
                            $winrmRecs += 'Basic auth enabled - sends credentials in clear text without HTTPS'
                        }
                    }
                    $hostObj['WinRM_Recommendations'] = if ($winrmRecs.Count -gt 0) { $winrmRecs -join '; ' } else { 'OK' }
                    
                    # Secure Boot KB Status (v3.3.0 - OS-aware, Required flag, SB_Action)
                    $sbKBs = if ($hi.SB_KBs) { $hi.SB_KBs } else { @() }
                    $kbInstalled = @($sbKBs | Where-Object { $_.Status -eq 'Installed' }      | ForEach-Object { $_.KB })
                    $kbMissing   = @($sbKBs | Where-Object { $_.Status -eq 'NotInstalled' -and $_.Required -eq $true } | ForEach-Object { $_.KB })
                    $hostObj['SB_KBs_Installed'] = if ($kbInstalled.Count -gt 0) { $kbInstalled -join ', ' } else { 'None' }
                    $hostObj['SB_KBs_Missing']   = if ($kbMissing.Count -gt 0)   { $kbMissing -join ', '   } else { 'None' }
                    $hostObj['SB_UEFIEnabled']   = if ($hi.SB_UEFIEnabled) { $true } else { $false }
                    $hostObj['SB_PendingUpdates'] = if ($hi.SB_AvailableUpdates -and $hi.SB_AvailableUpdates -ne '0') { $hi.SB_AvailableUpdates } else { 'None' }
                    $hostObj['SB_Action']         = if ($hi.SB_Action) { $hi.SB_Action } else { '' }
                    
                    # Network Connection Profile (v3.2.9)
                    $netProfiles = if ($hi.NetProfiles) { $hi.NetProfiles } else { @() }
                    $profileSummary = @($netProfiles | ForEach-Object { "$($_.InterfaceAlias): $($_.NetworkCategory)" }) -join '; '
                    $hostObj['NetworkProfile'] = if ($profileSummary) { $profileSummary } else { 'Unknown' }
                    # Flag the dominant category
                    $categories = @($netProfiles | ForEach-Object { $_.NetworkCategory })
                    $hostObj['NetworkCategory'] = if ($categories -contains 'Public') { 'Public' }
                                                   elseif ($categories -contains 'Private') { 'Private' }
                                                   elseif ($categories -contains 'DomainAuthenticated') { 'Domain' }
                                                   else { 'Unknown' }
                }
                
                $hostInfoList.Add([PSCustomObject]$hostObj)
            }
            
            # Reboot History (host-level, Event Log 1074)
            if ($hvHost.RebootHistory) {
                foreach ($evt in $hvHost.RebootHistory) {
                    $rebootHistory.Add([PSCustomObject]@{
                        Server     = $hostName
                        Computer   = if ($evt.Computer) { $evt.Computer } else { $hostName }
                        Date       = $evt.Date
                        Action     = $evt.Action
                        Reason     = $evt.Reason
                        User       = $evt.User
                        Process    = $evt.Process
                        Source     = 'HostEventLog'
                        RebootType = if ($evt.RebootType) { $evt.RebootType } else { 'Clean' }
                        DataSource = 'HYPER-V'
                    })
                }
            }
            
            # vSwitch Configuration (v3.2.0 Item 10)
            if ($hvHost.VSwitches) {
                foreach ($sw in $hvHost.VSwitches) {
                    $mgmtNicSummary = ''
                    if ($sw.ManagementNICs -and $sw.ManagementNICs.Count -gt 0) {
                        $mgmtNicSummary = ($sw.ManagementNICs | ForEach-Object {
                            $vlanStr = if ($_.VlanId -and $_.VlanId -gt 0) { " VLAN:$($_.VlanId)" } else { '' }
                            "$($_.Name)$vlanStr"
                        }) -join '; '
                    }
                    $vSwitchConfig.Add([PSCustomObject]@{
                        Host              = $hostName
                        SwitchName        = $sw.Name
                        SwitchType        = $sw.SwitchType
                        AllowManagementOS = $sw.AllowManagementOS
                        PhysicalAdapter   = $sw.NetAdapterName
                        BandwidthMode     = $sw.BandwidthMode
                        IovEnabled        = $sw.IovEnabled
                        ManagementNICs    = $mgmtNicSummary
                    })
                }
            }
            
            # Host Services (v3.6.1 - filtered at source, alert generation here)
            if ($hvHost.HostServices) {
                $svcSystemAccts = if ($ServicesFilter.SystemAccounts) {
                    $ServicesFilter.SystemAccounts
                } else {
                    @('LocalSystem','NT AUTHORITY\LocalService','NT AUTHORITY\NetworkService',
                      'NT AUTHORITY\Local Service','NT AUTHORITY\Network Service')
                }
                foreach ($svc in $hvHost.HostServices) {
                    $servicesList.Add([PSCustomObject]@{
                        Server      = $hostName
                        Type        = 'Host'
                        Host        = $hostName   # Host rows show own FQDN -- unified 10-col schema (v3.6.1)
                        Name        = $svc.Name
                        DisplayName = $svc.DisplayName
                        Status      = $svc.Status
                        StartMode   = $svc.StartMode
                        StartName   = $svc.StartName
                        PathName    = $svc.PathName
                        Description = $svc.Description
                    })
                    if (($ServicesFilter.FlagStoppedAuto -ne $false) -and
                        $svc.StartMode -eq 'Auto' -and $svc.Status -ne 'Running') {
                        $servicesAlerts.Add([PSCustomObject]@{
                            Server      = $hostName
                            Type        = 'Host'
                            Host        = $hostName
                            AlertType   = 'Stopped Auto-Start'
                            Severity    = 'Warning'
                            Name        = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status      = $svc.Status
                            StartMode   = $svc.StartMode
                            StartName   = $svc.StartName
                            Recommendation = 'Investigate why this Auto-start service is stopped on the Hyper-V host'
                        })
                    }
                    $acctNorm = $svc.StartName -replace '^\s+|\s+$', ''
                    $isSystemAcct = $svcSystemAccts | Where-Object { $_ -ieq $acctNorm } | Select-Object -First 1
                    if (-not $isSystemAcct -and $acctNorm -ne '' -and $acctNorm -notmatch '^NT ') {
                        $servicesAlerts.Add([PSCustomObject]@{
                            Server      = $hostName
                            Type        = 'Host'
                            Host        = $hostName
                            AlertType   = 'Non-Standard Service Account'
                            Severity    = 'Info'
                            Name        = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status      = $svc.Status
                            StartMode   = $svc.StartMode
                            StartName   = $svc.StartName
                            Recommendation = 'Verify this service account is authorized'
                        })
                    }
                }
            }
            
            # Host Scheduled Tasks (v3.6.1 - S4b)
            if ($hvHost.HostScheduledTasks) {
                foreach ($task in $hvHost.HostScheduledTasks) {
                    $scheduledTasksList.Add([PSCustomObject]@{
                        Server      = $hostName
                        Type        = 'Host'
                        Host        = $hostName   # Host rows show own FQDN -- unified schema
                        TaskName    = $task.TaskName
                        TaskPath    = $task.TaskPath
                        Status      = $task.Status
                        RunAs       = $task.RunAs
                        LastRunTime = $task.LastRunTime
                        NextRunTime = $task.NextRunTime
                        LastResult  = $task.LastResult
                        Description = $task.Description
                        Actions     = $task.Actions
                    })
                }
            }
            
            # Process VMs
            foreach ($vm in $hvHost.VMs) {
              try {
                # Determine OS info with KVP fallback for non-Windows VMs (v3.1.1)
                $osType    = if ($vm.OSInfo) { $vm.OSInfo.OSType } else { "Unknown" }
                $osName    = if ($vm.OSInfo) { $vm.OSInfo.OSName } else { "Unknown" }
                $osVersion = if ($vm.OSInfo) { $vm.OSInfo.OSVersion } else { "Unknown" }
                $osBuild   = if ($vm.OSInfo) { $vm.OSInfo.OSBuild } else { "Unknown" }
                
                # KVP fallback: if WinRM-based OS detection failed but KVP has data
                $kvp = $vm.KVP
                if (($osType -eq 'Unknown' -or $osName -eq 'Unknown') -and $kvp -and $kvp.Count -gt 0) {
                    if ($kvp['OSName']) {
                        $osName = $kvp['OSName']
                        # Determine OS type from KVP OSName
                        if ($osName -match 'Windows') { $osType = 'Windows' }
                        elseif ($osName -match 'Linux|Ubuntu|CentOS|Red Hat|RHEL|Debian|SUSE|Fedora|Oracle Linux|Alpine|EfficientIP|IPAM') { $osType = 'Linux' }
                        elseif ($osName -match 'FreeBSD') { $osType = 'FreeBSD' }
                        else { $osType = 'Other' }
                    }
                    if ($kvp['OSVersion'] -and $osVersion -eq 'Unknown') { $osVersion = $kvp['OSVersion'] }
                    if ($kvp['OSBuildNumber'] -and $osBuild -eq 'Unknown') { $osBuild = $kvp['OSBuildNumber'] }
                }
                
                # GuestOS string fallback (from Hyper-V IC report, not WinRM)
                if ($osName -eq 'Unknown' -and $vm.GuestOS) {
                    $osName = $vm.GuestOS
                    if ($vm.GuestOS -match 'Windows') { $osType = 'Windows (GuestOS)' }
                    elseif ($vm.GuestOS -match 'Linux|Ubuntu|CentOS|Red Hat|Debian|SUSE|Fedora|Oracle|Alpine|EfficientIP|IPAM') { $osType = 'Linux (GuestOS)' }
                    else { $osType = 'Other (GuestOS)' }
                }
                
                # Appliance/Linux hostname pattern fallback (v3.6.1)
                # When WinRM and KVP both fail (appliances with no Hyper-V IC),
                # use VM naming conventions to classify the OS type.
                if ($osType -eq 'Unknown' -or $osType -eq 'Other') {
                    $vmNameU  = if ($vm.Name) { $vm.Name.ToUpper() } else { "" }
                    $vmNotesU = if ($vm.Notes) { $vm.Notes.ToUpper() } else { '' }
                    $lxPats = @('IPAM','SCG','CONNEX','FORTIGATE','FORTIWEB','FORTIANALYZER',
                               'PFSENSE','OPNSENSE','TRUENAS','FREENAS','PROXMOX',
                               'UBUNTU','CENTOS','RHEL','DEBIAN','-LNX-','-LINUX-','-NIX-')
                    foreach ($pat in $lxPats) {
                        if ($vmNameU -like "*$pat*" -or $vmNotesU -like "*$pat*") {
                            $osType = 'Linux (Appliance)'
                            if ($osName -eq 'Unknown') { $osName = "Appliance ($pat)" }
                            break
                        }
                    }
                }

                # VM-level last update and pending reboot (from OS module data)
                $vmLastUpdateKB   = 'N/A'
                $vmLastUpdateDate = 'N/A'
                $vmRebootPending  = ''
                $vmRebootReasons  = ''
                $vmActivationStatus = ''
                $vmActivationMethod = ''
                $vmKMSServer      = ''
                $vmPartialKey     = ''
                if ($vm.OSInfo) {
                    if ($vm.OSInfo.LastUpdateKB)   { $vmLastUpdateKB   = $vm.OSInfo.LastUpdateKB }
                    if ($vm.OSInfo.LastUpdateDate)  { $vmLastUpdateDate = $vm.OSInfo.LastUpdateDate }
                    if ($null -ne $vm.OSInfo.RebootPending) { $vmRebootPending = $vm.OSInfo.RebootPending }
                    if ($vm.OSInfo.RebootReasons)   { $vmRebootReasons  = $vm.OSInfo.RebootReasons }
                    if ($vm.OSInfo.LicenseStatus)   { $vmActivationStatus = $vm.OSInfo.LicenseStatus }
                    if ($vm.OSInfo.ActivationMethod) { $vmActivationMethod = $vm.OSInfo.ActivationMethod }
                    if ($vm.OSInfo.KMSServer)       { $vmKMSServer = $vm.OSInfo.KMSServer }
                    if ($vm.OSInfo.PartialKey)      { $vmPartialKey = $vm.OSInfo.PartialKey }
                }
                
                # Secure Boot certificate risk assessment (v3.2.0 -- Item 7)
                $sbTemplate = if ($vm.FirmwareInfo) { $vm.FirmwareInfo.SecureBootTemplate } else { 'N/A' }
                $sbCertRisk = 'Not Applicable'
                if ($vm.Generation -eq 2 -and $vm.FirmwareInfo -and $vm.FirmwareInfo.SecureBootEnabled) {
                    if ($sbTemplate -match 'MicrosoftUEFICertificateAuthority') {
                        $sbCertRisk = 'At Risk'
                        # Check if KB5025885 is installed (mitigating update)
                        if ($vm.OSInfo -and $vm.OSInfo.LastUpdateKB) {
                            # We can't determine exact KB from Get-HotFix easily; mark for further check
                            # A full check would query for KB5025885 specifically
                            $sbCertRisk = 'At Risk (Verify KB5025885)'
                        }
                    }
                    elseif ($sbTemplate -match 'MicrosoftWindows') {
                        $sbCertRisk = 'Safe (Windows Template)'
                    }
                    elseif ($sbTemplate -match 'OpenSourceShieldedVM') {
                        $sbCertRisk = 'Safe (Linux Template)'
                    }
                    else {
                        $sbCertRisk = "Review ($sbTemplate)"
                    }
                }
                
                # VM Name analysis (v3.2.0)
                $vmName = $vm.VM
                $nameRec = ''
                if ($vmName -match '\s') {
                    $suggested = $vmName -replace '\s+', '_'
                    # Check for conflicts with existing VM names
                    $nameRec = "Rename: contains spaces. Suggest: $suggested"
                }
                elseif ($vmName -match '[^\w\-\.]') {
                    $cleanName = $vmName -replace '[^\w\-\.]', '_'
                    $nameRec = "Rename: special characters. Suggest: $cleanName"
                }
                elseif ($vmName -match '^\W') {
                    $nameRec = "Review: name starts with special character"
                }
                
                # VM Configuration Version analysis (v3.2.0)
                $configVersion = if ($vm.Version) { $vm.Version } else { '' }
                $configVerRec = ''
                if ($configVersion) {
                    $verNum = 0
                    try { $verNum = [double]($configVersion -replace '[^\d\.]','') } catch {}
                    if ($verNum -gt 0 -and $verNum -lt 10.0) {
                        $configVerRec = "Upgrade available (current: $configVersion)"
                    }
                    elseif ($verNum -ge 10.0) {
                        $configVerRec = "Current"
                    }
                }
                
                # Build vInfo object -- Basic gets fewer columns, Intermediate/Advanced get all
                # Get cluster info for this host (from parent hostData)
                $hostClusterName = if ($hvHost.ClusterInfo -and $hvHost.ClusterInfo.ClusterName) {
                    $hvHost.ClusterInfo.ClusterName
                } else { '' }
                
                $vInfoObj = [ordered]@{
                    VM                = $vmName
                    Host              = $hostName
                    ClusterName       = $hostClusterName
                    Powerstate        = $vm.Powerstate
                    GuestOS           = $vm.GuestOS
                    OSType            = $osType
                    OSName            = $osName
                    OSVersion         = $osVersion
                    OSBuild           = $osBuild
                    Generation        = $vm.Generation
                    FirmwareType      = if ($vm.FirmwareInfo) { $vm.FirmwareInfo.FirmwareType } else { "Unknown" }
                    SecureBootEnabled = if ($vm.FirmwareInfo) { $vm.FirmwareInfo.SecureBootEnabled } else { $false }
                    TPMEnabled        = if ($vm.FirmwareInfo) { $vm.FirmwareInfo.TPMEnabled } else { $false }
                    ConfigVersion     = $configVersion
                    ConfigVerRec      = $configVerRec
                    Heartbeat         = $vm.Heartbeat
                    VMCategory        = if ($vm.VMCategory) { $vm.VMCategory } else { 'Standard' }
                    Notes             = $vm.Notes
                    Path              = $vm.Path
                    NameRecommendation = $nameRec
                }
                
                # Guest ComputerName + AD Computer Object Name -- Basic level (v3.2.0 Item 22)
                $guestName = if ($vm.GuestComputerName) { $vm.GuestComputerName } else { '' }
                $adCompName = if ($vm.AD_ComputerName) { $vm.AD_ComputerName } else { '' }
                $vmShort = ($vmName -split '\.')[0]
                $nameMatch = ''
                if ($guestName -and $adCompName) {
                    if ($vmShort -eq $guestName -and $vmShort -eq $adCompName) { $nameMatch = 'Match' }
                    else { $nameMatch = "Mismatch: VM=$vmShort, Guest=$guestName, AD=$adCompName" }
                }
                elseif ($adCompName) {
                    if ($vmShort -eq $adCompName) { $nameMatch = 'Match (AD only)' }
                    else { $nameMatch = "Mismatch: VM=$vmShort, AD=$adCompName" }
                }
                elseif ($guestName) {
                    if ($vmShort -eq $guestName) { $nameMatch = 'Match (Guest only)' }
                    else { $nameMatch = "Mismatch: VM=$vmShort, Guest=$guestName" }
                }
                $vInfoObj['GuestComputerName'] = $guestName
                $vInfoObj['AD_ComputerName']   = $adCompName
                $vInfoObj['NameMatch']         = $nameMatch
                # v3.10.0 CR74: GuestOSDNSName - the name DNS records use
                # Priority: GuestComputerName (WinRM) > KVP FQDN hostname > VM display name
                $guestDNS = if ($guestName) { $guestName }
                            elseif ($vm.KVP -and $vm.KVP['FullyQualifiedDomainName'] -and $vm.KVP['FullyQualifiedDomainName'] -match '^([^\.]+)') {
                                $Matches[1]
                            }
                            else { '' }
                $vInfoObj['GuestOSDNSName'] = $guestDNS
                
                # Intermediate/Advanced columns (not shown on Basic)
                if ($isIntermediate) {
                    $vInfoObj['Version']          = $vm.Version
                    $vInfoObj['Uptime']           = $vm.Uptime
                    $vInfoObj['VMCreated']        = if ($vm.VMCreationTime) {
                        try { ([datetime]::Parse($vm.VMCreationTime)).ToString('yyyy-MM-dd HH:mm') } catch { $vm.VMCreationTime }
                    } else { '' }
                    $vInfoObj['ADCreated']        = if ($vm.AD_WhenCreated) {
                        try { ([datetime]::Parse($vm.AD_WhenCreated)).ToString('yyyy-MM-dd HH:mm') } catch { $vm.AD_WhenCreated }
                    } else { '' }
                    $vInfoObj['FirstSeen']        = if ($vm.FirstSeenInReport) { $vm.FirstSeenInReport } else { '' }
                    $vInfoObj['LastSeen']         = if ($vm.LastSeenInReport) { $vm.LastSeenInReport } else { '' }
                    $vInfoObj['VMId']             = if ($vm.VMId) { $vm.VMId } else { '' }
                    $vInfoObj['LastUpdateKB']     = $vmLastUpdateKB
                    $vInfoObj['LastUpdateDate']   = $vmLastUpdateDate
                    $vInfoObj['RebootPending']    = $vmRebootPending
                    $vInfoObj['RebootReasons']    = $vmRebootReasons
                    $vInfoObj['ActivationStatus'] = $vmActivationStatus
                    $vInfoObj['ActivationMethod'] = $vmActivationMethod
                    $vInfoObj['KMSServer']        = $vmKMSServer
                    $vInfoObj['PartialKey']       = $vmPartialKey
                    $vInfoObj['SB_Template']      = $sbTemplate
                    $vInfoObj['SB_CertRisk']      = $sbCertRisk
                    # WinRM/CredSSP from guest (v3.2.9 enhanced)
                    $vmPower = $vm.Powerstate
                    $vInfoObj['WinRM_Status']       = if ($vm.WinRM_Status) { $vm.WinRM_Status } else { if ($vmPower -eq 'poweredOn') { 'Unreachable' } else { 'N/A (Off)' } }
                    $vInfoObj['WinRM_Listeners']    = if ($vm.WinRM_Listeners) { $vm.WinRM_Listeners } else { '' }
                    $vInfoObj['WinRM_HTTPS']        = if ($vm.WinRM_HTTPS) { $true } else { $false }
                    $vInfoObj['WinRM_HTTPS_CertExp']= if ($vm.WinRM_HTTPS_CertExp) { $vm.WinRM_HTTPS_CertExp } else { '' }
                    $vInfoObj['WinRM_AuthKerberos'] = if ($vm.WinRM_AuthKerberos) { $vm.WinRM_AuthKerberos } else { '' }
                    $vInfoObj['WinRM_AuthCredSSP']  = if ($vm.WinRM_AuthCredSSP) { $vm.WinRM_AuthCredSSP } else { '' }
                    $vInfoObj['WinRM_MaxTimeoutMs'] = if ($vm.WinRM_MaxTimeoutMs) { $vm.WinRM_MaxTimeoutMs } else { '' }
                    # WinRM Recommendation
                    $vmWinrmRecs = @()
                    if ($vm.WinRM_Status -eq 'Running') {
                        if (-not $vm.WinRM_HTTPS) { $vmWinrmRecs += 'No HTTPS listener' }
                        if ($vm.WinRM_AllowUnencrypted -eq 'true') { $vmWinrmRecs += 'AllowUnencrypted=true' }
                    }
                    elseif ($vmPower -eq 'poweredOn' -and -not $vm.WinRM_Status) {
                        $vmWinrmRecs += 'WinRM unreachable - check firewall/domain trust/CredSSP'
                    }
                    $vInfoObj['WinRM_Recommendation'] = if ($vmWinrmRecs.Count -gt 0) { $vmWinrmRecs -join '; ' } else { if ($vm.WinRM_Status -eq 'Running') { 'OK' } else { '' } }
                    
                    # Secure Boot KB/Registry from guest (v3.3.0 - Required-only filter, SB_Action)
                    $vmSBKBs = if ($vm.SB_KBs) { $vm.SB_KBs } else { @() }
                    $vmKBInstalled = @($vmSBKBs | Where-Object { $_.Status -eq 'Installed' }                                    | ForEach-Object { $_.KB })
                    $vmKBMissing   = @($vmSBKBs | Where-Object { $_.Status -eq 'NotInstalled' -and $_.Required -eq $true }     | ForEach-Object { $_.KB })
                    $vInfoObj['SB_KBs_Installed'] = if ($vmKBInstalled.Count -gt 0) { $vmKBInstalled -join ', ' } else { 'None' }
                    $vInfoObj['SB_KBs_Missing']   = if ($vmKBMissing.Count -gt 0)   { $vmKBMissing -join ', '   } else { 'None' }
                    $vInfoObj['SB_UEFIEnabled']   = if ($vm.SB_UEFIEnabled) { $true } else { $false }
                    $vInfoObj['SB_PendingUpdates'] = if ($vm.SB_AvailableUpdates -and $vm.SB_AvailableUpdates -ne '0') { $vm.SB_AvailableUpdates } else { 'None' }
                    $vInfoObj['SB_DBXVersion']    = if ($vm.SB_DBXVersion) { $vm.SB_DBXVersion } else { '' }
                    $vInfoObj['SB_Action']         = if ($vm.SB_Action) { $vm.SB_Action } else { '' }
                    
                    # Network Connection Profile (v3.2.9)
                    $vmNetProfiles = if ($vm.NetProfiles) { $vm.NetProfiles } else { @() }
                    $vmCategories = @($vmNetProfiles | ForEach-Object { $_.NetworkCategory })
                    $vInfoObj['NetworkCategory'] = if ($vmCategories -contains 'Public') { 'Public' }
                                                    elseif ($vmCategories -contains 'Private') { 'Private' }
                                                    elseif ($vmCategories -contains 'DomainAuthenticated') { 'Domain' }
                                                    else { if ($vm.WinRM_Status -eq 'Running') { 'Unknown' } else { '' } }
                }

                # v3.10.12.26: AutomaticStartAction / AutomaticStopAction (all report levels)
                # Available directly from Get-VM -- no WinRM required, no additional cost.
                # AlertLevel logic:
                #   StartAction=Nothing -> Warning  (VM will not restart after host reboot)
                #   StopAction=TurnOff  -> Warning  (hard power-off, potential data loss)
                #   Both bad            -> Critical  (will not start AND risks data loss)
                $startAction = if ($vm.AutomaticStartAction) { $vm.AutomaticStartAction.ToString() } else { '' }
                $startDelay  = if ($vm.AutomaticStartDelay)  { [int]$vm.AutomaticStartDelay.TotalSeconds } else { 0 }
                $stopAction  = if ($vm.AutomaticStopAction)   { $vm.AutomaticStopAction.ToString()  } else { '' }

                $startBad = ($startAction -eq 'Nothing')
                $stopBad  = ($stopAction  -eq 'TurnOff')
                $startStopAlert = if ($startBad -and $stopBad)  { 'Critical' }
                                  elseif ($startBad -or $stopBad) { 'Warning' }
                                  else                             { 'OK' }

                $vInfoObj['AutomaticStartAction'] = $startAction
                $vInfoObj['AutomaticStartDelay']  = $startDelay
                $vInfoObj['AutomaticStopAction']  = $stopAction
                $vInfoObj['StartStopAlert']       = $startStopAlert

                # v3.10.12.26: Timezone audit columns (all report levels when IncludeTimezoneAudit = $true)
                $vmTZId      = if ($vm.OSInfo -and $vm.OSInfo.TimeZoneId) { $vm.OSInfo.TimeZoneId } else { '' }
                $vmTZDisplay = if ($vm.OSInfo -and $vm.OSInfo.TimeZone)   { $vm.OSInfo.TimeZone }   else { '' }
                $vmNTPSource = if ($vm.OSInfo -and $vm.OSInfo.NTPSource)  { $vm.OSInfo.NTPSource }  else { '' }
                $vmOffsetSec = if ($vm.OSInfo -and $null -ne $vm.OSInfo.TimeOffsetSeconds) { $vm.OSInfo.TimeOffsetSeconds } else { $null }

                $expectedTZ   = ''
                $expectedSite = ''
                $tzAlertLevel = ''
                $siteTimezones = if ($config -and $config.ContainsKey('SiteTimezones')) { $config.SiteTimezones } else { $null }
                $tzEnabled     = if ($config -and $config.ContainsKey('IncludeTimezoneAudit')) { $config.IncludeTimezoneAudit } else { $false }
                $tzWarnSec     = if ($config -and $config.ContainsKey('TimezoneOffsetWarningSeconds')) { $config.TimezoneOffsetWarningSeconds } else { 300 }

                if ($tzEnabled -and $siteTimezones) {
                    # Find primary RFC1918 IP from NICs.
                    # Source 1: Hyper-V management plane (Get-VMNetworkAdapter) -- populated
                    #   only when Integration Services KVP is healthy and reporting guest IPs.
                    #   Often empty for VMs on VLANs that don't publish IPs back to the host.
                    # Source 2 (OPEN-69 v3.10.12.28): OSInfo.GuestNetwork -- populated by
                    #   Get-NetIPAddress inside the guest via WinRM. Available for any VM
                    #   where WinRM collection succeeded. More reliable than Hyper-V ICs.
                    $primaryIP = ''
                    if ($vm.NetworkAdapters) {
                        foreach ($nic in $vm.NetworkAdapters) {
                            $nicIPs = if ($nic.IPAddresses) { $nic.IPAddresses } elseif ($nic.IPAddress) { @($nic.IPAddress) } else { @() }
                            $firstRFC1918 = @($nicIPs | Where-Object { $_ -match '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.' })[0]
                            if ($firstRFC1918) { $primaryIP = $firstRFC1918; break }
                        }
                    }
                    # OPEN-69: fallback to OSInfo.GuestNetwork (WinRM-collected IPs)
                    if (-not $primaryIP -and $vm.OSInfo -and $vm.OSInfo.GuestNetwork) {
                        foreach ($gnic in $vm.OSInfo.GuestNetwork) {
                            $gIP = if ($gnic.IPAddress) { $gnic.IPAddress } elseif ($gnic.IPv4Address) { $gnic.IPv4Address } else { '' }
                            if ($gIP -match '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.') {
                                $primaryIP = $gIP
                                break
                            }
                        }
                    }

                    # CIDR longest-prefix-match: iterate all SiteTimezones entries, keep the one
                    # with the longest prefix that contains primaryIP.
                    if ($primaryIP) {
                        try {
                            $ipLong = [uint32]0
                            $parts = $primaryIP.Split('.')
                            if ($parts.Count -eq 4) {
                                $ipLong = ([uint32]$parts[0] -shl 24) -bor ([uint32]$parts[1] -shl 16) -bor ([uint32]$parts[2] -shl 8) -bor [uint32]$parts[3]
                            }

                            $bestPfx  = -1
                            $bestTZ   = ''
                            $bestSite = ''
                            foreach ($entry in $siteTimezones) {
                                $cidr = $entry.Subnet
                                if (-not $cidr -or $cidr -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { continue }
                                $netStr = $Matches[1]; $pfxLen = [int]$Matches[2]
                                $nparts = $netStr.Split('.')
                                if ($nparts.Count -ne 4) { continue }
                                $netLong = ([uint32]$nparts[0] -shl 24) -bor ([uint32]$nparts[1] -shl 16) -bor ([uint32]$nparts[2] -shl 8) -bor [uint32]$nparts[3]
                                $mask    = if ($pfxLen -eq 0) { [uint32]0 } else { [uint32](0xFFFFFFFF -shl (32 - $pfxLen)) }
                                if (($ipLong -band $mask) -eq ($netLong -band $mask)) {
                                    if ($pfxLen -gt $bestPfx) {
                                        $bestPfx  = $pfxLen
                                        $bestTZ   = $entry.Timezone
                                        $bestSite = $entry.SiteName
                                    }
                                }
                            }
                            if ($bestPfx -ge 0) { $expectedTZ = $bestTZ; $expectedSite = $bestSite }
                        }
                        catch { $expectedTZ = ''; $expectedSite = '' }
                    }

                    # Alert derivation
                    if (-not $vmTZId)       { $tzAlertLevel = if ($vm.OSInfo) { 'Unknown' } else { 'N/A (no WinRM)' } }
                    elseif (-not $expectedTZ) { $tzAlertLevel = 'Unknown (no subnet match)' }
                    elseif ($vmTZId -eq $expectedTZ) { $tzAlertLevel = 'OK' }
                    else                    { $tzAlertLevel = 'Mismatch' }
                    if ($null -ne $vmOffsetSec -and [math]::Abs($vmOffsetSec) -gt $tzWarnSec) {
                        $tzAlertLevel += " / NTP Offset Warning ($($vmOffsetSec)s)"
                    }
                }

                $vInfoObj['TimeZoneId']        = $vmTZId
                $vInfoObj['TimeZoneDisplay']   = $vmTZDisplay
                $vInfoObj['ExpectedTimezone']  = $expectedTZ
                $vInfoObj['SiteNameMatch']     = $expectedSite
                $vInfoObj['TimezoneAlert']     = $tzAlertLevel
                $vInfoObj['TimeOffsetSeconds'] = if ($null -ne $vmOffsetSec) { $vmOffsetSec } else { '' }
                $vInfoObj['NTPSource']         = $vmNTPSource

                $vmInfo.Add([PSCustomObject]$vInfoObj)

                # v3.9.0: Cross-Domain-Auth diagnostic data (CR54)
                # v3.9.8 CR54 Phase 2: Add trust diagnostic columns for Warning/Critical VMs
                $cdaDomain = if ($vm.DetectedDomain) { $vm.DetectedDomain } else { 'unknown' }
                $cdaHasOS  = if ($vm.OSInfo) { $true } else { $false }
                $cdaAlert  = if ($vm.Powerstate -ne 'poweredOn') { 'N/A (Off)' }
                             elseif ($vm.OSInfo)                  { 'OK' }
                             elseif ($vm.WinRM_Status -eq 'Running') { 'OK' }
                             elseif ($cdaDomain -ne 'unknown')    { 'Warning' }
                             else { 'Critical' }

                # Diagnostic: why did auth fail? What's needed to fix it?
                $cdaFailReason = ''
                $cdaRemediation = ''
                if ($cdaAlert -eq 'Warning') {
                    # Domain detected but no OS data -- most likely WinRM or Kerberos issue
                    if (-not $vm.WinRM_Status -or $vm.WinRM_Status -eq 'N/A') {
                        $cdaFailReason = 'WinRM unreachable (connection failed or timed out)'
                        $cdaRemediation = "Verify WinRM is running: Invoke-Command -ComputerName $vmName -ScriptBlock { hostname }; Check firewall TCP 5985/5986; Verify SPN: setspn -L $vmName"
                    }
                    elseif ($vm.AuthMethod -eq 'AllFailed') {
                        $cdaFailReason = 'All credentials failed (AccessDenied on all domain credentials)'
                        if ($cdaDomain -ne $hostDomain) {
                            $cdaRemediation = "Cross-domain: verify trust between $hostDomain and $cdaDomain; Check: nltest /sc_query:$cdaDomain; Verify WinRM accepts cross-domain creds: winrm set winrm/config/service '@{AllowRemoteShellAccess=true}'"
                        } else {
                            $cdaRemediation = "Same domain: verify credential has admin access on $vmName; Check: Enter-PSSession -ComputerName $vmName -Credential (Get-Credential)"
                        }
                    }
                    else {
                        $cdaFailReason = 'Connection succeeded but OS data collection failed'
                        $cdaRemediation = "Check WMI access on $vmName; Run manually: Invoke-Command -ComputerName $vmName -ScriptBlock { Get-CimInstance Win32_OperatingSystem }"
                    }
                }
                elseif ($cdaAlert -eq 'Critical') {
                    if ($vmName -match 'APPLIANCE|IPAM|SCG|CONNEX|FORTI') {
                        $cdaFailReason = 'Non-domain appliance (not in AD)'
                        $cdaRemediation = 'Expected: Linux/network appliances cannot be inventoried via WinRM. Consider SSH collection for Linux VMs in a future module.'
                    }
                    else {
                        $cdaFailReason = 'Domain unknown -- DNS, KVP, and name analysis all failed to detect domain'
                        $cdaRemediation = "Verify VM has Hyper-V Integration Services installed and running; Check: Get-VM $vmName | Get-VMIntegrationService; Install VMIC if missing"
                    }
                }

                $crossDomainAuth.Add([PSCustomObject]@{
                    VM               = $vmName
                    Host             = $hostName
                    ClusterName      = $hostClusterName
                    Powerstate       = $vm.Powerstate
                    DetectedDomain   = $cdaDomain
                    DomainTier       = if ($vm.DomainTier)       { $vm.DomainTier }       else { 'none' }
                    CredentialUsed   = if ($vm.CredentialUsed)   { $vm.CredentialUsed }   else { '' }
                    CredentialSource = if ($vm.CredentialSource) { $vm.CredentialSource } else { '' }
                    AuthMethod       = if ($vm.AuthMethod)       { $vm.AuthMethod }       else { '' }
                    # v3.10.5 CR84 / v3.10.6 CR87: AuthProtocol shows Kerberos vs Negotiate vs PSDirect vs AllFailed
                    AuthProtocol     = if ($vm.AuthMethod -eq 'Kerberos')  { 'Kerberos' }
                                       elseif ($vm.AuthMethod -eq 'Negotiate') { 'Negotiate (NTLM)' }
                                       elseif ($vm.AuthMethod -eq 'PSDirect')  { 'PSDirect (VMBus)' }
                                       elseif ($vm.AuthMethod -eq 'AllFailed') { 'AllFailed' }
                                       elseif ($vm.Powerstate -ne 'poweredOn') { 'N/A (Off)' }
                                       else { '' }
                    WinRMStatus      = if ($vm.WinRM_Status)     { $vm.WinRM_Status }     else { 'N/A' }
                    HasOSData        = $cdaHasOS
                    GuestComputerName = if ($vm.GuestComputerName) { $vm.GuestComputerName } else { '' }
                    FailReason       = $cdaFailReason
                    Remediation      = $cdaRemediation
                    # v3.10.5 CR84: Kerberos-specific diagnostics (populated when Negotiate succeeded)
                    KerberosFailReason  = if ($vm.KerberosFailReason)  { $vm.KerberosFailReason }  else { '' }
                    KerberosRemediation = if ($vm.KerberosRemediation) { $vm.KerberosRemediation } else { '' }
                    # v3.10.10 CR100: Full untruncated PSDirect failure detail.
                    # PSDirectFailReason contains the per-credential error log when PSDirect
                    # was attempted and failed on all credentials. Unlike KerberosFailReason
                    # (which is a short summary limited by historical context), this holds
                    # the full story so analysts can diagnose which credential had which
                    # specific failure mode.
                    PSDirectFailReason  = if ($vm.PSDirectFailReason) { $vm.PSDirectFailReason } else { '' }
                    # PSDirectAttempts: compact serialization of the per-credential attempt log
                    # for JSON-parseability. Format: "[n] user [source] -> Category; ..."
                    PSDirectAttempts    = if ($vm.PSDirectAttempts -and @($vm.PSDirectAttempts).Count -gt 0) {
                                              (@($vm.PSDirectAttempts) | ForEach-Object {
                                                  "[$($_.Attempt)] $($_.Credential) [$($_.Source)] -> $($_.Result):$($_.ErrorCategory) ($($_.DurationMs)ms)"
                                              }) -join ' | '
                                          } else { '' }
                    AlertLevel       = $cdaAlert
                })
                if ($vm.RebootHistory) {
                    foreach ($evt in $vm.RebootHistory) {
                        $rebootHistory.Add([PSCustomObject]@{
                            Server     = $hostName
                            Computer   = if ($evt.Computer) { $evt.Computer } else { $vmName }
                            Date       = $evt.Date
                            Action     = $evt.Action
                            Reason     = $evt.Reason
                            User       = $evt.User
                            Process    = $evt.Process
                            Source     = 'VMEventLog'
                            RebootType = if ($evt.RebootType) { $evt.RebootType } else { 'Clean' }
                            DataSource = 'HYPER-V'
                        })
                    }
                }
                
                # VM Services (v3.6.1 - filtered at collection time, Auto-start only by default)
                if ($vm.Services) {
                    $svcSystemAccts = if ($ServicesFilter.SystemAccounts) {
                        $ServicesFilter.SystemAccounts
                    } else {
                        @('LocalSystem','NT AUTHORITY\LocalService','NT AUTHORITY\NetworkService',
                          'NT AUTHORITY\Local Service','NT AUTHORITY\Network Service')
                    }
                    foreach ($svc in $vm.Services) {
                        $servicesList.Add([PSCustomObject]@{
                            Server      = $vmName
                            Type        = 'VM'
                            Host        = $hostName
                            Name        = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status      = $svc.Status
                            StartMode   = $svc.StartMode
                            StartName   = $svc.StartName
                            PathName    = $svc.PathName
                            Description = $svc.Description
                        })
                        
                        # Services-Alerts: stopped Auto-start (S4-2)
                        if (($ServicesFilter.FlagStoppedAuto -ne $false) -and
                            $svc.StartMode -eq 'Auto' -and $svc.Status -ne 'Running') {
                            $servicesAlerts.Add([PSCustomObject]@{
                                Server      = $vmName
                                Type        = 'VM'
                                Host        = $hostName
                                AlertType   = 'Stopped Auto-Start'
                                Severity    = 'Warning'
                                Name        = $svc.Name
                                DisplayName = $svc.DisplayName
                                Status      = $svc.Status
                                StartMode   = $svc.StartMode
                                StartName   = $svc.StartName
                                Recommendation = 'Investigate why this Auto-start service is stopped - may indicate crash loop or manual intervention'
                            })
                        }
                        
                        # Services-Alerts: non-standard service account (S4-2)
                        $acctNorm = $svc.StartName -replace '^\s+|\s+$', ''
                        $isSystemAcct = $svcSystemAccts | Where-Object {
                            $_ -ieq $acctNorm } | Select-Object -First 1
                        if (-not $isSystemAcct -and $acctNorm -ne '' -and
                            $acctNorm -notmatch '^NT ') {
                            $servicesAlerts.Add([PSCustomObject]@{
                                Server      = $vmName
                                Type        = 'VM'
                                Host        = $hostName
                                AlertType   = 'Non-Standard Service Account'
                                Severity    = 'Info'
                                Name        = $svc.Name
                                DisplayName = $svc.DisplayName
                                Status      = $svc.Status
                                StartMode   = $svc.StartMode
                                StartName   = $svc.StartName
                                Recommendation = 'Verify this service account is authorized and uses a managed service account or gMSA'
                            })
                        }
                    }
                }
                
                # Local Administrators Group (v3.6.1 - domain-aware Required/Allowed/Review)
                # RequiredBuiltinMembers is now keyed by domain FQDN with a 'Default' fallback.
                # Legacy flat structure (pre-3.5.0) is still supported for backwards compat.
                #
                # Domain resolution order:
                #  1. $vm.OSInfo.Domain (from WinRM collection -- most accurate)
                #  2. Infer from VM's AD DNSHostName suffix (from $vm.DNSHostName if present)
                #  3. Infer from host's domain (HostInfo.Domain)
                #  4. Fall back to 'Default'
                if ($vm.LocalAdmins) {

                    # --- Resolve domain for this VM ---
                    $vmDomain = ''
                    if ($vm.OSInfo -and $vm.OSInfo.Domain -and $vm.OSInfo.Domain -ne '') {
                        $vmDomain = $vm.OSInfo.Domain.ToLower().Trim('.')
                    }
                    elseif ($vm.DNSHostName -and $vm.DNSHostName -match '\.(.+)$') {
                        $vmDomain = $matches[1].ToLower()
                    }
                    elseif ($hvHost.HostInfo -and $hvHost.HostInfo.Domain) {
                        $vmDomain = $hvHost.HostInfo.Domain.ToLower().Trim('.')
                    }

                    # --- Detect config format: domain-aware (nested) vs legacy (flat) ---
                    # Domain-aware: keys are domain FQDNs or 'Default'
                    # Legacy: key is group name like 'Administrators'
                    $isDomainAware = $false
                    if ($RequiredBuiltinMembers -and $RequiredBuiltinMembers.Count -gt 0) {
                        $firstKey = @($RequiredBuiltinMembers.Keys)[0]
                        # Domain-aware keys contain dots or equal 'Default'
                        $isDomainAware = ($firstKey -match '\.' -or $firstKey -eq 'Default')
                    }

                    # --- Select the correct domain config block ---
                    $domainConfig = $null
                    if ($isDomainAware -and $RequiredBuiltinMembers) {
                        # Try exact domain match first, then Default fallback
                        if ($vmDomain -ne '' -and $RequiredBuiltinMembers.ContainsKey($vmDomain)) {
                            $domainConfig = $RequiredBuiltinMembers[$vmDomain]
                        }
                        elseif ($RequiredBuiltinMembers.ContainsKey('Default')) {
                            $domainConfig = $RequiredBuiltinMembers['Default']
                        }
                    }
                    elseif ($RequiredBuiltinMembers) {
                        # Legacy flat format -- treat the whole hashtable as the domain config
                        $domainConfig = $RequiredBuiltinMembers
                    }

                    # --- Extract Administrators Required/Allowed from the resolved config ---
                    $adminsConfig = if ($domainConfig -and $domainConfig['Administrators']) {
                        $domainConfig['Administrators'] } else { $null }

                    # Normalise to tiered structure
                    if ($adminsConfig -is [hashtable] -and ($adminsConfig.Required -or $adminsConfig.Allowed)) {
                        $reqList     = @($adminsConfig.Required)
                        $allowedList = @($adminsConfig.Allowed)
                    }
                    elseif ($adminsConfig) {
                        $reqList     = @($adminsConfig)   # legacy flat array -- all Required
                        $allowedList = @()
                    }
                    else {
                        $reqList     = @()
                        $allowedList = @()
                    }

                    # Helper: does $name match any pattern in $patterns (exact or wildcard)?
                    $matchesAny = {
                        param($name, $patterns)
                        foreach ($p in $patterns) {
                            if ($name -like $p) { return $true }
                        }
                        return $false
                    }

                    # Track which Required members were found (for Missing detection)
                    $foundRequired = @{}

                    foreach ($member in $vm.LocalAdmins) {
                        $memberName = $member.Name
                        $inRequired = & $matchesAny $memberName $reqList
                        $inAllowed  = & $matchesAny $memberName $allowedList

                        if ($inRequired) {
                            $foundRequired[$memberName] = $true
                            $alertLevel = 'OK'
                            $tier = 'Required'
                        } elseif ($inAllowed) {
                            $alertLevel = 'OK'
                            $tier = 'Allowed'
                        } elseif ($reqList.Count -gt 0 -or $allowedList.Count -gt 0) {
                            $alertLevel = 'Review'
                            $tier = 'Unexpected'
                        } else {
                            $alertLevel = 'OK'      # No config defined -- informational only
                            $tier = 'Unconfigured'
                        }

                        $localAdminsList.Add([PSCustomObject]@{
                            VM              = $vmName
                            Host            = $hostName
                            Domain          = $vmDomain
                            MemberName      = $memberName
                            ObjectClass     = $member.ObjectClass
                            PrincipalSource = $member.PrincipalSource
                            Tier            = $tier
                            AlertLevel      = $alertLevel
                        })
                    }

                    # Add Missing rows for Required members not found on this VM
                    if ($reqList.Count -gt 0) {
                        foreach ($req in $reqList) {
                            # Only flag exact Required entries as Missing (wildcards are optional patterns)
                            if ($req -notmatch '\*' -and $req -notmatch '\?') {
                                $wasFound = $vm.LocalAdmins | Where-Object {
                                    $_.Name -like $req } | Select-Object -First 1
                                if (-not $wasFound) {
                                    $localAdminsList.Add([PSCustomObject]@{
                                        VM              = $vmName
                                        Host            = $hostName
                                        Domain          = $vmDomain
                                        MemberName      = $req
                                        ObjectClass     = 'N/A'
                                        PrincipalSource = 'N/A'
                                        Tier            = 'Required-Missing'
                                        AlertLevel      = 'Missing'
                                    })
                                }
                            }
                        }
                    }
                }
                
                # Local Built-in Groups (v3.8.0 - CR5: all builtin groups per VM, domain-aware per-group Required/Allowed)
                # Uses vm.LocalBuiltin (new) with fallback to vm.LocalAdmins for backward compat.
                # Each row carries GroupName so the tab can filter/sort by group.
                # RequiredBuiltinMembers config is keyed: domain -> groupname -> { Required, Allowed }
                $builtinSource = if ($vm.LocalBuiltin -and $vm.LocalBuiltin.Count -gt 0) { $vm.LocalBuiltin }
                                  elseif ($vm.LocalAdmins -and $vm.LocalAdmins.Count -gt 0) {
                                      # Backfill GroupName for legacy data
                                      $vm.LocalAdmins | ForEach-Object {
                                          $_ | Add-Member -NotePropertyName 'GroupName' -NotePropertyValue 'Administrators' -Force -PassThru
                                      }
                                  } else { @() }

                if ($builtinSource -and @($builtinSource).Count -gt 0) {
                    # Resolve domain (same logic as LocalAdmins above)
                    $lbDomain = ''
                    if ($vm.OSInfo -and $vm.OSInfo.Domain) { $lbDomain = $vm.OSInfo.Domain.ToLower().Trim('.') }
                    elseif ($vm.DNSHostName -and $vm.DNSHostName -match '\.(.+)$') { $lbDomain = $matches[1].ToLower() }
                    elseif ($hvHost.HostInfo -and $hvHost.HostInfo.Domain) { $lbDomain = $hvHost.HostInfo.Domain.ToLower().Trim('.') }

                    # Helper: match-any pattern
                    $lbMatchAny = {
                        param($name, $patterns)
                        foreach ($p in $patterns) { if ($name -like $p) { return $true } }
                        return $false
                    }

                    # Get per-group config
                    $lbDomainConfig = $null
                    if ($RequiredBuiltinMembers -and $RequiredBuiltinMembers.Count -gt 0) {
                        $firstKey = @($RequiredBuiltinMembers.Keys)[0]
                        $isDomainAwareBuiltin = ($firstKey -match '\.' -or $firstKey -eq 'Default')
                        if ($isDomainAwareBuiltin) {
                            if ($lbDomain -and $RequiredBuiltinMembers.ContainsKey($lbDomain)) {
                                $lbDomainConfig = $RequiredBuiltinMembers[$lbDomain]
                            } elseif ($RequiredBuiltinMembers.ContainsKey('Default')) {
                                $lbDomainConfig = $RequiredBuiltinMembers['Default']
                            }
                        } else {
                            $lbDomainConfig = $RequiredBuiltinMembers
                        }
                    }

                    # Track found Required per group for Missing rows
                    $lbFoundReq = @{}

                    foreach ($member in @($builtinSource)) {
                        $grpName    = if ($member.GroupName) { $member.GroupName } else { 'Administrators' }
                        $memberName = $member.Name

                        # Get group-specific Required/Allowed
                        $grpConfig   = if ($lbDomainConfig -and $lbDomainConfig[$grpName]) { $lbDomainConfig[$grpName] } else { $null }
                        $lbReqList   = @()
                        $lbAllowList = @()
                        if ($grpConfig -is [hashtable] -and ($grpConfig.Required -or $grpConfig.Allowed)) {
                            $lbReqList   = @($grpConfig.Required)
                            $lbAllowList = @($grpConfig.Allowed)
                        } elseif ($grpConfig) {
                            $lbReqList = @($grpConfig)
                        }

                        $inReq  = & $lbMatchAny $memberName $lbReqList
                        $inAllow = & $lbMatchAny $memberName $lbAllowList

                        $lbTier  = 'Unconfigured'
                        $lbAlert = 'OK'
                        if ($inReq) {
                            if (-not $lbFoundReq.ContainsKey($grpName)) { $lbFoundReq[$grpName] = @{} }
                            $lbFoundReq[$grpName][$memberName] = $true
                            $lbTier = 'Required'; $lbAlert = 'OK'
                        } elseif ($inAllow) {
                            $lbTier = 'Allowed'; $lbAlert = 'OK'
                        } elseif ($lbReqList.Count -gt 0 -or $lbAllowList.Count -gt 0) {
                            $lbTier = 'Unexpected'; $lbAlert = 'Review'
                        }

                        $localBuiltinList.Add([PSCustomObject]@{
                            VM              = $vmName
                            Host            = $hostName
                            Domain          = $lbDomain
                            GroupName       = $grpName
                            MemberName      = $memberName
                            ObjectClass     = $member.ObjectClass
                            PrincipalSource = $member.PrincipalSource
                            Tier            = $lbTier
                            AlertLevel      = $lbAlert
                        })
                    }

                    # Missing rows per group
                    if ($lbDomainConfig) {
                        foreach ($grpKey in $lbDomainConfig.Keys) {
                            $grpCfg = $lbDomainConfig[$grpKey]
                            $grpReqs = @()
                            if ($grpCfg -is [hashtable] -and $grpCfg.Required) { $grpReqs = @($grpCfg.Required) }
                            elseif ($grpCfg) { $grpReqs = @($grpCfg) }
                            foreach ($req in $grpReqs) {
                                if ($req -notmatch '\*' -and $req -notmatch '\?') {
                                    $wasFound = @($builtinSource) | Where-Object {
                                        $_.GroupName -eq $grpKey -and $_.Name -like $req } | Select-Object -First 1
                                    if (-not $wasFound) {
                                        $localBuiltinList.Add([PSCustomObject]@{
                                            VM              = $vmName
                                            Host            = $hostName
                                            Domain          = $lbDomain
                                            GroupName       = $grpKey
                                            MemberName      = $req
                                            ObjectClass     = 'N/A'
                                            PrincipalSource = 'N/A'
                                            Tier            = 'Required-Missing'
                                            AlertLevel      = 'Missing'
                                        })
                                    }
                                }
                            }
                        }
                    }
                }
                
                # VM Scheduled Tasks (v3.6.1 - S4b)
                if ($vm.ScheduledTasks) {
                    foreach ($task in $vm.ScheduledTasks) {
                        $scheduledTasksList.Add([PSCustomObject]@{
                            Server      = $vmName
                            Type        = 'VM'
                            Host        = $hostName
                            TaskName    = $task.TaskName
                            TaskPath    = $task.TaskPath
                            Status      = $task.Status
                            RunAs       = $task.RunAs
                            LastRunTime = $task.LastRunTime
                            NextRunTime = $task.NextRunTime
                            LastResult  = $task.LastResult
                            Description = $task.Description
                            Actions     = $task.Actions
                        })
                    }
                }
                
                # WinRM Health (v3.6.1 - S4-3)
                if ($vm.OSInfo -and $vm.OSInfo.OSType -eq 'Windows') {
                    $winrmStatus   = if ($vm.OSInfo.WinRM_Status)    { $vm.OSInfo.WinRM_Status }    else { 'Unknown' }
                    $winrmHttps    = if ($vm.OSInfo.WinRM_HTTPS)      { $vm.OSInfo.WinRM_HTTPS }     else { 'No' }
                    $winrmCredSSP  = if ($vm.OSInfo.WinRM_AuthCredSSP){ $vm.OSInfo.WinRM_AuthCredSSP } else { 'No' }
                    $winrmCertExp  = if ($vm.OSInfo.WinRM_HTTPS_CertExp) { $vm.OSInfo.WinRM_HTTPS_CertExp } else { '' }
                    $winrmRec      = if ($vm.OSInfo.WinRM_Recommendation) { $vm.OSInfo.WinRM_Recommendation } else { '' }
                    
                    # Calculate days until cert expiry for alert logic
                    $certDaysLeft = $null
                    if ($winrmCertExp -and $winrmCertExp -ne '') {
                        try {
                            $expDate = [datetime]::Parse($winrmCertExp)
                            $certDaysLeft = [int]($expDate - (Get-Date)).TotalDays
                        } catch { }
                    }
                    
                    $alertLevel = 'OK'
                    if ($winrmStatus -ne 'Running') { $alertLevel = 'Critical' }
                    elseif ($winrmHttps -eq 'No')   { $alertLevel = 'Warning' }
                    elseif ($certDaysLeft -ne $null -and $certDaysLeft -le 30) { $alertLevel = 'Warning' }
                    
                    $winrmHealth.Add([PSCustomObject]@{
                        VM                  = $vmName
                        Host                = $hostName
                        WinRM_Status        = $winrmStatus
                        WinRM_HTTPS         = $winrmHttps
                        WinRM_CertExpiry    = $winrmCertExp
                        WinRM_CertDaysLeft  = $certDaysLeft
                        WinRM_CredSSP       = $winrmCredSSP
                        WinRM_Listeners     = if ($vm.OSInfo.WinRM_Listeners) { $vm.OSInfo.WinRM_Listeners } else { '' }
                        WinRM_Recommendation = $winrmRec
                        AlertLevel          = $alertLevel
                    })
                }
                
                # CPU
                $cpuInfo.Add([PSCustomObject]@{
                    VM         = $vm.VM
                    Host       = $hostName
                    CPUs       = $vm.CPUs
                    CPUUsage   = $vm.CPUUsage
                    Powerstate = $vm.Powerstate
                })
                
                # Memory
                $memoryInfo.Add([PSCustomObject]@{
                    VM            = $vm.VM
                    Host          = $hostName
                    MemoryMB      = [math]::Round($vm.MemoryMB, 0)
                    MemoryPercent = $vm.MemoryPercent
                    Powerstate    = $vm.Powerstate
                })
                
                # Disks
                if ($vm.HardDrives) {
                    foreach ($disk in $vm.HardDrives) {
                        $diskInfo.Add([PSCustomObject]@{
                            VM                 = $vm.VM
                            Host               = $hostName
                            Controller         = $disk.ControllerType
                            ControllerNumber   = $disk.ControllerNumber
                            ControllerLocation = $disk.ControllerLocation
                            Path               = $disk.Path
                        })
                    }
                }
                
                # Disk Analysis (VHD details from consolidated collection)
                if ($vm.DiskDetails) {
                    foreach ($dd in $vm.DiskDetails) {
                        $diskAnalysis.Add([PSCustomObject]@{
                            VM                = $dd.VMName
                            Host              = $hostName
                            FileName          = $dd.FileName
                            FullPath          = $dd.FullPath
                            ResolvedPath      = $dd.ResolvedPath
                            JunctionSource    = $dd.JunctionSource
                            DiskType          = $dd.DiskType
                            DiskFormat        = $dd.DiskFormat
                            CurrentSizeGB     = $dd.CurrentSizeGB
                            MaxSizeGB         = $dd.MaxSizeGB
                            GrowthPotentialGB = $dd.GrowthPotentialGB
                            PercentUsed       = $dd.PercentUsed
                            HostVolume        = $dd.HostDrive
                            Fragmentation     = $dd.FragmentationPercent
                            # CR107: Backup correlation columns (from vInfo/checkpoint data)
                            BackupVendor      = if ($vm.BackupVendor)           { $vm.BackupVendor }           else { 'None' }
                            StuckBackupFlag   = if ($vm.StuckBackupFlag)         { $vm.StuckBackupFlag }         else { $false }
                            AvhdxChainDepth   = if ($vm.AvhdxChainDepth)        { [int]$vm.AvhdxChainDepth }   else { 0 }
                            BackupCPCount     = if ($vm.BackupCheckpointCount)  { [int]$vm.BackupCheckpointCount } else { 0 }
                            OldestCPAgeDays   = if ($vm.OldestBackupCheckpointAge) { [int]$vm.OldestBackupCheckpointAge } else { 0 }
                        })
                    }
                }
                
                # Network
                if ($vm.NetworkAdapters) {
                    # Build guest network lookup by MAC address (for matching HV NIC -> guest config)
                    $guestNetByMAC = @{}
                    if ($vm.GuestNetwork) {
                        foreach ($gn in $vm.GuestNetwork) {
                            $mac = if ($gn.MACAddress) { ($gn.MACAddress -replace '-','') -replace ':','' } else { '' }
                            if ($mac) { $guestNetByMAC[$mac.ToUpper()] = $gn }
                        }
                    }
                    
                    foreach ($nic in $vm.NetworkAdapters) {
                        # Split IPs into IPv4 and IPv6 (v3.2.0 -- Item 4)
                        $allIPs = @()
                        if ($nic.IPAddresses) { $allIPs = @($nic.IPAddresses) }
                        $ipv4List = @($allIPs | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' })
                        $ipv6List = @($allIPs | Where-Object { $_ -match ':' })
                        
                        # Match guest network config by MAC (v3.2.0 -- Item 4 full)
                        $nicMAC = if ($nic.MacAddress) { ($nic.MacAddress -replace '-','') -replace ':','' } else { '' }
                        $guestConfig = if ($nicMAC -and $guestNetByMAC.ContainsKey($nicMAC.ToUpper())) { $guestNetByMAC[$nicMAC.ToUpper()] } else { $null }
                        
                        $netObj = [ordered]@{
                            VM             = $vm.VM
                            Host           = $hostName
                            AdapterName    = $nic.Name
                            SwitchName     = $nic.SwitchName
                            MacAddress     = $nic.MacAddress
                            IPv4Addresses  = if ($ipv4List.Count -gt 0) { $ipv4List -join '; ' } else { '' }
                            IPv6Addresses  = if ($ipv6List.Count -gt 0) { $ipv6List -join '; ' } else { '' }
                            IPAddresses    = if ($nic.IPAddresses) { ($nic.IPAddresses -join '; ') } else { '' }
                            Status         = if ($nic.Status) { ($nic.Status | ForEach-Object { $_.ToString() }) -join '; ' } else { '' }
                        }
                        
                        # Guest-side config (Intermediate/Advanced only)
                        if ($isIntermediate) {
                            $netObj['AddressSource'] = if ($guestConfig) { $guestConfig.AddressSource } else { '' }
                            $netObj['SubnetMask']    = if ($guestConfig) { $guestConfig.SubnetMask } else { '' }
                            $netObj['SubnetPrefix']  = if ($guestConfig) { $guestConfig.SubnetPrefix } else { '' }
                            $netObj['Gateway']       = if ($guestConfig) { $guestConfig.Gateway } else { '' }
                            $netObj['DNSServers']    = if ($guestConfig) { $guestConfig.DNSServers } else { '' }
                            $netObj['DNSSuffix']     = if ($guestConfig -and $guestConfig.DNSSuffix) { $guestConfig.DNSSuffix } else { '' }
                            $netObj['DNSSuffixSearchList'] = if ($guestConfig -and $guestConfig.DNSSuffixSearchList) { $guestConfig.DNSSuffixSearchList } else { '' }
                            $netObj['LinkSpeed']     = if ($guestConfig) { $guestConfig.LinkSpeed } else { '' }
                            
                            # Network Connection Profile (v3.8.0 - CR3 fix: multi-source NetProfiles lookup)
                            # Root cause: NetProfiles only populated when WinRM succeeds AND domain trusts
                            # are working. For OHDC.com-domain VMs with WinRM but on a non-default profile,
                            # we try multiple sources in order of confidence.
                            #
                            # Source 1: vm.NetProfiles (collected via Get-NetConnectionProfile in OS module)
                            # Source 2: vm.OSInfo.NetProfiles (same data, different path through serialization)
                            # Source 3: guestConfig.DHCPEnabled / AddressSource for a basic DHCP/Static hint
                            # Source 4: NIC IP + known subnet ranges for a domain/private heuristic
                            $vmNetProfiles = @()
                            if ($vm.NetProfiles -and @($vm.NetProfiles).Count -gt 0) {
                                $vmNetProfiles = @($vm.NetProfiles)
                            } elseif ($vm.OSInfo -and $vm.OSInfo.NetProfiles -and @($vm.OSInfo.NetProfiles).Count -gt 0) {
                                $vmNetProfiles = @($vm.OSInfo.NetProfiles)
                            }

                            $nicAlias        = $nic.Name
                            $matchedProfile  = $null

                            # Try exact alias match first
                            if ($vmNetProfiles.Count -gt 0) {
                                $matchedProfile = $vmNetProfiles | Where-Object {
                                    $_.InterfaceAlias -eq $nicAlias } | Select-Object -First 1
                                # Partial match fallback
                                if (-not $matchedProfile) {
                                    $matchedProfile = $vmNetProfiles | Where-Object {
                                        $_.InterfaceAlias -like "*$nicAlias*" } | Select-Object -First 1
                                }
                                # MAC-based fallback: match on IP address
                                if (-not $matchedProfile -and $guestConfig -and $guestConfig.IPAddress) {
                                    $guestIP = $guestConfig.IPAddress
                                    $matchedProfile = $vmNetProfiles | Where-Object {
                                        # InterfaceAlias won't have IP, but Name sometimes does
                                        $_.Name -like "*$guestIP*" } | Select-Object -First 1
                                }
                                # Last resort: first profile if only one NIC
                                if (-not $matchedProfile -and $vmNetProfiles.Count -eq 1) {
                                    $matchedProfile = $vmNetProfiles[0]
                                }
                            }

                            # Derive category: if still no profile, use IP range heuristic
                            $resolvedCategory = ''
                            if ($matchedProfile) {
                                $resolvedCategory = $matchedProfile.NetworkCategory
                            } elseif ($ipv4List.Count -gt 0) {
                                # Heuristic: RFC1918 private ranges that are typically domain-joined
                                $firstIP = $ipv4List[0]
                                if ($firstIP -match '^10\.' -or $firstIP -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
                                    $firstIP -match '^192\.168\.') {
                                    $resolvedCategory = 'Domain (inferred)'
                                } elseif ($firstIP -notmatch '^169\.254\.') {
                                    $resolvedCategory = 'Unknown'
                                }
                            }

                            $netObj['NetworkCategory'] = $resolvedCategory
                            $netObj['ProfileName']     = if ($matchedProfile) { $matchedProfile.Name } else { '' }

                            # v3.9.0: DNS suffix assessment (CR56)
                            $vmSuffix = $netObj['DNSSuffix']
                            $vmSuffixList = $netObj['DNSSuffixSearchList']
                            if ($vm.Powerstate -ne 'poweredOn') {
                                $netObj['DNSSuffixAssessment'] = 'N/A (Off)'
                            }
                            elseif ($vmSuffix -or $vmSuffixList) {
                                $netObj['DNSSuffixAssessment'] = 'OK'
                            }
                            elseif (-not $guestConfig -or -not $guestConfig.DNSServers) {
                                $netObj['DNSSuffixAssessment'] = 'N/A (no DNS)'
                            }
                            else {
                                $netObj['DNSSuffixAssessment'] = 'MISSING -- No DNS suffix configured. Short-name resolution and Kerberos SPN lookup may fail.'
                            }
                        }
                        
                        # v3.9.2: DNS forward record match from DNS-Validation cross-reference
                        # v3.10.9 CR98: Fill blanks with explicit N/A values instead of empty string.
                        $netObj['DNSForwardMatch'] = ''
                        if ($DNSValidationData -and $DNSValidationData.DNSLookup) {
                            $vmNameKey = $vmName
                            $dnsRow = $DNSValidationData.DNSLookup[$vmNameKey]
                            if ($dnsRow) {
                                # OPEN-11: ForwardMatch may be blank if EfficientIP returned
                                # no entry for this host -- fill with N/A instead of leaving blank.
                                $netObj['DNSForwardMatch'] = if ($dnsRow.ForwardMatch) { $dnsRow.ForwardMatch } else { 'N/A' }
                            }
                            else {
                                # DNS validation ran but no entry for this VM
                                $netObj['DNSForwardMatch'] = 'N/A (not in DNS validation)'
                            }
                        }
                        else {
                            # DNS validation was disabled or not available
                            if ($vmPowerState -ne 'poweredOn') {
                                $netObj['DNSForwardMatch'] = 'N/A (Off)'
                            }
                            elseif (-not $netObj['IPv4Addresses'] -and -not $netObj['IPAddresses']) {
                                $netObj['DNSForwardMatch'] = 'N/A (no IP)'
                            }
                            else {
                                $netObj['DNSForwardMatch'] = 'N/A (DNS validation disabled)'
                            }
                        }

                        $networkInfo.Add([PSCustomObject]$netObj)
                    }
                }
                
                # Checkpoints (FIX: handle CreationTime as ISO string)
                if ($vm.Checkpoints -and $vm.Checkpoints.Count -gt 0) {
                    foreach ($cp in $vm.Checkpoints) {
                        $cpTime = if ($cp.CreationTime -is [datetime]) { $cp.CreationTime }
                                  elseif ($cp.CreationTime -is [string]) { [datetime]::Parse($cp.CreationTime) }
                                  else { Get-Date }
                        
                        $age = (Get-Date) - $cpTime
                        $warningLevel = "OK"
                        if ($age.Days -gt 30) { $warningLevel = "CRITICAL - $($age.Days) days old" }
                        elseif ($age.Days -gt 7) { $warningLevel = "WARNING - $($age.Days) days old" }
                        
                        $checkpointInfo.Add([PSCustomObject]@{
                            VM             = $vm.VM
                            Host           = $hostName
                            CheckpointName = $cp.Name
                            CheckpointId   = if ($cp.Id)       { $cp.Id }       else { '' }
                            ParentId       = if ($cp.ParentId) { $cp.ParentId } else { '' }
                            CreationTime   = $cpTime
                            AgeDays        = $age.Days
                            Warning        = $warningLevel
                            # v3.10.11 CR104: Backup-stuck detection fields
                            SnapshotType   = if ($cp.SnapshotType)   { $cp.SnapshotType }   else { 'Standard' }
                            BackupVendor   = if ($cp.BackupVendor)   { $cp.BackupVendor }   else { 'Manual' }
                            IsBackupOrigin = if ($cp.IsBackupOrigin) { $cp.IsBackupOrigin } else { $false }
                        })
                    }
                }
                
                # Integration Services
                if ($vm.IntegrationServices) {
                    foreach ($svc in $vm.IntegrationServices) {
                        $integrationInfo.Add([PSCustomObject]@{
                            VM      = $vm.VM
                            Host    = $hostName
                            Service = $svc.Name
                            Enabled = $svc.Enabled
                            Status  = $svc.PrimaryStatusDescription
                        })
                    }
                }
                
                # DVD Drives
                if ($vm.DVDDrives) {
                    foreach ($dvd in $vm.DVDDrives) {
                        $dvdInfo.Add([PSCustomObject]@{
                            VM                 = $vm.VM
                            Host               = $hostName
                            Controller         = $dvd.ControllerType
                            ControllerNumber   = $dvd.ControllerNumber
                            ControllerLocation = $dvd.ControllerLocation
                            Path               = $dvd.Path
                        })
                    }
                }
                
                # Replication
                if ($vm.Replication) {
                    $replicationInfo.Add([PSCustomObject]@{
                        VM                  = $vm.VM
                        Host                = $hostName
                        State               = $vm.Replication.State
                        Mode                = $vm.Replication.Mode
                        FrequencySec        = $vm.Replication.FrequencySec
                        ReplicaServer       = $vm.Replication.ReplicaServer
                        LastReplicationTime = $vm.Replication.LastReplicationTime
                    })
                }
                
                # OS Inventory
                if ($vm.OSInfo -and $vm.OSInfo.OSType -ne "Unknown") {
                    $osInventory.Add([PSCustomObject]@{
                        VM               = $vm.VM
                        Host             = $hostName
                        Type             = 'VM'         # OPEN-67
                        DataSource       = 'Hyper-V'    # OPEN-67
                        OSType           = $vm.OSInfo.OSType
                        OSName           = $vm.OSInfo.OSName
                        OSVersion        = $vm.OSInfo.OSVersion
                        OSBuild          = $vm.OSInfo.OSBuild
                        Architecture     = $vm.OSInfo.OSArchitecture
                        InstallDate      = $vm.OSInfo.InstallDate
                        LastBootTime     = $vm.OSInfo.LastBootTime
                        ServicePack      = $vm.OSInfo.ServicePack
                        LicenseStatus    = $vm.OSInfo.LicenseStatus
                        Domain           = $vm.OSInfo.Domain
                        KernelVersion    = $vm.OSInfo.KernelVersion
                        # v3.1.1: Update and Reboot status
                        LastUpdateKB     = if ($vm.OSInfo.LastUpdateKB) { $vm.OSInfo.LastUpdateKB } else { 'N/A' }
                        LastUpdateDate   = if ($vm.OSInfo.LastUpdateDate) { $vm.OSInfo.LastUpdateDate } else { 'N/A' }
                        RebootPending    = if ($null -ne $vm.OSInfo.RebootPending) { $vm.OSInfo.RebootPending } else { '' }
                        RebootReasons    = if ($vm.OSInfo.RebootReasons) { $vm.OSInfo.RebootReasons } else { '' }
                        # v3.2.0: Activation
                        ActivationStatus = if ($vm.OSInfo.LicenseStatus) { $vm.OSInfo.LicenseStatus } else { '' }
                        ActivationMethod = if ($vm.OSInfo.ActivationMethod) { $vm.OSInfo.ActivationMethod } else { '' }
                        KMSServer        = if ($vm.OSInfo.KMSServer) { $vm.OSInfo.KMSServer } else { '' }
                        PartialKey       = if ($vm.OSInfo.PartialKey) { $vm.OSInfo.PartialKey } else { '' }
                    })
                }
                
                # Applications
                if ($vm.Applications -and $vm.Applications.Count -gt 0) {
                    foreach ($app in $vm.Applications) {
                        $osType = if ($vm.OSInfo) { $vm.OSInfo.OSType } else { "Windows" }
                        if ($osType -eq "Windows") {
                            # App Compliance flags (v3.2.9)
                            $appCompType = ''
                            $appName = $app.Name
                            if ($AppCompliance) {
                                $isRemove = $AppCompliance.AppsToRemove | Where-Object { $appName -like "*$_*" }
                                $isRequired = $AppCompliance.AppsRequired | Where-Object { $appName -like "*$_*" }
                                $isRequiredPre2025 = $AppCompliance.AppsRequiredPre2025 | Where-Object { $appName -like "*$_*" }
                                $isSecTool = $AppCompliance.SecurityTools | Where-Object { $appName -like "*$_*" }
                                if ($isRemove) { $appCompType = 'Remove' }
                                elseif ($isRequired) { $appCompType = 'Required' }
                                elseif ($isRequiredPre2025) { $appCompType = 'Required (Pre-2025)' }
                                elseif ($isSecTool) { $appCompType = 'Security Tool' }
                            }
                            $applicationsWindows.Add([PSCustomObject]@{
                                VM          = $vm.VM
                                Host        = $hostName
                                Application = $app.Name
                                Version     = $app.Version
                                Publisher   = $app.Publisher
                                InstallDate = $app.InstallDate
                                SizeMB      = $app.EstimatedSizeMB
                                ComplianceType = $appCompType
                            })
                        }
                        elseif ($osType -eq "Linux") {
                            $applicationsLinux.Add([PSCustomObject]@{
                                VM        = $vm.VM
                                Host      = $hostName
                                Package   = $app.Name
                                Version   = $app.Version
                                Publisher = $app.Publisher
                            })
                        }
                    }
                    
                    # Check for MISSING required apps (v3.2.9)
                    if ($AppCompliance) {
                        $vmAppNames = @($vm.Applications | ForEach-Object { $_.Name })
                        $osName = if ($vm.OSInfo) { $vm.OSInfo.OSName } else { '' }
                        $isPre2025 = $osName -notmatch '2025'
                        
                        # Check required apps
                        foreach ($reqApp in $AppCompliance.AppsRequired) {
                            $found = $vmAppNames | Where-Object { $_ -like "*$reqApp*" }
                            if (-not $found) {
                                $applicationsWindows.Add([PSCustomObject]@{
                                    VM          = $vm.VM
                                    Host        = $hostName
                                    Application = $reqApp
                                    Version     = 'MISSING'
                                    Publisher   = ''
                                    InstallDate = ''
                                    SizeMB      = ''
                                    ComplianceType = 'Missing Required'
                                })
                            }
                        }
                        # Check Pre-2025 required apps
                        if ($isPre2025) {
                            foreach ($reqApp in $AppCompliance.AppsRequiredPre2025) {
                                $found = $vmAppNames | Where-Object { $_ -like "*$reqApp*" }
                                if (-not $found) {
                                    $applicationsWindows.Add([PSCustomObject]@{
                                        VM          = $vm.VM
                                        Host        = $hostName
                                        Application = $reqApp
                                        Version     = 'MISSING'
                                        Publisher   = ''
                                        InstallDate = ''
                                        SizeMB      = ''
                                        ComplianceType = 'Missing Required (Pre-2025)'
                                    })
                                }
                            }
                        }
                    }
                }
                
                # Security Compliance (v3.6.1 - unified schema: VM rows carry all columns,
                # host-specific fields blank; host rows carry all columns, VM-specific fields blank.
                # This ensures ImportExcel always sees a consistent column set regardless of row order.)
                if ($vm.FirmwareInfo) {
                    $complianceStatus = "Compliant"
                    if ($vm.FirmwareInfo.Generation -eq 1) {
                        $complianceStatus = "Non-Compliant - Gen 1 BIOS"
                    } elseif (-not $vm.FirmwareInfo.SecureBootEnabled) {
                        $complianceStatus = "Non-Compliant - Secure Boot Disabled"
                    }
                    
                    $securityCompliance.Add([PSCustomObject]@{
                        # --- Identity ---
                        VM                 = $vm.VM
                        Host               = $hostName
                        Type               = "VM"
                        # --- VM firmware fields ---
                        Generation         = $vm.Generation
                        FirmwareType       = $vm.FirmwareInfo.FirmwareType
                        SecureBootEnabled  = $vm.FirmwareInfo.SecureBootEnabled
                        SecureBootTemplate = $vm.FirmwareInfo.SecureBootTemplate
                        TPMEnabled         = $vm.FirmwareInfo.TPMEnabled
                        OSName             = if ($vm.GuestOS) { $vm.GuestOS } else { "Unknown" }
                        SB_CertRisk        = $sbCertRisk
                        # --- Host hardware fields (blank for VM rows) ---
                        HostType           = ''
                        Manufacturer       = ''
                        Model              = ''
                        SerialNumber       = ''
                        TPMVersion         = ''
                        SB_Has2023Certs    = ''
                        SB_UpdateRequired  = ''
                        SB_DaysUntilExp    = ''
                        SB_KBs_Missing     = ''
                        SB_Action          = ''
                        # --- Compliance outcome ---
                        ComplianceStatus   = $complianceStatus
                        # --- App compliance (VM rows only) ---
                        MissingApps        = if ($AppCompliance -and $vm.Applications) {
                            $vmAppNames = @($vm.Applications | ForEach-Object { $_.Name })
                            $missing = @()
                            foreach ($reqApp in $AppCompliance.AppsRequired) {
                                $found = $vmAppNames | Where-Object { $_ -like "*$reqApp*" }
                                if (-not $found) { $missing += $reqApp }
                            }
                            if ($missing.Count -gt 0) { "See Applications-Windows: $($missing -join ', ')" } else { '' }
                        } else { '' }
                        RemoveApps         = if ($AppCompliance -and $vm.Applications) {
                            $vmAppNames = @($vm.Applications | ForEach-Object { $_.Name })
                            $toRemove = @()
                            foreach ($rmApp in $AppCompliance.AppsToRemove) {
                                $found = $vmAppNames | Where-Object { $_ -like "*$rmApp*" }
                                if ($found) { $toRemove += $rmApp }
                            }
                            if ($toRemove.Count -gt 0) { "See Applications-Windows: $($toRemove -join ', ')" } else { '' }
                        } else { '' }
                    })
                }
              }
              catch {
                # v3.9.9 CR71: Catch null reference or other errors on individual VMs
                # Log the error and continue processing remaining VMs
                $errVM = if ($vm -and $vm.VM) { $vm.VM } else { '(unknown)' }
                Write-HVLog "  WARNING: Error processing VM '$errVM' on $hostName -- $($_.Exception.Message)" -Level Warning
              }
            }
            
            # Storage
            if ($hvHost.Storage) {
                # Build junction lookup: which junctions point to which volumes
                $juncLookup = @{}
                if ($hvHost.JunctionAlerts) {
                    foreach ($ja in $hvHost.JunctionAlerts) {
                        $tv = $ja.TargetVolume
                        if (-not $juncLookup.ContainsKey($tv)) { $juncLookup[$tv] = @() }
                        $juncLookup[$tv] += "$($ja.JunctionPath)"
                    }
                }
                
                foreach ($vol in $hvHost.Storage) {
                    $juncPaths = if ($juncLookup.ContainsKey($vol.Path)) { $juncLookup[$vol.Path] -join '; ' } else { $null }
                    $storageInfo.Add([PSCustomObject]@{
                        Host          = $hostName
                        Path          = $vol.Path
                        Label         = $vol.Label
                        FileSystem    = $vol.FileSystem
                        Type          = $vol.Type
                        DriveLetter   = $vol.DriveLetter
                        TotalGB       = $vol.TotalGB
                        FreeGB        = $vol.FreeGB
                        PercentFree   = $vol.PercentFree
                        JunctionPaths = $juncPaths
                        MultiHomed    = if ($juncPaths) { $true } else { $false }
                    })
                }
            }
            
            # VM Guest Storage (v3.6.1 - S3-4)
            # One row per VM-drive. Growth rate computed from GuestStorageHistory.
            # Recommendations are generated based on free space and projected 1-year usage.
            foreach ($vm in $hvHost.VMs) {
                if (-not $vm.GuestDisks -or $vm.GuestDisks.Count -eq 0) { continue }
                
                $vmKey = if ($vm.VMId) { "VMID:$($vm.VMId)" } else { $vm.VM.ToUpper() }
                $histEntry = if ($GuestStorageHistory -and $GuestStorageHistory.ContainsKey($vmKey)) { $GuestStorageHistory[$vmKey] } else { $null }
                
                foreach ($disk in $vm.GuestDisks) {
                    $driveKey  = $disk.DriveLetter
                    $totalGB   = [double]$disk.TotalGB
                    $usedGB    = [double]$disk.UsedGB
                    $freeGB    = [double]$disk.FreeGB
                    $pctFree   = [double]$disk.PercentFree
                    
                    # --- Growth Rate Calculation ---
                    $growthRateGBperDay  = $null
                    $projectedUsed1YrGB  = $null
                    $dataPointCount      = 0
                    $oldestDataPoint     = ''
                    $growthBasis         = 'Default (10% free - insufficient history)'
                    
                    if ($histEntry -and $histEntry.Drives) {
                        $driveHistory = $null
                        if ($histEntry.Drives -is [hashtable]) {
                            if ($histEntry.Drives.ContainsKey($driveKey)) { $driveHistory = $histEntry.Drives[$driveKey] }
                        }
                        else {
                            $dp = $histEntry.Drives.PSObject.Properties | Where-Object { $_.Name -eq $driveKey }
                            if ($dp) { $driveHistory = $dp.Value }
                        }
                        if ($driveHistory) {
                            $sorted = @($driveHistory | Sort-Object { [datetime]$_.Date })
                            $dataPointCount = $sorted.Count
                            if ($dataPointCount -ge 2) {
                                $oldest  = $sorted[0]
                                $newest  = $sorted[-1]
                                $daySpan = ([datetime]$newest.Date - [datetime]$oldest.Date).TotalDays
                                if ($daySpan -gt 0) {
                                    $growthRateGBperDay = ([double]$newest.UsedGB - [double]$oldest.UsedGB) / $daySpan
                                    $projectedUsed1YrGB = [math]::Round($usedGB + ($growthRateGBperDay * 365), 2)
                                    $oldestDataPoint    = $oldest.Date
                                    $growthBasis        = "$dataPointCount data points over $([math]::Round($daySpan,0))d ($([math]::Round($growthRateGBperDay*30,2)) GB/month)"
                                }
                            }
                            elseif ($dataPointCount -eq 1) { $oldestDataPoint = $sorted[0].Date }
                        }
                    }
                    
                    # --- Smart unit formatter ---
                    $fmt = {
                        param([double]$gb)
                        if ([math]::Abs($gb) -ge 1024) { return "$([math]::Round($gb/1024,2)) TB" }
                        if ([math]::Abs($gb) -ge 1)    { return "$([math]::Round($gb,2)) GB" }
                        if ([math]::Abs($gb) -ge 0.001){ return "$([math]::Round($gb*1024,1)) MB" }
                        return "$([math]::Round($gb*1048576,0)) KB"
                    }
                    
                    # --- Recommendation Engine ---
                    $recs      = [System.Collections.Generic.List[string]]::new()
                    $alertLevel = 'OK'
                    
                    if ($totalGB -eq 0) {
                        $alertLevel = 'Unknown'
                        $recs.Add("DATA QUALITY: Drive $driveKey on $($vm.VM) returned 0 GB total. WMI data may be incomplete - verify manually.")
                    }
                    else {
                        # Critical / Warning thresholds
                        if ($freeGB -le 0.1) {
                            $alertLevel = 'Critical'
                            $recs.Add("CRITICAL: Drive $driveKey on $($vm.VM) has $(& $fmt $freeGB) remaining - effectively OUT OF SPACE. VM writes may be failing. Expand disk or free space immediately.")
                        }
                        elseif ($pctFree -lt $GuestStorageCriticalPct) {
                            $alertLevel = 'Critical'
                            $recs.Add("CRITICAL: Drive $driveKey is at $pctFree% free ($(& $fmt $freeGB) remaining). Imminent failure risk - do not wait. Add capacity or clean up files now.")
                        }
                        elseif ($pctFree -lt $GuestStorageWarningPct) {
                            $alertLevel = 'Warning'
                            $recs.Add("WARNING: Drive $driveKey is at $pctFree% free ($(& $fmt $freeGB) remaining) - below recommended $GuestStorageWarningPct% minimum.")
                        }
                        
                        # Growth-based or threshold-based expansion recommendation
                        if ($projectedUsed1YrGB -ne $null -and $growthRateGBperDay -ne $null) {
                            if ($growthRateGBperDay -gt 0) {
                                $daysUntilFull     = if ($growthRateGBperDay -gt 0) { [math]::Round($freeGB / $growthRateGBperDay, 0) } else { 99999 }
                                $neededForGrowthGB = [math]::Max(0, $projectedUsed1YrGB - $totalGB + ($totalGB * ($GuestStorageBufferPct / 100)))
                                if ($neededForGrowthGB -gt 0.5) {
                                    if ($alertLevel -eq 'OK') { $alertLevel = 'Warning' }
                                    $recs.Add("GROWTH: At $(& $fmt ($growthRateGBperDay*30))/month, drive $driveKey fills in approximately $daysUntilFull days. Add $(& $fmt $neededForGrowthGB) to $($vm.VM) to support 1 year of growth plus a 10% buffer.")
                                }
                                else {
                                    $recs.Add("GROWTH OK: Drive $driveKey growth is $(& $fmt ($growthRateGBperDay*30))/month. Projected 1-year used: $(& $fmt $projectedUsed1YrGB) - within current capacity.")
                                }
                            }
                            elseif ($growthRateGBperDay -lt 0) {
                                $recs.Add("INFO: Drive $driveKey usage is decreasing ($(& $fmt ([math]::Abs($growthRateGBperDay*30)))/month freed). No expansion action needed.")
                            }
                            else {
                                $recs.Add("INFO: Drive $driveKey usage is stable. No growth trend detected.")
                            }
                        }
                        else {
                            # No growth history - default 10% threshold
                            $neededGB = [math]::Round(($totalGB * ($GuestStorageWarningPct / 100)) - $freeGB, 2)
                            if ($neededGB -gt 0.1) {
                                if ($alertLevel -eq 'OK') { $alertLevel = 'Warning' }
                                $recs.Add("THRESHOLD: Drive $driveKey on $($vm.VM) has $(& $fmt $freeGB) free - below the $GuestStorageWarningPct% minimum ($(& $fmt ($totalGB*$GuestStorageWarningPct/100))). Add $(& $fmt $neededGB) to meet minimum. Growth-based sizing will be available after 2+ report runs.")
                            }
                        }
                        
                        # Cleanup opportunity (Windows C: drive heuristic)
                        if ($driveKey -eq 'C:' -and $pctFree -lt 20) {
                            $recs.Add("CLEANUP OPPORTUNITY: C: is at $([math]::Round(100-$pctFree,1))% used. Potential temp/cleanup space: Windows\Temp, Users\*\AppData\Local\Temp, SoftwareDistribution\Download, IIS logs (if applicable). Command: Remove-Item C:\Windows\Temp\* -Recurse -Force -ErrorAction SilentlyContinue")
                        }
                        
                        if ($recs.Count -eq 0) {
                            $recs.Add("OK: Drive $driveKey has $(& $fmt $freeGB) free ($pctFree%). Healthy - no action needed.")
                        }
                    }
                    
                    # --- Build base row object ---
                    $guestStorageRow = [ordered]@{
                        VM                    = $vm.VM
                        Host                  = $hostName
                        DriveLetter           = $driveKey
                        Label                 = if ($disk.Label)      { $disk.Label }      else { '' }
                        FileSystem            = if ($disk.FileSystem) { $disk.FileSystem } else { '' }
                        TotalGB               = $totalGB
                        UsedGB                = $usedGB
                        FreeGB                = $freeGB
                        PercentFree           = $pctFree
                        PercentUsed           = if ($disk.PercentUsed) { [double]$disk.PercentUsed } else { [math]::Round(100-$pctFree,1) }
                        AlertLevel            = $alertLevel
                        DataPoints            = $dataPointCount
                        OldestDataPoint       = $oldestDataPoint
                        GrowthRate_GB_Month   = if ($growthRateGBperDay -ne $null) { [math]::Round($growthRateGBperDay * 30, 2) } else { '' }
                        Projected1Yr_UsedGB   = if ($projectedUsed1YrGB -ne $null) { $projectedUsed1YrGB } else { '' }
                        GrowthBasis           = $growthBasis
                        Recommendation        = $recs -join ' | '
                    }
                    
                    # --- Monthly growth columns (e.g. Jan_GrowthGB, Feb_GrowthGB ...) ---
                    # Each column = net UsedGB change for that calendar month.
                    # Requires at least 2 datapoints within the month (first and last).
                    # Positive = grew, Negative = freed, blank = insufficient data.
                    if ($GuestStorageMonthlyColumns -and $histEntry -and $histEntry.Drives) {
                        # Retrieve the drive's history array
                        $driveHistForMonth = $null
                        if ($histEntry.Drives -is [hashtable]) {
                            if ($histEntry.Drives.ContainsKey($driveKey)) { $driveHistForMonth = $histEntry.Drives[$driveKey] }
                        }
                        else {
                            $dp2 = $histEntry.Drives.PSObject.Properties | Where-Object { $_.Name -eq $driveKey }
                            if ($dp2) { $driveHistForMonth = $dp2.Value }
                        }
                        
                        if ($driveHistForMonth -and $driveHistForMonth.Count -ge 2) {
                            # Sort all datapoints by date
                            $sortedPoints = @($driveHistForMonth | Sort-Object {
                                try { [datetime]::Parse($_.Date) } catch { [datetime]::MinValue }
                            })
                            
                            # Determine range: from oldest point's month to current month
                            $firstDate   = try { [datetime]::Parse($sortedPoints[0].Date)  } catch { $null }
                            $currentDate = Get-Date
                            
                            if ($firstDate) {
                                $monthPtr = [datetime]::new($firstDate.Year, $firstDate.Month, 1)
                                $monthEnd = [datetime]::new($currentDate.Year, $currentDate.Month, 1)
                                
                                while ($monthPtr -le $monthEnd) {
                                    $colName      = $monthPtr.ToString('MMM_yyyy') + '_GrowthGB'
                                    $monthStart   = $monthPtr
                                    $monthLast    = $monthPtr.AddMonths(1).AddDays(-1)
                                    
                                    # Find first and last datapoint within this calendar month
                                    $monthPoints  = @($sortedPoints | Where-Object {
                                        try {
                                            $d = [datetime]::Parse($_.Date)
                                            $d -ge $monthStart -and $d -le $monthLast
                                        } catch { $false }
                                    })
                                    
                                    $monthGrowth = ''
                                    if ($monthPoints.Count -ge 2) {
                                        $firstUsed = [double]$monthPoints[0].UsedGB
                                        $lastUsed  = [double]$monthPoints[-1].UsedGB
                                        $monthGrowth = [math]::Round($lastUsed - $firstUsed, 2)
                                    }
                                    elseif ($monthPoints.Count -eq 1) {
                                        # Only one snapshot this month - can still estimate if previous month's
                                        # last point exists (cross-month delta)
                                        $prevMonthLast = @($sortedPoints | Where-Object {
                                            try { [datetime]::Parse($_.Date) -lt $monthStart } catch { $false }
                                        }) | Select-Object -Last 1
                                        if ($prevMonthLast) {
                                            $monthGrowth = [math]::Round([double]$monthPoints[0].UsedGB - [double]$prevMonthLast.UsedGB, 2)
                                        }
                                    }
                                    
                                    $guestStorageRow[$colName] = $monthGrowth
                                    $monthPtr = $monthPtr.AddMonths(1)
                                }
                            }
                        }
                        # If no history yet for this drive, monthly columns are simply absent from this row.
                        # ImportExcel will pad absent keys with blank for rows that have them elsewhere.
                    }
                    
                    $vmGuestStorage.Add([PSCustomObject]$guestStorageRow)
                }
            }
            
            # Host Security Compliance
            if ($hvHost.HostFirmware) {
                $hc = "Compliant"
                if ($hvHost.HostFirmware.FirmwareType -eq "BIOS") { $hc = "BIOS Firmware" }
                elseif (-not $hvHost.HostFirmware.SecureBootEnabled) { $hc = "Secure Boot Disabled" }
                
                # SecureBoot cert status overlay
                $sbCertStatus = if ($hvHost.HostFirmware.SB_UpdateRequired -eq 'Yes (Expiring 2026)') { 'CERT UPDATE REQUIRED' } else { '' }
                if ($sbCertStatus -and $hc -eq 'Compliant') { $hc = $sbCertStatus }
                elseif ($sbCertStatus) { $hc = "$hc | $sbCertStatus" }
                
                $securityCompliance.Add([PSCustomObject]@{
                    # --- Identity ---
                    VM                 = "N/A"
                    Host               = $hostName
                    Type               = "Host"
                    # --- VM firmware fields (blank for Host rows) ---
                    Generation         = ''
                    FirmwareType       = $hvHost.HostFirmware.FirmwareType
                    SecureBootEnabled  = $hvHost.HostFirmware.SecureBootEnabled
                    SecureBootTemplate = ''
                    TPMEnabled         = ''
                    OSName             = ''
                    SB_CertRisk        = ''
                    # --- Host hardware fields ---
                    HostType           = $hvHost.HostFirmware.HostType
                    Manufacturer       = $hvHost.HostFirmware.Manufacturer
                    Model              = $hvHost.HostFirmware.Model
                    SerialNumber       = if ($hvHost.HostFirmware.SerialNumber) { $hvHost.HostFirmware.SerialNumber } else { '' }
                    TPMVersion         = $hvHost.HostFirmware.TPMVersion
                    SB_Has2023Certs    = if ($hvHost.HostFirmware.SB_Has2023Certs) { $true } else { $false }
                    SB_UpdateRequired  = $hvHost.HostFirmware.SB_UpdateRequired
                    SB_DaysUntilExp    = $hvHost.HostFirmware.SB_DaysUntilExpiration
                    SB_KBs_Missing     = if ($hvHost.HostInfo -and $hvHost.HostInfo.SB_KBs) {
                        $missingRequired = @($hvHost.HostInfo.SB_KBs | Where-Object { $_.Status -eq 'NotInstalled' -and $_.Required -eq $true } | ForEach-Object { $_.KB })
                        if ($missingRequired.Count -gt 0) { $missingRequired -join ', ' } else { 'None' }
                    } else { '' }
                    SB_Action          = if ($hvHost.HostInfo -and $hvHost.HostInfo.SB_Action) { $hvHost.HostInfo.SB_Action } else { '' }
                    # --- Compliance outcome ---
                    ComplianceStatus   = $hc
                    # --- App compliance (blank for Host rows) ---
                    MissingApps        = ''
                    RemoveApps         = ''
                })
            }
        }
        
        # ======================================================================
        # S5a: Build AD-Auth-Detail, AD-Auth-Issues, and Roles-Features lists
        # Uses ADAuthData (from Invoke-ADAuthCollection) and FeaturesData (from OS module).
        # ======================================================================

        # Roles and Features (v3.6.1 - S5a)
        if ($FeaturesData -and $FeaturesData.Count -gt 0) {
            $highlightMap = @{
                'Web-Server'          = 'IIS Web Server'
                'DNS'                 = 'DNS Server'
                'DHCP'                = 'DHCP Server'
                'AD-Certificate'      = 'Certificate Authority'
                'AD-Domain-Services'  = 'Domain Controller'
                'ADFS-Federation'     = 'AD FS'
                'NPAS'                = 'NPS / RADIUS'
                'Print-Server'        = 'Print Server'
                'RDS-RD-Server'       = 'RDS Session Host'
                'Hyper-V'             = 'Hyper-V Role'
                'Failover-Clustering' = 'Failover Clustering'
                'DotNet-Framework'    = '.NET Framework'
                'DotNet-Core'         = '.NET Core / 5+'
            }
            foreach ($computer in ($FeaturesData.Keys | Sort-Object)) {
                $feats = $FeaturesData[$computer]
                if (-not $feats) { continue }
                foreach ($f in $feats) {
                    $cat = ''
                    foreach ($pat in $highlightMap.Keys) {
                        if ($f.Name -like "*$pat*" -or $f.DisplayName -like "*$pat*") {
                            $cat = $highlightMap[$pat]; break }
                    }
                    # Determine Type from host list (CR4: also handle MachineType from collected data)
                    $machineType = if ($HostData | Where-Object { $_.HostName -eq $computer }) { 'Host' } else { 'VM' }
                    # Override with collected MachineType if present (set in OS module)
                    $collectedType = if ($f.MachineType -and $f.MachineType -ne 'Unknown') { $f.MachineType } else { $machineType }
                    $rolesFeaturesList.Add([PSCustomObject]@{
                        Computer     = $computer
                        MachineType  = $collectedType
                        FeatureName  = $f.Name
                        DisplayName  = $f.DisplayName
                        FeatureType  = $f.FeatureType
                        InstallState = if ($f.InstallState) { $f.InstallState } else { 'Installed' }
                        Category     = $cat
                        Source       = $f.Source
                    })
                }
            }
        }

        # AD-Auth-Detail and AD-Auth-Issues (v3.6.1 - S5a)
        if ($ADAuthData -and $ADAuthData.Count -gt 0) {
            # Build WinRM cross-ref from vmInfo
            $winrmXref = @{}
            foreach ($vm in $vmInfo) {
                $k = ($vm.VM -replace '\..*$','').ToUpper()
                $winrmXref[$k] = @{
                    WinRMHTTPS  = $vm.WinRMHTTPS
                    WinRMStatus = $vm.WinRMStatus
                    CredSSP     = $vm.CredSSP
                    WinRMAuth   = $vm.WinRMAuth
                }
            }

            $severityOrder = @{ 'Critical' = 4; 'Warning' = 3; 'OK' = 2; 'Info' = 1 }

            foreach ($key in ($ADAuthData.Keys | Sort-Object)) {
                $ad      = $ADAuthData[$key]
                $winrmVM = $winrmXref[$key]

                # Determine WinRM transport
                $transport = 'Unknown'
                if ($winrmVM) {
                    $hasHTTPS = $winrmVM.WinRMHTTPS -eq $true -or $winrmVM.WinRMHTTPS -eq 'True'
                    $hasHTTP  = $winrmVM.WinRMStatus -match 'Online|Running|OK'
                    $transport = if ($hasHTTPS -and $hasHTTP) { 'HTTP + HTTPS' }
                                 elseif ($hasHTTPS)           { 'HTTPS' }
                                 elseif ($hasHTTP)            { 'HTTP only' }
                                 else                         { 'Not Running' }
                }

                # Risk classifications
                # Risk classifications
                # ADError = machine not in AD (Linux/appliance) -- display as N/A
                $displayDelegationType = switch ($ad.DelegationType) {
                    'ADError' { if ($ad.ADError -match 'Not found|no.*domain') { 'N/A (Non-Domain)' } else { 'N/A (AD Lookup Failed)' } }
                    default   { $ad.DelegationType }
                }

                $authRisk = switch ($ad.DelegationType) {
                    'Unconstrained' { 'Critical' }
                    'KCD'           { 'Warning'  }
                    'RBCD'          { 'OK'       }
                    'None'          { 'OK'       }
                    'ADError'       { 'Info'     }   # Non-domain: Linux/appliance
                    default         { 'Info'     }
                }
                if ($ad.SpnStatus -eq 'Missing' -and $authRisk -eq 'OK') { $authRisk = 'Warning' }

                $winrmRisk = switch ($transport) {
                    'HTTPS'        { 'OK'      }
                    'HTTP + HTTPS' { 'OK'      }
                    'HTTP only'    { 'Warning' }
                    'Not Running'  { 'Info'    }
                    default        { 'Info'    }
                }

                $lapsRisk = switch ($ad.LapsVersion) {
                    'Windows LAPS' { 'OK'      }
                    'Legacy LAPS'  { 'Warning' }
                    'None'         { 'Warning' }
                    default        { 'Info'    }
                }

                $overallRisk = @($authRisk, $winrmRisk, $lapsRisk) |
                    Sort-Object { $severityOrder[$_] } -Descending |
                    Select-Object -First 1

                $machineType = if ($HostData | Where-Object { $_.HostName -like "$($ad.ComputerName)*" }) { 'Host' } else { 'VM' }

                $adAuthDetailList.Add([PSCustomObject]@{
                    Computer         = $ad.ComputerName
                    Type             = $machineType
                    OU               = $ad.OU
                    Enabled          = $ad.Enabled
                    LastLogon        = $ad.LastLogonDate
                    DelegationType   = $displayDelegationType
                    DelegationDetail = $ad.DelegationDetail
                    SpnStatus        = $ad.SpnStatus
                    WsmanSpns        = $ad.WsmanSpns
                    WinRMTransport   = $transport
                    LapsVersion      = $ad.LapsVersion
                    LapsExpiry       = $ad.LapsExpiry
                    DelegationRisk   = $authRisk
                    WinRMRisk        = $winrmRisk
                    LapsRisk         = $lapsRisk
                    OverallRisk      = $overallRisk
                    ADError          = $ad.ADError
                })

                # Issues rows
                if ($ad.DelegationType -eq 'Unconstrained') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Critical'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'Delegation'
                        Finding     = 'Unconstrained Kerberos Delegation enabled'
                        Detail      = $ad.DelegationDetail
                        Remediation = 'Disable TrustedForDelegation. Migrate to RBCD or KCD. See documentation.'
                    })
                }
                elseif ($ad.DelegationType -eq 'KCD') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Warning'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'Delegation'
                        Finding     = 'Traditional KCD configured'
                        Detail      = $ad.DelegationDetail
                        Remediation = 'Review KCD SPN list. Consider migrating to RBCD for lower admin overhead.'
                    })
                }

                if ($ad.SpnStatus -eq 'Missing') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Warning'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'SPN'
                        Finding     = 'WSMAN SPNs missing -- Kerberos auth will fail, NTLM fallback only'
                        Detail      = 'No WSMAN SPNs registered in AD.'
                        Remediation = "setspn -A WSMAN/$($ad.ShortName) $($ad.ShortName) && setspn -A WSMAN/$($ad.ComputerName) $($ad.ShortName)"
                    })
                }
                elseif ($ad.SpnStatus -like 'Partial*') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Info'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'SPN'
                        Finding     = "WSMAN SPNs incomplete ($($ad.SpnStatus))"
                        Detail      = "Registered: $($ad.WsmanSpns)"
                        Remediation = 'Register missing SPN with setspn -A for both short name and FQDN.'
                    })
                }

                if ($transport -eq 'HTTP only') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Warning'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'WinRM-Transport'
                        Finding     = 'WinRM HTTP only -- credentials not encrypted on wire'
                        Detail      = 'No HTTPS listener configured.'
                        Remediation = 'Issue Machine Auth cert from internal CA, enable HTTPS listener via GPO. See documentation.'
                    })
                }

                if ($ad.LapsVersion -eq 'None') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Warning'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'LAPS'
                        Finding     = 'No LAPS detected -- local admin password unmanaged'
                        Detail      = 'Neither ms-Mcs-AdmPwd nor msLAPS-Password found in AD.'
                        Remediation = 'Deploy Windows LAPS via GPO. Requires WS2019+ or KB5025175.'
                    })
                }
                elseif ($ad.LapsVersion -eq 'Legacy LAPS') {
                    $adAuthIssuesList.Add([PSCustomObject]@{
                        Severity    = 'Warning'
                        Computer    = $ad.ComputerName
                        Type        = $machineType
                        Category    = 'LAPS'
                        Finding     = 'Legacy LAPS deployed -- plan migration to Windows LAPS'
                        Detail      = "Expiry: $($ad.LapsExpiry)"
                        Remediation = 'Migrate to Windows LAPS (built-in since WS2019/KB5025175).'
                    })
                }
            }

            # Sort issues: Critical first
            $sortedIssues = @($adAuthIssuesList | Sort-Object { $severityOrder[$_.Severity] } -Descending)
            $adAuthIssuesList.Clear()
            foreach ($row in $sortedIssues) { $adAuthIssuesList.Add($row) }
        }

        # Summary (v3.6.1 - S4-4: enhanced sectioned operational dashboard)
        $totalVMs      = $vmInfo.Count
        $runningVMs    = @($vmInfo | Where-Object Powerstate -eq 'poweredOn').Count
        $offVMs        = $totalVMs - $runningVMs
        $totalClusters = if ($ClusterData) { $ClusterData.Count } else { 0 }
        
        # --- ENVIRONMENT ---
        $summary.Add([PSCustomObject]@{ Section = 'Environment'; Metric = 'Total Hosts';     Value = $HostData.Count })
        $summary.Add([PSCustomObject]@{ Section = 'Environment'; Metric = 'Total Clusters';  Value = $totalClusters })
        $summary.Add([PSCustomObject]@{ Section = 'Environment'; Metric = 'Total VMs';       Value = $totalVMs })
        $summary.Add([PSCustomObject]@{ Section = 'Environment'; Metric = 'Running VMs';     Value = $runningVMs })
        $summary.Add([PSCustomObject]@{ Section = 'Environment'; Metric = 'Powered Off VMs'; Value = $offVMs })
        $unavailCount = if ($UnavailableHosts) { $UnavailableHosts.Count } else { 0 }
        if ($unavailCount -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Environment'; Metric = 'Unreachable Hosts'; Value = $unavailCount }) }
        
        # --- VM HEALTH ---
        $rebootPending = @($vmInfo | Where-Object { $_.RebootPending -eq $true -or $_.RebootPending -eq 'True' }).Count
        if ($rebootPending -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'VM Health'; Metric = 'VMs Pending Reboot'; Value = $rebootPending }) }
        $gen1vms = @($vmInfo | Where-Object { $_.Generation -eq '1' -or $_.Generation -eq 1 }).Count
        if ($gen1vms -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'VM Health'; Metric = 'Gen 1 VMs (BIOS - no Secure Boot)'; Value = $gen1vms }) }
        $activationIssues = @($vmInfo | Where-Object {
            $_.ActivationStatus -and $_.ActivationStatus -ne '' -and
            $_.ActivationStatus -notmatch 'Licensed|Activated' }).Count
        if ($activationIssues -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'VM Health'; Metric = 'VMs with Activation Issues'; Value = $activationIssues }) }
        if ($MissingVMs -and $MissingVMs.Count -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'VM Health'; Metric = 'Missing VMs (in history, not current run)'; Value = $MissingVMs.Count }) }
        
        # --- STORAGE HEALTH ---
        $gsCritical = @($vmGuestStorage | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
        $gsWarning  = @($vmGuestStorage | Where-Object { $_.AlertLevel -eq 'Warning'  }).Count
        if ($gsCritical -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Storage Health'; Metric = "VM Drives: Critical (< $GuestStorageCriticalPct% free)";  Value = $gsCritical }) }
        if ($gsWarning -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Storage Health'; Metric = "VM Drives: Warning (< $GuestStorageWarningPct% free)";  Value = $gsWarning }) }
        # Top 3 most critical guest drives
        $topCritical = @($vmGuestStorage | Where-Object { $_.AlertLevel -eq 'Critical' } |
            Sort-Object PercentFree | Select-Object -First 3)
        foreach ($td in $topCritical) {
            $summary.Add([PSCustomObject]@{
                Section = 'Storage Health'
                Metric  = "  Critical Drive: $($td.VM) $($td.DriveLetter)"
                Value   = "$($td.PercentFree)% free ($($td.FreeGB) GB)"
            })
        }
        
        # --- SECURITY ---
        $sbNeedUpdate    = @($securityCompliance | Where-Object { $_.RowType -eq 'Host' -and $_.SB_UpdateRequired -eq 'Yes (Expiring 2026)' }).Count
        $sbAlreadyUpdated = @($securityCompliance | Where-Object { $_.RowType -eq 'Host' -and $_.SB_UpdateRequired -eq 'No (Already Updated)' }).Count
        if ($sbNeedUpdate -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Security'; Metric = 'Hosts: SB Cert Update Required'; Value = $sbNeedUpdate }) }
        if ($sbAlreadyUpdated -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Security'; Metric = 'Hosts: SB Cert Already Updated'; Value = $sbAlreadyUpdated }) }
        # VMs with unexpected or missing required admins -- count distinct VMs, not member rows (v3.6.1)
        $vmsNeedingAdminReview = @($localAdminsList |
            Where-Object { $_.AlertLevel -eq 'Review' -or $_.AlertLevel -eq 'Missing' } |
            Select-Object -ExpandProperty VM -Unique).Count
        if ($vmsNeedingAdminReview -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Security'; Metric = 'VMs with Admin Review Needed (unexpected or missing members)'; Value = $vmsNeedingAdminReview }) }
        $criticalCompliance = @($ComplianceIssues | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
        if ($criticalCompliance -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Security'; Metric = 'Critical Compliance Issues'; Value = $criticalCompliance }) }
        
        # --- SERVICES HEALTH ---
        $stoppedAuto = @($servicesAlerts | Where-Object { $_.AlertType -eq 'Stopped Auto-Start' }).Count
        if ($stoppedAuto -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Services Health'; Metric = 'Stopped Auto-Start Services'; Value = $stoppedAuto }) }
        $nonStdAccts = @($servicesAlerts | Where-Object { $_.AlertType -eq 'Non-Standard Service Account' }).Count
        if ($nonStdAccts -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Services Health'; Metric = 'Non-Standard Service Accounts'; Value = $nonStdAccts }) }
        if ($scheduledTasksList.Count -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'Services Health'; Metric = 'Scheduled Tasks (non-Microsoft, Enabled/Ready)'; Value = $scheduledTasksList.Count }) }
        
        # --- WINRM HEALTH ---
        $winrmNotRunning = @($winrmHealth | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
        $winrmWarning    = @($winrmHealth | Where-Object { $_.AlertLevel -eq 'Warning'  }).Count
        $winrmCertSoon   = @($winrmHealth | Where-Object {
            $_.WinRM_CertDaysLeft -ne $null -and $_.WinRM_CertDaysLeft -le 30 }).Count
        if ($winrmNotRunning -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'WinRM Health'; Metric = 'VMs: WinRM Not Running'; Value = $winrmNotRunning }) }
        if ($winrmWarning -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'WinRM Health'; Metric = 'VMs: WinRM Warning (HTTP only / no CredSSP)'; Value = $winrmWarning }) }
        if ($winrmCertSoon -gt 0) {
            $summary.Add([PSCustomObject]@{ Section = 'WinRM Health'; Metric = 'VMs: WinRM HTTPS Cert Expiring <= 30 days'; Value = $winrmCertSoon }) }
        
        # --- AD AUTH (v3.6.1 - S5a) ---
        if ($adAuthDetailList.Count -gt 0) {
            $unconstr   = @($adAuthDetailList | Where-Object { $_.DelegationType -eq 'Unconstrained' }).Count
            $kcdCount   = @($adAuthDetailList | Where-Object { $_.DelegationType -eq 'KCD' }).Count
            $spnMissing = @($adAuthDetailList | Where-Object { $_.SpnStatus -eq 'Missing' }).Count
            $noLaps     = @($adAuthDetailList | Where-Object { $_.LapsVersion -eq 'None' }).Count
            $legacyLaps = @($adAuthDetailList | Where-Object { $_.LapsVersion -eq 'Legacy LAPS' }).Count
            $httpOnly   = @($adAuthDetailList | Where-Object { $_.WinRMTransport -eq 'HTTP only' }).Count
            if ($unconstr   -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'AD Auth'; Metric = 'CRITICAL: Unconstrained Kerberos Delegation'; Value = $unconstr }) }
            if ($kcdCount   -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'AD Auth'; Metric = 'Traditional KCD Configured'; Value = $kcdCount }) }
            if ($spnMissing -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'AD Auth'; Metric = 'Machines with Missing WSMAN SPNs'; Value = $spnMissing }) }
            if ($noLaps     -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'AD Auth'; Metric = 'Machines with No LAPS'; Value = $noLaps }) }
            if ($legacyLaps -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'AD Auth'; Metric = 'Machines with Legacy LAPS (migrate)'; Value = $legacyLaps }) }
            if ($httpOnly   -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'AD Auth'; Metric = 'WinRM HTTP only (no HTTPS)'; Value = $httpOnly }) }
        }

        # --- OS DISTRIBUTION (v3.9.6 CR65) ---
        # Build merged OS counts from OS-Inventory + vInfo GuestOS (same logic as exec summary chart)
        $osSumEntries = @{}
        if ($osInventory) {
            $osInvVMs = @{}
            foreach ($oi in $osInventory) {
                $vmk = if ($oi.VM) { $oi.VM.ToString().Trim() } else { '' }
                if ($vmk -and $oi.OSName) {
                    $osInvVMs[$vmk] = $true
                    $osn = $oi.OSName.ToString().Trim()
                    $osSumEntries[$osn] = ($osSumEntries[$osn] -as [int]) + 1
                }
            }
            if ($vmInfo) {
                foreach ($vi in $vmInfo) {
                    $vmk = if ($vi.VM) { $vi.VM.ToString().Trim() } else { '' }
                    if ($vmk -and -not $osInvVMs.ContainsKey($vmk)) {
                        $gos = if ($vi.GuestOS) { $vi.GuestOS.ToString().Trim() } else { '' }
                        if ($gos -and $gos -ne 'Unknown') {
                            $osSumEntries[$gos] = ($osSumEntries[$gos] -as [int]) + 1
                        }
                    }
                }
            }
        }
        foreach ($osKey in ($osSumEntries.GetEnumerator() | Sort-Object Value -Descending)) {
            $summary.Add([PSCustomObject]@{ Section = 'OS Distribution'; Metric = $osKey.Key; Value = $osKey.Value })
        }

        # --- TLS COMPLIANCE (v3.10.0 CR76) ---
        if ($tlsComplianceData -and $tlsComplianceData.Count -gt 0) {
            $tlsSumCompliant = @($tlsComplianceData | Where-Object { $_.OverallStatus -eq 'Compliant' }).Count
            $tlsSumPartial   = @($tlsComplianceData | Where-Object { $_.OverallStatus -eq 'Partial' }).Count
            $tlsSumNonComp   = @($tlsComplianceData | Where-Object { $_.OverallStatus -ne 'Compliant' -and $_.OverallStatus -ne 'Partial' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'TLS Compliance'; Metric = 'Hosts Assessed'; Value = $tlsComplianceData.Count })
            $summary.Add([PSCustomObject]@{ Section = 'TLS Compliance'; Metric = 'Compliant'; Value = $tlsSumCompliant })
            $summary.Add([PSCustomObject]@{ Section = 'TLS Compliance'; Metric = 'Partial'; Value = $tlsSumPartial })
            $summary.Add([PSCustomObject]@{ Section = 'TLS Compliance'; Metric = 'Non-Compliant'; Value = $tlsSumNonComp })
            if ($tlsRecommendations -and $tlsRecommendations.Count -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'TLS Compliance'; Metric = 'Total Remediation Items'; Value = $tlsRecommendations.Count })
            }
        }

        # --- NTLM READINESS (v3.10.0 CR76) ---
        if ($ntlmReadinessData -and $ntlmReadinessData.Count -gt 0) {
            $ntlmSumReady   = @($ntlmReadinessData | Where-Object { $_.ReadinessScore -eq 'Ready' }).Count
            $ntlmSumWork    = @($ntlmReadinessData | Where-Object { $_.ReadinessScore -eq 'Needs-Work' }).Count
            $ntlmSumBlocked = @($ntlmReadinessData | Where-Object { $_.ReadinessScore -eq 'Blocked' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'NTLM Readiness'; Metric = 'Machines Assessed'; Value = $ntlmReadinessData.Count })
            $summary.Add([PSCustomObject]@{ Section = 'NTLM Readiness'; Metric = 'Ready (all critical compliant)'; Value = $ntlmSumReady })
            $summary.Add([PSCustomObject]@{ Section = 'NTLM Readiness'; Metric = 'Needs-Work (1-3 non-critical)'; Value = $ntlmSumWork })
            $summary.Add([PSCustomObject]@{ Section = 'NTLM Readiness'; Metric = 'Blocked (NetBIOS/LLMNR/LmCompat/SMBv1)'; Value = $ntlmSumBlocked })
        }

        # --- CROSS-DOMAIN AUTH (v3.10.0 CR76, v3.10.5 CR84: auth protocol breakdown) ---
        if ($crossDomainAuth -and $crossDomainAuth.Count -gt 0) {
            $cdSumOK   = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'OK' }).Count
            $cdSumWarn = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $cdSumCrit = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $cdSumOff  = @($crossDomainAuth | Where-Object { $_.AlertLevel -match 'Off' }).Count
            $cdSumKrb  = @($crossDomainAuth | Where-Object { $_.AuthProtocol -eq 'Kerberos' }).Count
            $cdSumNeg  = @($crossDomainAuth | Where-Object { $_.AuthProtocol -eq 'Negotiate (NTLM)' }).Count
            $cdSumPsd  = @($crossDomainAuth | Where-Object { $_.AuthProtocol -eq 'PSDirect (VMBus)' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'VMs Assessed'; Value = $crossDomainAuth.Count })
            $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'OK (OS data collected)'; Value = $cdSumOK })
            $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'Warning (domain found, no OS data)'; Value = $cdSumWarn })
            $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'Critical (domain unknown)'; Value = $cdSumCrit })
            $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'Off (powered down)'; Value = $cdSumOff })
            if ($cdSumKrb -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'Authenticated via Kerberos'; Value = $cdSumKrb }) }
            if ($cdSumNeg -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'Authenticated via Negotiate (NTLM)'; Value = $cdSumNeg }) }
            if ($cdSumPsd -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'Cross-Domain Auth'; Metric = 'Authenticated via PSDirect (VMBus)'; Value = $cdSumPsd }) }
        }

        # --- IOPS UTILIZATION (v3.10.0 CR76) ---
        if ($resourceMeteringData -and $resourceMeteringData.IOPSRecommendations) {
            $iopsSumOK = 0; $iopsSumMon = 0; $iopsSumWarn = 0; $iopsSumCrit = 0
            foreach ($rec in $resourceMeteringData.IOPSRecommendations) {
                switch -Wildcard ($rec.Assessment) {
                    'OK*'       { $iopsSumOK++ }
                    'Monitor*'  { $iopsSumMon++ }
                    'Warning*'  { $iopsSumWarn++ }
                    'Critical*' { $iopsSumCrit++ }
                    default     { $iopsSumOK++ }
                }
            }
            $summary.Add([PSCustomObject]@{ Section = 'IOPS Utilization'; Metric = 'Hosts/Clusters Assessed'; Value = $resourceMeteringData.IOPSRecommendations.Count })
            $summary.Add([PSCustomObject]@{ Section = 'IOPS Utilization'; Metric = 'OK (below 60% capacity)'; Value = $iopsSumOK })
            if ($iopsSumMon -gt 0)  { $summary.Add([PSCustomObject]@{ Section = 'IOPS Utilization'; Metric = 'Monitor (60-80% capacity)'; Value = $iopsSumMon }) }
            if ($iopsSumWarn -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'IOPS Utilization'; Metric = 'Warning (80-90% capacity)'; Value = $iopsSumWarn }) }
            if ($iopsSumCrit -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'IOPS Utilization'; Metric = 'CRITICAL (above 90% capacity)'; Value = $iopsSumCrit }) }
        }

        # --- DNS VALIDATION (v3.10.1 CR78) ---
        if ($DNSValidationData -and $DNSValidationData.DNSRows -and $DNSValidationData.DNSRows.Count -gt 0) {
            $dnsRows = $DNSValidationData.DNSRows
            $dnsSumOK   = @($dnsRows | Where-Object { $_.AlertLevel -eq 'OK' }).Count
            $dnsSumWarn = @($dnsRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $dnsSumCrit = @($dnsRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $dnsMismatch = @($dnsRows | Where-Object { $_.NameMismatch -match '^Yes' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'DNS Validation'; Metric = 'Targets Validated'; Value = $dnsRows.Count })
            $summary.Add([PSCustomObject]@{ Section = 'DNS Validation'; Metric = 'OK (forward + reverse match)'; Value = $dnsSumOK })
            if ($dnsSumWarn -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'DNS Validation'; Metric = 'Warning (mismatch or missing PTR)'; Value = $dnsSumWarn }) }
            if ($dnsSumCrit -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'DNS Validation'; Metric = 'CRITICAL (no forward A record)'; Value = $dnsSumCrit }) }
            if ($dnsMismatch -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'DNS Validation'; Metric = 'VM Name Mismatches (display vs guest)'; Value = $dnsMismatch }) }
        }

        # --- RBAC COMPLIANCE (v3.10.1 CR78) ---
        if ($RBACComplianceData -and $RBACComplianceData.RBACCompliance -and @($RBACComplianceData.RBACCompliance).Count -gt 0) {
            $rbacSumRows = @($RBACComplianceData.RBACCompliance)
            $rbacSumComp = @($rbacSumRows | Where-Object { $_.Status -eq 'COMPLIANT' }).Count
            $rbacSumNon  = @($rbacSumRows | Where-Object { $_.Status -eq 'NON-COMPLIANT' }).Count
            $rbacSumWarn = @($rbacSumRows | Where-Object { $_.Status -eq 'WARNING' }).Count
            $rbacSumLnx  = @($rbacSumRows | Where-Object { $_.Status -eq 'LINUX' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'RBAC Compliance'; Metric = 'Total Checks'; Value = $rbacSumRows.Count })
            $summary.Add([PSCustomObject]@{ Section = 'RBAC Compliance'; Metric = 'Compliant'; Value = $rbacSumComp })
            if ($rbacSumNon -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'RBAC Compliance'; Metric = 'Non-Compliant'; Value = $rbacSumNon }) }
            if ($rbacSumWarn -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'RBAC Compliance'; Metric = 'Warning'; Value = $rbacSumWarn }) }
            if ($rbacSumLnx -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'RBAC Compliance'; Metric = 'Linux (needs SSH access)'; Value = $rbacSumLnx }) }
        }

        # --- OFFLINE DISK HEALTH (v3.10.4 CR83) ---
        if ($OfflineDiskData -and @($OfflineDiskData).Count -gt 0) {
            $offRows = @($OfflineDiskData)
            $offVMCount = @($offRows | Select-Object -Property VMName -Unique).Count
            $offTotalDisks = $offRows.Count
            $offTotalSizeGB = [math]::Round(($offRows | Measure-Object -Property SizeGB -Sum).Sum, 1)
            $offSANIssues = @($offRows | Where-Object { $_.SANPolicy -and $_.SANPolicy -ne 'Online All' -and $_.SANPolicy -ne 'OnlineAll' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'Offline Disk Health'; Metric = 'VMs with Offline Disks'; Value = $offVMCount })
            $summary.Add([PSCustomObject]@{ Section = 'Offline Disk Health'; Metric = 'Total Offline Disks'; Value = $offTotalDisks })
            $summary.Add([PSCustomObject]@{ Section = 'Offline Disk Health'; Metric = 'Total Offline Capacity (GB)'; Value = $offTotalSizeGB })
            if ($offSANIssues -gt 0) {
                $summary.Add([PSCustomObject]@{ Section = 'Offline Disk Health'; Metric = 'VMs with Non-OnlineAll SAN Policy'; Value = $offSANIssues })
            }
        }

        # --- SCCM CLIENT STATUS (v3.10.7 CR89) ---
        if ($SCCMData -and @($SCCMData).Count -gt 0) {
            $sccmSumTotal   = if ($SCCMStats -and $SCCMStats.Total)   { $SCCMStats.Total }   else { @($SCCMData).Count }
            $sccmSumActive  = if ($SCCMStats -and $SCCMStats.Active)  { $SCCMStats.Active }  else { @($SCCMData | Where-Object { $_.SCCMActive -eq 'Active' }).Count }
            $sccmSumHealthy = if ($SCCMStats -and $SCCMStats.Healthy) { $SCCMStats.Healthy } else { @($SCCMData | Where-Object { $_.HealthResult -eq 'Healthy' }).Count }
            $sccmSumMissing = if ($SCCMStats -and $SCCMStats.MissingClient) { $SCCMStats.MissingClient } else { @($SCCMData | Where-Object { $_.SCCMActive -eq 'Missing Client' }).Count }
            $sccmSumMatched = if ($SCCMStats -and $SCCMStats.MatchedToHV) { $SCCMStats.MatchedToHV } else { @($SCCMData | Where-Object { $_.HyperVMatch -eq 'Yes' }).Count }
            $sccmSumCrit    = @($SCCMData | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $sccmSumWarn    = @($SCCMData | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Total SCCM Clients'; Value = $sccmSumTotal })
            $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Active Clients'; Value = $sccmSumActive })
            $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Healthy (last eval passed)'; Value = $sccmSumHealthy })
            $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Matched to Hyper-V Inventory'; Value = $sccmSumMatched })
            if ($sccmSumMissing -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Running VMs Missing SCCM Client'; Value = $sccmSumMissing }) }
            if ($sccmSumCrit -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Critical (inactive or stale >90d)'; Value = $sccmSumCrit }) }
            if ($sccmSumWarn -gt 0) { $summary.Add([PSCustomObject]@{ Section = 'SCCM Client Status'; Metric = 'Warning (stale >30d or missing client)'; Value = $sccmSumWarn }) }
        }

        # --- REPORT INFO ---
        $reportVer = if ($ScriptVersion) { $ScriptVersion } else { (Get-Module HyperVInventory-Export | Select-Object -First 1).Version.ToString() }
        $summary.Add([PSCustomObject]@{ Section = 'Report'; Metric = 'Report Version';   Value = $reportVer })
        $summary.Add([PSCustomObject]@{ Section = 'Report'; Metric = 'Report Level';     Value = $ReportLevel })
        $summary.Add([PSCustomObject]@{ Section = 'Report'; Metric = 'Report Generated'; Value = Get-Date -Format 'yyyy-MM-dd HH:mm:ss' })
        
        # ReportLevel tab structure (v3.6.1):
        # Basic:        Summary, vInfo, vHost, vNetwork, Unavailable-Hosts
        # Intermediate: Basic + vDisk, vStorage, Host-Storage-Risk, vDisk-Analysis,
        #               OS-Inventory, vSwitch-Config, vCluster, Applications-Windows,
        #               Security-Compliance, VM-Guest-Storage, Storage-VHD-Detail,
        #               WinRM-Health, Services-Alerts           (NEW S4-3, S4-2)
        # Advanced:     Intermediate + vCPU, vMemory, vCheckpoint, vIntegration, vDVD,
        #               Applications-Linux, CPU-Analysis, Recommendations,
        #               Compliance-Issues, Missing-VMs, Reboot-History, Services,
        #               Local-Admins                            (NEW S4-1)
        #               Services is chunked to bypass Export-Excel 10K row limit.
        
        # Export all worksheets
        # Base export params -- BandedRows gives alternating row colours on every tab,
        # AutoFilter adds column dropdown filters, FreezeTopRow pins the header row.
        $params = @{
            Path         = $OutputPath
            AutoSize     = $true
            FreezeTopRow = $true
            TableStyle   = 'Medium2'
        }
        
        # Helper: chunk-export a large list to multiple numbered worksheet tabs.
        # ImportExcel's Export-Excel processes ~10K rows per call before silently
        # truncating. This function splits any list into $ChunkSize-row sheets.
        # For small lists it writes a single sheet with no suffix.
        function Export-ChunkedSheet {
            param(
                [System.Collections.Generic.List[object]]$Data,
                [hashtable]$ExcelParams,
                [string]$BaseName,
                [int]$ChunkSize = 8000
            )
            if ($Data.Count -eq 0) { return }
            if ($Data.Count -le $ChunkSize) {
                $Data | Export-Excel @ExcelParams -WorksheetName $BaseName
                return
            }
            $totalChunks = [math]::Ceiling($Data.Count / $ChunkSize)
            for ($i = 0; $i -lt $totalChunks; $i++) {
                $start     = $i * $ChunkSize
                $chunkData = $Data | Select-Object -Skip $start -First $ChunkSize
                $tabName   = "${BaseName}_$($i + 1)of$totalChunks"
                $chunkData | Export-Excel @ExcelParams -WorksheetName $tabName
            }
            Write-HVLog "  $BaseName chunked into $totalChunks tabs ($($Data.Count) total rows, $ChunkSize per tab)" -Level Info
        }
        
        # --- BASIC tabs (always included) ---
        # v3.9.6 CR61: Deduplicate vmInfo and osInventory (same VM+Host appearing twice)
        # Root cause: Get-VM can return duplicates for VMs with stale config entries or post-import state
        if ($vmInfo.Count -gt 0) {
            $vmInfoSeen = @{}
            $vmInfoClean = [System.Collections.Generic.List[object]]::new()
            foreach ($vi in $vmInfo) {
                $key = "$($vi.VM)|$($vi.Host)"
                if (-not $vmInfoSeen.ContainsKey($key)) {
                    $vmInfoSeen[$key] = $true
                    $vmInfoClean.Add($vi)
                }
            }
            if ($vmInfoClean.Count -lt $vmInfo.Count) {
                Write-HVLog "  vInfo dedup: removed $($vmInfo.Count - $vmInfoClean.Count) duplicate row(s)" -Level Info
            }
            $vmInfo = $vmInfoClean

            # OPEN-69 (v3.10.12.28): Log timezone match summary and top unmatched /24 prefixes.
            # This tells the operator exactly which subnets to add to SiteTimezones in Config-OHDC.psd1.
            $tzEnabled2 = if ($config -and $config.ContainsKey('IncludeTimezoneAudit')) { $config.IncludeTimezoneAudit } else { $false }
            if ($tzEnabled2) {
                $tzDist = @{}
                foreach ($vi in $vmInfo) {
                    $a = if ($vi.TimezoneAlert) { $vi.TimezoneAlert } else { '(blank)' }
                    $tzDist[$a] = ($tzDist[$a] -as [int]) + 1
                }
                $tzSummary = ($tzDist.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ' | '
                Write-HVLog "  Timezone audit summary: $tzSummary" -Level Info

                # Identify unmatched /24 prefixes to guide SiteTimezones expansion
                $unmatchedPrefixes = @{}
                foreach ($vi in $vmInfo) {
                    if ($vi.TimezoneAlert -like 'Unknown (no subnet match)*' -and $vi.SiteNameMatch -eq '') {
                        # Try to get IP from ExpectedTimezone absence -- check the raw VM data
                        # (We can only infer from the alert type that an IP WAS found but not matched)
                    }
                }
                # Count how many VMs had no IP at all vs had IP but no match
                $noIP     = @($vmInfo | Where-Object { $_.TimezoneAlert -like 'Unknown (no subnet match)*' }).Count
                $noWinRM  = @($vmInfo | Where-Object { $_.TimezoneAlert -like 'N/A (no WinRM)*' }).Count
                $tzOK     = @($vmInfo | Where-Object { $_.TimezoneAlert -like 'OK*' }).Count
                $tzMismatch = @($vmInfo | Where-Object { $_.TimezoneAlert -like 'Mismatch*' }).Count
                if ($noIP -gt 0) {
                    Write-HVLog "  OPEN-69: $noIP VMs had no matching SiteTimezones entry. To fix: review VM IPs on vInfo tab, then add their /24 subnets to SiteTimezones in Config-OHDC.psd1." -Level Info
                }
                if ($tzOK -gt 0 -or $tzMismatch -gt 0) {
                    Write-HVLog "  OPEN-69: Timezone matching active -- $tzOK OK, $tzMismatch Mismatch, $noWinRM no-WinRM" -Level Info
                }
            }
        }
        if ($osInventory -and $osInventory.Count -gt 0) {
            # OPEN-67: When AuditScope = HostsAndVMs or Full, prepend host OS rows to OS-Inventory.
            # Host OS data lives in HostData[*].OSInfo (collected at step 2 via WinRM on each host).
            if ($IncludeVMScope -and $HostData -and $HostData.Count -gt 0) {
                $hostOSAdded = 0
                foreach ($hd in $HostData) {
                    $hName = if ($hd.ComputerName) { $hd.ComputerName } elseif ($hd.HostName) { $hd.HostName } else { continue }
                    $hOSI  = $hd.OSInfo
                    if (-not $hOSI) { continue }
                    $osInventory.Insert(0, [PSCustomObject]@{
                        VM               = $hName      # host name in the VM column for row identification
                        Host             = $hName      # same -- host IS the machine
                        Type             = 'Host'      # OPEN-67
                        DataSource       = 'Hyper-V'   # OPEN-67
                        OSType           = if ($hOSI.OSType) { $hOSI.OSType } else { 'Windows' }
                        OSName           = if ($hOSI.OSName) { $hOSI.OSName } else { $hd.OperatingSystem }
                        OSVersion        = if ($hOSI.OSVersion) { $hOSI.OSVersion } else { '' }
                        OSBuild          = if ($hOSI.OSBuild) { $hOSI.OSBuild } else { '' }
                        Architecture     = if ($hOSI.OSArchitecture) { $hOSI.OSArchitecture } else { '' }
                        InstallDate      = if ($hOSI.InstallDate) { $hOSI.InstallDate } else { '' }
                        LastBootTime     = if ($hOSI.LastBootTime) { $hOSI.LastBootTime } else { '' }
                        ServicePack      = if ($hOSI.ServicePack) { $hOSI.ServicePack } else { '' }
                        LicenseStatus    = if ($hOSI.LicenseStatus) { $hOSI.LicenseStatus } else { '' }
                        Domain           = if ($hOSI.Domain) { $hOSI.Domain } else { '' }
                        KernelVersion    = if ($hOSI.KernelVersion) { $hOSI.KernelVersion } else { '' }
                        LastUpdateKB     = if ($hOSI.LastUpdateKB) { $hOSI.LastUpdateKB } else { 'N/A' }
                        LastUpdateDate   = if ($hOSI.LastUpdateDate) { $hOSI.LastUpdateDate } else { 'N/A' }
                        RebootPending    = if ($null -ne $hOSI.RebootPending) { $hOSI.RebootPending } else { '' }
                        RebootReasons    = if ($hOSI.RebootReasons) { $hOSI.RebootReasons } else { '' }
                        ActivationStatus = if ($hOSI.LicenseStatus) { $hOSI.LicenseStatus } else { '' }
                        ActivationMethod = if ($hOSI.ActivationMethod) { $hOSI.ActivationMethod } else { '' }
                        KMSServer        = if ($hOSI.KMSServer) { $hOSI.KMSServer } else { '' }
                        PartialKey       = if ($hOSI.PartialKey) { $hOSI.PartialKey } else { '' }
                    })
                    $hostOSAdded++
                }
                if ($hostOSAdded -gt 0) {
                    Write-HVLog "  OS-Inventory (OPEN-67): injected $hostOSAdded host rows (AuditScope = $AuditScope)" -Level Info
                }
            }
            $osSeen = @{}
            $osClean = [System.Collections.Generic.List[object]]::new()
            foreach ($oi in $osInventory) {
                $key = "$($oi.VM)|$($oi.Host)"
                if (-not $osSeen.ContainsKey($key)) {
                    $osSeen[$key] = $true
                    $osClean.Add($oi)
                }
            }
            if ($osClean.Count -lt $osInventory.Count) {
                Write-HVLog "  OS-Inventory dedup: removed $($osInventory.Count - $osClean.Count) duplicate row(s)" -Level Info
            }
            $osInventory = $osClean
        }

        # v3.9.7 CR68: Inject DataSource column into all data collections
        # Initially all "HYPER-V". Future modules (Nimble, NetApp, Isilon, SCCM, Forescout) will set their own source.
        $dataSourceValue = 'HYPER-V'
        $dataCollections = @(
            $vmInfo, $hostInfoList, $networkInfo, $diskInfo, $storageInfo,
            $diskAnalysis, $osInventory, $vSwitchConfig, $securityCompliance,
            $vmGuestStorage, $storageVHDDetail, $winrmHealth, $servicesAlerts,
            $rolesFeatures, $cpuInfo, $memoryInfo, $checkpointInfo, $integrationInfo,
            $replicationInfo, $dvdInfo, $applicationsWindows, $applicationsLinux,
            $scheduledTasksList, $localAdminsList, $localBuiltinList,
            $adAuthDetailList, $adAuthIssuesList, $rebootHistory
        )
        foreach ($coll in $dataCollections) {
            if ($coll -and $coll.Count -gt 0) {
                foreach ($obj in $coll) {
                    if ($obj -and -not ($obj.PSObject.Properties.Name -contains 'DataSource')) {
                        $obj | Add-Member -NotePropertyName 'DataSource' -NotePropertyValue $dataSourceValue -Force
                    }
                }
            }
        }
        if ($summary.Count -gt 0) { $summary | Export-Excel @params -WorksheetName "Summary" }
        if ($vmInfo.Count -gt 0) { $vmInfo | Sort-Object State, VM | Export-Excel @params -WorksheetName "vInfo" `
                -ConditionalText @(
                    New-ConditionalText -Text 'Off'      -BackgroundColor '#F5F5F5' -ConditionalTextColor '#999999'
                    New-ConditionalText -Text 'Paused'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'Mismatch' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                ) }
        if ($hostInfoList.Count -gt 0) { $hostInfoList | Sort-Object Host | Export-Excel @params -WorksheetName "vHost" }
        if ($networkInfo.Count -gt 0) { $networkInfo | Sort-Object Host, VMName | Export-Excel @params -WorksheetName "vNetwork" }
        if ($UnavailableHosts -and $UnavailableHosts.Count -gt 0) {
            # v3.10.10.6 CR110: Append filtered AD objects (CNOs, AG listeners, non-HV
            # machines) to the Unavailable-Hosts tab so users can see what was filtered
            # and why. These objects were never probed via WinRM -- they were classified
            # and removed during Step 1 AD discovery. The Reason column explains the
            # classification so nothing is silently hidden.
            $cr110Filtered = Get-CR110FilteredObjects
            if ($cr110Filtered -and $cr110Filtered.Count -gt 0) {
                $cr110Rows = @($cr110Filtered | ForEach-Object {
                    [PSCustomObject]@{
                        HostName       = $_.HostName
                        FQDN           = $_.FQDN
                        OperatingSystem = $_.OperatingSystem
                        LastLogon      = $_.LastLogon
                        Reason         = "CR110 $($_.FilterCategory): $($_.FilterReason)"
                        IsOnline       = 'N/A (not probed)'
                        DataSource     = 'HYPER-V'
                    }
                })
                $UnavailableHosts = @($UnavailableHosts) + $cr110Rows
                Write-HVLog "  Unavailable-Hosts: appended $($cr110Rows.Count) CR110-filtered objects (CNO/AG-Listener/NotHyperV)" -Level Info
            }
            $UnavailableHosts | Sort-Object Host | Export-Excel @params -WorksheetName "Unavailable-Hosts" `
                -ConditionalText @(
                    New-ConditionalText -Text 'Error' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                    New-ConditionalText -Text 'CR110 CNO' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'CR110 AG-Listener' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'CR110 SQL-FCI' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'CR110 NotHyperV' -BackgroundColor '#E0E0E0' -ConditionalTextColor '#404040'
                    New-ConditionalText -Text 'CR110 Excluded' -BackgroundColor '#E0E0E0' -ConditionalTextColor '#404040'
                )
        }
        else {
            # v3.10.10.6 CR110: Even if no hosts failed connectivity, we still need
            # to show the CR110-filtered objects on their own tab
            $cr110Filtered = Get-CR110FilteredObjects
            if ($cr110Filtered -and $cr110Filtered.Count -gt 0) {
                $cr110Rows = @($cr110Filtered | ForEach-Object {
                    [PSCustomObject]@{
                        HostName       = $_.HostName
                        FQDN           = $_.FQDN
                        OperatingSystem = $_.OperatingSystem
                        LastLogon      = $_.LastLogon
                        Reason         = "CR110 $($_.FilterCategory): $($_.FilterReason)"
                        IsOnline       = 'N/A (not probed)'
                        DataSource     = 'HYPER-V'
                    }
                })
                Write-HVLog "  Unavailable-Hosts: $($cr110Rows.Count) CR110-filtered objects (no failed hosts)" -Level Info
                $cr110Rows | Sort-Object HostName | Export-Excel @params -WorksheetName "Unavailable-Hosts" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'CR110 CNO' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'CR110 AG-Listener' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'CR110 SQL-FCI' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'CR110 NotHyperV' -BackgroundColor '#E0E0E0' -ConditionalTextColor '#404040'
                        New-ConditionalText -Text 'CR110 Excluded' -BackgroundColor '#E0E0E0' -ConditionalTextColor '#404040'
                    )
            }
        }
        
        # --- INTERMEDIATE tabs ---
        if ($isIntermediate) {
            if ($diskInfo.Count -gt 0)    { $diskInfo    | Sort-Object Host, VM | Export-Excel @params -WorksheetName "vDisk" }
            if ($storageInfo.Count -gt 0) { $storageInfo | Sort-Object Host, Volume | Export-Excel @params -WorksheetName "vStorage" }
            if ($StorageAnalysis -and $StorageAnalysis.Count -gt 0) {
                $StorageAnalysis | Sort-Object RiskLevel, Host | Export-Excel @params -WorksheetName "Host-Storage-Risk" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'CRITICAL' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'HIGH'     -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'MEDIUM'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'LOW'      -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    ) }
            if ($diskAnalysis.Count -gt 0) { $diskAnalysis | Sort-Object Host, VM |
                Export-Excel @params -WorksheetName "vDisk-Analysis" `
                    -ConditionalText @(
                        # CR107: Stuck backup chain highlighting
                        New-ConditionalText -Text 'True'         -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'   # StuckBackupFlag
                        # CR107 OPEN-25: Vendor color palette -- identical across vCheckpoint, vDisk-Analysis, VHD-Chain
                        New-ConditionalText -Text 'Commvault'    -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                        New-ConditionalText -Text 'Veeam'        -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'AzureBackup'  -BackgroundColor '#FFF3E0' -ConditionalTextColor '#E65100'
                        New-ConditionalText -Text 'DPM'          -BackgroundColor '#F3E5F5' -ConditionalTextColor '#6A1B9A'
                        New-ConditionalText -Text 'Altaro'       -BackgroundColor '#FFF8E1' -ConditionalTextColor '#F57F17'
                        New-ConditionalText -Text 'Nakivo'       -BackgroundColor '#FCE4EC' -ConditionalTextColor '#880E4F'
                        New-ConditionalText -Text 'Zerto'        -BackgroundColor '#E0F7FA' -ConditionalTextColor '#006064'
                        New-ConditionalText -Text 'Unknown-Backup' -BackgroundColor '#F5F5F5' -ConditionalTextColor '#616161'
                    ) }
            if ($osInventory.Count -gt 0)  { $osInventory  | Sort-Object Host, VM | Export-Excel @params -WorksheetName "OS-Inventory" `
                -ConditionalText @(
                    New-ConditionalText -Text 'EOL'       -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text '2008'      -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                    New-ConditionalText -Text '2012'      -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                ) }
            if ($vSwitchConfig.Count -gt 0){ $vSwitchConfig | Sort-Object Host | Export-Excel @params -WorksheetName "vSwitch-Config" }
            if ($ClusterData -and $ClusterData.Count -gt 0) {
                $ClusterData | Sort-Object Host | Export-Excel @params -WorksheetName "vCluster" }
            if ($applicationsWindows.Count -gt 0) {
                $sortedAppsWin = [System.Collections.Generic.List[object]]::new()
                $applicationsWindows | Sort-Object Host, Application | ForEach-Object { $sortedAppsWin.Add($_) }
                Write-HVLog "  Applications-Windows: $($sortedAppsWin.Count) rows (chunk threshold: 8000)" -Level Info
                Export-ChunkedSheet -Data $sortedAppsWin -ExcelParams $params -BaseName 'Applications-Windows'
            }
            if ($securityCompliance.Count -gt 0) {
                $securityCompliance | Sort-Object Severity, Host, VM | Export-Excel @params -WorksheetName "Security-Compliance" `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                ) }
            if ($vmGuestStorage.Count -gt 0) {
                $vmGuestStorage | Sort-Object Host, VM | Export-Excel @params -WorksheetName "VM-Guest-Storage" }
            
            # Storage-VHD-Detail: per-VHD breakdown of Host-Storage-Risk volumes (Intermediate+)
            if ($diskAnalysis.Count -gt 0) {
                $storageVHDDetail = [System.Collections.Generic.List[object]]::new()
                $volCapLookup = @{}
                foreach ($hvHost in $HostData) {
                    if ($hvHost.Error -or -not $hvHost.Storage) { continue }
                    foreach ($vol in $hvHost.Storage) {
                        $volCapLookup["$($hvHost.HostName)|$($vol.Path)"] = $vol
                    }
                }
                $grouped = $diskAnalysis | Sort-Object Host, HostVolume, VM | Group-Object Host, HostVolume
                foreach ($group in $grouped) {
                    $hName        = $group.Group[0].Host
                    $volume       = $group.Group[0].HostVolume
                    $totalCurrent = ($group.Group | Measure-Object -Property CurrentSizeGB -Sum).Sum
                    $totalMax     = ($group.Group | Measure-Object -Property MaxSizeGB     -Sum).Sum
                    $vi           = $volCapLookup["$hName|$volume"]
                    foreach ($vhd in $group.Group) {
                        $storageVHDDetail.Add([PSCustomObject]@{
                            Host                  = $hName
                            Volume                = $volume
                            VolumeType            = if ($vi) { $vi.Type }    else { 'Unknown' }
                            VolumeCapacityGB      = if ($vi) { $vi.TotalGB } else { 0 }
                            VolumeFreeGB          = if ($vi) { $vi.FreeGB }  else { 0 }
                            VM                    = $vhd.VM
                            VHDFile               = $vhd.FileName
                            FullPath              = $vhd.FullPath
                            ResolvedPath          = $vhd.ResolvedPath
                            JunctionSource        = $vhd.JunctionSource
                            DiskType              = $vhd.DiskType
                            CurrentSizeGB         = $vhd.CurrentSizeGB
                            MaxSizeGB             = $vhd.MaxSizeGB
                            GrowthPotentialGB     = $vhd.GrowthPotentialGB
                            PercentUsed           = $vhd.PercentUsed
                            VolumeVHDCurrentTotal = [math]::Round($totalCurrent, 2)
                            VolumeVHDMaxTotal     = [math]::Round($totalMax, 2)
                        })
                    }
                }
                if ($storageVHDDetail.Count -gt 0) {
                    $storageVHDDetail | Export-Excel @params -WorksheetName "Storage-VHD-Detail" }
            }
            
            # S4-3: WinRM-Health - operational view of WinRM status per Windows VM
            if ($winrmHealth.Count -gt 0) {
                $winrmHealth | Sort-Object AlertLevel, VM | Export-Excel @params -WorksheetName "WinRM-Health" }
            
            # S4-2: Services-Alerts - stopped Auto-start and non-standard accounts
            # Sorted by Severity then Server so critical items are at the top
            if ($servicesAlerts.Count -gt 0) {
                $servicesAlerts | Sort-Object AlertType, Server |
                    Export-Excel @params -WorksheetName "Services-Alerts" }
            
            # S4b: Scheduled-Tasks - Enabled/Ready non-Microsoft tasks from all VMs and hosts.
            # Chunked via Export-ChunkedSheet to handle large task counts gracefully.
            # Sorted: hosts first, then VMs; within each type alphabetically by Server.
            if ($scheduledTasksList.Count -gt 0) {
                $sortedTasks = $scheduledTasksList | Sort-Object Type, Server, TaskPath, TaskName
                Export-ChunkedSheet -Data $sortedTasks -ExcelParams $params -BaseName 'Scheduled-Tasks'
            }

            # S5a: Roles-Features - installed Windows features and .NET per VM/host (Intermediate+)
            if ($rolesFeaturesList.Count -gt 0) {
                $rolesFeaturesList | Sort-Object Computer, FeatureType, FeatureName |
                    Export-Excel @params -WorksheetName "Roles-Features"
            }
        }
        
        # --- ADVANCED tabs ---
        if ($isAdvanced) {
            if ($cpuInfo.Count -gt 0)       { $cpuInfo       | Sort-Object Host, VM | Export-Excel @params -WorksheetName "vCPU" }
            if ($memoryInfo.Count -gt 0)    { $memoryInfo     | Sort-Object Host, VM | Export-Excel @params -WorksheetName "vMemory" }
            if ($checkpointInfo.Count -gt 0){ $checkpointInfo | Sort-Object { if($_.Warning -like 'CRITICAL*'){0}elseif($_.Warning -like 'WARNING*'){1}else{2} }, Host, VM | Export-Excel @params -WorksheetName "vCheckpoint" `
                -ConditionalText @(
                    New-ConditionalText -Text 'CRITICAL' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'WARNING'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    # CR107: Per-vendor color correlation (matches vDisk-Analysis vendor colors)
                    New-ConditionalText -Text 'Commvault'   -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                    New-ConditionalText -Text 'Veeam'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    New-ConditionalText -Text 'AzureBackup' -BackgroundColor '#FFF3E0' -ConditionalTextColor '#E65100'
                    New-ConditionalText -Text 'DPM'         -BackgroundColor '#F3E5F5' -ConditionalTextColor '#6A1B9A'
                    New-ConditionalText -Text 'Altaro'      -BackgroundColor '#FFF8E1' -ConditionalTextColor '#F57F17'
                    New-ConditionalText -Text 'Nakivo'      -BackgroundColor '#FCE4EC' -ConditionalTextColor '#880E4F'
                    New-ConditionalText -Text 'Zerto'       -BackgroundColor '#E0F7FA' -ConditionalTextColor '#006064'
                    New-ConditionalText -Text 'Unknown-Backup' -BackgroundColor '#F5F5F5' -ConditionalTextColor '#616161'
                ) }

            # ---- v3.10.12 CR105: VHD-Chain tab (Advanced) ----
            # Full parent chain per disk per VM: Active/Checkpoint/Base hierarchy,
            # per-link sizes, stale checkpoint detection, consolidation recommendations.
            # Also cross-references with CR106 to stamp RemediationScriptPath column.
            if ($VHDChainData -and @($VHDChainData).Count -gt 0) {
                # Build a remediation path lookup keyed on VMName
                $remPathByVM = @{}
                if ($VHDChainRemediationResults -and @($VHDChainRemediationResults).Count -gt 0) {
                    foreach ($r in $VHDChainRemediationResults) {
                        if ($r.GeneratedOK -and $r.VMName) {
                            $remPathByVM[$r.VMName] = $r.RelativePath
                        }
                    }
                }

                # CR107 OPEN-25: Build BackupVendor lookup from checkpoint data for cross-tab correlation
                $backupVendorByVM = @{}
                if ($checkpointInfo -and $checkpointInfo.Count -gt 0) {
                    foreach ($cp in $checkpointInfo) {
                        $vmKey = if ($cp.VM) { $cp.VM } elseif ($cp.VMName) { $cp.VMName } else { $null }
                        if ($vmKey -and $cp.BackupVendor -and $cp.BackupVendor -ne 'Manual' -and $cp.BackupVendor -ne 'None') {
                            $backupVendorByVM[$vmKey] = $cp.BackupVendor
                        }
                    }
                }

                $vhdChainRows = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($row in $VHDChainData) {
                    $remPath = if ($row.ChainLevel -eq 0 -and $remPathByVM.ContainsKey($row.VMName)) {
                        $remPathByVM[$row.VMName]
                    } else { '' }

                    # CR107: Inherit BackupVendor from checkpoint correlation
                    $bkVendor = if ($backupVendorByVM.ContainsKey($row.VMName)) { $backupVendorByVM[$row.VMName] } else { '' }

                    $vhdChainRows.Add([PSCustomObject]@{
                        VMName               = $row.VMName
                        Host                 = $row.Host
                        ClusterName          = $row.ClusterName
                        ControllerType       = $row.ControllerType
                        ControllerNum        = $row.ControllerNum
                        ControllerLoc        = $row.ControllerLoc
                        ChainLevel           = $row.ChainLevel
                        LinkType             = $row.LinkType
                        FilePath             = $row.FilePath
                        FileSizeMB           = $row.FileSizeMB
                        FileFormat           = $row.FileFormat
                        ParentPath           = $row.ParentPath
                        CreatedOn            = $row.CreatedOn
                        IsBaseDisk           = $row.IsBaseDisk
                        ChainDepth           = $row.ChainDepth
                        ChainTotalMB         = $row.ChainTotalMB
                        AlertLevel           = $row.AlertLevel
                        Recommendation       = $row.Recommendation
                        BackupVendor         = $bkVendor
                        RemediationScriptPath = $remPath
                        Error                = $row.Error
                        DataSource           = $row.DataSource
                    })
                }

                $vhdCritCount  = @($vhdChainRows | Where-Object { $_.ChainLevel -eq 0 -and $_.AlertLevel -eq 'Critical' }).Count
                $vhdWarnCount  = @($vhdChainRows | Where-Object { $_.ChainLevel -eq 0 -and $_.AlertLevel -eq 'Warning'  }).Count
                $vhdBroken     = @($vhdChainRows | Where-Object { $_.LinkType -eq 'BrokenParent' }).Count

                $vhdChainRows | Sort-Object AlertLevel, Host, VMName, ControllerNum, ControllerLoc, ChainLevel |
                    Export-Excel @params -WorksheetName "VHD-Chain" `
                        -Title "VHD Parent Chain Inventory -- Full Chain per Disk per VM (CR105)" `
                        -ConditionalText @(
                            # Alert level colors
                            New-ConditionalText -Text 'Critical'      -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'Warning'       -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'BrokenParent'  -BackgroundColor '#FF0000' -ConditionalTextColor '#FFFFFF'
                            # CR107 OPEN-25: LinkType colors -- chosen to NOT clash with vendor colors below
                            New-ConditionalText -Text 'Active'        -BackgroundColor '#C8E6C9' -ConditionalTextColor '#1B5E20'
                            New-ConditionalText -Text 'Base'          -BackgroundColor '#BBDEFB' -ConditionalTextColor '#0D47A1'
                            New-ConditionalText -Text 'Checkpoint'    -BackgroundColor '#FFE082' -ConditionalTextColor '#5D4037'
                            New-ConditionalText -Text 'Passthrough'   -BackgroundColor '#E0E0E0' -ConditionalTextColor '#424242'
                            New-ConditionalText -Text 'Error'         -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            # CR107 OPEN-25: BackupVendor column -- identical palette to vCheckpoint + vDisk-Analysis
                            New-ConditionalText -Text 'Commvault'     -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                            New-ConditionalText -Text 'Veeam'         -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                            New-ConditionalText -Text 'AzureBackup'   -BackgroundColor '#FFF3E0' -ConditionalTextColor '#E65100'
                            New-ConditionalText -Text 'DPM'           -BackgroundColor '#F3E5F5' -ConditionalTextColor '#6A1B9A'
                            New-ConditionalText -Text 'Altaro'        -BackgroundColor '#FFF8E1' -ConditionalTextColor '#F57F17'
                            New-ConditionalText -Text 'Nakivo'        -BackgroundColor '#FCE4EC' -ConditionalTextColor '#880E4F'
                            New-ConditionalText -Text 'Zerto'         -BackgroundColor '#E0F7FA' -ConditionalTextColor '#006064'
                            New-ConditionalText -Text 'Unknown-Backup' -BackgroundColor '#F5F5F5' -ConditionalTextColor '#616161'
                        )
                Write-HVLog "  VHD-Chain: $($vhdChainRows.Count) links -- $vhdCritCount Critical VMs, $vhdWarnCount Warning VMs$(if($vhdBroken){', ' + $vhdBroken + ' broken chain(s)'})" -Level Info
            }
            elseif ($isAdvanced) {
                Write-HVLog "  VHD-Chain: skipped (no data -- VHDChain module may not be loaded)" -Level Info
            }
            if ($integrationInfo.Count -gt 0) {
                $integrationInfo | Sort-Object Host, VM, Service | Export-Excel @params -WorksheetName "vIntegration" `
                    -ConditionalText @(New-ConditionalText -Text 'False' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404')
            }
            if ($replicationInfo.Count -gt 0){ $replicationInfo | Sort-Object Host, VM | Export-Excel @params -WorksheetName "vReplication" }
            if ($dvdInfo.Count -gt 0)       { $dvdInfo        | Sort-Object Host, VM | Export-Excel @params -WorksheetName "vDVD" }
            if ($applicationsLinux.Count -gt 0) {
                $applicationsLinux | Sort-Object Server, PackageName | Export-Excel @params -WorksheetName "Applications-Linux" }
            if ($CPUAnalysis -and $CPUAnalysis.Count -gt 0) {
                $CPUAnalysis | Sort-Object Host | Export-Excel @params -WorksheetName "CPU-Analysis" `
                -ConditionalText @(New-ConditionalText -Text 'OverCommitted' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000') }
            if ($Recommendations -and $Recommendations.Count -gt 0) {
                $Recommendations | Sort-Object Priority, Category, Host | Export-Excel @params -WorksheetName "Recommendations" `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'High'     -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                    New-ConditionalText -Text 'Medium'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                ) }
            if ($ComplianceIssues -and $ComplianceIssues.Count -gt 0) {
                $ComplianceIssues | Sort-Object Severity, Category, VM | Export-Excel @params -WorksheetName "Compliance-Issues" `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                ) }
            if ($MissingVMs -and $MissingVMs.Count -gt 0) {
                $MissingVMs | Sort-Object VM | Export-Excel @params -WorksheetName "Missing-VMs" `
                -ConditionalText @(New-ConditionalText -Text 'Missing' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000') }
            if ($rebootHistory.Count -gt 0) {
                $rebootHistory | Sort-Object Server | Export-Excel @params -WorksheetName "Reboot-History" }
            
            # S4-2: Services tab - Auto-start only by default (filtered at collection).
            # Chunked into 8K-row sheets to bypass Import-Excel's ~10K row export limit.
            # With Auto-only filtering: ~3,200 rows = single tab. If Manual is added
            # to CollectStartModes the chunker handles expansion automatically.
            Export-ChunkedSheet -Data $servicesList -ExcelParams $params -BaseName 'Services'
            
            # S4-1: Local-Admins - Administrators group membership (kept for backward compat)
            # with authorization status against RequiredBuiltinMembers config
            if ($localAdminsList.Count -gt 0) {
                $localAdminsList | Sort-Object AlertLevel, VM |
                    Export-Excel @params -WorksheetName "Local-Admins" }

            # S4-1b: Local-Builtin - ALL Windows built-in group membership (v3.8.0 - CR5)
            # Replaces/supersedes Local-Admins with full group coverage.
            # GroupName column identifies which built-in group each row belongs to.
            if ($localBuiltinList.Count -gt 0) {
                $localBuiltinList | Sort-Object GroupName, AlertLevel, VM |
                    Export-Excel @params -WorksheetName "Local-Builtin" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'Missing'    -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'Review'     -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Unexpected' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        )
                Write-HVLog "  Local-Builtin: $($localBuiltinList.Count) rows across all built-in groups" -Level Info
            }

            # S5b: AD-Auth-Detail - per-machine Kerberos delegation, SPN, LAPS, WinRM transport (Advanced)
            if ($adAuthDetailList.Count -gt 0) {
                $adAuthDetailList | Sort-Object OverallRisk, Computer |
                    Export-Excel @params -WorksheetName "AD-Auth-Detail"
                Write-HVLog "  AD-Auth-Detail: $($adAuthDetailList.Count) rows" -Level Info
            }

            # S5b: AD-Auth-Issues - rolled-up Critical/Warning/Info auth findings (Advanced)
            if ($adAuthIssuesList.Count -gt 0) {
                $adAuthIssuesList | Sort-Object Severity, Category, Computer | Export-Excel @params -WorksheetName "AD-Auth-Issues" `
                -ConditionalText @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                )
                Write-HVLog "  AD-Auth-Issues: $($adAuthIssuesList.Count) findings" -Level Info
            }

            # S5b: Remediation-Commands - index tab pointing to the generated .ps1 alongside this xlsx
            # Keeps the report clean -- full commands are in the script, not repeated here.
            $remediationIndex = [System.Collections.Generic.List[PSObject]]::new()

            # Script reference header row
            $scriptFileName = if ($RemediationScriptPath) { [System.IO.Path]::GetFileName($RemediationScriptPath) } else { 'Not generated' }
            $remediationIndex.Add([PSCustomObject]@{
                Category    = 'Script Reference'
                Computer    = ''
                Severity    = ''
                Finding     = "Remediation script: $scriptFileName"
                QuickCommand = "Run with -WhatIf first: .\$scriptFileName -WhatIf"
                Notes        = 'Generated alongside this xlsx. Covers Delegation, SPN, WinRM HTTPS, LAPS.'
            })
            $remediationIndex.Add([PSCustomObject]@{
                Category    = 'Script Reference'
                Computer    = ''; Severity = ''
                Finding     = 'Filter by machine:  .\' + $scriptFileName + ' -ComputerName MYSERVER -WhatIf'
                QuickCommand = ''
                Notes        = ''
            })
            $remediationIndex.Add([PSCustomObject]@{
                Category    = 'Script Reference'
                Computer    = ''; Severity = ''
                Finding     = 'Filter by category: .\' + $scriptFileName + ' -Category WinRM -WhatIf'
                QuickCommand = ''
                Notes        = 'Categories: Delegation | SPN | WinRM | LAPS'
            })
            $remediationIndex.Add([PSCustomObject]@{
                Category    = '---'; Computer = ''; Severity = ''; Finding = ''; QuickCommand = ''; Notes = ''
            })

            # Issue summary rows
            if ($RemediationIssues) {
                $issueList = @($RemediationIssues)
                $catOrder  = @{ 'Delegation' = 1; 'SPN' = 2; 'WinRM-Transport' = 3; 'LAPS' = 4 }
                $sevOrder  = @{ 'Critical' = 4; 'Warning' = 3; 'Info' = 1 }
                $sorted    = $issueList | Sort-Object {
                    $co = $catOrder[$_.Category]; if ($null -eq $co) { 9 } else { $co }
                }, { $sevOrder[$_.Severity] } -Descending

                foreach ($iss in $sorted) {
                    $remediationIndex.Add([PSCustomObject]@{
                        Category     = $iss.Category
                        Computer     = $iss.Computer
                        Severity     = $iss.Severity
                        Finding      = $iss.Finding
                        QuickCommand = ".\$scriptFileName -ComputerName $($iss.Computer) -Category $($iss.Category -replace '-Transport','')"
                        Notes        = if ($iss.Detail) { $iss.Detail } else { '' }
                    })
                }
            }

            if ($remediationIndex.Count -gt 0) {
                $remediationIndex | Export-Excel @params -WorksheetName "Remediation-Commands" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    )
                Write-HVLog "  Remediation-Commands: $($remediationIndex.Count) rows (script: $scriptFileName)" -Level Info
            }

            # S5c: SPN-Inventory tab -- all registered SPNs categorized with gap/duplicate flags
            if ($SPNAuditResults -and @($SPNAuditResults).Count -gt 0) {
                $spnRows = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($row in $SPNAuditResults) {
                    $alertColor = switch ($row.AlertLevel) {
                        'Warning' { 'Warning' }
                        'OK'      { 'Good' }
                        default   { '' }
                    }
                    $spnRows.Add([PSCustomObject]@{
                        Computer      = $row.Computer
                        SPN           = $row.SPN
                        ServiceClass  = $row.ServiceClass
                        Instance      = $row.Instance
                        RoleHint      = $row.RoleHint
                        Status        = $row.Status
                        AlertLevel    = $row.AlertLevel
                        DuplicateOn   = $row.DuplicateOn
                        Notes         = $row.Notes
                    })
                }

                $spnOK        = @($spnRows | Where-Object { $_.Status -eq 'OK'           }).Count
                $spnMissing   = @($spnRows | Where-Object { $_.Status -like 'Missing*'   }).Count
                $spnDuplicate = @($spnRows | Where-Object { $_.Status -eq 'Duplicate'    }).Count

                $spnRows | Sort-Object AlertLevel, Computer, ServiceClass |
                    Export-Excel @params -WorksheetName "SPN-Inventory" `
                        -Title "SPN Inventory -- All Service Principal Names" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'Duplicate'         -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'Missing'           -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Missing-RoleBased' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        )
                Write-HVLog "  SPN-Inventory: $($spnRows.Count) entries ($spnMissing missing, $spnDuplicate duplicate, $spnOK OK)" -Level Info
            }

            # S5c: DoubleHop-Map tab -- domain-account services/tasks/IIS pools with delegation assessment
            if ($DoublehopResults -and @($DoublehopResults).Count -gt 0) {
                $hopRows = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($row in $DoublehopResults) {
                    $hopRows.Add([PSCustomObject]@{
                        Computer         = $row.Computer
                        Host             = $row.Host
                        Type             = $row.Type
                        Source           = $row.Source
                        ServiceName      = $row.Name
                        DisplayName      = $row.DisplayName
                        RunAs            = $row.RunAs
                        DelegationType   = $row.DelegationType
                        DelegationDetail = $row.DelegationDetail
                        DelegationGap    = if ($row.DelegationGap) { 'Yes' } else { 'No' }
                        NTLMRisk         = $row.NTLMRisk
                        GapDetail        = $row.GapDetail
                        Remediation      = $row.Remediation
                    })
                }

                $hopHigh   = @($hopRows | Where-Object { $_.NTLMRisk -eq 'High'   }).Count
                $hopReview = @($hopRows | Where-Object { $_.NTLMRisk -eq 'Review' }).Count
                $hopIIS    = @($hopRows | Where-Object { $_.Source   -eq 'IIS-AppPool' }).Count

                $hopRows | Sort-Object NTLMRisk, Computer, Source |
                    Export-Excel @params -WorksheetName "DoubleHop-Map" `
                        -Title "Kerberos Double-Hop Map -- Domain Account Services" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'High'   -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'Review' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Yes'    -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        )
                Write-HVLog "  DoubleHop-Map: $($hopRows.Count) domain-account entries ($hopHigh high-risk, $hopReview review, $hopIIS IIS pools)" -Level Info
            }

            # S5c: NTLM-Elimination tab -- per-machine risk score + inline setspn/Set-ADComputer commands
            if ($NTLMRiskResults -and @($NTLMRiskResults).Count -gt 0) {
                $ntlmRows = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($row in $NTLMRiskResults) {
                    $ntlmRows.Add([PSCustomObject]@{
                        Priority           = $row.PriorityOrder
                        Computer           = $row.Computer
                        FQDN               = $row.FQDN
                        OU                 = $row.OU
                        NTLMRisk           = $row.NTLMRisk
                        DelegationType     = $row.DelegationType
                        TotalSPNs          = $row.TotalSPNs
                        MissingSPNs        = $row.MissingSPNs
                        DuplicateSPNs      = $row.DuplicateSPNs
                        DomainAcctServices = $row.DomainAcctServices
                        HighRiskHops       = $row.HighRiskHops
                        IISAppPools        = $row.IISAppPools
                        Factors            = $row.Factors
                        RemediationCmds    = $row.RemediationCmds
                        VerifyCmd          = $row.VerifyCmd
                    })
                }

                $ntlmCritical = @($ntlmRows | Where-Object { $_.NTLMRisk -eq 'Critical' }).Count
                $ntlmHigh     = @($ntlmRows | Where-Object { $_.NTLMRisk -eq 'High'     }).Count
                $ntlmMedium   = @($ntlmRows | Where-Object { $_.NTLMRisk -eq 'Medium'   }).Count
                $ntlmOK       = @($ntlmRows | Where-Object { $_.NTLMRisk -eq 'OK'       }).Count

                $ntlmRows | Sort-Object Priority, Computer |
                    Export-Excel @params -WorksheetName "NTLM-Elimination" `
                        -Title "NTLM Elimination Plan -- Per-Machine Kerberos Risk Assessment" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'High'     -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Medium'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        )
                Write-HVLog "  NTLM-Elimination: $($ntlmRows.Count) machines -- $ntlmCritical Critical, $ntlmHigh High, $ntlmMedium Medium, $ntlmOK OK" -Level Info
            }

            # S6: Live-Migration tab -- per-host live migration config, auth type, performance, network assessment
            if ($LiveMigData -and @($LiveMigData).Count -gt 0) {
                $params.TableStyle = 'Medium6'
                @($LiveMigData) | Sort-Object Host |
                    Export-Excel @params -WorksheetName "Live-Migration" `
                        -Title "Live Migration Configuration -- Per-Host Validation" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'CredSSP'   -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'Warning'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Review'    -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'ERROR'     -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        )
                $lmEnabled = @($LiveMigData | Where-Object { $_.LiveMigEnabled }).Count
                $lmCredSSP = @($LiveMigData | Where-Object { $_.AuthType -eq 'CredSSP' }).Count
                Write-HVLog "  Live-Migration: $(@($LiveMigData).Count) hosts -- $lmEnabled enabled, $lmCredSSP CredSSP" -Level Info
                $params.TableStyle = 'Medium2'
            }

            # S6: Host-NIC-Audit tab -- all physical/virtual NICs with gateway and DNS violation assessment
            if ($NICauditData -and @($NICauditData).Count -gt 0) {
                $nicViolations = @($NICauditData | Where-Object { $_.GatewayAssessment -like 'VIOLATION*' }).Count
                $params.TableStyle = 'Medium6'
                @($NICauditData) | Sort-Object Host, InferredRole, InterfaceAlias |
                    Export-Excel @params -WorksheetName "Host-NIC-Audit" `
                        -Title "Host NIC Audit -- Gateway, DNS, and VLAN Assessment" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'VIOLATION' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'Yes'       -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Management' -BackgroundColor '#E8F4FD' -ConditionalTextColor '#1565C0'
                        )
                Write-HVLog "  Host-NIC-Audit: $(@($NICauditData).Count) NIC entries -- $nicViolations gateway violation(s)" -Level Info
                $params.TableStyle = 'Medium2'
            }

            # S6: DC-GUID-Validation tab -- DC DSA GUID retrieval and _msdcs CNAME ping validation
            if ($DCGuidData -and @($DCGuidData).Count -gt 0) {
                $dcFail = @($DCGuidData | Where-Object { $_.CNAMEStatus -like 'FAIL*' }).Count
                $dcWarn = @($DCGuidData | Where-Object { $_.CNAMEStatus -like 'WARNING*' }).Count
                $params.TableStyle = 'Medium6'
                @($DCGuidData) | Sort-Object Domain, DCName |
                    Export-Excel @params -WorksheetName "DC-GUID-Validation" `
                        -Title "Domain Controller DSA GUID and _msdcs CNAME Validation" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'FAIL'    -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'WARNING' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'OK'      -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        )
                Write-HVLog "  DC-GUID-Validation: $(@($DCGuidData).Count) DCs -- $dcFail failures, $dcWarn warnings" -Level Info
                $params.TableStyle = 'Medium2'
            }
        }

        # S7: VHD-Drive-Map tab -- VHD file to guest drive letter correlation (Intermediate+)
        # Available at Intermediate and Advanced levels to give storage owners actionable disk mapping
        if ($VHDDriveMap -and @($VHDDriveMap).Count -gt 0 -and ($isIntermediate -or $isAdvanced)) {
            $vhdRows       = @($VHDDriveMap)
            $vhdResolved   = @($vhdRows | Where-Object { $_.CorrelationMethod -in 'SCSI-LUN','IDE-Slot','SerialNumber','SizeMatch' }).Count
            $vhdUnresolved = @($vhdRows | Where-Object { $_.CorrelationMethod -eq 'Unresolved' }).Count
            $vhdNoWinRM    = @($vhdRows | Where-Object { $_.CorrelationMethod -eq 'WinRM-Unavailable' }).Count
            $vhdLowFree    = @($vhdRows | Where-Object { $_.GuestPctFree -gt 0 -and $_.GuestPctFree -lt 10 }).Count

            $params.TableStyle = 'Medium9'
            $vhdRows | Sort-Object { if($_.IsSnapshot){0}else{1} }, Host, VMName, ControllerSlot |
                Export-Excel @params -WorksheetName "VHD-Drive-Map" `
                    -Title "VHD to Guest Drive Letter Correlation Map" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'CRITICAL'          -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'WARNING'           -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Unresolved'        -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'WinRM-Unavailable' -BackgroundColor '#F5F5F5' -ConditionalTextColor '#666666'
                        New-ConditionalText -Text 'SCSI-LUN'          -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'SizeMatch'         -BackgroundColor '#FFF8E1' -ConditionalTextColor '#F57F17'
                    )
            Write-HVLog "  VHD-Drive-Map: $(@($vhdRows).Count) rows -- $vhdResolved correlated, $vhdUnresolved unresolved, $vhdNoWinRM WinRM-unavailable, $vhdLowFree low-disk (<10% free)" -Level Info
            if ($vhdLowFree -gt 0) {
                Write-HVLog "  [WARNING] $vhdLowFree VHD(s) backing drives with <10% free space -- expand VHD or clean up guest" -Level Warning
            }
            $params.TableStyle = 'Medium2'
        }

        # S8b: S2D-Storage-Audit -- Storage Spaces Direct health and capacity audit (Advanced)
        # Covers MHOHCLUHV cluster and any other S2D-enabled clusters in the environment.
        if ($S2DAuditData -and $S2DAuditData.S2DRows -and @($S2DAuditData.S2DRows).Count -gt 0) {
            $s2dAllRows = @($S2DAuditData.S2DRows)
            $s2dCritical = @($s2dAllRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $s2dWarning  = @($s2dAllRows | Where-Object { $_.AlertLevel -eq 'Warning'  }).Count
            $params.TableStyle = 'Medium9'
            $s2dAllRows | Sort-Object Cluster, Section, Name |
                Export-Excel @params -WorksheetName "S2D-Storage-Audit" `
                    -Title "Storage Spaces Direct - Comprehensive Health Audit" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical'  -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Unhealthy' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'Degraded'  -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'OK'        -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    )
            Write-HVLog "  S2D-Storage-Audit: $($s2dAllRows.Count) rows -- $s2dCritical critical, $s2dWarning warnings" -Level Info
            $params.TableStyle = 'Medium2'
        }
        if ($S2DAuditData -and $S2DAuditData.S2DSummaryRows -and @($S2DAuditData.S2DSummaryRows).Count -gt 0) {
            @($S2DAuditData.S2DSummaryRows) | Sort-Object Cluster, Section, Item |
                Export-Excel @params -WorksheetName "S2D-Config-Summary"
            Write-HVLog "  S2D-Config-Summary: $(@($S2DAuditData.S2DSummaryRows).Count) rows" -Level Info
        }

        # S8d: VM Resource Metering + IOPS tabs (v3.8.7)
        # Four tabs: VM-IOPS-Summary, VM-IOPS-PerDisk, Host-IOPS-Summary, IOPS-Recommendations
        if ($ResourceMeteringData -and $ResourceMeteringData.Count -gt 0) {

            # VM-IOPS-Summary -- one row per VM with metering data
            if ($ResourceMeteringData.VMIOPSSummary -and @($ResourceMeteringData.VMIOPSSummary).Count -gt 0) {
                $iopsVMRows = @($ResourceMeteringData.VMIOPSSummary)
                $iopsMeteringOn  = @($iopsVMRows | Where-Object { $_.MeteringEnabled -eq $true }).Count
                $iopsMeteringOff = @($iopsVMRows | Where-Object { $_.MeteringEnabled -ne $true }).Count
                $params.TableStyle = 'Medium9'
                $iopsVMRows | Sort-Object NormalizedIOPS -Descending |
                    Export-Excel @params -WorksheetName "VM-IOPS-Summary" `
                        -Title "VM Resource Metering -- IOPS and Performance Summary" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'False' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        )
                Write-HVLog "  VM-IOPS-Summary: $($iopsVMRows.Count) VMs -- $iopsMeteringOn metered, $iopsMeteringOff not metered" -Level Info
                $params.TableStyle = 'Medium2'
            }

            # VM-IOPS-PerDisk -- one row per VHD with per-disk IOPS
            if ($ResourceMeteringData.VMIOPSPerDisk -and @($ResourceMeteringData.VMIOPSPerDisk).Count -gt 0) {
                $iopsDiskRows = @($ResourceMeteringData.VMIOPSPerDisk)
                $params.TableStyle = 'Medium9'
                $iopsDiskRows | Sort-Object NormalizedIOPS -Descending |
                    Export-Excel @params -WorksheetName "VM-IOPS-PerDisk" `
                        -Title "VM Resource Metering -- Per-VHD IOPS Detail"
                Write-HVLog "  VM-IOPS-PerDisk: $($iopsDiskRows.Count) VHD entries" -Level Info
                $params.TableStyle = 'Medium2'
            }

            # Host-IOPS-Summary -- one row per host with aggregate IOPS and disk detection
            if ($ResourceMeteringData.HostIOPSSummary -and @($ResourceMeteringData.HostIOPSSummary).Count -gt 0) {
                $iopsHostRows = @($ResourceMeteringData.HostIOPSSummary)
                $params.TableStyle = 'Medium6'
                $iopsHostRows | Sort-Object TotalNormalizedIOPS -Descending |
                    Export-Excel @params -WorksheetName "Host-IOPS-Summary" `
                        -Title "Host Storage IOPS Summary -- Aggregate VM Load and Physical Disk Detection"
                Write-HVLog "  Host-IOPS-Summary: $($iopsHostRows.Count) hosts" -Level Info
                $params.TableStyle = 'Medium2'
            }

            # IOPS-Recommendations -- per host/cluster capacity recommendations
            if ($ResourceMeteringData.IOPSRecommendations -and @($ResourceMeteringData.IOPSRecommendations).Count -gt 0) {
                $iopsRecoRows = @($ResourceMeteringData.IOPSRecommendations)
                $iopsCritical = @($iopsRecoRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
                $iopsWarning  = @($iopsRecoRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
                $params.TableStyle = 'Medium6'
                $iopsRecoRows | Sort-Object AlertLevel, UtilizationPct -Descending |
                    Export-Excel @params -WorksheetName "IOPS-Recommendations" `
                        -Title "IOPS Capacity Recommendations -- Storage Utilization Analysis" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Monitor'  -BackgroundColor '#E8F4FD' -ConditionalTextColor '#1565C0'
                            New-ConditionalText -Text 'OK'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        )
                Write-HVLog "  IOPS-Recommendations: $($iopsRecoRows.Count) targets -- $iopsCritical critical, $iopsWarning warnings" -Level Info
                $params.TableStyle = 'Medium2'
            }
        }

        # ── IOPS-Trends and IOPS-Heatmap (v3.8.9.2 Session 8d-2) ──
        if ($IOPSCollectorData -and $IOPSCollectorData.Count -gt 0) {
            # IOPS-Trends tab: daily per-host peak/avg/p95
            if ($IOPSCollectorData.IOPSTrends -and @($IOPSCollectorData.IOPSTrends).Count -gt 0) {
                $trendRows = @($IOPSCollectorData.IOPSTrends)
                $params.TableStyle = 'None'
                $trendRows | Sort-Object Host, Date |
                    Export-Excel @params -WorksheetName "IOPS-Trends" `
                        -Title "IOPS Trend Analysis -- Daily Peak/Avg/P95 from Standalone Collector" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        )
                Write-HVLog "  IOPS-Trends: $($trendRows.Count) daily rows across $($IOPSCollectorData.CollectorMeta.HostsFound) hosts" -Level Info
                $params.TableStyle = 'Medium2'
            }

            # IOPS-Heatmap tab: hourly demand curve per host
            if ($IOPSCollectorData.IOPSHeatmap -and @($IOPSCollectorData.IOPSHeatmap).Count -gt 0) {
                $heatmapRows = @($IOPSCollectorData.IOPSHeatmap)
                $params.TableStyle = 'None'
                $heatmapRows | Sort-Object Host, HourNum |
                    Export-Excel @params -WorksheetName "IOPS-Heatmap" `
                        -Title "IOPS Heatmap -- Hour-of-Day Demand Curve per Host" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'High'   -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'Medium' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'Low'    -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                            New-ConditionalText -Text 'Idle'   -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        )
                Write-HVLog "  IOPS-Heatmap: $($heatmapRows.Count) hourly rows across $($IOPSCollectorData.CollectorMeta.HostsFound) hosts" -Level Info
                $params.TableStyle = 'Medium2'
            }
        }

        # ── TLS / Secure Channel Compliance tabs (v3.9.0 Session 8e) ──
        if ($TLSAuditData -and $TLSAuditData.Count -gt 0) {
            if ($TLSAuditData.TLSCompliance -and @($TLSAuditData.TLSCompliance).Count -gt 0) {
                $tlsCompRows = @($TLSAuditData.TLSCompliance)
                $params.TableStyle = 'Medium6'
                $tlsCompRows | Sort-Object OverallStatus, MachineName |
                    Export-Excel @params -WorksheetName "TLS-Compliance" `
                        -Title "TLS / Secure Channel Compliance Audit -- Per-Machine Status" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'COMPLIANT'     -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                            New-ConditionalText -Text 'PARTIAL'       -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                            New-ConditionalText -Text 'NON-COMPLIANT' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'PASS'          -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                            New-ConditionalText -Text 'FAIL'          -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'ERROR'         -BackgroundColor '#E0E0E0' -ConditionalTextColor '#666666'
                        )
                $tlsNonComp = @($tlsCompRows | Where-Object { $_.OverallStatus -eq 'NON-COMPLIANT' }).Count
                $tlsPartial = @($tlsCompRows | Where-Object { $_.OverallStatus -eq 'PARTIAL' }).Count
                Write-HVLog "  TLS-Compliance: $($tlsCompRows.Count) machines -- $tlsNonComp non-compliant, $tlsPartial partial" -Level Info
                $params.TableStyle = 'Medium2'
            }
            if ($TLSAuditData.TLSRecommendations -and @($TLSAuditData.TLSRecommendations).Count -gt 0) {
                $tlsRecoRows = @($TLSAuditData.TLSRecommendations)
                $params.TableStyle = 'Medium6'
                $tlsRecoRows | Sort-Object Priority, Severity, MachineName |
                    Export-Excel @params -WorksheetName "TLS-Recommendations" `
                        -Title "TLS Remediation Recommendations -- Prioritized Action Items" `
                        -ConditionalText @(
                            New-ConditionalText -Text 'CRITICAL' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                            New-ConditionalText -Text 'HIGH'     -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                            New-ConditionalText -Text 'MEDIUM'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        )
                Write-HVLog "  TLS-Recommendations: $($tlsRecoRows.Count) items" -Level Info
                $params.TableStyle = 'Medium2'
            }
        }

        # ── Cipher / Kerberos Encryption-Type tabs (v3.10.12.27, OPEN-68) ─────
        # Writes Cipher-Audit, Kerberos-Etypes, Cipher-Interop,
        # Cipher-Diagnostics and Etype-Reference. Export-CipherAuditTabs is
        # self-contained: it clones $params, sets its own TableStyle per tab
        # and restores it, so no other change to this file is required.
        if ($CipherAuditData -and $CipherAuditData.Count -gt 0) {
            if (Get-Command Export-CipherAuditTabs -ErrorAction SilentlyContinue) {
                Export-CipherAuditTabs -ExcelParams $params -CipherAuditData $CipherAuditData -ReportLevel $ReportLevel
            }
            else {
                Write-HVLog "  Cipher tabs skipped -- Export-CipherAuditTabs not available (HyperVInventory-Cyphers.psm1 not loaded)" -Level Warning
            }
        }

        # ── DNS Record Validation tab (v3.9.2 CR57) ─────
        if ($DNSValidationData -and $DNSValidationData.DNSRows -and @($DNSValidationData.DNSRows).Count -gt 0) {
            $dnsRows = @($DNSValidationData.DNSRows)
            $dnsCritical = @($dnsRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $dnsWarning  = @($dnsRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $dnsRows | Sort-Object AlertLevel, Domain, Name |
                Export-Excel @params -WorksheetName "DNS-Validation" `
                    -Title "DNS Record Validation -- Forward and Reverse Lookup Results" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Missing'  -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'Mismatch' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'OK'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Yes'      -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    )
            Write-HVLog "  DNS-Validation: $($dnsRows.Count) targets -- $dnsCritical critical, $dnsWarning warnings" -Level Info
        }

        # ── Disk Format / Partition Audit tab (v3.9.0 Session 8f) ─────
        if ($DiskFormatData -and @($DiskFormatData).Count -gt 0) {
            $dfRows = @($DiskFormatData)
            $params.TableStyle = 'Medium6'
            $dfRows | Sort-Object Host, MountPath |
                Export-Excel @params -WorksheetName "Disk-Format-Config" `
                    -Title "Disk Format and Partition Configuration -- Per-Host Volume Details" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Parity'  -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'Simple'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Mirror'  -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'MBR'     -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'ERROR'   -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    )
            $parityCount = @($dfRows | Where-Object { $_.SSResiliency -eq 'Parity' }).Count
            $simpleCount = @($dfRows | Where-Object { $_.SSResiliency -eq 'Simple' }).Count
            Write-HVLog "  Disk-Format-Config: $($dfRows.Count) volumes -- $parityCount parity (WARNING), $simpleCount simple (WARNING)" -Level Info
            $params.TableStyle = 'Medium2'
        }

        # ── RBAC Builtin Group Compliance tab (v3.8.9 Session 8h) ─────
        if ($RBACComplianceData -and $RBACComplianceData.RBACCompliance -and
            @($RBACComplianceData.RBACCompliance).Count -gt 0) {

            $rbacRows = @($RBACComplianceData.RBACCompliance)
            $params.TableStyle = 'Medium6'
            $rbacRows | Sort-Object Status, MachineName, BuiltinGroup |
                Export-Excel @params -WorksheetName "RBAC-Compliance" `
                    -Title "RBAC Builtin Group Compliance Audit -- Per-Server Per-Group Validation" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'COMPLIANT'     -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'NON-COMPLIANT' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'WARNING'       -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'LINUX'         -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                    )
            $rbacNonComp = @($rbacRows | Where-Object { $_.Status -eq 'NON-COMPLIANT' }).Count
            $rbacWarning = @($rbacRows | Where-Object { $_.Status -eq 'WARNING' }).Count
            $rbacCompliant = @($rbacRows | Where-Object { $_.Status -eq 'COMPLIANT' }).Count
            $rbacLinux = @($rbacRows | Where-Object { $_.Status -eq 'LINUX' }).Count
            Write-HVLog "  RBAC-Compliance: $($rbacRows.Count) checks -- $rbacCompliant compliant, $rbacNonComp non-compliant, $rbacWarning warning, $rbacLinux linux" -Level Info
            $params.TableStyle = 'Medium2'
        }

        # ── NTLM Deprecation Readiness tab (v3.8.9 Session 5e) ───────
        if ($NTLMReadinessData -and @($NTLMReadinessData).Count -gt 0) {
            $nrRows = @($NTLMReadinessData)
            $params.TableStyle = 'Medium6'
            $nrRows | Sort-Object OverallReadiness, Computer |
                Export-Excel @params -WorksheetName "NTLM-Readiness" `
                    -Title "NTLM Deprecation Readiness Audit -- Per-Machine Protocol Configuration" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Ready'      -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Needs-Work' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Blocked'    -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'ERROR'      -BackgroundColor '#E0E0E0' -ConditionalTextColor '#666666'
                    )
            $nrBlocked = @($nrRows | Where-Object { $_.OverallReadiness -eq 'Blocked' }).Count
            $nrReady   = @($nrRows | Where-Object { $_.OverallReadiness -eq 'Ready' }).Count
            Write-HVLog "  NTLM-Readiness: $($nrRows.Count) machines -- $nrReady Ready, $nrBlocked Blocked" -Level Info
            $params.TableStyle = 'Medium2'
        }

        # ── Service Account SPN Audit tab (v3.8.9 Session 5f) ────────
        if ($SvcAccountSPNData -and @($SvcAccountSPNData).Count -gt 0) {
            $saRows = @($SvcAccountSPNData)
            $params.TableStyle = 'Medium6'
            $saRows | Sort-Object AlertLevel, Domain, AccountName |
                Export-Excel @params -WorksheetName "SPN-ServiceAccounts" `
                    -Title "Service Account SPN Audit -- User Objects with Registered SPNs" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Info'     -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                    )
            $saCritical = @($saRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $saAccounts = @($saRows | Select-Object -Property AccountName -Unique).Count
            Write-HVLog "  SPN-ServiceAccounts: $($saRows.Count) SPNs across $saAccounts accounts -- $saCritical Critical" -Level Info
            $params.TableStyle = 'Medium2'
        }

        # ---- v3.8.9.2: KCD-Validation tab (Advanced) ----
        if ($isAdvanced -and $KCDValidationData -and $KCDValidationData.Count -gt 0) {
            $params.TableStyle = 'None'

            # v3.10.12 OPEN-61: Add KCD and RBCD configuration guidance columns.
            # For each delegation entry, generate concrete PowerShell commands that
            # would fix the identified gap. Both KCD and RBCD remediation are provided
            # so the admin can choose their preferred approach.
            $enrichedKCD = @($KCDValidationData | ForEach-Object {
                $row = $_
                $kcdSteps  = ''
                $rbcdSteps = ''
                $srcComputer = $row.ComputerName
                $targetSPN   = $row.DelegationTargetSPN
                $targetHost  = $row.TargetHostname
                $delegType   = $row.DelegationType
                $alertLevel  = $row.AlertLevel

                if ($alertLevel -eq 'Critical' -and $delegType -eq 'Unconstrained') {
                    # Unconstrained delegation -- needs migration to KCD or RBCD
                    $kcdSteps = "# STEP 1: Remove unconstrained delegation`n" +
                        "Set-ADAccountControl -Identity '$srcComputer' -TrustedForDelegation `$false`n" +
                        "# STEP 2: Set KCD to specific SPNs (add all required target SPNs)`n" +
                        "Set-ADComputer -Identity '$srcComputer' -Add @{'msDS-AllowedToDelegateTo'=@('cifs/$targetHost','Microsoft Virtual System Migration Service/$targetHost')}"
                    $rbcdSteps = "# STEP 1: Remove unconstrained delegation`n" +
                        "Set-ADAccountControl -Identity '$srcComputer' -TrustedForDelegation `$false`n" +
                        "# STEP 2: Configure RBCD on the DESTINATION host`n" +
                        "`$src = Get-ADComputer -Identity '$srcComputer'`n" +
                        "Set-ADComputer -Identity '$targetHost' -PrincipalsAllowedToDelegateToAccount @(`$src)"
                }
                elseif ($alertLevel -eq 'Critical' -and $row.Issues -match 'missing.*SPN|SPN.*not registered') {
                    # Target SPN not registered
                    $kcdSteps = "# Register the missing SPN on the target computer`n" +
                        "setspn -S $targetSPN $targetHost"
                    $rbcdSteps = "# SPN registration is also needed for RBCD`n" +
                        "setspn -S $targetSPN $targetHost"
                }
                elseif ($row.IsLiveMigrationSPN -eq 'Yes' -and $row.MissingLMTargets) {
                    # Live migration delegation gap
                    $missingTargets = $row.MissingLMTargets -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $kcdSpnList = @()
                    $rbcdCmds = @()
                    foreach ($mt in $missingTargets) {
                        $kcdSpnList += "'cifs/$mt'"
                        $kcdSpnList += "'Microsoft Virtual System Migration Service/$mt'"
                        $rbcdCmds += "Set-ADComputer -Identity '$mt' -PrincipalsAllowedToDelegateToAccount @((Get-ADComputer '$srcComputer'))"
                    }
                    $kcdSteps = "# Add missing live migration delegation SPNs`n" +
                        "Set-ADComputer -Identity '$srcComputer' -Add @{'msDS-AllowedToDelegateTo'=@($($kcdSpnList -join ','))}"
                    $rbcdSteps = "# Configure RBCD on each missing target (destination controls trust)`n" +
                        ($rbcdCmds -join "`n")
                }
                elseif ($delegType -eq 'None' -and $alertLevel -ne 'OK') {
                    # No delegation configured
                    $kcdSteps = "# Configure KCD for this source to the target SPN`n" +
                        "Set-ADComputer -Identity '$srcComputer' -Add @{'msDS-AllowedToDelegateTo'=@('$targetSPN')}"
                    $rbcdSteps = "# Configure RBCD on the destination (preferred)`n" +
                        "`$src = Get-ADComputer -Identity '$srcComputer'`n" +
                        "Set-ADComputer -Identity '$targetHost' -PrincipalsAllowedToDelegateToAccount @(`$src)"
                }
                else {
                    # OK or Info -- no remediation needed
                    $kcdSteps  = 'No action needed -- delegation is correctly configured'
                    $rbcdSteps = 'No action needed -- delegation is correctly configured'
                }

                # Add the two new columns to the existing row
                $row | Add-Member -NotePropertyName 'KCDConfigSteps'  -NotePropertyValue $kcdSteps  -Force
                $row | Add-Member -NotePropertyName 'RBCDConfigSteps' -NotePropertyValue $rbcdSteps -Force
                $row
            })

            # OPEN-61 Part B: Generate per-host KCD/RBCD remediation scripts for Critical/Warning rows.
            # Groups qualifying rows by host, generates one .ps1 per host with embedded gap detail.
            # OPEN-61 Bug fix (v3.10.12.26): use $global:HVI_fnKCDRemediationScript captured at run
            # start (three-tier pattern) instead of Get-Command, which cannot see PSM1-fallback functions
            # from inside a different module scope.
            $kcdRemediationResults = @()
            $kcdFn    = $global:HVI_fnKCDRemediationScript
            $kcdIdxFn = $global:HVI_fnKCDRemediationIndex
            if ($kcdFn) {
                $remBase = if ($RemediationScriptFolder) { $RemediationScriptFolder }
                           elseif ($OutputPath) { Join-Path (Split-Path $OutputPath -Parent) 'Remediation' }
                           else { Join-Path $env:TEMP 'HVI_Remediation' }
                $qualifyingRows = @($enrichedKCD | Where-Object { $_.AlertLevel -in @('Critical','Warning') })
                if ($qualifyingRows.Count -gt 0) {
                    # Group by the host associated with each source computer (ComputerName on the row IS the HV host)
                    $byHost = @{}
                    foreach ($row in $qualifyingRows) {
                        $hKey = $row.ComputerName
                        if (-not $byHost.ContainsKey($hKey)) { $byHost[$hKey] = @() }
                        $byHost[$hKey] += $row
                    }
                    $kcdScriptResults = [System.Collections.Generic.List[object]]::new()
                    foreach ($hName in ($byHost.Keys | Sort-Object)) {
                        try {
                            $r = & $kcdFn -HostName $hName -KCDRows @($byHost[$hName]) `
                                     -RemediationFolder $remBase -ScriptVersion $ScriptVersion
                            $kcdScriptResults.Add($r)
                            if ($r.Success) {
                                Write-HVLog "  OPEN-61: KCD script generated for $hName ($($r.CritCount) Critical, $($r.WarnCount) Warning) -> $(Split-Path $r.ScriptPath -Leaf)" -Level Info
                            }
                        }
                        catch {
                            Write-HVLog "  OPEN-61: KCD script failed for $hName -- $($_.Exception.Message)" -Level Warning
                        }
                    }
                    $kcdRemediationResults = @($kcdScriptResults)
                    # Build index
                    if ($kcdIdxFn -and $kcdScriptResults.Count -gt 0) {
                        & $kcdIdxFn -Results @($kcdScriptResults) -RemediationFolder $remBase | Out-Null
                    }
                    # Stamp RemediationScriptPath on enrichedKCD rows (links Excel -> .ps1)
                    $scriptMap = @{}
                    foreach ($r in $kcdScriptResults) {
                        if ($r.Success) { $scriptMap[$r.HostName] = $r.ScriptPath }
                    }
                    $enrichedKCD = @($enrichedKCD | ForEach-Object {
                        $sPath = if ($scriptMap.ContainsKey($_.ComputerName)) { $scriptMap[$_.ComputerName] } else { '' }
                        $_ | Add-Member -NotePropertyName 'KCDRemediationScript' -NotePropertyValue $sPath -Force
                        $_
                    })
                    Write-HVLog "  OPEN-61: KCD remediation scripts: $(@($kcdScriptResults | Where-Object { $_.Success }).Count) generated, $(@($kcdScriptResults | Where-Object { -not $_.Success }).Count) failed" -Level Info
                }
                else {
                    Write-HVLog "  OPEN-61: No Critical/Warning KCD rows -- no remediation scripts generated" -Level Info
                }
            }
            else {
                Write-HVLog "  OPEN-61: KCD remediation function not available -- skipping script generation" -Level Warning
            }

            $enrichedKCD | Sort-Object AlertLevel, ComputerName |
                Export-Excel @params -WorksheetName "KCD-Validation" `
                    -Title "Kerberos Constrained Delegation Validation" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'OK'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Info'     -BackgroundColor '#E3F2FD' -ConditionalTextColor '#1565C0'
                    )
            $kcdCritical = @($KCDValidationData | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $kcdWarning  = @($KCDValidationData | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            Write-HVLog "  KCD-Validation: $($KCDValidationData.Count) delegation entries -- $kcdCritical Critical, $kcdWarning Warning (with KCD/RBCD guidance columns)" -Level Info
            $params.TableStyle = 'Medium2'
        }

        # ---- v3.9.0: Cross-Domain-Auth diagnostic tab (Advanced) ----
        if ($isAdvanced -and $crossDomainAuth -and $crossDomainAuth.Count -gt 0) {
            $cdaCritical = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $cdaWarning  = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $cdaOK       = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'OK' }).Count
            # v3.10.5 CR84: Auth protocol breakdown
            $cdaKrb      = @($crossDomainAuth | Where-Object { $_.AuthProtocol -eq 'Kerberos' }).Count
            $cdaNeg      = @($crossDomainAuth | Where-Object { $_.AuthProtocol -eq 'Negotiate (NTLM)' }).Count
            $cdaPsd      = @($crossDomainAuth | Where-Object { $_.AuthProtocol -eq 'PSDirect (VMBus)' }).Count
            $crossDomainAuth | Sort-Object AlertLevel, DetectedDomain, VM |
                Export-Excel @params -WorksheetName "Cross-Domain-Auth" `
                    -Title "Cross-Domain WinRM Authentication Diagnostic -- Per-VM Credential Resolution" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'AllFailed' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Negotiate (NTLM)' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'PSDirect (VMBus)' -BackgroundColor '#D4E6F1' -ConditionalTextColor '#1B4F72'
                        New-ConditionalText -Text 'OK'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Kerberos' -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    )
            Write-HVLog "  Cross-Domain-Auth: $($crossDomainAuth.Count) VMs -- $cdaOK OK, $cdaWarning warning, $cdaCritical critical | Auth: $cdaKrb Kerberos, $cdaNeg Negotiate, $cdaPsd PSDirect" -Level Info
        }

        # ---- v3.10.2: VM-Activity-Audit tab (Advanced, Session 14) ----
        if ($isAdvanced -and $VMActivityData -and @($VMActivityData).Count -gt 0) {
            $actRows = @($VMActivityData)
            $actCritical = @($actRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $actWarning  = @($actRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count

            # v3.10.10.5 CR-VMActivityCrash: Defensive try/catch + diagnostic logging.
            # The 2026-04-13 run with v3.10.10.4 deployed crashed Export-Excel here
            # with "Error saving file" mid-stream after Cross-Domain-Auth completed
            # successfully. Root cause unknown -- could be row count, conditional
            # formatting rule conflict, or a bad property value (e.g. CR95
            # ForensicNote column with non-string content) that EPPlus rejects.
            #
            # This block:
            #   1. Logs the row count BEFORE the Export-Excel call so we know how
            #      large the data is even if the export crashes
            #   2. Logs property type analysis for non-primitive values that could
            #      poison the EPPlus serializer
            #   3. Wraps the Export-Excel call in try/catch so a crash here does
            #      not abort the entire Advanced workbook -- the remaining tabs
            #      (VM-Offline-Disks, Host-NIC-Audit, etc.) will still be written
            #   4. On crash, dumps a sample row to the log so we can see what data
            #      EPPlus refused to serialize
            Write-HVLog "  VM-Activity-Audit: preparing to export $($actRows.Count) events ($actCritical critical, $actWarning warning)" -Level Info

            # v3.10.10.5 Option A: JSON dump of the data being passed to Export-Excel.
            # When debug-dump is enabled, the complete row set is serialized to a
            # sibling _debug folder before the export attempt. If Export-Excel
            # crashes, the JSON is on disk for offline analysis. The dump runs
            # unconditionally (not just on crash) so we capture forensic state even
            # when the export succeeds -- useful for comparing crash runs against
            # working runs to identify what changed in the data shape.
            #
            # Two ways to enable (in order of precedence):
            #   1. Environment variable: $env:HYPERVREPORT_DEBUG_DUMP = '1'
            #      (set this in the PowerShell session before running Run_Report.ps1
            #       to get a one-shot debug dump without editing config files)
            #   2. Config file key: DebugDumpFailedTabs = $true in Config-OHDC.psd1
            #      (persistent setting; will dump on every run)
            #
            # Default is OFF -- production runs do not generate extra files.
            #
            # Note: the Export function does not currently receive the Config object
            # as a parameter, so we have to detect the flag via env var or by
            # locating and re-reading the Config file from a known location relative
            # to this module. This is intentionally lightweight to avoid changing
            # the orchestrator function signature for a debug-only feature.
            $debugDumpEnabled = $false
            if ($env:HYPERVREPORT_DEBUG_DUMP -eq '1' -or $env:HYPERVREPORT_DEBUG_DUMP -eq 'true') {
                $debugDumpEnabled = $true
            }
            else {
                # Fallback: locate Config-OHDC.psd1 in the deploy folder
                # (one level up from \Modules\HyperVInventory-Export.psm1)
                try {
                    $modulePath = $PSCommandPath
                    if (-not $modulePath) { $modulePath = $MyInvocation.MyCommand.Path }
                    if ($modulePath) {
                        $deployFolder = Split-Path -Parent (Split-Path -Parent $modulePath)
                        foreach ($cfgName in @('Config-OHDC.psd1','Config.psd1')) {
                            $cfgPath = Join-Path $deployFolder $cfgName
                            if (Test-Path -LiteralPath $cfgPath) {
                                $cfgData = Import-PowerShellDataFile -LiteralPath $cfgPath -ErrorAction Stop
                                if ($cfgData.ContainsKey('DebugDumpFailedTabs') -and $cfgData['DebugDumpFailedTabs']) {
                                    $debugDumpEnabled = $true
                                }
                                break
                            }
                        }
                    }
                }
                catch {
                    # Silently ignore -- debug feature, do not perturb the export pipeline
                }
            }
            if ($debugDumpEnabled) {
                try {
                    $debugFolder = Join-Path (Split-Path -Parent $params.Path) '_debug'
                    if (-not (Test-Path -LiteralPath $debugFolder)) {
                        New-Item -Path $debugFolder -ItemType Directory -Force | Out-Null
                    }
                    $debugFile = Join-Path $debugFolder 'VM-Activity-Audit.json'
                    # Use depth 6 to capture nested objects without runaway serialization
                    $actRows | ConvertTo-Json -Depth 6 -Compress:$false |
                        Out-File -FilePath $debugFile -Encoding UTF8 -Force
                    Write-HVLog "  VM-Activity-Audit: forensic dump written to $debugFile ($($actRows.Count) rows)" -Level Info
                }
                catch {
                    Write-HVLog "  VM-Activity-Audit: forensic dump FAILED -- $($_.Exception.Message) (continuing with export)" -Level Warning
                }
            }

            # Property type sanity check: find any non-primitive properties on the first row
            if ($actRows.Count -gt 0) {
                $sampleRow = $actRows[0]
                $propIssues = @()
                foreach ($p in $sampleRow.PSObject.Properties) {
                    if ($null -ne $p.Value) {
                        $t = $p.Value.GetType().FullName
                        # EPPlus is happy with: String, Int*, Double, Decimal, DateTime, Boolean
                        # Anything else (Hashtable, PSCustomObject, Object[], etc.) may break Save()
                        $okTypes = @('System.String','System.Int32','System.Int64','System.Double',
                                     'System.Decimal','System.DateTime','System.Boolean','System.Single',
                                     'System.UInt32','System.UInt64','System.Byte','System.Int16')
                        if ($t -notin $okTypes) {
                            $propIssues += "$($p.Name)=[$t]"
                        }
                    }
                }
                if ($propIssues.Count -gt 0) {
                    Write-HVLog "  VM-Activity-Audit: WARNING -- non-primitive property types detected on sample row: $($propIssues -join ', ')" -Level Warning
                }
            }

            try {
                # v3.10.12.10: Create backup FIRST, before ANY processing.
                # Previous versions had backup after sanitization, so a crash in
                # the regex sanitization loop left the xlsx unprotected.
                $bakPath = $null
                if (-not $VMActivitySeparateFile -and (Test-Path $params.Path)) {
                    $bakPath = $params.Path + '.vmactivity.bak'
                    try {
                        Copy-Item -LiteralPath $params.Path -Destination $bakPath -Force -ErrorAction Stop
                        Write-HVLog "  VM-Activity-Audit: pre-export backup saved to $bakPath" -Level Info
                    }
                    catch {
                        Write-HVLog "  VM-Activity-Audit: WARNING -- backup copy failed: $($_.Exception.Message)" -Level Warning
                        $bakPath = $null
                    }
                }

                # v3.10.12 CR-VMActivityCrash: Sanitize typed .NET objects to plain
                # strings/numbers before Export-Excel.
                # v3.10.12.9: Also strip Unicode surrogates and non-BMP characters.
                # Root cause identified: Hyper-V event log messages (EventID 3084
                # Worker-Admin, EventID 36000 VMMS-Admin) contain binary data
                # (memory addresses, handle values) misinterpreted as text.
                # These produce lone UTF-16 surrogates (U+D800-U+DFFF) that cause
                # System.Text.EncoderFallbackException in EPPlus Save() when it
                # tries to encode them as UTF-8 for the xlsx XML.
                # Fix: regex-strip all surrogates and replace with U+FFFD placeholder.
                #
                # IMPORTANT PS 5.1 COMPAT: [regex]::Replace($val, $pattern, [char]X)
                # fails in PS 5.1 because it resolves the [char] arg to the
                # MatchEvaluator overload instead of the string overload.
                # Must cast replacement to [string] explicitly.
                $replacementChar = [string][char]0xFFFD   # U+FFFD REPLACEMENT CHARACTER
                $badCharPattern  = '[\uD800-\uDFFF\x00-\x08\x0B\x0C\x0E-\x1F]'

                $sanitizedRows = @($actRows | ForEach-Object {
                    $row = $_
                    $safe = [ordered]@{}
                    foreach ($p in $row.PSObject.Properties) {
                        $val = $p.Value
                        if ($null -eq $val) {
                            $safe[$p.Name] = ''
                        }
                        elseif ($val -is [string]) {
                            # Strip lone surrogates (U+D800-U+DFFF) and control chars
                            # (except tab U+0009, newline U+000A, carriage return U+000D)
                            # that crash EPPlus XML serialization.
                            $safe[$p.Name] = [regex]::Replace($val, $badCharPattern, $replacementChar)
                        }
                        elseif ($val -is [bool]) {
                            $safe[$p.Name] = $val
                        }
                        elseif ($val -is [int] -or $val -is [long] -or $val -is [double] -or $val -is [decimal]) {
                            $safe[$p.Name] = $val
                        }
                        elseif ($val -is [datetime]) {
                            $safe[$p.Name] = $val.ToString('o')
                        }
                        else {
                            $clean = [string]$val
                            $safe[$p.Name] = [regex]::Replace($clean, $badCharPattern, $replacementChar)
                        }
                    }
                    [PSCustomObject]$safe
                })

                # v3.10.12.9: Count rows that had Unicode sanitization applied
                # so the log shows whether the surrogate fix is actively cleaning data.
                $unicodeSanitizedCount = 0
                foreach ($origRow in $actRows) {
                    foreach ($p in $origRow.PSObject.Properties) {
                        if ($p.Value -is [string] -and $p.Value -match '[\uD800-\uDFFF\x00-\x08\x0B\x0C\x0E-\x1F]') {
                            $unicodeSanitizedCount++
                            break  # count each row only once
                        }
                    }
                }
                if ($unicodeSanitizedCount -gt 0) {
                    Write-HVLog "  VM-Activity-Audit: Unicode sanitization applied to $unicodeSanitizedCount row(s) (lone surrogates/control chars replaced with U+FFFD)" -Level Warning
                }

                # v3.10.12.9 CR-VMActivityCrash: Chunked export with conditional
                # formatting per chunk + Option B separate file + backup/restore.
                #
                # Chunk size is configurable via VMActivityChunkSize in config.
                # Default 5000 rows per tab. EPPlus 4.x (ImportExcel 7.x) has been
                # observed to fail Save() with large text columns + conditional
                # formatting above ~8K rows. 5000 provides conservative headroom.
                $actChunkSize = 5000
                if ($VMActivityChunkSize -gt 0) {
                    $actChunkSize = $VMActivityChunkSize
                }
                $sortedAct = @($sanitizedRows | Sort-Object Timestamp -Descending)
                $actConditional = @(
                    New-ConditionalText -Text 'Critical' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'Info'     -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                )

                # v3.10.12.9 Option B: If VMActivitySeparateFile is enabled, write
                # VM-Activity-Audit to its own xlsx file instead of the main workbook.
                # This avoids the EPPlus Save() crash caused by cumulative xlsx size
                # (~50 tabs + 8K rows of long text + conditional formatting).
                if ($VMActivitySeparateFile) {
                    $actOutputDir = Split-Path -Parent $params.Path
                    $actBaseName  = [System.IO.Path]::GetFileNameWithoutExtension($params.Path)
                    # Replace 'Inventory_Advanced' with 'VMActivity_Advanced' in filename
                    $actFileName  = ($actBaseName -replace 'Inventory', 'VMActivity') + '.xlsx'
                    $actFilePath  = Join-Path $actOutputDir $actFileName
                    if (Test-Path $actFilePath) { Remove-Item $actFilePath -Force }

                    $actParams = @{
                        Path         = $actFilePath
                        AutoSize     = $true
                        FreezeTopRow = $true
                        TableStyle   = 'Medium2'
                    }

                    Write-HVLog "  VM-Activity-Audit: exporting to SEPARATE file (VMActivitySeparateFile=`$true): $actFilePath" -Level Info
                }
                else {
                    # Option A: Same file with backup protection
                    # (backup already created at top of try block)
                    $actParams = $params

                    # v3.10.12.9 Debug: Log xlsx file size and tab count before export
                    if (Test-Path $actParams.Path) {
                        $preCrashSize = (Get-Item $actParams.Path).Length
                        Write-HVLog "  VM-Activity-Audit: xlsx size before export = $([math]::Round($preCrashSize/1MB,2)) MB" -Level Info
                    }
                }

                # v3.10.12.9 Debug: Log process memory before export
                $procBefore = Get-Process -Id $PID
                Write-HVLog "  VM-Activity-Audit: process memory before export = $([math]::Round($procBefore.WorkingSet64/1MB,1)) MB (private: $([math]::Round($procBefore.PrivateMemorySize64/1MB,1)) MB)" -Level Info

                if ($sortedAct.Count -le $actChunkSize) {
                    # Single chunk -- export normally with title + conditional formatting
                    $sortedAct | Export-Excel @actParams -WorksheetName "VM-Activity-Audit" `
                        -Title "VM Lifecycle Activity Audit -- Events with Trigger Correlation" `
                        -ConditionalText $actConditional
                    Write-HVLog "  VM-Activity-Audit: $($actRows.Count) events -- $actCritical critical, $actWarning warning" -Level Info
                }
                else {
                    # Multiple chunks needed -- each chunk gets its own conditional formatting
                    $actTotalChunks = [math]::Ceiling($sortedAct.Count / $actChunkSize)
                    for ($ci = 0; $ci -lt $actTotalChunks; $ci++) {
                        $start     = $ci * $actChunkSize
                        $chunkData = $sortedAct | Select-Object -Skip $start -First $actChunkSize
                        $tabName   = "VM-Activity-Audit_$($ci + 1)of$actTotalChunks"
                        $chunkData | Export-Excel @actParams -WorksheetName $tabName `
                            -Title "VM Lifecycle Activity Audit -- Part $($ci + 1) of $actTotalChunks ($($sortedAct.Count) total events)" `
                            -ConditionalText $actConditional
                    }
                    Write-HVLog "  VM-Activity-Audit chunked into $actTotalChunks tabs ($($sortedAct.Count) total rows, $actChunkSize per tab) -- $actCritical critical, $actWarning warning" -Level Info
                }

                # v3.10.12.9 Debug: Log process memory after export
                $procAfter = Get-Process -Id $PID
                Write-HVLog "  VM-Activity-Audit: process memory after export = $([math]::Round($procAfter.WorkingSet64/1MB,1)) MB (private: $([math]::Round($procAfter.PrivateMemorySize64/1MB,1)) MB)" -Level Info

                # Clean up backup on success (Option A only)
                if (-not $VMActivitySeparateFile -and $bakPath -and (Test-Path $bakPath)) {
                    Remove-Item $bakPath -Force -ErrorAction SilentlyContinue
                    Write-HVLog "  VM-Activity-Audit: export succeeded -- backup removed" -Level Info
                }

                # If separate file, log the path for the user
                if ($VMActivitySeparateFile) {
                    Write-HVLog "  VM-Activity-Audit: separate file export complete: $actFilePath" -Level Success
                }
            }
            catch {
                # v3.10.12.9 CR-VMActivityCrash: Enhanced crash diagnostics

                # 1. Walk the full inner exception chain to find the real error
                #    (EPPlus wraps the root cause in generic "Error saving file")
                $innerEx = $_.Exception.InnerException
                while ($innerEx) {
                    Write-HVLog "  VM-Activity-Audit: INNER EXCEPTION -- [$($innerEx.GetType().FullName)] $($innerEx.Message)" -Level Error
                    $innerEx = $innerEx.InnerException
                }

                # 2. Log process memory at time of crash
                $procCrash = Get-Process -Id $PID
                Write-HVLog "  VM-Activity-Audit: process memory at crash = $([math]::Round($procCrash.WorkingSet64/1MB,1)) MB (private: $([math]::Round($procCrash.PrivateMemorySize64/1MB,1)) MB)" -Level Error

                # 3. Original crash logging
                Write-HVLog "  VM-Activity-Audit: EXPORT FAILED -- $($_.Exception.Message)" -Level Error
                Write-HVLog "  VM-Activity-Audit: stack trace -- $($_.ScriptStackTrace -replace '\r?\n',' | ')" -Level Error
                Write-HVLog "  VM-Activity-Audit: row count was $($actRows.Count); skipping this tab so remaining tabs can complete" -Level Error

                # 4. Dump first 3 rows for forensic analysis
                $dumpCount = [Math]::Min(3, $actRows.Count)
                for ($i = 0; $i -lt $dumpCount; $i++) {
                    $r = $actRows[$i]
                    $propDump = @()
                    foreach ($p in $r.PSObject.Properties) {
                        $val = if ($null -eq $p.Value) { '<null>' }
                               elseif ($p.Value -is [string]) {
                                   $v = $p.Value
                                   if ($v.Length -gt 80) { $v = $v.Substring(0,80) + '...' }
                                   "'$v'"
                               }
                               else { "[$($p.Value.GetType().Name)] $($p.Value)" }
                        $propDump += "$($p.Name)=$val"
                    }
                    Write-HVLog "  VM-Activity-Audit: sample row [$i] -- $($propDump -join ' | ')" -Level Error
                }

                # 5. Restore xlsx from backup if crash corrupted the file (Option A only)
                if (-not $VMActivitySeparateFile -and $bakPath -and (Test-Path $bakPath)) {
                    try {
                        Copy-Item -LiteralPath $bakPath -Destination $params.Path -Force -ErrorAction Stop
                        Write-HVLog "  VM-Activity-Audit: RESTORED xlsx from pre-export backup -- all prior tabs preserved" -Level Warning
                        # Verify restoration
                        $restoredSize = (Get-Item $params.Path).Length
                        Write-HVLog "  VM-Activity-Audit: restored file size = $([math]::Round($restoredSize/1MB,2)) MB" -Level Info
                    }
                    catch {
                        Write-HVLog "  VM-Activity-Audit: CRITICAL -- backup restore FAILED: $($_.Exception.Message)" -Level Error
                        Write-HVLog "  VM-Activity-Audit: backup file still available at: $bakPath" -Level Error
                    }
                }

                Write-HVLog "  VM-Activity-Audit: continuing with remaining tabs" -Level Warning
            }
        }
        elseif ($isAdvanced) {
            Write-HVLog "  VM-Activity-Audit: skipped (no data or feature disabled)" -Level Info
        }
        
        # ---- v3.10.11 CR102: LAPS-Usage tab (Advanced) ----
        if ($isAdvanced -and $LAPSData -and @($LAPSData).Count -gt 0) {
            $lapsRows = @($LAPSData)
            $lapsCritical = @($lapsRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $lapsWarning  = @($lapsRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $lapsManaged  = @($lapsRows | Where-Object { $_.LAPSBackend -ne 'None' -and $_.LAPSBackend -ne 'NotDomainJoined' -and $_.LAPSBackend -ne 'Error' }).Count
            $lapsRows | Sort-Object AlertLevel, VM |
                Export-Excel @params -WorksheetName "LAPS-Usage" `
                    -Title "Windows LAPS Posture Audit -- Managed Password Status per VM" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical'        -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'         -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Unmanaged'       -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'NotEnabled'      -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'AD-Both'         -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'AD-WindowsLAPS'  -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'AD-Legacy'       -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    )
            Write-HVLog "  LAPS-Usage: $($lapsRows.Count) VMs -- $lapsManaged managed, $lapsCritical critical, $lapsWarning warning" -Level Info
        }
        elseif ($isAdvanced) {
            Write-HVLog "  LAPS-Usage: skipped (LAPSMode=Disabled or no data)" -Level Info
        }

        # ---- v3.10.11 Step 5q: AD-Info tab (Advanced) ----
        # Forest + domain topology: functional levels, FSMO roles, DC list, trust
        # relationships, site/subnet count, schema version, LAPS schema detection.
        # Data populated by Step 5q in the orchestrator (Get-ADForest + Get-ADDomain
        # + Get-ADDomainController across all configured domains via DomainCredentials).
        if ($isAdvanced -and $ADInfoData -and @($ADInfoData).Count -gt 0) {
            $adInfoRows = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($row in $ADInfoData) {
                $adInfoRows.Add([PSCustomObject]@{
                    Scope                 = $row.Scope
                    Name                  = $row.Name
                    FunctionalLevel       = $row.FunctionalLevel
                    SchemaMaster          = $row.SchemaMaster
                    DomainNaming          = $row.DomainNaming
                    PDCEmulator           = $row.PDCEmulator
                    RIDMaster             = $row.RIDMaster
                    InfrastructureMaster  = $row.InfrastructureMaster
                    LAPSSchemaLevel       = if ($row.LAPSSchemaLevel) { $row.LAPSSchemaLevel } else { '' }
                    Notes                 = $row.Notes
                })
            }

            $adForestRows = @($adInfoRows | Where-Object { $_.Scope -eq 'Forest' })
            $adDomainRows = @($adInfoRows | Where-Object { $_.Scope -eq 'Domain' })
            Write-HVLog "  AD-Info: $($adForestRows.Count) forest row(s), $($adDomainRows.Count) domain row(s)" -Level Info

            $adInfoRows | Sort-Object Scope, Name |
                Export-Excel @params -WorksheetName "AD-Info" `
                    -Title "Active Directory Forest and Domain Topology" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Forest'  -BackgroundColor '#E3F2FD' -ConditionalTextColor '#0D47A1'
                        New-ConditionalText -Text 'Domain'  -BackgroundColor '#F3E5F5' -ConditionalTextColor '#4A148C'
                        New-ConditionalText -Text 'None'    -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'Windows2016' -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Windows2012' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    )
        }
        elseif ($isAdvanced) {
            Write-HVLog "  AD-Info: skipped (no domain credential configured or AD query failed)" -Level Info
        }

        # ---- v3.10.12 OPEN-66: SPN-Inventory-Full tab (Advanced) ----
        # AD-wide SPN inventory across all computer + user accounts in every domain.
        # Analogous to "setspn -L" for every account in the forest.
        # Controlled by IncludeSPNInventoryFull = $true in config.
        if ($isAdvanced -and $SPNInventoryFullData -and @($SPNInventoryFullData).Count -gt 0) {
            $spnFullRows = @($SPNInventoryFullData)
            $spnFCritical = @($spnFullRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $spnFWarning  = @($spnFullRows | Where-Object { $_.AlertLevel -eq 'Warning'  }).Count
            $spnFDupe     = @($spnFullRows | Where-Object { $_.IsDuplicate -eq $true      }).Count
            $spnFAccounts = @($spnFullRows | Select-Object -Property AccountName -Unique).Count

            $spnFullRows | Sort-Object AlertLevel, Domain, AccountName, ServiceClass |
                Export-Excel @params -WorksheetName "SPN-Inventory-Full" `
                    -Title "AD-Wide SPN Inventory -- All Accounts Across All Domains" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical'      -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'       -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'True'          -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'HyperV'        -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'ServiceAccount' -BackgroundColor '#E3F2FD' -ConditionalTextColor '#0D47A1'
                    )
            Write-HVLog "  SPN-Inventory-Full: $($spnFullRows.Count) rows across $spnFAccounts accounts -- $spnFCritical Critical (dupes: $spnFDupe), $spnFWarning Warning" -Level Info
            if ($spnFDupe -gt 0) {
                Write-HVLog "  [WARNING] $spnFDupe duplicate SPN rows detected in SPN-Inventory-Full -- Kerberos auth WILL fail for affected services" -Level Warning
            }
        }
        elseif ($isAdvanced) {
            Write-HVLog "  SPN-Inventory-Full: skipped (IncludeSPNInventoryFull=`$false or no data)" -Level Info
        }

        # ---- v3.10.12 OPEN-60: Permissions-Groups tab (Advanced) ----
        $permGroupData = if ($PermissionData.GroupData) { @($PermissionData.GroupData) } else { @() }
        if ($isAdvanced -and $permGroupData.Count -gt 0) {
            $permGroupData | Sort-Object Computer, GroupName, MemberName |
                Export-Excel @params -WorksheetName "Permissions-Groups" `
                    -Title "Local Group Membership Audit -- Who Has Access to Each Machine" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Warning'        -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Administrators' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                    )
            Write-HVLog "  Permissions-Groups: $($permGroupData.Count) entries across $(($permGroupData | Select-Object -Property Computer -Unique).Count) machines" -Level Info
        }
        elseif ($isAdvanced) {
            Write-HVLog "  Permissions-Groups: skipped (IncludePermissionAudit=`$false or no data)" -Level Info
        }

        # ---- v3.10.12 OPEN-60: Permissions-Privileges tab (Advanced) ----
        $permPrivData = if ($PermissionData.PrivilegeData) { @($PermissionData.PrivilegeData) } else { @() }
        if ($isAdvanced -and $permPrivData.Count -gt 0) {
            $permPrivData | Sort-Object Computer, PrivilegeName, AssignedTo |
                Export-Excel @params -WorksheetName "Permissions-Privileges" `
                    -Title "User Rights Assignment Audit -- Who Can Shut Down, Log On, Back Up Each Machine" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Warning'              -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'SeDebugPrivilege'     -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'SeTakeOwnership'      -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'SeShutdownPrivilege'  -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    )
            Write-HVLog "  Permissions-Privileges: $($permPrivData.Count) entries across $(($permPrivData | Select-Object -Property Computer -Unique).Count) machines" -Level Info
        }
        elseif ($isAdvanced) {
            Write-HVLog "  Permissions-Privileges: skipped (IncludePermissionAudit=`$false or no data)" -Level Info
        }

        # ---- v3.10.12: Permissions-Security tab (Security Options from secedit) ----
        $permSecData = if ($PermissionData.SecurityOptionData) { @($PermissionData.SecurityOptionData) } else { @() }
        if ($isAdvanced -and $permSecData.Count -gt 0) {
            $permSecData | Sort-Object Computer, Section, FriendlyName |
                Export-Excel @params -WorksheetName "Permissions-Security" `
                    -Title "Security Options per Host -- secedit /export (Account Policy, User Rights, Registry Values)" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Warning' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Account Policy' -BackgroundColor '#E3F2FD' -ConditionalTextColor '#0D47A1'
                        New-ConditionalText -Text 'Security Options' -BackgroundColor '#F3E5F5' -ConditionalTextColor '#4A148C'
                    )
            Write-HVLog "  Permissions-Security: $($permSecData.Count) entries across $(($permSecData | Select-Object -Property Computer -Unique).Count) machines" -Level Info
        }
        elseif ($isAdvanced) {
            Write-HVLog "  Permissions-Security: skipped (IncludePermissionAudit=`$false or no data)" -Level Info
        }

        # ---- v3.10.4 CR83: VM-Offline-Disks tab (Advanced, original position) ----
        if ($isAdvanced -and $OfflineDiskData -and @($OfflineDiskData).Count -gt 0) {
            $offRows = @($OfflineDiskData)
            $offRows | Sort-Object VMName, DiskNumber |
                Export-Excel @params -WorksheetName "VM-Offline-Disks" `
                    -Title "VM Offline Disk Detection -- Disks Not Online Inside Guest OS" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'True' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Offline' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'OfflineShared' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'OfflineInternal' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    )
            Write-HVLog "  VM-Offline-Disks: $($offRows.Count) offline disks across $(($offRows | Select-Object -Property VMName -Unique).Count) VMs" -Level Warning
        }
        
        # ---- v3.10.7 CR89: SCCM-Status tab (Advanced, Session 9) ----
        if ($isAdvanced -and $SCCMData -and @($SCCMData).Count -gt 0) {
            $sccmRows = @($SCCMData)
            $sccmMissing  = @($sccmRows | Where-Object { $_.SCCMActive -eq 'Missing Client' }).Count
            $sccmCritical = @($sccmRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $sccmWarning  = @($sccmRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $sccmRows | Sort-Object AlertLevel, ComputerName |
                Export-Excel @params -WorksheetName "SCCM-Status" `
                    -Title "SCCM/MECM Client Status Audit -- Client Health, Policy & Hardware Scan Correlation" `
                    -ConditionalText @(
                        New-ConditionalText -Text 'Critical'       -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'Warning'        -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                        New-ConditionalText -Text 'Missing Client' -BackgroundColor '#FFE0E0' -ConditionalTextColor '#CC0000'
                        New-ConditionalText -Text 'Inactive'       -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                        New-ConditionalText -Text 'OK'             -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Active'         -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                        New-ConditionalText -Text 'Healthy'        -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    )
            Write-HVLog "  SCCM-Status: $($sccmRows.Count) entries -- $sccmMissing missing client, $sccmCritical critical, $sccmWarning warning" -Level Info
        }
        
        # ============================================================
        # Q4d: Tab reorder -- group related tabs together for navigation
        # Q5:  Executive Summary tab with charts
        # ============================================================
        try {
            $pkg = Open-ExcelPackage -Path $OutputPath

            # --------------------------------------------------------
            # Q5: Build Executive Summary tab with charts
            # --------------------------------------------------------
            $summaryWs = $pkg.Workbook.Worksheets.Add('00-Executive-Summary')

            # Helper to write a labelled value cell
            function Set-SummaryCell {
                param($ws, $row, $col, $val, $bold=$false, $size=11, $bg=$null, $fg=$null)
                $cell = $ws.Cells[$row, $col]
                $cell.Value = $val
                $cell.Style.Font.Size = $size
                $cell.Style.Font.Bold = $bold
                if ($bg) {
                    $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb([System.Convert]::ToInt32($bg.Replace('#',''), 16)))
                }
                if ($fg) {
                    $cell.Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb([System.Convert]::ToInt32($fg.Replace('#',''), 16)))
                }
            }

            # Title
            $summaryWs.Cells[1,1].Value = 'Hyper-V Infrastructure - Executive Summary'
            $summaryWs.Cells[1,1].Style.Font.Size = 18
            $summaryWs.Cells[1,1].Style.Font.Bold = $true
            $summaryWs.Cells[2,1].Value = "Generated: $ReportTimestamp   |   Level: $ReportLevel   |   Version: v$ScriptVersion   |   Hosts: $($HostData.Count)/$($HostData.Count + $(if ($UnavailableHosts) { $UnavailableHosts.Count } else { 0 }))"
            $summaryWs.Cells[2,1].Style.Font.Size = 10
            $summaryWs.Cells[2,1].Style.Font.Italic = $true

            # --- KPI Block (row 4) ---
            $kpiLabels = @('Total VMs','Running','Off/Paused','Total Hosts','Total vCPUs','Total RAM (GB)','Total VHDs','Snapshots Active')
            $totalVMs    = if ($vmInfo)       { @($vmInfo).Count }                                                         else { 0 }
            $runningVMs  = if ($vmInfo)       { @($vmInfo | Where-Object { $_.Powerstate -eq 'poweredOn' }).Count }          else { 0 }
            $offVMs      = $totalVMs - $runningVMs
            $totalHosts  = if ($hostInfoList) { @($hostInfoList).Count }                                                    else { 0 }
            $totalVCPUs  = if ($cpuInfo)      { ($cpuInfo | Measure-Object -Property CPUs -Sum).Sum }                      else { 0 }
            $totalRAM    = if ($memoryInfo)   { [math]::Round(($memoryInfo | Where-Object { $_.MemoryMB -gt 0 } | Measure-Object -Property MemoryMB -Sum -ErrorAction SilentlyContinue).Sum / 1024, 0) } else { 0 }
            $totalVHDs   = if ($VHDDriveMap)  { @($VHDDriveMap).Count }                                                    else { 0 }
            $activeSnaps = if ($checkpointInfo){ @($checkpointInfo).Count }                                                 else { 0 }
            $kpiVals = @($totalVMs, $runningVMs, $offVMs, $totalHosts, $totalVCPUs, $totalRAM, $totalVHDs, $activeSnaps)

            # Section header
            $summaryWs.Cells[4,1].Value = 'KEY METRICS'
            $summaryWs.Cells[4,1].Style.Font.Bold = $true
            $summaryWs.Cells[4,1].Style.Font.Size = 12

            for ($ki = 0; $ki -lt $kpiLabels.Count; $ki++) {
                $col = $ki + 1
                Set-SummaryCell $summaryWs 5 $col $kpiLabels[$ki] $true 10 '#1F4E79' '#FFFFFF'
                Set-SummaryCell $summaryWs 6 $col $kpiVals[$ki]   $true 14 '#DEEAF1' '#1F4E79'
                $summaryWs.Column($col).Width = 16
            }

            # --- Issues Block (row 9) ---
            [int]$criticalCount  = if ($adAuthIssuesList)    { @($adAuthIssuesList | Where-Object { $_.Severity -eq 'Critical' }).Count }              else { 0 }
            [int]$criticalCount += if ($ComplianceIssues)    { @($ComplianceIssues | Where-Object { $_.Severity -eq 'Critical' }).Count }              else { 0 }
            [int]$warningCount   = if ($adAuthIssuesList)    { @($adAuthIssuesList | Where-Object { $_.Severity -eq 'Warning'  }).Count }              else { 0 }
            [int]$warningCount  += if ($securityCompliance)  { @($securityCompliance | Where-Object { $_.Severity -eq 'Warning' }).Count }              else { 0 }
            [int]$snapshotCrit   = if ($checkpointInfo)      { @($checkpointInfo | Where-Object { $_.Warning -like 'CRITICAL*' }).Count }              else { 0 }
            [int]$snapshotWarn   = if ($checkpointInfo)      { @($checkpointInfo | Where-Object { $_.Warning -like 'WARNING*'  }).Count }              else { 0 }
            [int]$storageHighRisk= if ($StorageAnalysis)     { @($StorageAnalysis | Where-Object { $_.RiskLevel -in 'CRITICAL','HIGH' }).Count }       else { 0 }
            [int]$winrmFail      = if ($winrmHealth)         { @($winrmHealth | Where-Object { $_.AlertLevel -ne 'OK' }).Count }                        else { 0 }
            [int]$unavailHosts   = if ($UnavailableHosts)    { @($UnavailableHosts).Count }                                                              else { 0 }

            $summaryWs.Cells[9,1].Value  = 'ISSUES REQUIRING ATTENTION'
            $summaryWs.Cells[9,1].Style.Font.Bold = $true
            $summaryWs.Cells[9,1].Style.Font.Size = 12

            # v3.10.6 CR86: Changed from @() fixed array to List[object] to fix op_Addition bug.
            # The original @() created a [System.Object[]] which doesn't support += inside
            # certain PowerShell scopes (try/catch blocks), causing "does not contain a method
            # named 'op_Addition'" errors. DNS Critical and Offline Disk issue rows were silently
            # dropped from the Exec Summary.
            $issueItems = [System.Collections.Generic.List[object]]::new()
            $issueItems.Add(@{ Label='Critical Security Issues';    Val=$criticalCount;   Tab='AD-Auth-Issues';    BG=if($criticalCount -gt 0){'#FF6B6B'}else{'#E8F5E9'}; FG=if($criticalCount -gt 0){'#FFFFFF'}else{'#2E7D32'} })
            $issueItems.Add(@{ Label='Warning Issues';              Val=$warningCount;    Tab='Security-Compliance'; BG=if($warningCount -gt 0){'#FFF3CD'}else{'#E8F5E9'}; FG=if($warningCount -gt 0){'#856404'}else{'#2E7D32'} })
            $issueItems.Add(@{ Label='Snapshots >30d (CRITICAL)';   Val=$snapshotCrit;    Tab='vCheckpoint';         BG=if($snapshotCrit -gt 0){'#FF6B6B'}else{'#E8F5E9'}; FG=if($snapshotCrit -gt 0){'#FFFFFF'}else{'#2E7D32'} })
            $issueItems.Add(@{ Label='Snapshots >7d (WARNING)';     Val=$snapshotWarn;    Tab='vCheckpoint';         BG=if($snapshotWarn -gt 0){'#FFF3CD'}else{'#E8F5E9'}; FG=if($snapshotWarn -gt 0){'#856404'}else{'#2E7D32'} })
            $issueItems.Add(@{ Label='Storage HIGH/CRITICAL Vols';  Val=$storageHighRisk; Tab='Host-Storage-Risk';   BG=if($storageHighRisk -gt 0){'#FFE0E0'}else{'#E8F5E9'}; FG=if($storageHighRisk -gt 0){'#CC0000'}else{'#2E7D32'} })
            $issueItems.Add(@{ Label='WinRM Health Alerts';         Val=$winrmFail;       Tab='WinRM-Health';         BG=if($winrmFail -gt 0){'#FFF3CD'}else{'#E8F5E9'}; FG=if($winrmFail -gt 0){'#856404'}else{'#2E7D32'} })
            $issueItems.Add(@{ Label='Unavailable Hosts';           Val=$unavailHosts;    Tab='Unavailable-Hosts';   BG=if($unavailHosts -gt 0){'#FFE0E0'}else{'#E8F5E9'}; FG=if($unavailHosts -gt 0){'#CC0000'}else{'#2E7D32'} })

            # v3.10.3: Add DNS Critical count if DNS validation ran
            [int]$dnsCritCount = if ($DNSValidationData -and $DNSValidationData.DNSRows) { @($DNSValidationData.DNSRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count } else { 0 }
            if ($dnsCritCount -gt 0) {
                $issueItems.Add(@{ Label='DNS Missing Records (CRITICAL)'; Val=$dnsCritCount; Tab='DNS-Validation'; BG='#FFE0E0'; FG='#CC0000' })
            }
            # v3.10.4: Add offline disk count if any found
            [int]$offlineDiskCount = if ($OfflineDiskData) { @($OfflineDiskData).Count } else { 0 }
            [int]$offlineDiskVMs   = if ($OfflineDiskData) { @($OfflineDiskData | Select-Object -Property VMName -Unique).Count } else { 0 }
            if ($offlineDiskCount -gt 0) {
                $issueItems.Add(@{ Label="VMs with Offline Disks ($offlineDiskVMs VMs, $offlineDiskCount disks)"; Val=$offlineDiskVMs; Tab='VM-Offline-Disks'; BG='#FF6B6B'; FG='#FFFFFF' })
            }

            for ($ii = 0; $ii -lt $issueItems.Count; $ii++) {
                $row = 10 + $ii
                $item = $issueItems[$ii]
                Set-SummaryCell $summaryWs $row 1 $item.Label $false 10
                Set-SummaryCell $summaryWs $row 2 $item.Val   $true  12 $item.BG $item.FG
                Set-SummaryCell $summaryWs $row 3 "-> See: $($item.Tab)" $false 10
            }
            $summaryWs.Column(1).Width = 32
            $summaryWs.Column(2).Width = 12
            $summaryWs.Column(3).Width = 28

            # --- Chart data tables (row 20+) ---
            # Chart 1: VM State distribution (Running/Off/Paused/Saved)
            $chartDataRow = 20
            $summaryWs.Cells[$chartDataRow, 5].Value = 'VM State'
            $summaryWs.Cells[$chartDataRow, 6].Value = 'Count'
            $summaryWs.Cells[$chartDataRow, 5].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 6].Style.Font.Bold = $true
            $vmStates = if ($vmInfo) { @(
                @{ Label='Running';  Filter='poweredOn' }
                @{ Label='Off';      Filter='poweredOff' }
                @{ Label='Paused';   Filter='Paused' }
                @{ Label='Saved';    Filter='Saved' }
                @{ Label='UNKNOWN';  Filter='__OTHER__' }
            ) } else { @() }
            $chartR = $chartDataRow + 1
            foreach ($st in $vmStates) {
                $cnt = if ($st.Filter -eq '__OTHER__') {
                    if ($vmInfo) { @($vmInfo | Where-Object { $_.Powerstate -notin 'poweredOn','poweredOff','Paused','Saved' }).Count } else { 0 }
                } else {
                    if ($vmInfo) { @($vmInfo | Where-Object { $_.Powerstate -eq $st.Filter }).Count } else { 0 }
                }
                $summaryWs.Cells[$chartR, 5].Value = $st.Label
                $summaryWs.Cells[$chartR, 6].Value = $cnt
                $chartR++
            }
            # Chart 2: Storage Risk distribution
            $summaryWs.Cells[$chartDataRow, 8].Value  = 'Storage Risk'
            $summaryWs.Cells[$chartDataRow, 9].Value  = 'Volumes'
            $summaryWs.Cells[$chartDataRow, 8].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 9].Style.Font.Bold = $true
            $riskLevels = @('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')
            $chartR2 = $chartDataRow + 1
            foreach ($rl in $riskLevels) {
                $cnt = if ($StorageAnalysis) { @($StorageAnalysis | Where-Object { $_.RiskLevel -eq $rl }).Count } else { 0 }
                $summaryWs.Cells[$chartR2, 8].Value = $rl
                $summaryWs.Cells[$chartR2, 9].Value = $cnt
                $chartR2++
            }
            # Chart 3: Checkpoint age distribution
            $summaryWs.Cells[$chartDataRow, 11].Value  = 'Checkpoint Age'
            $summaryWs.Cells[$chartDataRow, 12].Value  = 'Count'
            $summaryWs.Cells[$chartDataRow, 11].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 12].Style.Font.Bold = $true
            $cpBuckets = [ordered]@{ '>30 days'=0; '8-30 days'=0; '0-7 days'=0 }
            if ($checkpointInfo) {
                foreach ($cp in $checkpointInfo) {
                    if ($cp.AgeDays -gt 30)    { $cpBuckets['>30 days']++ }
                    elseif ($cp.AgeDays -gt 7) { $cpBuckets['8-30 days']++ }
                    else                        { $cpBuckets['0-7 days']++ }
                }
            }
            $chartR3 = $chartDataRow + 1
            foreach ($bk in $cpBuckets.Keys) {
                $summaryWs.Cells[$chartR3, 11].Value = $bk
                $summaryWs.Cells[$chartR3, 12].Value = $cpBuckets[$bk]
                $chartR3++
            }
            # Chart 4: OS version spread  
            $summaryWs.Cells[$chartDataRow, 14].Value  = 'OS Version'
            $summaryWs.Cells[$chartDataRow, 15].Value  = 'Count'
            $summaryWs.Cells[$chartDataRow, 14].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 15].Style.Font.Bold = $true
            # v3.9.5 CR60: Merge vInfo GuestOS with OS-Inventory for complete coverage
            #   - OS-Inventory has WinRM-collected data (182 VMs) with full edition info
            #   - vInfo GuestOS has Hyper-V integration services data (255 VMs) including Linux
            #   - Merge: use OS-Inventory OSName where available, fall back to vInfo GuestOS
            $osAllEntries = [System.Collections.Generic.List[string]]::new()
            $osInventoryVMs = @{}
            if ($osInventory) {
                foreach ($oi in $osInventory) {
                    $vmKey = if ($oi.VM) { $oi.VM.ToString().Trim() } else { '' }
                    if ($vmKey -and $oi.OSName) {
                        $osInventoryVMs[$vmKey] = $oi.OSName.ToString().Trim()
                        $osAllEntries.Add($oi.OSName.ToString().Trim())
                    }
                }
            }
            if ($vmInfo) {
                foreach ($vi in $vmInfo) {
                    $vmKey = if ($vi.VM) { $vi.VM.ToString().Trim() } else { '' }
                    if ($vmKey -and -not $osInventoryVMs.ContainsKey($vmKey)) {
                        $gos = if ($vi.GuestOS) { $vi.GuestOS.ToString().Trim() } else { '' }
                        if ($gos -and $gos -ne 'Unknown') {
                            $osAllEntries.Add($gos)
                        }
                    }
                }
            }
            $osGroups = if ($osAllEntries.Count -gt 0) {
                $osAllEntries | ForEach-Object {
                    $raw = $_
                    $short = $raw
                    if ($raw -match 'Windows Server (\d{4})') {
                        $yr = $Matches[1]
                        $ed = if ($raw -match 'Datacenter') { 'DC' }
                              elseif ($raw -match 'Standard') { 'Std' }
                              elseif ($raw -match 'Foundation') { 'Fnd' }
                              elseif ($raw -match 'Essentials') { 'Ess' }
                              elseif ($raw -match 'Small Business') { 'SBS' }
                              else { '' }
                        $short = "Server $yr $ed".Trim()
                    }
                    elseif ($raw -match '(?i)(Ubuntu|Oracle|Red\s*Hat|CentOS|SUSE|SLES|Debian|Alma|Rocky|Fedora|Amazon)\s*(?:Linux\s*(?:Server\s*)?)?(\d[\d\.]*)?') {
                        $distro = $Matches[1]
                        $ver = if ($Matches[2]) { " $($Matches[2] -replace '\..*$','')" } else { '' }
                        $short = "$distro$ver"
                    }
                    elseif ($raw -match '(?i)linux') {
                        $short = 'Linux (other)'
                    }
                    elseif ($raw -match '(?i)Server\s*2003') {
                        $short = 'Server 2003'
                    }
                    elseif ($raw -eq 'Unknown' -or [string]::IsNullOrWhiteSpace($raw)) {
                        $short = 'Unknown'
                    }
                    [PSCustomObject]@{ OSShort = $short }
                } | Group-Object OSShort | Sort-Object Count -Descending
            } else { @() }
            $chartR4 = $chartDataRow + 1
            foreach ($og in $osGroups) {
                $summaryWs.Cells[$chartR4, 14].Value = $og.Name
                $summaryWs.Cells[$chartR4, 15].Value = $og.Count
                $chartR4++
            }

            # v3.9.5 CR59: Additional chart data (columns 17-24)
            # Chart 5 data: TLS Compliance
            $summaryWs.Cells[$chartDataRow, 17].Value = 'TLS Status'
            $summaryWs.Cells[$chartDataRow, 18].Value = 'Count'
            $summaryWs.Cells[$chartDataRow, 17].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 18].Style.Font.Bold = $true
            $tlsCompliant    = if ($tlsComplianceData) { @($tlsComplianceData | Where-Object { $_.OverallStatus -eq 'Compliant' }).Count } else { 0 }
            $tlsPartial      = if ($tlsComplianceData) { @($tlsComplianceData | Where-Object { $_.OverallStatus -eq 'Partial' }).Count } else { 0 }
            $tlsNonCompliant = if ($tlsComplianceData) { @($tlsComplianceData | Where-Object { $_.OverallStatus -ne 'Compliant' -and $_.OverallStatus -ne 'Partial' }).Count } else { 0 }
            $summaryWs.Cells[($chartDataRow+1), 17].Value = 'Compliant';     $summaryWs.Cells[($chartDataRow+1), 18].Value = $tlsCompliant
            $summaryWs.Cells[($chartDataRow+2), 17].Value = 'Partial';       $summaryWs.Cells[($chartDataRow+2), 18].Value = $tlsPartial
            $summaryWs.Cells[($chartDataRow+3), 17].Value = 'Non-Compliant'; $summaryWs.Cells[($chartDataRow+3), 18].Value = $tlsNonCompliant

            # Chart 6 data: Cross-Domain Auth
            $summaryWs.Cells[$chartDataRow, 20].Value = 'Auth Status'
            $summaryWs.Cells[$chartDataRow, 21].Value = 'Count'
            $summaryWs.Cells[$chartDataRow, 20].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 21].Style.Font.Bold = $true
            $cdOK   = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'OK' }).Count
            $cdWarn = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
            $cdCrit = @($crossDomainAuth | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            $cdOff  = @($crossDomainAuth | Where-Object { $_.AlertLevel -match 'Off' }).Count
            $summaryWs.Cells[($chartDataRow+1), 20].Value = 'OK';       $summaryWs.Cells[($chartDataRow+1), 21].Value = $cdOK
            $summaryWs.Cells[($chartDataRow+2), 20].Value = 'Warning';  $summaryWs.Cells[($chartDataRow+2), 21].Value = $cdWarn
            $summaryWs.Cells[($chartDataRow+3), 20].Value = 'Critical'; $summaryWs.Cells[($chartDataRow+3), 21].Value = $cdCrit
            $summaryWs.Cells[($chartDataRow+4), 20].Value = 'Off';      $summaryWs.Cells[($chartDataRow+4), 21].Value = $cdOff

            # Chart 7 data: NTLM Readiness
            $summaryWs.Cells[$chartDataRow, 23].Value = 'NTLM Status'
            $summaryWs.Cells[$chartDataRow, 24].Value = 'Count'
            $summaryWs.Cells[$chartDataRow, 23].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 24].Style.Font.Bold = $true
            $ntlmReady   = if ($ntlmReadinessData) { @($ntlmReadinessData | Where-Object { $_.ReadinessScore -eq 'Ready' }).Count } else { 0 }
            $ntlmWork    = if ($ntlmReadinessData) { @($ntlmReadinessData | Where-Object { $_.ReadinessScore -eq 'Needs-Work' }).Count } else { 0 }
            $ntlmBlocked = if ($ntlmReadinessData) { @($ntlmReadinessData | Where-Object { $_.ReadinessScore -eq 'Blocked' }).Count } else { 0 }
            $summaryWs.Cells[($chartDataRow+1), 23].Value = 'Ready';      $summaryWs.Cells[($chartDataRow+1), 24].Value = $ntlmReady
            $summaryWs.Cells[($chartDataRow+2), 23].Value = 'Needs-Work'; $summaryWs.Cells[($chartDataRow+2), 24].Value = $ntlmWork
            $summaryWs.Cells[($chartDataRow+3), 23].Value = 'Blocked';    $summaryWs.Cells[($chartDataRow+3), 24].Value = $ntlmBlocked

            # Chart 8 data: IOPS Utilization
            $summaryWs.Cells[$chartDataRow, 26].Value = 'IOPS Status'
            $summaryWs.Cells[$chartDataRow, 27].Value = 'Hosts'
            $summaryWs.Cells[$chartDataRow, 26].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 27].Style.Font.Bold = $true
            $iopsOK = 0; $iopsMonitor = 0; $iopsWarn = 0; $iopsCrit = 0
            if ($resourceMeteringData -and $resourceMeteringData.IOPSRecommendations) {
                foreach ($rec in $resourceMeteringData.IOPSRecommendations) {
                    switch -Wildcard ($rec.Assessment) {
                        'OK*'       { $iopsOK++ }
                        'Monitor*'  { $iopsMonitor++ }
                        'Warning*'  { $iopsWarn++ }
                        'Critical*' { $iopsCrit++ }
                        default     { $iopsOK++ }
                    }
                }
            }
            $summaryWs.Cells[($chartDataRow+1), 26].Value = 'OK';       $summaryWs.Cells[($chartDataRow+1), 27].Value = $iopsOK
            $summaryWs.Cells[($chartDataRow+2), 26].Value = 'Monitor';  $summaryWs.Cells[($chartDataRow+2), 27].Value = $iopsMonitor
            $summaryWs.Cells[($chartDataRow+3), 26].Value = 'Warning';  $summaryWs.Cells[($chartDataRow+3), 27].Value = $iopsWarn
            $summaryWs.Cells[($chartDataRow+4), 26].Value = 'Critical'; $summaryWs.Cells[($chartDataRow+4), 27].Value = $iopsCrit

            # v3.9.7 CR67: Chart 9 data: Cluster Health
            $summaryWs.Cells[$chartDataRow, 29].Value = 'Cluster Status'
            $summaryWs.Cells[$chartDataRow, 30].Value = 'Count'
            $summaryWs.Cells[$chartDataRow, 29].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 30].Style.Font.Bold = $true
            $clsActive = 0; $clsNonHV = 0; $clsStale = 0; $clsOther = 0
            if ($ClusterData) {
                foreach ($cls in $ClusterData) {
                    $st = if ($cls.Status) { $cls.Status.ToString() } else { '' }
                    if     ($st -match 'Active.*HV|^Active$')   { $clsActive++ }
                    elseif ($st -match 'Active.*Non')            { $clsNonHV++ }
                    elseif ($st -match 'Stale')                  { $clsStale++ }
                    else                                          { $clsOther++ }
                }
            }
            $summaryWs.Cells[($chartDataRow+1), 29].Value = 'Active (HV)';  $summaryWs.Cells[($chartDataRow+1), 30].Value = $clsActive
            $summaryWs.Cells[($chartDataRow+2), 29].Value = 'Active (Non-HV)'; $summaryWs.Cells[($chartDataRow+2), 30].Value = $clsNonHV
            $summaryWs.Cells[($chartDataRow+3), 29].Value = 'Stale';        $summaryWs.Cells[($chartDataRow+3), 30].Value = $clsStale
            $summaryWs.Cells[($chartDataRow+4), 29].Value = 'Other';        $summaryWs.Cells[($chartDataRow+4), 30].Value = $clsOther

            # v3.10.3: Chart 10 data: DNS Validation
            $summaryWs.Cells[$chartDataRow, 32].Value = 'DNS Status'
            $summaryWs.Cells[$chartDataRow, 33].Value = 'Count'
            $summaryWs.Cells[$chartDataRow, 32].Style.Font.Bold = $true
            $summaryWs.Cells[$chartDataRow, 33].Style.Font.Bold = $true
            [int]$dnsChartOK = 0; [int]$dnsChartWarn = 0; [int]$dnsChartCrit = 0
            if ($DNSValidationData -and $DNSValidationData.DNSRows) {
                $dnsChartOK   = @($DNSValidationData.DNSRows | Where-Object { $_.AlertLevel -eq 'OK' }).Count
                $dnsChartWarn = @($DNSValidationData.DNSRows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
                $dnsChartCrit = @($DNSValidationData.DNSRows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
            }
            $summaryWs.Cells[($chartDataRow+1), 32].Value = 'OK';       $summaryWs.Cells[($chartDataRow+1), 33].Value = $dnsChartOK
            $summaryWs.Cells[($chartDataRow+2), 32].Value = 'Warning';  $summaryWs.Cells[($chartDataRow+2), 33].Value = $dnsChartWarn
            $summaryWs.Cells[($chartDataRow+3), 32].Value = 'Critical'; $summaryWs.Cells[($chartDataRow+3), 33].Value = $dnsChartCrit

            # =============================================================
            # v3.10.3: Charts -- all 600x400, 5 rows of 2
            Write-HVLog "  DEBUG: Building 10 Exec Summary charts..." -Level Info
            # Row 1 (27):  VM State, Storage Risk
            # Row 2 (49):  Checkpoint Age, OS Distribution
            # Row 3 (71):  TLS Compliance, Cross-Domain Auth
            # Row 4 (93):  NTLM Readiness, IOPS Utilization
            # Row 5 (115): Cluster Health, DNS Validation
            # =============================================================

            # Chart 1: VM State pie
            $vmStateRange      = $summaryWs.Cells["F$(($chartDataRow+1)):F$(($chartDataRow+4))"]
            $vmStateLabelRange = $summaryWs.Cells["E$(($chartDataRow+1)):E$(($chartDataRow+4))"]
            try {
                $chart1 = $summaryWs.Drawings.AddChart('VMStateChart', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
                $chart1.Title.Text = 'VM State Distribution'
                $s1 = $chart1.Series.Add($vmStateRange, $vmStateLabelRange)
                $s1.Header = 'VMs'
                $chart1.SetPosition(27, 0, 0, 0)
                $chart1.SetSize(600, 400)
                $chart1.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
            } catch {}

            # Chart 2: Storage risk bar
            $storRiskRange  = $summaryWs.Cells["I$(($chartDataRow+1)):I$(($chartDataRow+5))"]
            $storLabelRange = $summaryWs.Cells["H$(($chartDataRow+1)):H$(($chartDataRow+5))"]
            try {
                $chart2 = $summaryWs.Drawings.AddChart('StorageRiskChart', [OfficeOpenXml.Drawing.Chart.eChartType]::BarClustered)
                $chart2.Title.Text = 'Storage Volume Risk Levels'
                $s2 = $chart2.Series.Add($storRiskRange, $storLabelRange)
                $s2.Header = 'Volumes'
                $chart2.SetPosition(27, 0, 8, 0)
                $chart2.SetSize(600, 400)
                $chart2.PlotArea.ChartTypes[0].Axis[0].Orientation = [OfficeOpenXml.Drawing.Chart.eAxisOrientation]::MaxMin
            } catch {}

            # Chart 3: Checkpoint age bar
            $cpRange      = $summaryWs.Cells["L$(($chartDataRow+1)):L$(($chartDataRow+3))"]
            $cpLabelRange = $summaryWs.Cells["K$(($chartDataRow+1)):K$(($chartDataRow+3))"]
            try {
                $chart3 = $summaryWs.Drawings.AddChart('CheckpointChart', [OfficeOpenXml.Drawing.Chart.eChartType]::BarClustered)
                $chart3.Title.Text = 'Checkpoint Age Buckets'
                $s3 = $chart3.Series.Add($cpRange, $cpLabelRange)
                $s3.Header = 'Checkpoints'
                $chart3.SetPosition(49, 0, 0, 0)
                $chart3.SetSize(600, 400)
            } catch {}

            # Chart 4: OS spread bar (v3.9.5 CR60: no entry cap, includes Linux)
            $osRowEnd     = $chartDataRow + [math]::Max(1, $osGroups.Count)
            $osRange      = $summaryWs.Cells["O$(($chartDataRow+1)):O$osRowEnd"]
            $osLabelRange = $summaryWs.Cells["N$(($chartDataRow+1)):N$osRowEnd"]
            try {
                $chart4 = $summaryWs.Drawings.AddChart('OSChart', [OfficeOpenXml.Drawing.Chart.eChartType]::BarClustered)
                $chart4.Title.Text = 'VM Operating System Distribution'
                $s4 = $chart4.Series.Add($osRange, $osLabelRange)
                $s4.Header = 'VMs'
                $chart4.SetPosition(49, 0, 8, 0)
                $chart4.SetSize(600, 400)
            } catch {}

            # v3.9.5 CR59: Additional charts (Row 3 + Row 4)

            # Chart 5: TLS Compliance pie
            try {
                $chart5 = $summaryWs.Drawings.AddChart('TLSChart', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
                $chart5.Title.Text = 'TLS Compliance'
                $s5 = $chart5.Series.Add($summaryWs.Cells["R$(($chartDataRow+1)):R$(($chartDataRow+3))"], $summaryWs.Cells["Q$(($chartDataRow+1)):Q$(($chartDataRow+3))"])
                $s5.Header = 'Hosts'
                $chart5.SetPosition(71, 0, 0, 0)
                $chart5.SetSize(600, 400)
                $chart5.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
            } catch {}

            # Chart 6: Cross-Domain Auth pie
            try {
                $chart6 = $summaryWs.Drawings.AddChart('CrossDomainChart', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
                $chart6.Title.Text = 'Cross-Domain Authentication'
                $s6 = $chart6.Series.Add($summaryWs.Cells["U$(($chartDataRow+1)):U$(($chartDataRow+4))"], $summaryWs.Cells["T$(($chartDataRow+1)):T$(($chartDataRow+4))"])
                $s6.Header = 'VMs'
                $chart6.SetPosition(71, 0, 8, 0)
                $chart6.SetSize(600, 400)
                $chart6.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
            } catch {}

            # Chart 7: NTLM Readiness pie
            try {
                $chart7 = $summaryWs.Drawings.AddChart('NTLMChart', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
                $chart7.Title.Text = 'NTLM Deprecation Readiness'
                $s7 = $chart7.Series.Add($summaryWs.Cells["X$(($chartDataRow+1)):X$(($chartDataRow+3))"], $summaryWs.Cells["W$(($chartDataRow+1)):W$(($chartDataRow+3))"])
                $s7.Header = 'Machines'
                $chart7.SetPosition(93, 0, 0, 0)
                $chart7.SetSize(600, 400)
                $chart7.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
            } catch {}

            # Chart 8: IOPS Utilization bar
            try {
                $chart8 = $summaryWs.Drawings.AddChart('IOPSChart', [OfficeOpenXml.Drawing.Chart.eChartType]::BarClustered)
                $chart8.Title.Text = 'IOPS Capacity Utilization'
                $s8 = $chart8.Series.Add($summaryWs.Cells["AA$(($chartDataRow+1)):AA$(($chartDataRow+4))"], $summaryWs.Cells["Z$(($chartDataRow+1)):Z$(($chartDataRow+4))"])
                $s8.Header = 'Hosts'
                $chart8.SetPosition(93, 0, 8, 0)
                $chart8.SetSize(600, 400)
            } catch {}

            # v3.9.7 CR67: Chart 9: Cluster Health pie
            try {
                $chart9 = $summaryWs.Drawings.AddChart('ClusterChart', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
                $chart9.Title.Text = 'Cluster Health'
                $s9 = $chart9.Series.Add($summaryWs.Cells["AD$(($chartDataRow+1)):AD$(($chartDataRow+4))"], $summaryWs.Cells["AC$(($chartDataRow+1)):AC$(($chartDataRow+4))"])
                $s9.Header = 'Clusters'
                $chart9.SetPosition(115, 0, 0, 0)
                $chart9.SetSize(600, 400)
                $chart9.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
            } catch {}

            # v3.10.3: Chart 10: DNS Validation pie
            try {
                $chart10 = $summaryWs.Drawings.AddChart('DNSChart', [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
                $chart10.Title.Text = 'DNS Validation'
                $s10 = $chart10.Series.Add($summaryWs.Cells["AG$(($chartDataRow+1)):AG$(($chartDataRow+3))"], $summaryWs.Cells["AF$(($chartDataRow+1)):AF$(($chartDataRow+3))"])
                $s10.Header = 'Targets'
                $chart10.SetPosition(115, 0, 8, 0)
                $chart10.SetSize(600, 400)
                $chart10.Legend.Position = [OfficeOpenXml.Drawing.Chart.eLegendPosition]::Right
            } catch {}

            # --------------------------------------------------------
            # Q4d: Tab reorder using Move-ExcelWorksheet
            # Target order (grouped by function):
            # 00-Executive-Summary
            # VM: vInfo, vCPU, vMemory, vDisk, vCheckpoint, vDVD, vIntegration, vReplication
            # Host: vHost, vNetwork, vSwitch-Config, vCluster, Live-Migration, Host-NIC-Audit
            # Storage: vStorage, Host-Storage-Risk, Storage-VHD-Detail, vDisk-Analysis, VM-Guest-Storage, VHD-Drive-Map
            # S2D: S2D-Storage-Audit, S2D-Config-Summary
            # IOPS: VM-IOPS-Summary, VM-IOPS-PerDisk, Host-IOPS-Summary, IOPS-Recommendations
            # OS/SW: OS-Inventory, Roles-Features, Applications-Windows, Applications-Linux, Services, Services-Alerts, Scheduled-Tasks
            # Security: Security-Compliance, WinRM-Health, Local-Admins, AD-Auth-Detail, AD-Auth-Issues
            # Kerberos: SPN-Inventory, DoubleHop-Map, NTLM-Elimination, Remediation-Commands, DC-GUID-Validation
            # Analysis: CPU-Analysis, Recommendations, Compliance-Issues, Missing-VMs, Reboot-History
            # Admin: Summary, Unavailable-Hosts
            # --------------------------------------------------------
            $tabOrder = @(
                '00-Executive-Summary'
                '01-Index'
                'Legend'
                'vInfo', 'vCPU', 'vMemory', 'vDisk', 'vCheckpoint', 'VHD-Chain', 'vDVD', 'vIntegration', 'vReplication', 'VM-Activity-Audit', 'VM-Offline-Disks'
                'vHost', 'vNetwork', 'vSwitch-Config', 'vCluster', 'Live-Migration', 'Host-NIC-Audit'
                'vStorage', 'Host-Storage-Risk', 'Storage-VHD-Detail', 'vDisk-Analysis', 'VM-Guest-Storage', 'VHD-Drive-Map'
                'S2D-Storage-Audit', 'S2D-Config-Summary', 'Disk-Format-Config'
                'VM-IOPS-Summary', 'VM-IOPS-PerDisk', 'Host-IOPS-Summary', 'IOPS-Recommendations', 'IOPS-Trends', 'IOPS-Heatmap'
                'OS-Inventory', 'Roles-Features', 'Applications-Windows', 'Applications-Linux', 'Services', 'Services-Alerts', 'Scheduled-Tasks'
                'Security-Compliance', 'WinRM-Health', 'Local-Builtin', 'RBAC-Compliance', 'Local-Admins', 'AD-Auth-Detail', 'AD-Auth-Issues'
                'SPN-Inventory', 'DoubleHop-Map', 'NTLM-Elimination', 'NTLM-Readiness', 'SPN-ServiceAccounts', 'SPN-Inventory-Full', 'KCD-Validation', 'Cross-Domain-Auth', 'DNS-Validation', 'Remediation-Commands', 'DC-GUID-Validation'
                'TLS-Compliance', 'TLS-Recommendations'
                'LAPS-Usage'
                'Permissions-Groups', 'Permissions-Privileges', 'Permissions-Security'
                'SCCM-Status', 'AD-Info'
                'CPU-Analysis', 'Recommendations', 'Compliance-Issues', 'Missing-VMs', 'Reboot-History'
                'Summary', 'Unavailable-Hosts'
            )

            # Apply tab colouring by group
            $tabGroupColours = @{
                '00-Executive-Summary' = '1F4E79'
                '01-Index'             = '1F4E79'
                'Legend'               = '1F4E79'
                'vInfo' = '2E75B6'; 'vCPU' = '2E75B6'; 'vMemory' = '2E75B6'; 'vDisk' = '2E75B6'
                'vCheckpoint' = 'C00000'; 'VHD-Chain' = 'C00000'; 'vDVD' = '2E75B6'; 'vIntegration' = '2E75B6'; 'vReplication' = '2E75B6'
                'VM-Activity-Audit' = '2E75B6'
                'VM-Offline-Disks' = 'C00000'
                'vHost' = '375623'; 'vNetwork' = '375623'; 'vSwitch-Config' = '375623'; 'vCluster' = '375623'
                'Live-Migration' = '375623'; 'Host-NIC-Audit' = '375623'
                'vStorage' = '7030A0'; 'Host-Storage-Risk' = '7030A0'; 'Storage-VHD-Detail' = '7030A0'
                'vDisk-Analysis' = '7030A0'; 'VM-Guest-Storage' = '7030A0'; 'VHD-Drive-Map' = '7030A0'
                'S2D-Storage-Audit' = '7030A0'; 'S2D-Config-Summary' = '7030A0'; 'Disk-Format-Config' = '7030A0'
                'VM-IOPS-Summary' = '0E6655'; 'VM-IOPS-PerDisk' = '0E6655'
                'Host-IOPS-Summary' = '0E6655'; 'IOPS-Recommendations' = '0E6655'
                'IOPS-Trends' = '0E6655'; 'IOPS-Heatmap' = '0E6655'
                'OS-Inventory' = '833C00'; 'Roles-Features' = '833C00'; 'Applications-Windows' = '833C00'
                'Applications-Linux' = '833C00'; 'Services' = '833C00'; 'Services-Alerts' = '833C00'; 'Scheduled-Tasks' = '833C00'
                'Security-Compliance' = 'C55A11'; 'WinRM-Health' = 'C55A11'; 'Local-Admins' = 'C55A11'
                'Local-Builtin' = 'C55A11'; 'RBAC-Compliance' = 'C55A11'
                'AD-Auth-Detail' = 'C55A11'; 'AD-Auth-Issues' = 'C55A11'
                'SPN-Inventory' = '833C00'; 'DoubleHop-Map' = '833C00'; 'NTLM-Elimination' = '833C00'
                'NTLM-Readiness' = '833C00'; 'SPN-ServiceAccounts' = '833C00'; 'KCD-Validation' = '833C00'
                'SPN-Inventory-Full' = '833C00'  # v3.10.12 OPEN-66: AD-wide SPN inventory -> Kerberos group
                'Remediation-Commands' = '833C00'; 'DC-GUID-Validation' = '833C00'; 'Cross-Domain-Auth' = '833C00'; 'DNS-Validation' = '833C00'
                'TLS-Compliance' = 'C55A11'; 'TLS-Recommendations' = 'C55A11'
                'LAPS-Usage' = 'C55A11'          # v3.10.11 CR102: LAPS posture audit -> Security group
                'Permissions-Groups' = 'C55A11'  # v3.10.12 OPEN-60: Local group membership audit -> Security group
                'Permissions-Privileges' = 'C55A11' # v3.10.12 OPEN-60: User rights audit -> Security group
                'Permissions-Security' = 'C55A11'   # v3.10.12: Security Options (secedit) -> Security group
                'SCCM-Status' = '548235'
                'AD-Info' = '548235'              # v3.10.11: AD Forest/Domain info -> Infrastructure Mgmt group
                'CPU-Analysis' = '404040'; 'Recommendations' = '404040'; 'Compliance-Issues' = '404040'
                'Missing-VMs' = '404040'; 'Reboot-History' = '404040'
                'Summary' = '404040'; 'Unavailable-Hosts' = 'C00000'
            }

            # Move worksheets into desired order
            Write-HVLog "  DEBUG: Starting tab reorder ($($tabOrder.Count) tabs)..." -Level Info
            $pos = 1
            foreach ($tabName in $tabOrder) {
                $ws = $pkg.Workbook.Worksheets[$tabName]
                if ($ws) {
                    # Apply tab colour
                    $colHex = $tabGroupColours[$tabName]
                    if ($colHex) {
                        $ws.TabColor = [System.Drawing.Color]::FromArgb(
                            [System.Convert]::ToInt32($colHex.Substring(0,2),16),
                            [System.Convert]::ToInt32($colHex.Substring(2,2),16),
                            [System.Convert]::ToInt32($colHex.Substring(4,2),16)
                        )
                    }
                    $pkg.Workbook.Worksheets.MoveToStart($tabName) | Out-Null
                }
            }
            # MoveToStart puts them at position 1 in reverse, so reverse our order first
            # Redo: move in reverse order so position 1 ends up correct
            $reversedOrder = [array]::Reverse($tabOrder.Clone()); $reversedOrder = $tabOrder[$($tabOrder.Count-1)..0]
            foreach ($tabName in $reversedOrder) {
                $ws = $pkg.Workbook.Worksheets[$tabName]
                if ($ws) { $pkg.Workbook.Worksheets.MoveToStart($tabName) | Out-Null }
            }

            # Make Executive Summary the active sheet
            $execWs = $pkg.Workbook.Worksheets['00-Executive-Summary']
            if ($execWs) { $pkg.Workbook.View.ActiveTab = $execWs.Index - 1 }

            # v3.8.9: Apply tab colours to chunked tabs (Services_1of2, Applications-Windows_1of2, etc.)
            # These don't appear in $tabOrder by exact name, so match by prefix.
            foreach ($ws in $pkg.Workbook.Worksheets) {
                $wsName = $ws.Name
                # Skip if already colored (in $tabOrder)
                if ($tabGroupColours.ContainsKey($wsName)) { continue }
                # Check if it's a chunked tab (contains _NofM pattern)
                if ($wsName -match '^(.+)_\d+of\d+$') {
                    $baseName = $Matches[1]
                    $colHex = $tabGroupColours[$baseName]
                    if ($colHex) {
                        try {
                            $ws.TabColor = [System.Drawing.Color]::FromArgb(
                                [System.Convert]::ToInt32($colHex.Substring(0,2),16),
                                [System.Convert]::ToInt32($colHex.Substring(2,2),16),
                                [System.Convert]::ToInt32($colHex.Substring(4,2),16)
                            )
                        } catch {}
                    }
                }
            }

            # ============================================================
            # CR7: Build 01-Index tab -- color legend + per-tab directory
            Write-HVLog "  DEBUG: Building 01-Index tab..." -Level Info
            # ============================================================
            $indexWs = $pkg.Workbook.Worksheets.Add('01-Index')
            $r = 1

            # Title
            $indexWs.Cells[$r, 1].Value = 'Hyper-V Inventory Report - Tab Index & Color Legend'
            $indexWs.Cells[$r, 1].Style.Font.Size = 16
            $indexWs.Cells[$r, 1].Style.Font.Bold = $true
            $r += 1
            $indexWs.Cells[$r, 1].Value = 'Use this tab to navigate the workbook. Each tab is color-coded by category. Column headers on every data tab carry a comment (red triangle) explaining the data source.'
            $indexWs.Cells[$r, 1].Style.Font.Size = 10
            $indexWs.Cells[$r, 1].Style.Font.Italic = $true
            $r += 2

            # Helper: write a colored legend row
            function Write-IndexColorRow {
                param($ws, [int]$Row, [string]$ColorHex, [string]$GroupName, [string]$Description)
                $swatch = $ws.Cells[$Row, 1]
                $swatch.Value = '  '
                $swatch.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $swatch.Style.Fill.BackgroundColor.SetColor(
                    [System.Drawing.Color]::FromArgb(
                        [System.Convert]::ToInt32($ColorHex.Substring(0,2),16),
                        [System.Convert]::ToInt32($ColorHex.Substring(2,2),16),
                        [System.Convert]::ToInt32($ColorHex.Substring(4,2),16)))
                $ws.Cells[$Row, 2].Value = $GroupName
                $ws.Cells[$Row, 2].Style.Font.Bold = $true
                $ws.Cells[$Row, 3].Value = $Description
            }

            # COLOR LEGEND section header
            $indexWs.Cells[$r, 1].Value = 'TAB COLOR CODE LEGEND'
            $indexWs.Cells[$r, 1].Style.Font.Bold = $true
            $indexWs.Cells[$r, 1].Style.Font.Size = 13
            $r += 1

            $colorGroups = @(
                @{ Hex='1F4E79'; Name='Navigation';   Desc='00-Executive-Summary, 01-Index -- report overview and navigation' }
                @{ Hex='2E75B6'; Name='VM Data';       Desc='vInfo, vCPU, vMemory, vDisk, vCheckpoint, vDVD, vIntegration, vReplication -- per-VM configuration and state' }
                @{ Hex='C00000'; Name='VM Alerts';     Desc='vCheckpoint (red) -- checkpoints older than 7 days are flagged; Unavailable-Hosts (red)' }
                @{ Hex='375623'; Name='Host & Network';Desc='vHost, vNetwork, vSwitch-Config, vCluster, Live-Migration, Host-NIC-Audit -- physical host and network configuration' }
                @{ Hex='7030A0'; Name='Storage';       Desc='vStorage, Host-Storage-Risk, Storage-VHD-Detail, vDisk-Analysis, VM-Guest-Storage, VHD-Drive-Map, S2D-Storage-Audit, S2D-Config-Summary, Disk-Format-Config -- all storage tiers' }
                @{ Hex='0E6655'; Name='Performance / IOPS'; Desc='VM-IOPS-Summary, VM-IOPS-PerDisk, Host-IOPS-Summary, IOPS-Recommendations, IOPS-Trends, IOPS-Heatmap -- resource metering and storage performance' }
                @{ Hex='833C00'; Name='OS / Software / Kerberos'; Desc='OS-Inventory, Roles-Features, Applications, Services, Scheduled-Tasks, SPN-Inventory, DoubleHop-Map, NTLM-Elimination, NTLM-Readiness, SPN-ServiceAccounts, Remediation-Commands, DC-GUID-Validation' }
                @{ Hex='C55A11'; Name='Security';      Desc='Security-Compliance, WinRM-Health, Local-Builtin, RBAC-Compliance, Local-Admins, AD-Auth-Detail, AD-Auth-Issues, TLS-Compliance, TLS-Recommendations, LAPS-Usage -- access control, compliance, RBAC audit, secure channel audit, and LAPS posture' }
                @{ Hex='548235'; Name='Infrastructure Mgmt'; Desc='SCCM-Status, AD-Info -- SCCM/MECM client health, AD forest/domain topology and configuration' }
                @{ Hex='404040'; Name='Analysis / Admin'; Desc='CPU-Analysis, Recommendations, Compliance-Issues, Missing-VMs, Reboot-History, Summary, Unavailable-Hosts -- aggregated findings' }
            )
            foreach ($cg in $colorGroups) {
                Write-IndexColorRow $indexWs $r $cg.Hex $cg.Name $cg.Desc
                $r++
            }
            $r += 1

            # PER-TAB DIRECTORY
            $indexWs.Cells[$r, 1].Value = 'TAB DIRECTORY'
            $indexWs.Cells[$r, 1].Style.Font.Bold = $true
            $indexWs.Cells[$r, 1].Style.Font.Size = 13
            $r += 1

            # Column headers for the directory table
            foreach ($hdrText in @('Tab Name','Color Group','Report Level','Purpose','Data Source / Notes')) {
                $hdrCol = switch ($hdrText) {
                    'Tab Name'         { 1 }
                    'Color Group'      { 2 }
                    'Report Level'     { 3 }
                    'Purpose'          { 4 }
                    'Data Source / Notes' { 5 }
                }
                $indexWs.Cells[$r, $hdrCol].Value = $hdrText
                $indexWs.Cells[$r, $hdrCol].Style.Font.Bold = $true
                $indexWs.Cells[$r, $hdrCol].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $indexWs.Cells[$r, $hdrCol].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0x1F,0x4E,0x79))
                $indexWs.Cells[$r, $hdrCol].Style.Font.Color.SetColor([System.Drawing.Color]::White)
            }
            $r += 1

            # Directory rows: Tab, Group, Level, Purpose, Notes
            $dirRows = @(
                @('00-Executive-Summary','Navigation','All','High-level KPI dashboard with VM/storage/security counts and 4 charts.','Built from all collected data. Charts: VM state, storage risk, checkpoint age, OS spread.'),
                @('01-Index','Navigation','All','This tab. Color legend and tab directory.','Static reference. No live data.'),
                @('Summary','Analysis / Admin','All','Sectioned operational metrics table (Environment / VM Health / Storage / Security / WinRM / AD Auth).','Aggregated from all tabs at export time.'),
                @('vInfo','VM Data','Basic+','One row per VM: identity, OS, firmware, activation, SB cert risk, WinRM, network profile.','Get-VM + WinRM OS collection + AD computer object lookup.'),
                @('vCPU','VM Data','Advanced','Per-VM CPU count and current usage.','Get-VM.ProcessorCount and Get-VMProcessor + performance counter.'),
                @('vMemory','VM Data','Advanced','Per-VM memory assignment and utilization percent.','Get-VM.MemoryAssigned / Get-VMMemory.'),
                @('vDisk','VM Data','Intermediate+','Per-VM VHD attachment: controller type, number, location, path.','Get-VMHardDiskDrive per VM.'),
                @('vCheckpoint','VM Data','Advanced','Active checkpoints with age in days. CRITICAL (>30d) and WARNING (>7d) highlighted.','Get-VMSnapshot per VM. Age = (Now - CreationTime).Days.'),
                @('VHD-Chain','VM Data','Advanced','Full VHD parent chain per disk per VM: Active/Checkpoint/Base hierarchy, per-link FileSizeMB, ChainDepth, ChainTotalMB, CreatedOn, AlertLevel, consolidation Recommendation. Source of truth for AvhdxChainDepth used by vCheckpoint (CR104). RemediationScriptPath links to CR106 generated scripts.','CR105: Invoke-VHDChainCollection walks ParentPath recursively via Get-VHD on each host. Test-Path guard prevents hangs on broken chains. Thresholds: VHDChainWarningDepth=3, VHDChainCriticalDepth=5, VHDChainStaleCheckpointDays=7.'),
                @('vDVD','VM Data','Advanced','DVD drive attachments including mounted ISO paths.','Get-VMDvdDrive per VM.'),
                @('vIntegration','VM Data','Advanced','Integration service status per VM (Heartbeat, VSS, KVP, etc.).','Get-VMIntegrationService per VM.'),
                @('vReplication','VM Data','Advanced','Hyper-V Replica state, mode, frequency, and last replication time.','Get-VMReplication per VM.'),
                @('VM-Activity-Audit','VM Data','Advanced','VM lifecycle event audit with trigger correlation: shutdowns, power-on/off, snapshots, failovers. Identifies WHO/WHAT triggered each event (human, guest OS, cluster failover, host reboot, automation).','v3.10.2 Session 14: Invoke-VMActivityAudit. Queries VMMS-Admin, Worker-Admin, System, FailoverClustering event logs per host. Correlation window +/-30 seconds.'),
                @('VM-Offline-Disks','VM Data','Advanced','VMs with offline or non-operational disks inside the guest OS. Common after V2V migrations (VMware SAN policy carryover). Applications on offline drives silently fail. Includes SAN policy, offline reason, and remediation commands.','v3.10.4 CR83: Get-Disk via WinRM inside each reachable VM. Detects IsOffline=True or OperationalStatus != Online. SANPolicy from diskpart. Remediation: Set-Disk -IsOffline $false.'),
                @('SCCM-Status','Infrastructure Mgmt','Advanced','SCCM/MECM client status audit: client health evaluation, last policy request, hardware scan timestamp, collection membership. Correlates SCCM clients with Hyper-V VM inventory. Flags running VMs missing SCCM client.','v3.10.7 CR89: Invoke-SCCMClientAudit queries SMS_R_System, SMS_CH_ClientSummary, SMS_G_System_WORKSTATION_STATUS, SMS_FullCollectionMembership via WMI on site server.'),
                @('AD-Info','Infrastructure Mgmt','Advanced','Active Directory forest and domain topology: forest name, functional levels, domain controllers, FSMO role holders, trust relationships, sites/subnets, schema version.','v3.10.11: Get-ADForest, Get-ADDomain, Get-ADDomainController, Get-ADTrust, Get-ADReplicationSite. Provides domain infrastructure visibility without per-machine collection.'),
                @('LAPS-Usage','Security','Advanced','Per-VM LAPS posture audit: backend type (Legacy/Windows LAPS/Both/None), password age, rotation status, managed account name, migration status. Critical = no LAPS configured; Warning = password age exceeds threshold.','v3.10.11 CR102+CR103: Invoke-LAPSAudit queries ms-Mcs-AdmPwd (Legacy) and msLAPS-* (Windows LAPS) AD attributes per VM. LAPSMode config key controls Audit vs Retrieve level.'),
                @('Permissions-Groups','Security','Advanced','Local group membership per Hyper-V host: Administrators, Hyper-V Administrators, Remote Desktop Users, Remote Management Users, Backup Operators, and others. Flags non-domain accounts in Administrators (Warning). Opt-in: IncludePermissionAudit = $true.','v3.10.12 OPEN-60: Invoke-PermissionAudit via WinRM Get-LocalGroupMember on each host.'),
                @('Permissions-Privileges','Security','Advanced','User Rights Assignment per host: full set matching gpedit.msc Local Policies > User Rights Assignment (44 rights). Covers all logon rights, shutdown, debug, backup, impersonate, delegation, and deny rights. Flags SeDebugPrivilege and SeTcbPrivilege (Warning). Opt-in: IncludePermissionAudit = $true.','v3.10.12 OPEN-60: secedit /export parsed on each host. [Privilege Rights] section. SIDs resolved to account names.'),
                @('Permissions-Security','Security','Advanced','Security Options per host from secedit /export: Account Policies (password/lockout), Domain Member settings, Interactive Logon settings, Network Access/Security settings, UAC configuration, and Registry Values. Matches gpedit.msc Security Options node. Opt-in: IncludePermissionAudit = $true.','v3.10.12: secedit /export [System Access] and [Registry Values] sections parsed. 30+ Security Option policies mapped to friendly names.'),
                @('vHost','Host & Network','Basic+','Per-host: CPU, RAM, firmware, TPM, SecureBoot cert status, WinRM config, Docker/WSL.','Get-VMHost + Win32_ComputerSystem + WinRM registry + SB KB check.'),
                @('vNetwork','Host & Network','Basic+','Per-VM NIC: MAC, switch, IPs, gateway, DNS, link speed, network category/profile.','Get-VMNetworkAdapter + guest Get-NetIPConfiguration + Get-NetConnectionProfile.'),
                @('vSwitch-Config','Host & Network','Intermediate+','Virtual switch definitions on each host: type, physical adapter, bandwidth mode, management NICs.','Get-VMSwitch + Get-VMNetworkAdapter -ManagementOS.'),
                @('vCluster','Host & Network','Intermediate+','Failover cluster resources, groups, CSVs, and node membership.','Get-ClusterResource / Get-ClusterGroup / Get-ClusterSharedVolume.'),
                @('Live-Migration','Host & Network','Advanced','Per-host live migration: enabled state, auth type (Kerberos/CredSSP), perf option, network subnets.','Get-VMHost.VirtualMachineMigrationAuthenticationType + Get-VMMigrationNetwork.'),
                @('Host-NIC-Audit','Host & Network','Advanced','Physical/virtual NICs on each host: IP, gateway, DNS, VLAN, inferred role (Mgmt/Migration/Storage/VM).','Get-NetAdapter + Get-NetIPConfiguration + Get-VMNetworkAdapter -ManagementOS.'),
                @('vStorage','Storage','Intermediate+','Host volumes: path, label, filesystem, total/free GB, junction paths.','Get-Volume + junction point discovery via Get-Item.'),
                @('Host-Storage-Risk','Storage','Intermediate+','Per-volume risk level (CRITICAL/HIGH/MEDIUM/LOW) based on free space vs VHD footprint projections. Includes Shared* columns aggregating VHD totals across all hosts on the same CSV/LUN for cluster-wide risk assessment.','Analysis module: FreeGB vs AllocatedVHDsGB vs projected growth. Shared storage post-processing groups by volume path.'),
                @('Storage-VHD-Detail','Storage','Intermediate+','VHD files grouped by host volume showing current/max sizes and growth potential.','Joined from vDisk-Analysis and vStorage; calculates VolumeVHDCurrentTotal and VolumeVHDMaxTotal.'),
                @('vDisk-Analysis','Storage','Intermediate+','Per-VHD: disk type, format (VHDX/VHD), current/max size, growth potential, fragmentation, host volume.','Get-VHD per VM hard drive (runs on Hyper-V host, not guest).'),
                @('VM-Guest-Storage','Storage','Intermediate+','Guest logical drives (C:, D:, etc.) with free space, growth rate (GB/month), and 1-year projection.','Win32_LogicalDisk inside VM via WinRM. Growth rate = linear regression over GuestStorageHistory snapshots.'),
                @('VHD-Drive-Map','Storage','Intermediate+','Correlates VHD host file to guest drive letter using SCSI LUN, IDE slot, serial number, or size matching.','Cross-references Get-VHD controller slot with guest disk serial/size from WinRM.'),
                @('S2D-Storage-Audit','Storage','Advanced','Full Storage Spaces Direct health: pool, virtual disks, physical disks, fault domains, CSVs, storage jobs, QoS.','Invoke-S2DAudit via Invoke-Command to cluster; Get-StoragePool, Get-VirtualDisk, Get-PhysicalDisk, Get-ClusterSharedVolume.'),
                @('S2D-Config-Summary','Storage','Advanced','S2D cluster-level configuration and node status summary rows.','Get-ClusterStorageSpacesDirect + Get-ClusterNode.'),
                @('Disk-Format-Config','Storage','Advanced','Per-host volume filesystem, partition style, allocation unit size, NTFS UseLargeFRS, ReFS integrity streams.','Invoke-DiskFormatAudit: WinRM Get-Volume + Get-Partition + Get-Disk + fsutil + Get-FileIntegrity.'),
                @('VM-IOPS-Summary','Performance / IOPS','Intermediate+','Per-VM resource metering: NormalizedIOPS, AvgLatency, CPU, RAM, disk read/write totals, metering duration.','Enable-VMResourceMetering + Measure-VM per VM on each host. Auto-enabled at report run time.'),
                @('VM-IOPS-PerDisk','Performance / IOPS','Advanced','Per-VHD IOPS detail: NormalizedIOPS, latency, read/write MB for each virtual hard disk.','Measure-VM.HardDiskMetrics expansion. One row per VHD per VM.'),
                @('Host-IOPS-Summary','Performance / IOPS','Intermediate+','Per-host aggregate: total VM IOPS, peak VM, physical disk count/type detection (SSD/SAS/NVMe/SATA), perfmon counters.','Invoke-ResourceMeteringCollection: Measure-VM aggregate + Get-PhysicalDisk + Get-Counter Hyper-V Virtual Storage Device.'),
                @('IOPS-Recommendations','Performance / IOPS','Intermediate+','Per host/cluster: current vs estimated IOPS capacity, utilization %, min/max thresholds, alert level, actionable recommendation.','Estimate-HostIOPSCapacity: disk count x type baseline x RAID penalty. Thresholds: <60% OK, 60-80% Monitor, 80-90% Warning, >90% Critical.'),
                @('IOPS-Trends','Performance / IOPS','Advanced','Daily IOPS trend analysis per host from standalone Collect-ServerIOPS.ps1 collector: peak/avg/P95 IOPS, top VM, perfmon read/write averages.','Import-IOPSCollectorData: reads JSON Lines from collector output share. Configurable lookback window (IOPSCollectorDaysBack).'),
                @('IOPS-Heatmap','Performance / IOPS','Advanced','Hour-of-day IOPS demand curve per host (24 hourly buckets). Shows average and peak IOPS per hour with intensity classification (High/Medium/Low/Idle).','Import-IOPSCollectorData: aggregates collector snapshots by hour across the lookback window.'),
                @('OS-Inventory','OS / Software','Intermediate+','Per-VM OS details, install date, last boot, license/activation, KMS server, reboot pending.','Win32_OperatingSystem + SoftwareLicensingProduct via WinRM. Reboot detection via registry keys.'),
                @('Roles-Features','OS / Software','Intermediate+','INSTALLED Windows Server roles and features (+ .NET versions) per VM and host.','Get-WindowsFeature | Where InstallState -eq Installed. .NET from registry/filesystem. InstallState=Installed is explicit.'),
                @('Applications-Windows','OS / Software','Intermediate+','Installed Windows applications with compliance flags (Required / Remove / Security Tool / Missing).','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall via WinRM. Compliance from Config-OHDC.psd1 AppCompliance.'),
                @('Applications-Linux','OS / Software','Advanced','Linux package inventory (dpkg/rpm) for Linux VMs.','SSH or WinRM Linux subsystem; pkg manager query.'),
                @('Services','OS / Software','Advanced','All Auto-start services (filtered at collection; can include Manual/Disabled via config).','Win32_Service via WinRM. Chunked 2-of-2 or 3-of-3 if >8,000 rows.'),
                @('Services-Alerts','OS / Software','Intermediate+','Stopped Auto-start services and non-standard service accounts only -- the actionable noise-filtered view.','Filtered from Services collection at export: Status!=Running where StartMode=Auto; non-system account services.'),
                @('Scheduled-Tasks','OS / Software','Intermediate+','Non-Microsoft Enabled/Ready scheduled tasks from all VMs and hosts.','Get-ScheduledTask | Where State -in Enabled,Ready and TaskPath -notlike \Microsoft\. Chunked if needed.'),
                @('Security-Compliance','Security','Intermediate+','Firmware/SecureBoot compliance per VM and host; missing required apps; SB cert risk assessment.','FirmwareInfo from Get-VMFirmware + SecureBootTemplate + host TPM. SB_CertRisk = At Risk if MicrosoftUEFICertificateAuthority template.'),
                @('WinRM-Health','Security','Intermediate+','Per-VM WinRM status, HTTPS listener, cert expiry, CredSSP, and alert level.','WinRM config from guest registry via WinRM. Alert: Critical=not running, Warning=no HTTPS or cert <30d.'),
                @('Local-Builtin','Security','Advanced','Members of ALL Windows built-in local groups per VM. Shows GroupName, Required/Allowed/Unexpected/Missing status.','Get-LocalGroupMember for each built-in group (WS2016+) or ADSI WinNT fallback. Config: RequiredBuiltinMembers in Config-OHDC.psd1.'),
                @('RBAC-Compliance','Security','Advanced','Per-server per-builtin-group RBAC validation using guest OS computer name (not Hyper-V display name). Appliances (IPAM, FortiGate) excluded. Linux VMs flagged for SSH access. Expected AD group (ACL_SERVER_SUFFIX) existence, membership, and population checked.','Invoke-RBACComplianceAudit: guest name from WinRM/KVP, appliance pattern filter, Linux detection. Status: COMPLIANT/NON-COMPLIANT/WARNING/LINUX.'),
                @('Local-Admins','Security','Advanced','Members of the Administrators group only (legacy view; superseded by Local-Builtin).','Subset of Local-Builtin where GroupName=Administrators.'),
                @('AD-Auth-Detail','Security','Advanced','Per-machine Kerberos delegation type, WSMAN SPNs, LAPS version, WinRM transport, and overall risk.','Invoke-ADAuthCollection: Get-ADComputer delegation + SPN attributes + LAPS attribute presence.'),
                @('AD-Auth-Issues','Security','Advanced','Rolled-up Critical/Warning/Info auth findings sorted by severity: Unconstrained delegation, missing SPNs, no LAPS, HTTP-only WinRM.','Derived from AD-Auth-Detail rows at export time.'),
                @('SPN-Inventory','Kerberos','Advanced','All registered SPNs across the environment, categorized by service class, with missing and duplicate gap detection.','Invoke-SPNAudit: Get-ADComputer -Properties ServicePrincipalName + expected SPN derivation from DNS hostnames.'),
                @('DoubleHop-Map','Kerberos','Advanced','Domain-account services, scheduled tasks, and IIS app pools that require Kerberos double-hop, cross-referenced against delegation config.','Resolve-DoublehopMap: Win32_Service + ScheduledTask + IIS AppPool RunAs accounts vs AD delegation config.'),
                @('NTLM-Elimination','Kerberos','Advanced','Per-machine NTLM risk score (Critical/High/Medium/Low/OK) with inline setspn and Set-ADComputer remediation commands.','Build-NTLMRiskMap: combines delegation type + SPN gaps + CredSSP use + domain-account services into a weighted risk score.'),
                @('NTLM-Readiness','Kerberos','Advanced','Per-machine NTLM deprecation readiness: NetBIOS, LLMNR, WINS, LmCompatLevel, NTLM restrictions, SMBv1, SMB signing, Kerberos enc types. Traffic-light score: Ready/Needs-Work/Blocked.','Invoke-NTLMReadinessAudit: WinRM remote registry checks on every host and Windows VM for protocol-layer NTLM configuration.'),
                @('SPN-ServiceAccounts','Kerberos','Advanced','AD user accounts with registered SPNs: service class, hostname, port, cross-referenced against running services, duplicate detection vs computer SPNs, stale/disabled account flagging.','Invoke-ServiceAccountSPNAudit: Get-ADUser -Filter ServicePrincipalName, cross-reference against inventory services, computer SPN duplicate check.'),
                @('SPN-Inventory-Full','Kerberos','Advanced','AD-wide SPN inventory: ALL computer and user accounts with registered SPNs across every configured domain, parsed into ServiceClass/Hostname/Port. Flags duplicates (Critical -- Kerberos auth WILL fail), disabled accounts, and stale accounts. Equivalent to running setspn -L against every account in the forest. Opt-in: IncludeSPNInventoryFull = $true.','Invoke-SPNInventoryFull: Get-ADComputer + Get-ADUser -Filter ServicePrincipalName -like *, cross-domain duplicate detection, AccountScope = HyperV/ServiceAccount/Other.'),
                @('KCD-Validation','Kerberos','Advanced','Kerberos Constrained Delegation validation: delegation target SPN reachability, A2D2S protocol transition, RBCD vs traditional KCD, live migration delegation cross-check.','Invoke-KCDValidationAudit: Get-ADComputer msDS-AllowedToDelegateTo + msDS-AllowedToActOnBehalfOfOtherIdentity, SPN target resolution, cross-reference Set-HyperVKerberosLiveMigration targets.'),
                @('Cross-Domain-Auth','Kerberos','Advanced','Per-VM cross-domain authentication diagnostic: detected domain (DNS/KVP/AD), credential used, auth method (Primary/Fallback/AllFailed), WinRM status. Identifies VMs where OS data collection failed due to cross-domain credential issues.','v3.9.0: DNS Tier 0 domain detection + credential rotation tracking. AlertLevel: Critical = no OS data and no domain detected, Warning = domain detected but no OS data, OK = OS data collected.'),
                @('DNS-Validation','Network','Advanced','Per-VM/host forward (A) and reverse (PTR) DNS validation using the guest OS computer name (not the Hyper-V display name). Auto-detects DNS source per domain: EfficientIP IPAM for ohdc.com, AD-integrated DNS for overheaddoor.com. Detects VM display name vs guest OS name mismatches.','v3.9.6: GuestOSDNSName + NameMismatch columns. DNS lookups use guest OS name from KVP/WinRM. EfficientIP via Get-EfficientIPByHostname, AD-DNS via Resolve-DnsName. AlertLevel: Critical = no A record, Warning = mismatch/missing PTR, OK = both match.'),
                @('Remediation-Commands','Kerberos','Advanced','Index pointing to the generated HyperV-Remediation_<timestamp>.ps1 script. Covers Delegation, SPN, WinRM HTTPS, and LAPS fixes.','Script generated alongside this xlsx. Run with -WhatIf first. Filter by -ComputerName or -Category.'),
                @('DC-GUID-Validation','Kerberos','Advanced','Domain Controller DSA GUID retrieval and _msdcs CNAME DNS ping validation to detect AD replication DNS gaps.','Invoke-LiveMigrationCollection DC section: Get-ADDomainController DSA GUID + Resolve-DnsName _msdcs CNAME.'),
                @('TLS-Compliance','Security','Advanced','Per-machine TLS/Secure Channel compliance: SChannel protocols (SSL 2.0-3.0, TLS 1.0-1.3), .NET strong crypto, WinHTTP, RDP, LDAP, SMB -- pass/fail per area.','Invoke-TLSComplianceAudit: WinRM remote registry checks on every host and Windows VM.'),
                @('TLS-Recommendations','Security','Advanced','Prioritized remediation items per machine: which registry keys to set, severity, category, remediation script reference.','Build-Recommendations from TLS compliance data. Fix-*.ps1 universal scripts generated in output folder.'),
                @('CPU-Analysis','Analysis / Admin','Advanced','Per-host CPU over-commit analysis: logical procs vs vCPUs assigned, ratio, and over-committed flag.','CPUAnalysis from main Analysis module: SUM(VM.CPUs) / Host.LogicalProcessors.'),
                @('Recommendations','Analysis / Admin','Advanced','Prioritized recommendations (Critical/High/Medium/Low) covering VM config, storage, and security findings.','Generated by Analysis module from all collected data. Priority = Critical/High/Medium/Low.'),
                @('Compliance-Issues','Analysis / Admin','Advanced','Detailed compliance violation list: severity, category, VM/host, finding, and remediation text.','Generated by Analysis module and Security collection. Severity: Critical / Warning / Info.'),
                @('Missing-VMs','Analysis / Admin','Advanced','VMs present in the previous run history but absent from this run -- potential deletions or renames.','Compared against GuestStorageHistory VMId keys. If VMID existed before but not now = Missing.'),
                @('Reboot-History','Analysis / Admin','Advanced','Last 10 reboot events (Event ID 1074) per VM and host showing user, process, reason, and action.','Get-WinEvent -FilterHashtable @{LogName=System;Id=1074} inside each VM and host via WinRM.'),
                @('Unavailable-Hosts','Admin','Basic+','Hosts that failed inventory collection with error type and message.','Hosts that did not respond to ping or failed WinRM authentication during the inventory run.')
            )

            $altBg = $false
            foreach ($dr in $dirRows) {
                for ($dc = 1; $dc -le $dr.Count; $dc++) {
                    $cell = $indexWs.Cells[$r, $dc]
                    $cell.Value = $dr[$dc - 1]
                    if ($altBg) {
                        $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                        $cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0xEE,0xF2,0xFF))
                    }
                }
                $altBg = -not $altBg
                $r++
            }

            # Column widths for index tab
            $indexWs.Column(1).Width = 26
            $indexWs.Column(2).Width = 20
            $indexWs.Column(3).Width = 14
            $indexWs.Column(4).Width = 50
            $indexWs.Column(5).Width = 60
            $indexWs.Column(1).Style.WrapText = $true
            $indexWs.Column(4).Style.WrapText = $true
            $indexWs.Column(5).Style.WrapText = $true

            # v3.8.9.2: Position 01-Index tab as second tab (after 00-Executive-Summary)
            # The 01-Index is created after the initial tab reorder, so it needs explicit repositioning.
            try {
                $execWsIdx = $pkg.Workbook.Worksheets['00-Executive-Summary']
                if ($execWsIdx) {
                    $pkg.Workbook.Worksheets.MoveAfter('01-Index', '00-Executive-Summary')
                } else {
                    $pkg.Workbook.Worksheets.MoveToStart('01-Index') | Out-Null
                }
                # Apply tab colour
                $indexWs.TabColor = [System.Drawing.Color]::FromArgb(0x1F, 0x4E, 0x79)
            } catch {
                Write-HVLog "  01-Index positioning warning: $($_.Exception.Message)" -Level Warning
            }
            # Every tab (except 00-Executive-Summary and 01-Index) gets an
            # Excel comment on each header cell explaining the data source
            # and/or formula used to produce that column's values.
            # ============================================================
            #
            # Master dictionary: TabName -> { ColumnHeader -> CommentText }
            # Column header names must match EXACTLY what Export-Excel writes
            # (the PSCustomObject property names used when building each list).
            # Author string used for all comments.
            $commentAuthor = 'HyperV-Inventory-Suite'

            # Helper: given an open worksheet, apply comments to row-1 headers.
            # $Notes is a hashtable of ColumnName -> CommentText.
            # Silently skips any column name not found in this worksheet.
            # Tabs exported with -Title have: row 1 = title text, row 2 = column headers.
            # Tabs without -Title have: row 1 = column headers directly.
            # We track which tabs used -Title so header comments target the correct row.
            $titledTabs = @(
                'SPN-Inventory', 'DoubleHop-Map', 'NTLM-Elimination',
                'Live-Migration', 'Host-NIC-Audit', 'DC-GUID-Validation', 'VHD-Chain',
                'VHD-Drive-Map', 'S2D-Storage-Audit',
                'VM-IOPS-Summary', 'VM-IOPS-PerDisk', 'Host-IOPS-Summary', 'IOPS-Recommendations',
                'IOPS-Trends', 'IOPS-Heatmap',
                'TLS-Compliance', 'TLS-Recommendations',
                'Disk-Format-Config', 'RBAC-Compliance',
                'NTLM-Readiness', 'SPN-ServiceAccounts', 'SPN-Inventory-Full', 'KCD-Validation',
                'Cross-Domain-Auth', 'DNS-Validation', 'VM-Activity-Audit', 'VM-Offline-Disks',
                'SCCM-Status', 'LAPS-Usage', 'AD-Info',
                'Permissions-Groups', 'Permissions-Privileges', 'Permissions-Security'
            )

            $applyHeaderComments = {
                param(
                    [OfficeOpenXml.ExcelWorksheet]$ws,
                    [hashtable]$Notes,
                    [string]$Author,
                    [string[]]$TitledTabs
                )
                if (-not $ws) { return }
                # Determine header row: row 2 for tabs that used Export-Excel -Title, row 1 otherwise
                $headerRow = 1
                if ($TitledTabs -contains $ws.Name) { $headerRow = 2 }
                # Build a header->column index map from the correct row
                $headerMap = @{}
                $lastCol = $ws.Dimension.End.Column
                for ($c = 1; $c -le $lastCol; $c++) {
                    $hdr = $ws.Cells[$headerRow, $c].Text
                    if ($hdr) { $headerMap[$hdr] = $c }
                }
                foreach ($colName in $Notes.Keys) {
                    if (-not $headerMap.ContainsKey($colName)) { continue }
                    $col  = $headerMap[$colName]
                    $cell = $ws.Cells[$headerRow, $col]
                    $note = $Notes[$colName]
                    # Remove any existing comment on this cell first
                    $existingComment = $ws.Comments | Where-Object {
                        $_.CellAddress -eq $cell.Address } | Select-Object -First 1
                    if ($existingComment) {
                        $ws.Comments.Remove($existingComment)
                    }
                    try {
                        $null = $ws.Comments.Add($cell, $note, $Author)
                    } catch { }
                }
            }

            # ----------------------------------------------------------
            # Per-tab column notes
            # ----------------------------------------------------------

            $tabNotes = @{}

            # ---- Summary ----
            $tabNotes['Summary'] = @{
                'Section' = 'Logical grouping for this metric row (Environment / VM Health / Storage / Security / etc.).'
                'Metric'  = 'Name of the KPI or operational metric being measured.'
                'Value'   = 'Current value of the metric, calculated at report generation time.'
            }

            # ---- vInfo ----
            $tabNotes['vInfo'] = @{
                'VM'                = 'VM display name as returned by Get-VM on the Hyper-V host.'
                'Host'              = 'Hyper-V host that owns this VM (from Get-VM).'
                'ClusterName'       = 'Failover cluster name if the host is a cluster node; blank if standalone (from Get-ClusterNode).'
                'Powerstate'        = 'VM power state: poweredOn / Off / Paused / Saved (from VM.State).'
                'GuestOS'           = 'Guest OS string reported by Hyper-V Integration Components (KVP exchange).'
                'OSType'            = 'Derived OS type: Windows / Linux / FreeBSD / Other. Detected via WinRM, KVP fallback, then name-pattern matching.'
                'OSName'            = 'Full OS caption from Win32_OperatingSystem (WinRM) or KVP OSName key.'
                'OSVersion'         = 'OS version string (e.g. 10.0.20348) from Win32_OperatingSystem or KVP.'
                'OSBuild'           = 'OS build number from Win32_OperatingSystem.BuildNumber or KVP OSBuildNumber.'
                'Generation'        = 'Hyper-V VM generation: 1 (BIOS/IDE) or 2 (UEFI/SCSI). From Get-VMFirmware.'
                'FirmwareType'      = 'BIOS or UEFI, derived from VM generation and Get-VMFirmware.'
                'SecureBootEnabled' = 'True/False - Secure Boot state from Get-VMFirmware.SecureBootEnabled.'
                'TPMEnabled'        = 'True/False - vTPM presence from Get-VMSecurity.TpmEnabled.'
                'ConfigVersion'     = 'VM configuration version (e.g. 10.0) from VM.Version - governs which Hyper-V features are available.'
                'ConfigVerRec'      = 'Derived recommendation: "Current" if >= 10.0, "Upgrade available" if lower. Calculated from ConfigVersion numeric comparison.'
                'Heartbeat'         = 'Integration Services heartbeat status from VM.Heartbeat (OkApplicationsUnknown = healthy).'
                'VMCategory'        = 'VM category tag (Infrastructure / Application / etc.) from VM.Notes parsing or default "Standard".'
                'Notes'             = 'VM notes field from Get-VM.Notes - free-text administrator annotation.'
                'Path'              = 'VM configuration file path from Get-VM.Path.'
                'NameRecommendation' = 'Derived flag if VM name contains spaces or special chars; suggests a corrected name.'
                'GuestComputerName' = 'Computer name from inside the guest OS (Invoke-Command $env:COMPUTERNAME via WinRM).'
                'GuestOSDNSName'    = 'v3.10.0: The actual hostname used for DNS record registration. Priority: GuestComputerName (WinRM) > KVP FullyQualifiedDomainName hostname (integration services) > blank. This may differ from the VM display name (e.g. VM="BALOH-Bartend-P01" but GuestOSDNSName="BALOH-BARTEND-1"). Cross-references the DNS-Validation tab.'
                'AD_ComputerName'   = 'Computer name from Active Directory (Get-ADComputer -Filter).'
                'NameMatch'         = 'Derived: compares VM name, guest ComputerName, and AD name. "Match" if all align; "Mismatch: VM=x, Guest=y, AD=z" if they differ.'
                'Version'           = 'VM configuration version (Intermediate+). Same source as ConfigVersion - shown for reference.'
                'Uptime'            = 'VM uptime timespan from VM.Uptime (only populated when VM is running).'
                'VMCreated'         = 'VM creation timestamp from VM.CreationTime (stored in VM config XML).'
                'ADCreated'         = 'Computer object creation date from AD (Get-ADComputer -Properties WhenCreated).'
                'FirstSeen'         = 'Date this VM first appeared in a report run (stored in GuestStorageHistory JSON).'
                'LastSeen'          = 'Date this VM was last seen in a report run (from history file).'
                'VMId'              = 'VM GUID from Get-VM.VMId - unique identifier stable across renames.'
                'LastUpdateKB'      = 'Most recent hotfix KB number installed in the guest, from Get-HotFix sorted by InstalledOn descending.'
                'LastUpdateDate'    = 'Install date of the most recent hotfix (yyyy-MM-dd), from Get-HotFix via WinRM.'
                'RebootPending'     = 'True/False - derived from registry checks: CBS RebootPending, WU RebootRequired, PendingFileRenameOperations, and ComputerName mismatch keys.'
                'RebootReasons'     = 'Semicolon-delimited list of pending-reboot triggers: CBS, WU, FileRename, Rename.'
                'ActivationStatus'  = 'Windows license status from SoftwareLicensingProduct.LicenseStatus (Licensed / Unlicensed / OOB Grace / etc.).'
                'ActivationMethod'  = 'Derived activation method: AVMA / KMS / MAK / Retail / Activated (from SoftwareLicensingProduct.Description pattern match).'
                'KMSServer'         = 'KMS server hostname from SoftwareLicensingProduct.DiscoveredKeyManagementServiceMachineName (populated only for KMS-activated guests).'
                'PartialKey'        = 'Last 5 characters of the product key from SoftwareLicensingProduct.PartialProductKey.'
                'SB_Template'       = 'Secure Boot template from Get-VMFirmware.SecureBootTemplate (MicrosoftWindows / MicrosoftUEFICertificateAuthority / OpenSourceShieldedVM).'
                'SB_CertRisk'       = 'Derived risk: "At Risk" if using MicrosoftUEFICertificateAuthority template with Secure Boot enabled (KB5025885 required). "Safe" otherwise.'
                'WinRM_Status'      = 'WinRM connectivity status: "Running" if Invoke-Command succeeded; "Unreachable" if WinRM connection failed; "N/A (Off)" if VM is powered off.'
                'WinRM_Listeners'   = 'WinRM listener summary from Get-WSManInstance winrm/config/Listener (e.g. HTTP://*:5985; HTTPS://*:5986).'
                'WinRM_HTTPS'       = 'True/False - whether an HTTPS WinRM listener is configured, from Get-WSManInstance.'
                'WinRM_HTTPS_CertExp' = 'Expiry date of the WinRM HTTPS listener certificate from Cert:\LocalMachine\My matching the listener thumbprint.'
                'WinRM_AuthKerberos' = 'Kerberos auth enabled for WinRM service: from Get-WSManInstance winrm/config/Service Auth.Kerberos.'
                'WinRM_AuthCredSSP' = 'CredSSP auth enabled for WinRM service: from Get-WSManInstance winrm/config/Service Auth.CredSSP.'
                'WinRM_MaxTimeoutMs' = 'WinRM maximum timeout in milliseconds from winrm/config MaxTimeoutms.'
                'WinRM_Recommendation' = 'Derived advisory: flags no HTTPS listener, AllowUnencrypted=true, expired/expiring certs, or unreachable WinRM.'
                'SB_KBs_Installed'  = 'Comma-delimited list of Secure Boot KBs (KB5012170, KB5032370, etc.) found installed via Get-HotFix.'
                'SB_KBs_Missing'    = 'Required Secure Boot KBs not found by Get-HotFix. "None" = all required KBs present.'
                'SB_UEFIEnabled'    = 'True/False - UEFI Secure Boot enabled per HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled.'
                'SB_PendingUpdates' = 'Value of HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates registry key (non-zero = updates pending).'
                'SB_DBXVersion'     = 'Secure Boot forbidden signature database (dbx) presence from Get-SecureBootUEFI -Name dbx.'
                'SB_Action'         = 'Derived action recommendation based on SB cert status and missing KBs.'
                'NetworkCategory'   = 'Dominant network connection profile from Get-NetConnectionProfile inside the guest: Domain / Private / Public / Unknown.'
                'AutomaticStartAction' = 'v3.10.12.26: What Hyper-V does with this VM when the host boots. Nothing = VM stays off (WARNING -- silent outage if host reboots). StartIfRunning = restart only if it was running when host shut down (recommended for most VMs). Start = always power on regardless of prior state. Source: Get-VM.AutomaticStartAction.'
                'AutomaticStartDelay'  = 'v3.10.12.26: Seconds to wait after host boot before starting this VM. 0 = no delay. Used to stagger startup and avoid resource contention when many VMs start simultaneously. Source: Get-VM.AutomaticStartDelay.TotalSeconds.'
                'AutomaticStopAction'  = 'v3.10.12.26: What happens to this VM when the Hyper-V host shuts down. TurnOff = hard power-off (WARNING -- data loss risk on production VMs, equivalent to pulling the power cord). Save = save VM state to disk (safe, slow). ShutDown = send guest shutdown signal via integration services (recommended for Windows VMs with Integration Services installed). Source: Get-VM.AutomaticStopAction.'
                'StartStopAlert'       = 'v3.10.12.26: Derived alert. Critical = Nothing start AND TurnOff stop (VM never restarts, AND risks data loss on shutdown). Warning = one of the two. OK = StartIfRunning or Start, AND Save or ShutDown. Review any Warning/Critical rows for production VMs.'
                'TimeZoneId'           = 'v3.10.12.26: Windows timezone identifier from (Get-TimeZone).Id inside the guest via WinRM (e.g. "Eastern Standard Time"). Empty if WinRM unreachable or VM offline. This is what the OS is actually configured to use.'
                'TimeZoneDisplay'      = 'v3.10.12.26: Human-readable timezone from (Get-TimeZone).DisplayName inside the guest (e.g. "(UTC-05:00) Eastern Time (US & Canada)"). Empty if WinRM unreachable.'
                'ExpectedTimezone'     = 'v3.10.12.26: Expected Windows timezone ID for this VM, derived by matching the VM primary NIC IP against SiteTimezones in Config-OHDC.psd1 using CIDR longest-prefix matching. The most specific subnet entry wins. Empty if IP does not match any configured SiteTimezones entry, or IncludeTimezoneAudit = $false.'
                'SiteNameMatch'        = 'v3.10.12.26: The SiteName of the SiteTimezones entry that matched this VM IP. Identifies which site the IP belongs to per the config. Empty if no subnet matched.'
                'TimezoneAlert'        = 'v3.10.12.26: OK = TimeZoneId matches ExpectedTimezone. Mismatch = configured timezone differs from expected (flag for correction via Set-TimezoneBySubnet). Unknown (no subnet match) = VM IP not covered by any SiteTimezones entry -- add entry to Config-OHDC.psd1. N/A (no WinRM) = VM offline or unreachable. May append "/ NTP Offset Warning (Ns)" if offset exceeds TimezoneOffsetWarningSeconds (default 300s).'
                'TimeOffsetSeconds'    = 'v3.10.12.26: Guest clock offset from NTP time source in seconds from w32tm /query /status inside the guest. Positive = guest ahead. Negative = behind. Blank if WinRM unreachable. Values beyond TimezoneOffsetWarningSeconds trigger warning appended to TimezoneAlert.'
                'NTPSource'            = 'v3.10.12.26: NTP time source server name from w32tm /query /status on the guest. Should reflect your NTP hierarchy (typically a DC). Blank if WinRM unreachable.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vHost ----
            $tabNotes['vHost'] = @{
                'Host'              = 'Hyper-V host FQDN as resolved by AD lookup or Get-Item WSMan:\localhost\Client\TrustedHosts.'
                'Domain'            = 'Domain the host is joined to, from Win32_ComputerSystem.Domain via WinRM.'
                'State'             = 'Host reachability state: Online / Unreachable / CredSSP-Only (from WinRM probe).'
                'LogicalProcessors' = 'Logical processor count from Get-VMHost.LogicalProcessorCount.'
                'MemoryGB'          = 'Total physical RAM in GB from Get-VMHost or Win32_ComputerSystem.TotalPhysicalMemory / 1GB.'
                'MemoryAvailableGB' = 'Available RAM in GB from Get-VMHost.MemoryAvailable (MB) / 1024.'
                'VMs'               = 'Total VM count on this host from (Get-VM).Count.'
                'RunningVMs'        = 'Count of VMs with State = Running from (Get-VM | Where State -eq Running).Count.'
                'ClusterInfo'       = 'Cluster membership summary: cluster name and node role (from Get-ClusterNode).'
                'HyperVVersion'     = 'Hyper-V version string from Get-VMHost.HyperVisorVersion.'
                'HostType'          = 'Physical / Virtual - derived from Win32_ComputerSystem.Model; "Virtual" if model matches known hypervisor strings.'
                'FirmwareType'      = 'BIOS or UEFI - from Win32_BIOS and UEFI registry key presence check.'
                'SecureBootEnabled' = 'True/False - host Secure Boot state from Confirm-SecureBootUEFI or registry.'
                'TPMVersion'        = 'TPM version from Win32_TPM.SpecVersion (1.2 / 2.0 / None).'
                'Manufacturer'      = 'Hardware manufacturer from Win32_ComputerSystem.Manufacturer.'
                'Model'             = 'Hardware model from Win32_ComputerSystem.Model.'
                'SerialNumber'      = 'Chassis serial number from Win32_BIOS.SerialNumber.'
                'BIOSVersion'       = 'BIOS version string from Win32_BIOS.SMBIOSBIOSVersion.'
                'BIOSDate'          = 'BIOS release date from Win32_BIOS.ReleaseDate (converted from WMI datetime).'
                'CPUModel'          = 'Processor model name from Win32_Processor.Name (first physical CPU).'
                'PhysicalCPUs'      = 'Number of physical CPU sockets from (Get-CimInstance Win32_Processor | Select -Unique SocketDesignation).Count.'
                'TotalCores'        = 'Total physical cores across all sockets from Win32_Processor.NumberOfCores sum.'
                'TotalLogicalProcs' = 'Total logical processors (cores x HT threads) from Win32_Processor.NumberOfLogicalProcessors sum.'
                'HW_MemoryGB'       = 'Total installed physical RAM in GB from Win32_ComputerSystem.TotalPhysicalMemory / 1GB.'
                'SB_Capable'        = 'True/False - host UEFI firmware supports Secure Boot (from firmware type check).'
                'SB_Has2023Certs'   = 'True/False - host Secure Boot DB contains updated 2023 Microsoft UEFI CA certificates (from Get-SecureBootUEFI -Name db byte-scan).'
                'SB_CertCount'      = 'Number of certificates found in the Secure Boot DB via Get-SecureBootUEFI -Name db.'
                'SB_UpdateRequired' = 'Derived: "Yes (Expiring 2026)" if old certs only; "No (Already Updated)" if 2023 certs present; "N/A" for BIOS hosts.'
                'SB_DaysUntilExp'   = 'Days until the oldest Secure Boot certificate expires. Calculated: (cert.NotAfter - today).Days.'
                'SB_CertDetails'    = 'Semicolon-delimited cert subject/expiry pairs from the Secure Boot DB.'
                'LastUpdateKB'      = 'Most recent hotfix on the host from Get-HotFix sorted by InstalledOn descending.'
                'LastUpdateDate'    = 'Install date (yyyy-MM-dd) of most recent hotfix via Get-HotFix on host.'
                'RebootPending'     = 'True/False - checked via same 4-key registry method as guest VMs (CBS, WU, FileRename, Rename).'
                'RebootReasons'     = 'Semicolon-delimited reboot trigger reasons (CBS / WU / FileRename / Rename).'
                'DockerRunning'     = 'True/False - whether the Docker service is running on this Hyper-V host (Get-Service docker).'
                'DockerServices'    = 'Docker-related service names found running (Get-Service | Where Name -like "*docker*").'
                'WSLEnabled'        = 'True/False - WSL feature enabled on host (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).'
                'WinRM_Status'      = 'WinRM service state on the host (from Get-Service WinRM).'
                'WinRM_StartType'   = 'WinRM service start type (Automatic / Manual / Disabled) from Get-Service WinRM.StartType.'
                'WinRM_Listeners'   = 'WinRM listener summary from Get-WSManInstance winrm/config/Listener on the host.'
                'WinRM_HTTPS'       = 'True/False - HTTPS WinRM listener present on host.'
                'WinRM_HTTPS_CertExp' = 'HTTPS listener certificate expiry date on the host.'
                'WinRM_HTTPS_Subject' = 'Subject CN of the WinRM HTTPS certificate on the host.'
                'WinRM_HTTPS_Issuer' = 'Issuer CN of the WinRM HTTPS certificate on the host.'
                'WinRM_AuthKerberos' = 'Kerberos auth enabled for host WinRM service.'
                'WinRM_AuthCredSSP' = 'CredSSP auth enabled for host WinRM service.'
                'WinRM_AuthNegotiate' = 'Negotiate auth enabled for host WinRM service (covers NTLM + Kerberos).'
                'WinRM_AllowUnencrypt' = 'True/False - AllowUnencrypted WinRM setting (security risk if true).'
                'CredSSP_Server'    = 'CredSSP server-side enablement state from Get-WSManInstance winrm/config/Service Auth.CredSSP.'
                'CredSSP_Client'    = 'CredSSP client-side delegated host list from Get-WSManCredSSP.'
                'WinRM_TrustedHosts' = 'WinRM TrustedHosts list from Get-Item WSMan:\localhost\Client\TrustedHosts.'
                'WinRM_MaxTimeoutMs' = 'WinRM max operation timeout (ms) from winrm/config MaxTimeoutms.'
                'WinRM_NetworkDelayMs' = 'WinRM network delay setting (ms) - custom value set for intercontinental hosts (e.g. Bengaluru).'
                'WinRM_IdleTimeoutMs' = 'WinRM idle shell timeout (ms) from winrm/config/Shell IdleTimeOut.'
                'WinRM_MaxEnvKb'    = 'WinRM max envelope size in KB from winrm/config MaxEnvelopeSizekb.'
                'WinRM_MaxShellsPerUser' = 'Max concurrent shells per user from winrm/config/Shell MaxShellsPerUser.'
                'WinRM_MaxMemPerShellMB' = 'Max memory per shell in MB from winrm/config/Shell MaxMemoryPerShellMB.'
                'WinRM_Recommendations' = 'Derived advisory: flags missing HTTPS listener, expired cert, AllowUnencrypted, or Basic auth enabled.'
                'SB_KBs_Installed'  = 'Secure Boot KBs confirmed installed on the host via Get-HotFix.'
                'SB_KBs_Missing'    = 'Required Secure Boot KBs not found on the host. "None" = all present.'
                'SB_UEFIEnabled'    = 'Host UEFI Secure Boot enabled state from registry.'
                'SB_PendingUpdates' = 'Host Secure Boot AvailableUpdates registry value.'
                'SB_Action'         = 'Derived host-level Secure Boot action recommendation.'
                'NetworkProfile'    = 'Semicolon-delimited per-adapter network profiles from Get-NetConnectionProfile on host.'
                'NetworkCategory'   = 'Dominant network category on host: Domain / Private / Public / Unknown.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vNetwork ----
            $tabNotes['vNetwork'] = @{
                'VM'            = 'VM name owning this network adapter.'
                'Host'          = 'Hyper-V host the VM runs on.'
                'AdapterName'   = 'Virtual NIC name from Get-VMNetworkAdapter.Name.'
                'SwitchName'    = 'Hyper-V virtual switch the NIC is connected to (Get-VMNetworkAdapter.SwitchName).'
                'MacAddress'    = 'MAC address assigned to the virtual NIC (Get-VMNetworkAdapter.MacAddress).'
                'IPv4Addresses' = 'IPv4 addresses reported by Hyper-V IC; filtered from IPAddresses list (excludes 169.254.x.x APIPA).'
                'IPv6Addresses' = 'IPv6 addresses reported by Hyper-V IC; filtered from IPAddresses list.'
                'IPAddresses'   = 'All IP addresses (IPv4 + IPv6) from Get-VMNetworkAdapter.IPAddresses (populated by Integration Components).'
                'Status'        = 'NIC connection status from Get-VMNetworkAdapter.Status (Connected / Disconnected).'
                'AddressSource' = '(Intermediate+) DHCP or Static - from Get-NetIPInterface.Dhcp inside the guest via WinRM.'
                'SubnetMask'    = '(Intermediate+) IPv4 subnet mask in dotted notation, calculated from PrefixLength inside the guest.'
                'SubnetPrefix'  = '(Intermediate+) CIDR prefix length from Get-NetIPAddress.PrefixLength inside the guest.'
                'Gateway'       = '(Intermediate+) Default gateway from Get-NetIPConfiguration.IPv4DefaultGateway.NextHop inside the guest.'
                'DNSServers'    = '(Intermediate+) DNS server IPs from Get-DnsClientServerAddress inside the guest (IPv4 only).'
                'DNSSuffix'     = '(Intermediate+) Connection-specific DNS suffix from Get-DnsClient.ConnectionSpecificSuffix inside the guest. This is the domain appended to short hostnames for DNS resolution on this NIC.'
                'DNSSuffixSearchList' = '(Intermediate+) Ordered DNS suffix search list from Get-DnsClient.ConnectionSpecificSuffixSearchList or Get-DnsClientGlobalSetting.SuffixSearchList. Used for short-name resolution across multiple domains.'
                'LinkSpeed'     = '(Intermediate+) Physical link speed of the matching guest adapter from Get-NetAdapter.LinkSpeed.'
                'NetworkCategory' = '(Intermediate+) Windows network profile for this adapter from Get-NetConnectionProfile matched by InterfaceAlias inside the guest.'
                'ProfileName'   = '(Intermediate+) Network profile name from Get-NetConnectionProfile.Name inside the guest.'
                'DNSSuffixAssessment' = '(Intermediate+) Validation: OK = DNS suffix configured, MISSING = no suffix (short-name DNS resolution and Kerberos SPN lookup may fail), N/A = VM off or no DNS configured on this NIC.'
                'DNSForwardMatch' = '(Advanced) Cross-reference from DNS-Validation tab: Yes = forward DNS record IP matches this NIC IP, Mismatch = record exists but IP differs, Missing = no A record found. Blank if DNS validation is disabled.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Unavailable-Hosts ----
            $tabNotes['Unavailable-Hosts'] = @{
                'HostName'        = 'Short hostname of the host or AD object that could not be inventoried (from AD computer object sAMAccountName).'
                'FQDN'            = 'Fully qualified domain name (from AD DNSHostName attribute).'
                'OperatingSystem'  = 'OS string from the AD computer object OperatingSystem attribute. Shows what the host is running without needing WinRM access.'
                'LastLogon'       = 'Last AD logon date from Get-ADComputer.LastLogonDate. A recent date means the host is alive in AD but not responding to the report. A stale date suggests the host may be decommissioned or offline.'
                'Reason'          = 'Why this entry failed or was filtered. For connectivity failures: "Host is not responding to ping" (offline/firewall), WinRM auth errors (Access is denied / CredSSP delegation), or "Get-VMHost not recognized" (host exists but Hyper-V role not installed). For CR110-filtered entries: prefixed with "CR110 <category>:" where category is CNO (Cluster Name Object), AG-Listener (SQL Always-On AG listener), SQL-FCI (SQL Failover Cluster Instance), NotHyperV (server without Hyper-V role), or Excluded (in ExcludeHostNames config list). CR110 entries were never probed via WinRM -- they were classified and removed during AD discovery to avoid false failures and save run time.'
                'IsOnline'        = 'True/False for connectivity-failed hosts (Test-Connection result). "N/A (not probed)" for CR110-filtered entries that were removed before connectivity testing.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows.'
            }

            # ---- vDisk ----
            $tabNotes['vDisk'] = @{
                'VM'                 = 'VM that owns this virtual disk.'
                'Host'               = 'Hyper-V host the VM runs on.'
                'Controller'         = 'Controller type: IDE or SCSI (from Get-VMHardDiskDrive.ControllerType).'
                'ControllerNumber'   = 'Controller number (0 or 1 for IDE; 0-3 for SCSI) from Get-VMHardDiskDrive.ControllerNumber.'
                'ControllerLocation' = 'Slot position on the controller from Get-VMHardDiskDrive.ControllerLocation (0-based).'
                'Path'               = 'Full path to the VHD/VHDX file from Get-VMHardDiskDrive.Path.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vStorage ----
            $tabNotes['vStorage'] = @{
                'Host'          = 'Hyper-V host that owns this storage volume.'
                'Path'          = 'Volume mount path (e.g. C:\ or E:\ClusterStorage\Volume1) from Get-Volume or Win32_Volume.'
                'Label'         = 'Volume label from Get-Volume.FileSystemLabel.'
                'FileSystem'    = 'File system type: NTFS / ReFS / CSVFS from Get-Volume.FileSystem.'
                'Type'          = 'Volume type: Fixed / Removable / CD-ROM / Unknown from Win32_Volume.DriveType.'
                'DriveLetter'   = 'Drive letter (if assigned) from Get-Volume.DriveLetter.'
                'TotalGB'       = 'Total volume capacity in GB: Win32_Volume.Capacity / 1GB, rounded 2 decimal places.'
                'FreeGB'        = 'Free space in GB: Win32_Volume.FreeSpace / 1GB, rounded 2 decimal places.'
                'PercentFree'   = 'Calculated: (FreeGB / TotalGB) * 100, rounded 1 decimal place.'
                'JunctionPaths' = 'Semicolon-delimited list of junction points that target this volume (from NTFS reparse point scan).'
                'MultiHomed'    = 'True if one or more junction paths redirect to this volume (derived from JunctionPaths).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Host-Storage-Risk ----
            $tabNotes['Host-Storage-Risk'] = @{
                'Host'                    = 'Hyper-V host the volume belongs to.'
                'Volume'                  = 'Volume mount path or drive letter on the host (from Get-Volume / vStorage collection).'
                'VolumeLabel'             = 'Volume label from Win32_Volume.Label or Get-Volume.FileSystemLabel.'
                'VolumeType'              = 'Volume classification: Fixed (local disk), CSV (Cluster Shared Volume), or Removable. Derived from drive type and cluster CSV detection.'
                'CapacityGB'              = 'Total volume capacity in GB from Get-Volume.Size / 1GB or Win32_Volume.Capacity / 1GB.'
                'FreeSpaceGB'             = 'Free space in GB from Get-Volume.SizeRemaining / 1GB. This is the actual space available right now.'
                'VMCount'                 = 'Count of VMs that have VHD/VHDX files stored on this volume (cross-referenced from vDisk-Analysis).'
                'UsedByVHDsGB'            = 'Sum of CurrentSizeGB for all VHDs on this volume. This is the current on-disk footprint of all VM virtual disks. Calculated: SUM(Get-VHD.FileSize / 1GB) grouped by host volume.'
                'UsedPercent'             = 'Calculated: ((CapacityGB - FreeSpaceGB) / CapacityGB) * 100. How full the volume is right now.'
                'MaxPotentialGB'          = 'Sum of MaxSizeGB for all Dynamic VHDs on this volume. This is the worst-case space consumption if every Dynamic VHD grows to its maximum provisioned size. Fixed VHDs already consume their max. Calculated: SUM(Get-VHD.Size / 1GB) grouped by host volume.'
                'PotentialPercent'        = 'Calculated: (MaxPotentialGB / CapacityGB) * 100. Volume utilization if all Dynamic VHDs fully expand. Values >100% indicate over-provisioning -- the volume cannot hold all VHDs at max size simultaneously.'
                'OverProvisioningGB'      = 'Calculated: MaxPotentialGB - CapacityGB (clamped to 0 minimum). How many GB the volume is over-provisioned by. Zero means all VHDs can reach max size without exhausting the volume.'
                'OverProvisioningPercent' = 'Calculated: (OverProvisioningGB / CapacityGB) * 100. The percentage by which worst-case VHD demand exceeds volume capacity.'
                'AvailableGrowthGB'       = 'Calculated: FreeSpaceGB - (MaxPotentialGB - UsedByVHDsGB). The effective free space after reserving room for Dynamic VHD growth. Negative values mean VHDs will run out of space before reaching max size.'
                'RiskLevel'               = 'Derived risk tier based on multiple factors: CRITICAL (volume <5% free OR AvailableGrowthGB negative), HIGH (<10% free OR PotentialPercent >100%), MEDIUM (<20% free), LOW (>=20% free and no over-provisioning). The formula combines current free space with projected VHD growth headroom.'
                'JunctionPaths'           = 'Semicolon-delimited junction point paths that redirect to this volume (e.g. C:\HV -> D:). Junctions affect VHD path resolution -- a VHD path showing C:\HV\... actually lives on D:.'
                'MultiHomed'              = 'True if one or more junction paths redirect to this volume. Indicates VHD path resolution may not match the apparent drive letter.'
                'SharedHostCount'           = 'Number of Hyper-V hosts that share this volume. 1 = dedicated local storage (per-host columns are authoritative). >1 = shared CSV or LUN (Shared* columns show the true aggregate risk). For MHOHCLUHV this is 5 (all nodes see the same CSV); for standalone hosts this is 1.'
                'SharedTotalVMCount'        = 'Total VM count across ALL hosts sharing this volume. Calculated: SUM(VMCount) for every host row with the same Volume path. Compare to per-host VMCount to see how much of the shared volume each host consumes.'
                'SharedTotalVHDCurrentGB'   = 'Sum of UsedByVHDsGB across ALL hosts sharing this volume. This is the actual on-disk VHD footprint from every host combined. For dedicated storage, equals UsedByVHDsGB. For shared CSV/LUN, this is the true total consumption.'
                'SharedTotalVHDMaxGB'       = 'Sum of MaxPotentialGB across ALL hosts sharing this volume. Worst-case space consumption if every Dynamic VHD on every host grows to its maximum provisioned size. This is the number to compare against CapacityGB for shared storage risk.'
                'SharedUsedPercent'         = 'Calculated: (SharedTotalVHDCurrentGB / CapacityGB) * 100. How full the shared volume is right now when considering ALL hosts. For dedicated storage, equals UsedPercent.'
                'SharedPotentialPercent'    = 'Calculated: (SharedTotalVHDMaxGB / CapacityGB) * 100. Volume utilization if ALL Dynamic VHDs on ALL hosts fully expand. Values >100% indicate cluster-wide over-provisioning.'
                'SharedOverProvisioningGB'  = 'Calculated: SharedTotalVHDMaxGB - CapacityGB. How many GB the volume is over-provisioned by across all hosts combined. Negative means capacity exceeds worst-case demand. Compare to per-host OverProvisioningGB to see the difference shared storage makes.'
                'SharedAvailableGrowthGB'   = 'Calculated: FreeSpaceGB - (SharedTotalVHDMaxGB - SharedTotalVHDCurrentGB). Effective free space after reserving room for ALL Dynamic VHD growth across ALL hosts. Negative values mean the shared volume cannot accommodate full VHD expansion. This is the most important shared storage metric.'
                'SharedRiskLevel'           = 'Cluster-wide risk tier using same thresholds as per-host RiskLevel but applied to shared totals: CRITICAL (SharedPotentialPercent >= 90%), HIGH (>= 75%), MEDIUM (>= 60%), LOW (< 60%). When SharedHostCount > 1, this column is more meaningful than per-host RiskLevel for capacity planning.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vDisk-Analysis ----
            $tabNotes['vDisk-Analysis'] = @{
                'VM'                = 'VM that owns this VHD.'
                'Host'              = 'Host the VM runs on.'
                'FileName'          = 'VHD/VHDX file name without path.'
                'FullPath'          = 'Full path to the VHD as stored in VM config.'
                'ResolvedPath'      = 'Actual path after junction/symlink resolution (may differ from FullPath if a junction point is involved).'
                'JunctionSource'    = 'Junction point path that points to ResolvedPath, if applicable.'
                'DiskType'          = 'VHD type: Dynamic (thin-provisioned, grows to MaxSize) or Fixed (pre-allocated to MaxSize).'
                'DiskFormat'        = 'File format: VHD (legacy, max 2TB) or VHDX (modern, max 64TB).'
                'CurrentSizeGB'     = 'Current file size on disk in GB from Get-VHD.FileSize / 1GB. For Dynamic, this is actual used space.'
                'MaxSizeGB'         = 'Maximum allocated size in GB from Get-VHD.Size / 1GB. For Fixed, equals CurrentSizeGB.'
                'GrowthPotentialGB' = 'Calculated: MaxSizeGB - CurrentSizeGB. Space a Dynamic VHD can still grow before filling its max.'
                'PercentUsed'       = 'Calculated: (CurrentSizeGB / MaxSizeGB) * 100. How full this Dynamic VHD is relative to its maximum.'
                'HostVolume'        = 'Volume on the host where the VHD file resides (derived from FullPath drive letter / mount point).'
                'Fragmentation'     = 'VHD file fragmentation percent from Optimize-VHD -Mode Full -Passthru (only collected when deep scan enabled).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- OS-Inventory ----
            $tabNotes['OS-Inventory'] = @{
                'VM'             = 'VM or host name (Type=VM shows guest, Type=Host shows Hyper-V host when AuditScope=HostsAndVMs).'
                'Host'           = 'Host the VM runs on (same as VM column when row is a host).'
                'Type'           = 'OPEN-67: Row scope -- Host (Hyper-V host) or VM (guest). Host rows appear when AuditScope = HostsAndVMs or Full.'
                'DataSource'     = 'Data platform source identifier: Hyper-V. Future: VMware, Nutanix, Active Directory.'
                'OSType'         = 'Detected OS type: Windows / Linux / FreeBSD / Other (via WinRM, KVP, or name pattern).'
                'OSName'         = 'Full OS caption from Win32_OperatingSystem.Caption (Windows) or /etc/os-release PRETTY_NAME (Linux).'
                'OSVersion'      = 'OS version string from Win32_OperatingSystem.Version or /etc/os-release VERSION_ID.'
                'OSBuild'        = 'Build number from Win32_OperatingSystem.BuildNumber (Windows only).'
                'Architecture'   = 'CPU architecture from Win32_OperatingSystem.OSArchitecture or uname -m (Linux).'
                'InstallDate'    = 'OS install date from Win32_OperatingSystem.InstallDate (converted from WMI datetime).'
                'LastBootTime'   = 'Last reboot time from Win32_OperatingSystem.LastBootUpTime (WMI datetime conversion).'
                'ServicePack'    = 'Service Pack level from Win32_OperatingSystem.ServicePackMajorVersion. "N/A" if no SP.'
                'LicenseStatus'  = 'Windows activation status from SoftwareLicensingProduct.LicenseStatus numeric code (1=Licensed).'
                'Domain'         = 'Domain the guest is joined to from Win32_ComputerSystem.Domain via WinRM.'
                'KernelVersion'  = 'Linux kernel version from uname -r (Linux only; N/A for Windows).'
                'LastUpdateKB'   = 'Most recent hotfix KB from Get-HotFix sorted by InstalledOn descending.'
                'LastUpdateDate' = 'Install date of most recent hotfix (yyyy-MM-dd).'
                'RebootPending'  = 'True/False - registry-based reboot detection (CBS/WU/FileRename/Rename keys).'
                'RebootReasons'  = 'Semicolon-delimited reboot trigger names.'
                'ActivationStatus' = 'Windows license status string (Licensed / Unlicensed / OOB Grace / etc.).'
                'ActivationMethod' = 'Derived: AVMA / KMS / MAK / Retail from SoftwareLicensingProduct.Description.'
                'KMSServer'      = 'KMS server from SoftwareLicensingProduct.DiscoveredKeyManagementServiceMachineName.'
                'PartialKey'     = 'Last 5 chars of product key from SoftwareLicensingProduct.PartialProductKey.'
            }

            # ---- vSwitch-Config ----
            $tabNotes['vSwitch-Config'] = @{
                'Host'              = 'Hyper-V host the virtual switch is on.'
                'SwitchName'        = 'Virtual switch name from Get-VMSwitch.Name.'
                'SwitchType'        = 'Switch type: External (bound to physical NIC) / Internal / Private (from Get-VMSwitch.SwitchType).'
                'AllowManagementOS' = 'True/False - whether the Hyper-V management OS (host) has access to this switch (Get-VMSwitch.AllowManagementOS).'
                'PhysicalAdapter'   = 'Physical NIC bound to this switch from Get-VMSwitch.NetAdapterInterfaceDescription or NetAdapterName.'
                'BandwidthMode'     = 'QoS bandwidth mode: None / Default / Weight / Absolute (Get-VMSwitch.BandwidthReservationMode).'
                'IovEnabled'        = 'True/False - SR-IOV (single-root I/O virtualization) enabled on the switch (Get-VMSwitch.IovEnabled).'
                'ManagementNICs'    = 'Semicolon-delimited host management NICs bound to this switch (Get-VMNetworkAdapter -ManagementOS), with VLAN if tagged.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vCluster ----
            $tabNotes['vCluster'] = @{
                'ClusterName'     = 'Failover cluster name from Get-Cluster.Name or AD computer object CNO (Cluster Name Object).'
                'Error'           = 'Error message if the cluster could not be contacted (e.g. WinRM failure, DNS resolution, access denied). Blank if cluster is reachable.'
                'LastLogon'       = 'Last AD logon date for the cluster computer object from Get-ADComputer.LastLogonDate. Stale dates indicate the cluster CNO may be offline or orphaned.'
                'ADObjectAge'     = 'Age in days of the cluster AD computer object. Calculated: (today - Get-ADComputer.WhenCreated).Days.'
                'Resources'       = 'Total count of cluster resources from Get-ClusterResource (includes VMs, IPs, disks, network names). For active clusters queried via Invoke-Command; for AD-only objects this is 0.'
                'NodeCount'       = 'Number of cluster nodes. For active clusters: (Get-ClusterNode).Count. For AD-only objects: derived from stored node list or 0.'
                'Status'          = 'Cluster classification: Active-HV (reachable Hyper-V cluster), Active-NonHV (reachable but no Hyper-V role), Stale (AD object exists but cluster unreachable), VM-Hosted (cluster CNO runs inside a VM).'
                'CSVCount'        = 'Count of Cluster Shared Volumes from (Get-ClusterSharedVolume).Count. 0 for non-S2D or unreachable clusters.'
                'Domain'          = 'AD domain the cluster CNO belongs to (from Get-ADComputer.DNSHostName suffix).'
                'ADCreated'       = 'Creation date of the cluster AD computer object from Get-ADComputer.WhenCreated.'
                'FQDN'            = 'Fully qualified domain name of the cluster from Get-ADComputer.DNSHostName or constructed from Name + domain.'
                'Nodes'           = 'Semicolon-delimited list of cluster node FQDNs from Get-ClusterNode. Blank if cluster is unreachable.'
                'ClusterType'     = 'Derived cluster type: HyperV (nodes have Hyper-V role), SQL (SQL Server AG/FCI), Storage (S2D/SOFS), General (other), Unknown. Based on cluster resource types and node roles.'
                'ParentCluster'   = 'If this is a VM-hosted cluster, the name of the Hyper-V cluster hosting the VM nodes. Blank for physical clusters.'
                'QuorumType'      = 'Cluster quorum configuration from Get-ClusterQuorum: NodeMajority / NodeAndDiskMajority / NodeAndFileShareMajority / NodeAndCloudWitness / etc.'
                'Recommendation'  = 'Derived advisory: flags stale clusters for cleanup, VM-hosted clusters for review, missing quorum witness, node count concerns, etc.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Applications-Windows ----
            $tabNotes['Applications-Windows'] = @{
                'VM'            = 'VM the application is installed on.'
                'Host'          = 'Hyper-V host the VM runs on.'
                'Application'   = 'Application display name from registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* DisplayName.'
                'Version'       = 'Application version from registry DisplayVersion. "MISSING" if this is a compliance gap row.'
                'Publisher'     = 'Publisher from registry Publisher value.'
                'InstallDate'   = 'Install date from registry InstallDate (yyyyMMdd format from vendor).'
                'SizeMB'        = 'Estimated size in MB: registry EstimatedSize (KB) / 1024, rounded 2 decimal places.'
                'ComplianceType' = 'Derived compliance flag: Required / Missing Required / Remove / Security Tool / Required (Pre-2025) based on AppCompliance config in Config-OHDC.psd1.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Applications-Linux ----
            # OPEN-50/51 closeout 2026-04-12: tabNotes coverage for Linux app inventory.
            # Populated by future SSH/probe modules (Guest\Linux\ in v4.0.0 layout).
            # Until those collectors ship, this tab may be empty -- the notes are still
            # attached so the tab is self-documenting if/when rows appear.
            $tabNotes['Applications-Linux'] = @{
                'VM'            = 'Linux VM (or physical Linux host) the package is installed on. Future module: SSH-based collection from Guest\Linux\ probes.'
                'Host'          = 'Hypervisor host that owns this VM (blank for bare-metal Linux). Source: cross-reference from the platform collector that discovered the VM.'
                'Distribution'  = 'Linux distribution name and version: Ubuntu 22.04 / RHEL 9.3 / SLES 15.5 / etc. Source: /etc/os-release PRETTY_NAME field via SSH.'
                'PackageManager' = 'Native package manager detected on the host: apt / dnf / yum / zypper / apk / pacman. Determines which inventory command was used.'
                'Package'       = 'Package name as reported by the native package manager (e.g. apt: dpkg-query -W; rpm-based: rpm -qa --queryformat).'
                'Version'       = 'Installed package version string from the native package manager. Format varies by distro.'
                'Architecture'  = 'Package architecture: amd64 / x86_64 / aarch64 / noarch. Source: native package manager.'
                'InstallDate'   = 'Install date if the package manager records it. dpkg does not; rpm-based managers do via INSTALLTIME header. May be blank for apt-managed packages.'
                'SizeKB'        = 'Installed size in kilobytes from the native package manager. dpkg: Installed-Size field; rpm: SIZE header.'
                'Source'        = 'Repository or source the package came from (apt: sources.list entry; dnf/yum: repo ID). Helps identify out-of-band installs from third-party repos or manual builds.'
                'ComplianceType' = 'Derived compliance flag: Required / Missing Required / Remove / Security Tool. Same model as Applications-Windows but with Linux-specific package name patterns. Configured via AppCompliance.Linux section in Config-OHDC.psd1 (future).'
                'AlertLevel'    = 'Calculated alert level: OK / Warning / Critical. Critical for missing required security packages, Warning for outdated versions, OK otherwise.'
                'DataSource'    = 'Data platform source identifier. Will be set to LINUX-SSH or LINUX-AGENT depending on collection method when the Guest\Linux\ collector ships.'
            }

            # ---- Security-Compliance ----
            $tabNotes['Security-Compliance'] = @{
                'VM'                 = 'VM name (N/A for Host rows).'
                'Host'               = 'Host name.'
                'Type'               = 'Row type: VM or Host.'
                'Generation'         = 'VM generation (VM rows only): 1 = BIOS/IDE, 2 = UEFI/SCSI.'
                'FirmwareType'       = 'BIOS or UEFI from VM firmware or host firmware check.'
                'SecureBootEnabled'  = 'True/False - Secure Boot enabled for VM or host.'
                'SecureBootTemplate' = 'VM Secure Boot template (VM rows): MicrosoftWindows / MicrosoftUEFICertificateAuthority / OpenSourceShieldedVM.'
                'TPMEnabled'         = 'True/False - vTPM enabled (VM rows) or physical TPM present (Host rows).'
                'OSName'             = 'Guest OS caption (VM rows, from Hyper-V IC).'
                'SB_CertRisk'        = 'Derived: "At Risk" if VM uses MicrosoftUEFICertificateAuthority template with Secure Boot on. See KB5025885.'
                'HostType'           = 'Physical or Virtual (Host rows only).'
                'Manufacturer'       = 'Hardware manufacturer (Host rows only).'
                'Model'              = 'Hardware model (Host rows only).'
                'SerialNumber'       = 'Chassis serial number (Host rows only).'
                'TPMVersion'         = 'TPM spec version: 1.2 / 2.0 / None (Host rows only).'
                'SB_Has2023Certs'    = 'True/False - updated 2023 Secure Boot CA certs present in host DB (Host rows only).'
                'SB_UpdateRequired'  = 'Derived: "Yes (Expiring 2026)" / "No (Already Updated)" / "N/A" (Host rows only).'
                'SB_DaysUntilExp'    = 'Days until oldest Secure Boot cert expires. Calculated: (cert.NotAfter - today).Days (Host rows).'
                'SB_KBs_Missing'     = 'Required Secure Boot KBs not found on this host.'
                'SB_Action'          = 'Recommended action for Secure Boot cert update.'
                'ComplianceStatus'   = 'Derived overall compliance: Compliant / Non-Compliant - Gen 1 BIOS / Secure Boot Disabled / CERT UPDATE REQUIRED.'
                'MissingApps'        = 'VM rows: required applications not found installed. Cross-reference Applications-Windows tab.'
                'RemoveApps'         = 'VM rows: flagged applications present that should be removed per AppCompliance config.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- VM-Guest-Storage ----
            $tabNotes['VM-Guest-Storage'] = @{
                'VM'                  = 'VM name.'
                'Host'                = 'Host the VM runs on.'
                'DriveLetter'         = 'Drive letter inside the guest (e.g. C:, D:) from Win32_LogicalDisk.DeviceID (DriveType=3 fixed disks only).'
                'Label'               = 'Volume label from Win32_LogicalDisk.VolumeName.'
                'FileSystem'          = 'File system type from Win32_LogicalDisk.FileSystem (NTFS / ReFS).'
                'TotalGB'             = 'Drive capacity in GB: Win32_LogicalDisk.Size / 1GB, rounded 2 decimal places.'
                'UsedGB'              = 'Calculated: TotalGB - FreeGB.'
                'FreeGB'              = 'Free space in GB: Win32_LogicalDisk.FreeSpace / 1GB, rounded 2 decimal places.'
                'PercentFree'         = 'Calculated: (FreeGB / TotalGB) * 100, rounded 1 decimal place.'
                'PercentUsed'         = 'Calculated: 100 - PercentFree, rounded 1 decimal place.'
                'AlertLevel'          = 'Derived: Critical (below GuestStorageCriticalPct% free or effectively 0), Warning (below GuestStorageWarningPct% free or growth-based projection), OK otherwise. Thresholds configurable in Config-OHDC.psd1.'
                'DataPoints'          = 'Number of historical snapshots available for this drive in GuestStorageHistory JSON file.'
                'OldestDataPoint'     = 'Date of the oldest historical data point for growth calculation.'
                'GrowthRate_GB_Month' = 'Calculated: ((NewestUsedGB - OldestUsedGB) / DaySpan) * 30. Requires 2+ data points.'
                'Projected1Yr_UsedGB' = 'Calculated: CurrentUsedGB + (GrowthRateGBperDay * 365). Projected used space in 1 year.'
                'GrowthBasis'         = 'Description of how the growth rate was calculated (data point count, date range, monthly rate). "Default" if insufficient history.'
                'Recommendation'      = 'Derived advisory combining free space threshold checks, growth-based expansion sizing, and C: cleanup opportunities.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }
            # Dynamically add monthly growth column notes -- these columns are generated
            # at runtime based on the date range in GuestStorageHistory JSON (e.g. Feb_2026_GrowthGB,
            # Mar_2026_GrowthGB). Each represents the net change in UsedGB for that calendar month.
            # We pre-populate the 12 most recent months so notes are available for any run date.
            $now = Get-Date
            for ($mi = 0; $mi -lt 24; $mi++) {
                $monthDate = $now.AddMonths(-$mi)
                $colName = '{0}_{1}_GrowthGB' -f $monthDate.ToString('MMM'), $monthDate.ToString('yyyy')
                $tabNotes['VM-Guest-Storage'][$colName] = (
                    "Monthly growth in GB for {0} {1}. Calculated: UsedGB at end of month minus UsedGB at start of month, " +
                    "using the closest data points from GuestStorage-History.json. Each report run records a snapshot of " +
                    "every guest drive''s UsedGB into the history file (controlled by GuestStorageTrackingMode in Config-OHDC.psd1). " +
                    "Negative values indicate space was reclaimed (cleanup, file deletion). Blank means no data points exist " +
                    "for that month yet (drive was not inventoried or VM was powered off)."
                ) -f $monthDate.ToString('MMMM'), $monthDate.ToString('yyyy')
            }

            # ---- Storage-VHD-Detail ----
            $tabNotes['Storage-VHD-Detail'] = @{
                'Host'                  = 'Hyper-V host the VHD is stored on.'
                'Volume'                = 'Host volume (mount path) where the VHD resides.'
                'VolumeType'            = 'Volume type from vStorage (Fixed / CSV / etc.).'
                'VolumeCapacityGB'      = 'Total volume capacity in GB.'
                'VolumeFreeGB'          = 'Free space on the volume in GB.'
                'VM'                    = 'VM that owns this VHD.'
                'VHDFile'               = 'VHD/VHDX file name.'
                'FullPath'              = 'Full VHD path in the VM config.'
                'ResolvedPath'          = 'Actual path after junction resolution.'
                'JunctionSource'        = 'Junction that redirects to this VHD, if applicable.'
                'DiskType'              = 'Dynamic or Fixed.'
                'CurrentSizeGB'         = 'Current file size on disk in GB.'
                'MaxSizeGB'             = 'Maximum provisioned size in GB.'
                'GrowthPotentialGB'     = 'Calculated: MaxSizeGB - CurrentSizeGB (space remaining for Dynamic VHDs).'
                'PercentUsed'           = 'Calculated: (CurrentSizeGB / MaxSizeGB) * 100.'
                'VolumeVHDCurrentTotal' = 'Calculated: sum of CurrentSizeGB for all VHDs on this volume and host. Shows total disk footprint vs VolumeFreeGB.'
                'VolumeVHDMaxTotal'     = 'Calculated: sum of MaxSizeGB for all VHDs on this volume. Worst-case space if all Dynamic VHDs fully expand.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- WinRM-Health ----
            $tabNotes['WinRM-Health'] = @{
                'VM'                 = 'VM name.'
                'Host'               = 'Host the VM runs on.'
                'WinRM_Status'       = '"Running" if Invoke-Command succeeded; "Unreachable" if WinRM failed; "N/A (Off)" if VM is powered off.'
                'WinRM_HTTPS'        = '"No" if no HTTPS listener; "Yes" or True if HTTPS listener is configured.'
                'WinRM_CertExpiry'   = 'WinRM HTTPS certificate NotAfter date from Cert:\LocalMachine\My.'
                'WinRM_CertDaysLeft' = 'Calculated: (WinRM_CertExpiry - today).TotalDays as integer. Negative = already expired.'
                'WinRM_CredSSP'      = 'CredSSP server-side enabled state from Get-WSManInstance winrm/config/Service Auth.CredSSP.'
                'WinRM_Listeners'    = 'Listener summary string (e.g. HTTP://*:5985; HTTPS://*:5986).'
                'WinRM_Recommendation' = 'Derived advisory for this VM: No HTTPS / AllowUnencrypted / cert expiry warning.'
                'AlertLevel'         = 'Derived: Critical if WinRM not running; Warning if no HTTPS or cert expiring <30 days; OK otherwise.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Services-Alerts ----
            $tabNotes['Services-Alerts'] = @{
                'Server'         = 'VM or host name where the service alert was found.'
                'Type'           = 'Row type: VM or Host.'
                'Host'           = 'Hyper-V host (for VM rows, the parent host; for Host rows, the host itself).'
                'AlertType'      = '"Stopped Auto-Start" if an Auto-start service is not Running; "Non-Standard Service Account" if StartName is not a built-in system account.'
                'Severity'       = '"Warning" for Stopped Auto-Start; "Info" for Non-Standard Service Account.'
                'Name'           = 'Service internal name from Win32_Service.Name.'
                'DisplayName'    = 'Service friendly name from Win32_Service.DisplayName.'
                'Status'         = 'Current service state: Running / Stopped / etc. (Win32_Service.State).'
                'StartMode'      = 'Startup type: Auto / Manual / Disabled (Win32_Service.StartMode).'
                'StartName'      = 'Service account (Win32_Service.StartName). Flagged if not in SystemAccounts config list.'
                'Recommendation' = 'Derived advisory explaining what to investigate.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Scheduled-Tasks (chunked tabs) ----
            # Applied to each chunk tab e.g. Scheduled-Tasks, Scheduled-Tasks_1of2
            $scheduledTasksNotes = @{
                'Server'      = 'VM or host name where this task is defined.'
                'Type'        = 'Row type: VM or Host.'
                'Host'        = 'Hyper-V host (parent host for VMs, the host itself for Host rows).'
                'TaskName'    = 'Task name from Get-ScheduledTask.TaskName.'
                'TaskPath'    = 'Task folder path from Get-ScheduledTask.TaskPath (e.g. \Microsoft\Windows\...).'
                'Status'      = 'Task state: Ready / Running / Disabled (Get-ScheduledTask.State).'
                'RunAs'       = 'Account the task runs as: Get-ScheduledTask.Principal.UserId or GroupId.'
                'LastRunTime' = 'Last execution time from Get-ScheduledTask.LastRunTime (yyyy-MM-dd HH:mm:ss).'
                'NextRunTime' = 'Next scheduled run time from Get-ScheduledTask.NextRunTime.'
                'LastResult'  = 'Last task result code in hex (0x00000000 = success) from Get-ScheduledTask.LastTaskResult.'
                'Description' = 'Task description (truncated to 200 chars) from Get-ScheduledTask.Description.'
                'Actions'     = 'Pipe-delimited action summary: executable path + arguments, or COM handler ClassId (truncated to 300 chars).'
            }
            $tabNotes['Scheduled-Tasks'] = $scheduledTasksNotes
            # Also apply to any chunked variants
            for ($chk = 1; $chk -le 9; $chk++) {
                $tabNotes["Scheduled-Tasks_${chk}of2"] = $scheduledTasksNotes
                $tabNotes["Scheduled-Tasks_${chk}of3"] = $scheduledTasksNotes
            }

            # ---- Roles-Features ----
            $tabNotes['Roles-Features'] = @{
                'Computer'     = 'VM or host name where this feature is installed.'
                'MachineType'  = 'Whether this machine is a "Host" (Hyper-V hypervisor) or "VM" (virtual machine). Determined by checking if Computer matches a known Hyper-V host FQDN or short name in the collected HostData. If a match is found the row is tagged "Host"; otherwise "VM". This classification drives filtering in the report -- you can filter to see only host-level roles or only VM-level roles.'
                'FeatureName'  = 'Role/feature internal name from Get-WindowsFeature.Name (e.g. "Web-Server", "DNS", "Hyper-V"). This is the programmatic name used in PowerShell commands like Install-WindowsFeature.'
                'DisplayName'  = 'Friendly display name from Get-WindowsFeature.DisplayName (e.g. "Web Server (IIS)", "DNS Server"). This is the name shown in Server Manager.'
                'FeatureType'  = 'Classification: Role (top-level server role like IIS/DNS/AD DS), Role Service (sub-component of a role), Feature (standalone feature like .NET/Telnet), Framework (.NET version detected via registry), FileSystem (.NET Core/SDK detected via file presence in Program Files). Roles and Role Services come from Get-WindowsFeature; Framework from HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP; FileSystem from dotnet --list-runtimes or folder check.'
                'InstallState' = 'Installation state of the feature from Get-WindowsFeature.InstallState: Installed (feature is active), Available (feature is in the image but not installed -- only shown if IncludeAvailable is set), Removed (feature payload removed from image). For .NET Framework/Core rows this is always "Installed" since detection means presence.'
                'Category'     = 'Derived highlight category for notable roles: "IIS Web Server" / "DNS Server" / "Domain Controller" / "Hyper-V Role" / "DHCP Server" / "File Server" / "Failover Clustering" / etc. Blank for non-highlighted features. Used for quick filtering to find critical infrastructure roles across all machines.'
                'Source'       = 'Collection method: "WindowsFeature" (from Get-WindowsFeature via WinRM), "Registry" (.NET Framework version from HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\Release key), or "FileSystem" (.NET Core/SDK presence detected via dotnet folder check in Program Files).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vCPU ----
            $tabNotes['vCPU'] = @{
                'VM'         = 'VM name.'
                'Host'       = 'Host the VM runs on.'
                'CPUs'       = 'Number of virtual CPUs assigned from Get-VM.ProcessorCount.'
                'CPUUsage'   = 'CPU utilization percent from Get-VM.CPUUsage (instantaneous sample at collection time).'
                'Powerstate' = 'VM power state at collection time.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vMemory ----
            $tabNotes['vMemory'] = @{
                'VM'            = 'VM name.'
                'Host'          = 'Host the VM runs on.'
                'MemoryMB'      = 'Memory assigned in MB from Get-VM.MemoryAssigned / 1MB, rounded to whole number.'
                'MemoryPercent' = 'Memory demand as percent from Get-VM.MemoryDemand / Get-VM.MemoryAssigned * 100 (Dynamic Memory metric).'
                'Powerstate'    = 'VM power state.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vCheckpoint ----
            $tabNotes['vCheckpoint'] = @{
                'VM'             = 'VM name.'
                'Host'           = 'Host the VM runs on.'
                'CheckpointName' = 'Checkpoint name from Get-VMSnapshot.Name. Backup-origin checkpoints typically contain the vendor name (e.g. "Commvault_IntelliSnap_...", "Veeam Backup Temporary Checkpoint").'
                'CheckpointId'   = 'Checkpoint GUID from Get-VMSnapshot.Id.'
                'ParentId'       = 'Parent checkpoint GUID (for checkpoint chains) from Get-VMSnapshot.ParentSnapshotId. When ParentId is populated, this checkpoint is part of a chain -- the VM has multiple AVHDX files stacked. Long chains cause I/O amplification.'
                'CreationTime'   = 'Checkpoint creation timestamp from Get-VMSnapshot.CreationTime.'
                'AgeDays'        = 'Calculated: (today - CreationTime).Days. Age of the checkpoint in whole days.'
                'Warning'        = 'Derived alert: "CRITICAL - N days old" if AgeDays > 30; "WARNING - N days old" if > 7; "OK" otherwise.'
                'SnapshotType'   = 'v3.10.11 CR104: Checkpoint type from Get-VMSnapshot.SnapshotType. "Standard" = user-created or backup-created checkpoint. "Recovery" = recovery checkpoint (Server 2016+ production checkpoints). "Standard" on older Hyper-V versions where SnapshotType property does not exist.'
                'BackupVendor'   = 'v3.10.11 CR104: Detected backup vendor from checkpoint name pattern matching. Values: Commvault (CV_DVSNAP/IntelliSnap), Veeam (VeeamBackup/Consolidation), AzureBackup (IaaSBcdr), DPM (Data Protection Manager), Altaro (Hornetsecurity), Nakivo, Zerto, Unknown-Backup (generic "Backup" keyword), Manual (no backup vendor pattern matched -- user-created checkpoint). Blue highlighting for backup-origin checkpoints.'
                'IsBackupOrigin' = 'v3.10.11 CR104: True if BackupVendor is not "Manual" -- this checkpoint was created by a backup solution. Backup-origin checkpoints older than BackupCheckpointStaleDays (config, default 3) indicate a stuck/failed backup that left a checkpoint behind, causing AVHDX chain growth and potential I/O storms. Cross-reference with the backup vendor''s console to determine if the backup job needs remediation.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows.'
            }

            # ---- VHD-Chain (v3.10.12 CR105) ----
            $tabNotes['VHD-Chain'] = @{
                'VMName'               = 'Hyper-V VM display name. Matches VM column on vCheckpoint and vDisk tabs.'
                'Host'                 = 'Hyper-V host the VM is running on. Scripts must be run on this host (or the current cluster owner).'
                'ClusterName'          = 'Failover cluster name if the host is part of a cluster (e.g. RICTX-UCS-CLS, MHOHCLUHV). Blank for standalone hosts.'
                'ControllerType'       = 'Disk controller type: IDE or SCSI. SCSI is standard for Hyper-V Gen 2 VMs. IDE used for Gen 1 boot disks.'
                'ControllerNum'        = 'Controller number (0-3). Gen 2 VMs typically use SCSI controller 0.'
                'ControllerLoc'        = 'Controller location (disk slot, 0-63 for SCSI). Combined with ControllerNum uniquely identifies the disk attachment point.'
                'ChainLevel'           = '0 = the active disk (top of chain, currently written to). 1+ = parent delta layers. Highest number = base .vhdx disk. Filter on ChainLevel=0 to see one row per disk (the summary row with Recommendation).'
                'LinkType'             = 'Active (level 0 running .avhdx or .vhdx if no checkpoints), Checkpoint (intermediate .avhdx delta), Base (bottom-of-chain .vhdx with no ParentPath), Passthrough (raw disk attachment, no .vhdx file), BrokenParent (ParentPath set but file missing or inaccessible -- Critical), Error (Get-VHD call failed on this link).'
                'FilePath'             = 'Full UNC or local path to this VHD/AVHDX file as seen from the Hyper-V host.'
                'FileSizeMB'           = 'Current file size in MB (rounded to 2 decimals). For differencing disks (.avhdx), this is the size of the delta, not the logical disk size. Backup checkpoint deltas grow with each backup cycle write.'
                'FileFormat'           = 'VHDX (current format, default for Hyper-V Gen 2), VHD (legacy format, Gen 1), Passthrough, or Unknown (if Get-VHD failed).'
                'ParentPath'           = 'Path to the parent file in the chain. Blank for the base disk (IsBaseDisk = True). If this path is set but the file is missing, LinkType = BrokenParent.'
                'CreatedOn'            = 'File creation timestamp (Get-Item.CreationTime). For Checkpoint links, this is approximately when the backup was taken. Old CreatedOn values on Checkpoint links indicate stuck backup chains.'
                'IsBaseDisk'           = 'True only for the bottom-of-chain file (no ParentPath). This is the file that will remain after a successful merge operation.'
                'ChainDepth'           = 'Total number of links in this disk''s chain (denormalized on every row for easy filtering). ChainDepth=1 means no checkpoints (base disk only -- healthy). ChainDepth=2 means active + base (typically a linked clone or single checkpoint). ChainDepth>=3 means active + one or more deltas + base. ChainDepth>=5 is Critical (stuck backup chain). Thresholds configurable: VHDChainCriticalDepth, VHDChainWarningDepth.'
                'ChainTotalMB'         = 'Sum of FileSizeMB across all links in this disk''s chain (denormalized). Useful for capacity planning: total chain storage is often 20-40% larger than the base disk size for heavily checkpointed VMs.'
                'AlertLevel'           = 'OK (depth 1-2, no stale checkpoints, no errors), Warning (depth >= VHDChainWarningDepth OR any Checkpoint link older than VHDChainStaleCheckpointDays), Critical (depth >= VHDChainCriticalDepth, OR LinkType = BrokenParent/Error, OR any Checkpoint link older than 30 days).'
                'Recommendation'       = 'Consolidation guidance generated from the chain state. Populated ONLY on ChainLevel=0 rows (other rows blank to avoid duplication). Ranges from "Healthy -- no action needed" to "STUCK backup chain -- pause backups and merge".'
                'RemediationScriptPath' = 'Relative path to the auto-generated per-VM repair script (CR106). Only populated for Critical/Warning VMs when EnableRemediationScripts = $true in config. Path is relative to the report output folder. Script must be reviewed and run manually on the owning Hyper-V host.'
                'Error'                = 'Error message if Get-VHD or Test-Path failed for this link. Blank on healthy rows.'
                'DataSource'           = 'Always HYPER-V. Chain collection runs via Invoke-Command on each Hyper-V host.'
            }

            # ---- vIntegration ----
            $tabNotes['vIntegration'] = @{
                'VM'      = 'VM name.'
                'Host'    = 'Host the VM runs on.'
                'Service' = 'Integration Service name from Get-VMIntegrationService.Name (e.g. Heartbeat, VSS, Guest Service Interface).'
                'Enabled' = 'True/False - whether this Integration Service is enabled (Get-VMIntegrationService.Enabled).'
                'Status'  = 'Service status description from Get-VMIntegrationService.PrimaryStatusDescription (OK / Error / etc.).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vDVD ----
            $tabNotes['vDVD'] = @{
                'VM'                 = 'VM name.'
                'Host'               = 'Host the VM runs on.'
                'Controller'         = 'Controller type: IDE or SCSI (from Get-VMDvdDrive.ControllerType).'
                'ControllerNumber'   = 'Controller number from Get-VMDvdDrive.ControllerNumber.'
                'ControllerLocation' = 'Slot on the controller from Get-VMDvdDrive.ControllerLocation.'
                'Path'               = 'ISO file path if an image is mounted; blank if empty or physical drive (Get-VMDvdDrive.Path).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- vReplication ----
            # OPEN-50/51 closeout 2026-04-12: Hyper-V Replica state per VM.
            # Source cmdlet: Get-VMReplication on each Hyper-V host. Only rows
            # for VMs that have replication enabled (no row = not replicating).
            $tabNotes['vReplication'] = @{
                'VM'                  = 'Replicated VM name (from Get-VMReplication.Name).'
                'Host'                = 'Primary Hyper-V host that owns the source VM (Get-VMReplication.ComputerName).'
                'ReplicationState'    = 'Replication state from Get-VMReplication.State: Disabled / ReadyForInitialReplication / InitialReplicationInProgress / WaitingForInitialReplication / Replicating / PreparedForFailover / FailedOverWaitingCompletion / FailedOver / SuspendedReplication / Error / Resynchronizing / ResynchronizeSuspended / RecoveryInProgress / FailbackInProgress / FailbackComplete / Critical. Replicating = healthy steady state. Error/Critical/Resynchronizing = needs attention.'
                'ReplicationMode'     = 'Replication mode from Get-VMReplication.ReplicationMode: Primary / Replica / TestReplica / ExtendedReplica. Primary = source side; Replica = target/destination side.'
                'ReplicationHealth'   = 'Replication health from Get-VMReplication.Health: Normal / Warning / Critical / NotApplicable. Critical typically means resync needed.'
                'PrimaryServer'       = 'Hostname of the primary (source) Hyper-V host from Get-VMReplication.PrimaryServerName.'
                'ReplicaServer'       = 'Hostname of the replica (target) Hyper-V host from Get-VMReplication.ReplicaServerName.'
                'ReplicaServerPort'   = 'TCP port used for replication traffic from Get-VMReplication.ReplicaServerPort. Default 80 (HTTP / Kerberos auth) or 443 (HTTPS / certificate auth).'
                'AuthenticationType'  = 'Auth type from Get-VMReplication.AuthenticationType: Kerberos (default, port 80) or Certificate (port 443). Certificate required for cross-domain or untrusted forest replication.'
                'Frequency'           = 'Replication frequency in seconds from Get-VMReplication.FrequencySec: 30 / 300 / 900 (30s / 5min / 15min). Frequency is fixed at VM enable time, not dynamic.'
                'LastReplicationType' = 'Last replication operation type from Get-VMReplication.LastReplicationType: Initial / Regular / Resynchronize / FailbackPlanned / FailbackComplete.'
                'LastReplicationTime' = 'Timestamp of the last successful replication (Get-VMReplication.LastReplicationTime). Stale timestamps (>4x Frequency) indicate the link is broken or paused.'
                'AlertLevel'          = 'Derived alert level: OK if Replicating + Normal health + recent LastReplicationTime; Warning if health=Warning OR LastReplicationTime is stale; Critical if health=Critical OR ReplicationState in (Error, Critical, Resynchronizing).'
                'DataSource'          = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- CPU-Analysis ----
            $tabNotes['CPU-Analysis'] = @{
                'VM'              = 'VM name. Each row represents one running VM and its CPU utilization metrics.'
                'Host'            = 'Hyper-V host the VM runs on.'
                'AllocatedCPUs'   = 'Number of virtual CPUs assigned to this VM from Get-VM.ProcessorCount.'
                'AvgCPUPercent'   = 'Average CPU utilization percent for this VM at collection time from Get-VM.CPUUsage. This is an instantaneous sample, not a historical average.'
                'PeakCPUPercent'  = 'Peak CPU utilization captured during the collection window. For single-sample collection this equals AvgCPUPercent.'
                'WastePercent'    = 'Calculated: 100 - AvgCPUPercent. Represents the percentage of allocated CPU capacity not being used. High values (>80%) suggest the VM may be over-provisioned for its workload.'
                'Status'          = 'Derived CPU efficiency status: Idle (<5% avg), Underutilized (<25% avg), Normal (25-75%), Busy (75-90%), Critical (>90%). Based on AvgCPUPercent thresholds.'
                'Recommendation'  = 'Derived advisory: suggests reducing vCPU count for idle/underutilized VMs, monitoring for busy VMs, or adding vCPUs for critical VMs.'
                'PotentialSavings' = 'Estimated vCPU count that could be reclaimed if the VM were right-sized. Calculated based on current utilization vs allocated CPUs. Blank if no savings opportunity.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Recommendations ----
            $tabNotes['Recommendations'] = @{
                'Type'             = 'Recommendation category: Storage / CPU / Memory / Security / Network / Configuration / Checkpoint.'
                'Severity'         = 'Severity level: Critical / High / Medium / Low / Info. Determines remediation priority.'
                'Target'           = 'The VM or host name this recommendation applies to.'
                'Issue'            = 'Description of the issue or condition that triggered this recommendation.'
                'Recommendation'   = 'Suggested corrective action with specific details (e.g. expand VHD by X GB, reduce vCPU count to Y).'
                'PotentialSavings' = 'Estimated resource savings if the recommendation is implemented (e.g. "2 vCPUs", "50 GB disk"). Blank if not quantifiable.'
                'Priority'         = 'Numeric priority for remediation ordering (1 = highest). Derived from Severity and category weighting.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Compliance-Issues ----
            $tabNotes['Compliance-Issues'] = @{
                'Type'           = 'Issue category: Security / Storage / Configuration / Network / Checkpoint.'
                'Severity'       = 'Issue severity: Critical / Warning / Info. Determines remediation urgency.'
                'Target'         = 'The VM or host name where the compliance issue was found.'
                'TargetType'     = 'Whether the target is a VM or Host. Used for filtering and grouping.'
                'Issue'          = 'Description of the compliance violation or non-conformance.'
                'Recommendation' = 'Recommended corrective action to resolve this compliance issue.'
                'Impact'         = 'Description of the operational or security impact if this issue is not addressed.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Missing-VMs ----
            $tabNotes['Missing-VMs'] = @{
                'VM'                = 'VM display name that was present in a previous report run but not found in the current run.'
                'VMId'              = 'VM GUID from Get-VM.VMId (stable across renames). Used to track VM identity across report runs even if the display name changes.'
                'FirstSeen'         = 'Date this VM first appeared in a report run (from VM-History.json). Indicates when the VM was originally created or first inventoried.'
                'LastSeen'          = 'Date the VM was last seen in a successful report run (from VM-History.json). The most recent run where this VM was found on any host.'
                'DaysSinceLastSeen' = 'Calculated: (today - LastSeen).Days. How many days since this VM was last inventoried. VMs missing for longer than MissingVMDropoffDays (Config-OHDC.psd1, default 90) are automatically pruned from history.'
                'PreviousHosts'     = 'Semicolon-delimited list of all hosts where this VM has been observed across all report runs. Shows migration history and helps locate where the VM was last running.'
                'Status'            = 'Current classification: "Missing" (was in history, not in current run), "Excluded" (matches an ExcludeVMPatterns filter), or "Decommissioned" (absent beyond dropoff threshold).'
                'DropoffIn'         = 'Days remaining before this VM is automatically pruned from VM-History.json. Calculated: MissingVMDropoffDays - DaysSinceLastSeen. When this reaches 0, the VM is permanently removed from the Missing-VMs list on the next run.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Reboot-History ----
            $tabNotes['Reboot-History'] = @{
                'Server'   = 'Hyper-V host name that the event was collected from.'
                'Computer' = 'Computer name from inside the event log record (may be the VM guest name for VM rows).'
                'Date'     = 'Event timestamp from EventLog System event ID 1074 (yyyy-MM-dd HH:mm:ss).'
                'Action'   = 'Action taken: "shutdown" / "restart" from event ReplacementStrings[4].'
                'Reason'   = 'Shutdown reason string from event ReplacementStrings[2].'
                'User'     = 'User who initiated the shutdown from event ReplacementStrings[6].'
                'Process'  = 'Process that initiated the shutdown from event ReplacementStrings[0].'
                'Source'   = '"HostEventLog" for events collected from the Hyper-V host; "VMEventLog" for events from inside a VM guest via WinRM.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Services (chunked) ----
            $servicesNotes = @{
                'Server'      = 'VM or host name where this service is running.'
                'Type'        = 'Row type: VM or Host.'
                'Host'        = 'Hyper-V host (parent host for VMs; host itself for Host rows).'
                'Name'        = 'Service internal name from Win32_Service.Name.'
                'DisplayName' = 'Service friendly display name from Win32_Service.DisplayName.'
                'Status'      = 'Current state: Running / Stopped / StartPending / etc. (Win32_Service.State).'
                'StartMode'   = 'Startup type: Auto / Manual / Disabled (Win32_Service.StartMode). Collection is filtered to Auto-start by default.'
                'StartName'   = 'Account the service runs as (Win32_Service.StartName). Non-system accounts are flagged in Services-Alerts.'
                'PathName'    = 'Executable path of the service binary from Win32_Service.PathName.'
                'Description' = 'Service description text (truncated to 200 chars) from Win32_Service.Description.'
            }
            $tabNotes['Services'] = $servicesNotes
            for ($chk = 1; $chk -le 9; $chk++) {
                $tabNotes["Services_${chk}of2"] = $servicesNotes
                $tabNotes["Services_${chk}of3"] = $servicesNotes
            }

            # ---- Local-Admins ----
            $tabNotes['Local-Admins'] = @{
                'VM'              = 'VM name.'
                'Host'            = 'Host the VM runs on.'
                'Domain'          = 'Domain the VM is joined to (resolved from OSInfo.Domain, then DNSHostName suffix, then parent host domain).'
                'MemberName'      = 'Full account name in DOMAIN\Name format from Get-LocalGroupMember or ADSI WinNT provider fallback.'
                'ObjectClass'     = '"User" or "Group" from Get-LocalGroupMember.ObjectClass.'
                'PrincipalSource' = 'Source: "ActiveDirectory" / "Local" / "MicrosoftAccount" / "ADSI" (ADSI = WS2012 fallback).'
                'Tier'            = 'Derived authorization tier: Required (in RequiredBuiltinMembers config) / Allowed / Unexpected (present but not in config) / Unconfigured (no config defined) / Required-Missing.'
                'AlertLevel'      = 'Derived: "OK" for Required/Allowed; "Review" for Unexpected members; "Missing" for Required members absent from the group.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- AD-Auth-Detail ----
            $tabNotes['AD-Auth-Detail'] = @{
                'Computer'         = 'Machine name (shortname) from AD lookup.'
                'Type'             = '"Host" if matches a known Hyper-V host; "VM" otherwise.'
                'OU'               = 'AD OU path from Get-ADComputer.DistinguishedName (parsed to parent OU).'
                'Enabled'          = 'True/False - AD computer account enabled state from Get-ADComputer.Enabled.'
                'LastLogon'        = 'Last AD logon date from Get-ADComputer.LastLogonDate.'
                'DelegationType'   = 'Kerberos delegation type: Unconstrained / KCD (traditional constrained) / RBCD (resource-based constrained) / None / N/A (non-domain). From AD computer object TrustedForDelegation and msDS-AllowedToDelegateTo attributes.'
                'DelegationDetail' = 'Detail of constrained delegation targets or RBCD security descriptor (from AD attributes).'
                'SpnStatus'        = '"OK" if both WSMAN/short and WSMAN/FQDN SPNs registered; "Missing" if none; "Partial-Short" or "Partial-FQDN" if only one. From Get-ADComputer.ServicePrincipalNames.'
                'WsmanSpns'        = 'Registered WSMAN SPNs for this computer from AD (Get-ADComputer -Properties ServicePrincipalNames).'
                'WinRMTransport'   = 'Derived WinRM transport assessment: HTTPS / HTTP + HTTPS / HTTP only / Not Running. Cross-referenced from vInfo WinRM data.'
                'LapsVersion'      = 'LAPS type detected: "Windows LAPS" (msLAPS-Password in AD), "Legacy LAPS" (ms-Mcs-AdmPwd in AD), or "None".'
                'LapsExpiry'       = 'LAPS password expiry from ms-Mcs-AdmPwdExpirationTime or msLAPS-PasswordExpirationTime (Legacy/Windows LAPS respectively).'
                'DelegationRisk'   = 'Derived risk for delegation: Critical (Unconstrained) / Warning (KCD) / OK (RBCD/None) / Info (N/A).'
                'WinRMRisk'        = 'Derived risk for WinRM transport: OK (HTTPS) / Warning (HTTP only) / Info (not running).'
                'LapsRisk'         = 'Derived risk for LAPS: OK (Windows LAPS) / Warning (Legacy or None).'
                'OverallRisk'      = 'Highest of DelegationRisk, WinRMRisk, LapsRisk. Sort order: Critical > Warning > OK > Info.'
                'ADError'          = 'AD lookup error message if Get-ADComputer failed (e.g. non-domain Linux appliances).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- AD-Auth-Issues ----
            $tabNotes['AD-Auth-Issues'] = @{
                'Severity'    = 'Finding severity: Critical / Warning / Info. Critical = Unconstrained Delegation.'
                'Computer'    = 'Machine the finding applies to.'
                'Type'        = '"Host" or "VM".'
                'Category'    = 'Finding category: Delegation / SPN / WinRM-Transport / LAPS.'
                'Finding'     = 'Short description of the security finding.'
                'Detail'      = 'Supporting data (e.g. delegation targets, SPN list, cert info).'
                'Remediation' = 'Recommended PowerShell command or action to remediate this finding.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Remediation-Commands ----
            $tabNotes['Remediation-Commands'] = @{
                'Category'     = 'Remediation category: Delegation / SPN / WinRM / LAPS / Script Reference.'
                'Computer'     = 'Machine the remediation applies to.'
                'Severity'     = 'Priority: Critical / Warning / Info.'
                'Finding'      = 'Issue description or script reference instruction.'
                'QuickCommand' = 'Scoped command to run the generated .ps1 for this specific machine and category.'
                'Notes'        = 'Additional context or the full remediation detail for this finding.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- SPN-Inventory ----
            $tabNotes['SPN-Inventory'] = @{
                'Computer'     = 'Computer account the SPN is registered under in AD.'
                'SPN'          = 'Full SPN string (e.g. WSMAN/server.ohdc.com) from Get-ADComputer.ServicePrincipalNames.'
                'ServiceClass' = 'SPN service class prefix (e.g. WSMAN / HTTP / MSSQLSvc / HOST) parsed from SPN string.'
                'Instance'     = 'SPN instance portion (hostname or hostname:port) parsed from SPN string.'
                'RoleHint'     = 'Derived role hint based on ServiceClass: WinRM / IIS / SQL / Exchange / etc.'
                'Status'       = '"OK" (registered), "Missing" (expected but absent), "Missing-RoleBased" (role implies SPN should exist), "Duplicate" (same SPN on multiple accounts).'
                'AlertLevel'   = '"Warning" for Missing or Duplicate; "OK" for registered SPNs.'
                'DuplicateOn'  = 'Semicolon-delimited list of other computer accounts also holding the same SPN (populated for Duplicate rows).'
                'Notes'        = 'Derived explanation: why this SPN was expected, or which accounts conflict on a duplicate.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- DoubleHop-Map ----
            $tabNotes['DoubleHop-Map'] = @{
                'Computer'         = 'Machine where the domain-account service/task/IIS pool was found.'
                'Host'             = 'Hyper-V host (parent if VM).'
                'Type'             = 'Row type: VM or Host.'
                'Source'           = 'Where the domain account was found: Service / ScheduledTask / IIS-AppPool.'
                'ServiceName'      = 'Service Name, Task Name, or App Pool Name.'
                'DisplayName'      = 'Friendly display name of the service or task.'
                'RunAs'            = 'Domain account running this service/task/pool (e.g. OHDC1\svc-backup).'
                'DelegationType'   = 'Kerberos delegation type for the RunAs account (from AD-Auth-Detail cross-reference).'
                'DelegationDetail' = 'Constrained delegation target list for the RunAs account.'
                'DelegationGap'    = '"Yes" if the service appears to need Kerberos double-hop (accesses remote resources) but no delegation is configured.'
                'NTLMRisk'         = '"High" if critical domain service with no delegation configured; "Review" if needs investigation; blank if OK.'
                'GapDetail'        = 'Explanation of why a delegation gap was detected.'
                'Remediation'      = 'Recommended delegation configuration or RBCD command to fix the gap.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- NTLM-Elimination ----
            $tabNotes['NTLM-Elimination'] = @{
                'Priority'           = 'Sort order for remediation (1 = highest priority). Calculated from NTLMRisk level and delegation type.'
                'Computer'           = 'Machine name (short).'
                'FQDN'               = 'Fully qualified domain name of the machine.'
                'OU'                 = 'AD OU path.'
                'NTLMRisk'           = 'Derived NTLM risk score: Critical / High / Medium / Low / OK. Calculated from delegation type, SPN gaps, domain-account services, and double-hop findings.'
                'DelegationType'     = 'Kerberos delegation type from AD-Auth-Detail.'
                'TotalSPNs'          = 'Total SPNs registered for this machine in AD.'
                'MissingSPNs'        = 'Count of expected SPNs not registered (from SPN-Inventory findings for this machine).'
                'DuplicateSPNs'      = 'Count of duplicate SPNs involving this machine.'
                'DomainAcctServices' = 'Count of services/tasks/IIS pools running as domain accounts on this machine (from DoubleHop-Map).'
                'HighRiskHops'       = 'Count of High-risk double-hop gaps for this machine (from DoubleHop-Map).'
                'IISAppPools'        = 'Count of IIS application pools running as domain accounts on this machine.'
                'Factors'            = 'Pipe-delimited list of risk factors used to derive the NTLMRisk score.'
                'RemediationCmds'    = 'Inline PowerShell remediation commands (setspn / Set-ADComputer) to address the highest-priority gaps for this machine.'
                'VerifyCmd'          = 'Command to verify SPN registration after remediation: setspn -L <computername>.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Live-Migration ----
            $tabNotes['Live-Migration'] = @{
                'Host'              = 'Hyper-V host name.'
                'LiveMigEnabled'    = 'True/False - live migration enabled on this host (Get-VMHost.VirtualMachineMigrationEnabled).'
                'AuthType'          = 'Authentication type in use: Kerberos or CredSSP (Get-VMHost.VirtualMachineMigrationAuthenticationType). CredSSP is flagged as non-preferred.'
                'SimultaneousMigs'  = 'Max simultaneous live migrations from Get-VMHost.MaximumVirtualMachineMigrations.'
                'StorMigEnabled'    = 'True/False - storage live migration enabled (Get-VMHost.VirtualMachineMigrationStorageEnabled).'
                'MigNetwork'        = 'Migration network binding from Get-VMMigrationNetwork: IP ranges allowed for live migration traffic.'
                'SMBEnabled'        = 'True/False - SMB live migration (over RDMA) enabled.'
                'Assessment'        = 'Derived overall assessment: OK if Kerberos; Warning/Review if CredSSP or misconfigured.'
                'Notes'             = 'Additional context: CredSSP deprecation notice, recommended Kerberos RBCD migration steps.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Host-NIC-Audit ----
            $tabNotes['Host-NIC-Audit'] = @{
                'Host'               = 'Hyper-V host the NIC belongs to.'
                'InterfaceAlias'     = 'NIC name from Get-NetAdapter.InterfaceAlias (e.g. "Ethernet0", "vEthernet (Management)").'
                'InterfaceDesc'      = 'Full adapter description from Get-NetAdapter.InterfaceDescription.'
                'MACAddress'         = 'Physical MAC address from Get-NetAdapter.MacAddress.'
                'LinkSpeed'          = 'Negotiated link speed from Get-NetAdapter.LinkSpeed (e.g. "10 Gbps").'
                'IPAddress'          = 'Assigned IPv4 address(es) from Get-NetIPAddress.'
                'SubnetPrefix'       = 'CIDR prefix length from Get-NetIPAddress.PrefixLength.'
                'VLAN'               = 'VLAN ID from Get-NetAdapterAdvancedProperty or switch port configuration.'
                'Gateway'            = 'Default gateway from Get-NetIPConfiguration.IPv4DefaultGateway.NextHop.'
                'DNSServers'         = 'DNS server IPs from Get-DnsClientServerAddress.'
                'DNSViolation'       = 'Yes = DNS server IPs configured on a non-management NIC (storage, migration, CSV). Best practice: only management NICs should have DNS configured. No = clean configuration.'
                'DNSSuffix'          = 'Connection-specific DNS suffix from Get-DnsClient.ConnectionSpecificSuffix. The domain appended to short hostnames for DNS resolution on this NIC.'
                'DNSSuffixSearchList' = 'Ordered DNS suffix search list from Get-DnsClient.ConnectionSpecificSuffixSearchList. Used for short-name resolution across multiple domains (e.g. "ohdc.com; overheaddoor.com").'
                'DNSSuffixAssessment' = 'Validation: OK = DNS suffix configured, MISSING = management NIC without suffix (Kerberos/WinRM will fail for short names), OK (storage/migration -- suffix optional) = non-DNS NICs. Only NICs with IP addresses are assessed.'
                'InferredRole'       = 'Derived NIC role: Management / LiveMigration / CSV / Storage / VM-Traffic / Unknown. Based on name patterns and gateway presence.'
                'GatewayAssessment'  = 'Derived: "VIOLATION - Gateway on non-management NIC" if a gateway is present on a NIC that should not have one (CSV, Storage, LiveMig); "OK" otherwise.'
                'Notes'              = 'Additional context about the assessment finding.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- DC-GUID-Validation ----
            $tabNotes['DC-GUID-Validation'] = @{
                'Domain'        = 'AD domain the DC belongs to (from Get-ADDomainController).'
                'DCName'        = 'Domain controller hostname.'
                'DSAGUID'       = 'DC DSA object GUID from Get-ADDomainController.ObjectGUID (the GUID used in _msdcs CNAME records).'
                'ExpectedCNAME' = 'Expected _msdcs CNAME: <DSAGUID>._msdcs.<domain>. This record must exist for AD replication and Kerberos.'
                'CNAMEStatus'   = '"OK" if the CNAME resolves correctly via Resolve-DnsName; "FAIL" if missing or points to wrong DC; "WARNING" if DNS query returned partial results.'
                'ResolvedTo'    = 'FQDN the CNAME record resolves to (from Resolve-DnsName lookup result).'
                'Notes'         = 'Additional detail if CNAMEStatus is not OK (e.g. DNS server used, error message).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- VHD-Drive-Map ----
            $tabNotes['VHD-Drive-Map'] = @{
                'VMName'             = 'VM name that owns this VHD.'
                'Host'               = 'Hyper-V host the VM runs on.'
                'ControllerType'     = 'Controller type: IDE or SCSI (from Get-VMHardDiskDrive.ControllerType).'
                'ControllerNumber'   = 'Controller number on the host (Get-VMHardDiskDrive.ControllerNumber).'
                'ControllerLocation' = 'Slot position on the controller (Get-VMHardDiskDrive.ControllerLocation). Used as SCSI LUN for correlation.'
                'ControllerSlot'     = 'Display string: "SCSI 0:1" or "IDE 0:0" combining ControllerNumber and ControllerLocation.'
                'VHDPath'            = 'Full path to the VHD/VHDX file from Get-VMHardDiskDrive.Path.'
                'VHDType'            = 'Dynamic or Fixed from Get-VHD.VhdType.'
                'VHDSizeGB'          = 'Maximum provisioned VHD size in GB from Get-VHD.Size / 1GB.'
                'VHDCurrentGB'       = 'Current on-disk file size in GB from Get-VHD.FileSize / 1GB.'
                'IsSnapshot'         = 'True if this VHD path contains ".avhd" or ".avhdx" (snapshot differencing disk).'
                'GuestDriveLetter'   = 'Drive letter inside the guest OS mapped to this VHD (e.g. "C:", "D:"). Populated when CorrelationMethod succeeds.'
                'GuestLabel'         = 'Volume label of the matched guest drive from Win32_LogicalDisk.VolumeName.'
                'GuestTotalGB'       = 'Total capacity of the guest drive in GB from Win32_LogicalDisk.Size / 1GB.'
                'GuestFreeGB'        = 'Free space on the guest drive in GB from Win32_LogicalDisk.FreeSpace / 1GB.'
                'GuestPctFree'       = 'Calculated: (GuestFreeGB / GuestTotalGB) * 100. Percent free space inside the guest for this drive.'
                'CorrelationMethod'  = 'Method used to match VHD to guest drive: "SCSI-LUN" (SCSILogicalUnit match), "IDE-Slot", "SerialNumber" (Fixed VHD UniqueId), "SizeMatch" (fallback by size), "Unresolved" (no match found), "WinRM-Unavailable".'
                'AlertLevel'         = 'Derived: "CRITICAL" if GuestPctFree < 5%; "WARNING" if < 10%; "OK" otherwise. Blank if WinRM-Unavailable.'
                'Notes'              = 'Explanation of correlation result or reason for unresolved/unavailable status.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Local-Builtin (v3.8.0 CR5) ----
            $tabNotes['Local-Builtin'] = @{
                'VM'              = 'VM name (or host name for host rows). Source: Get-VM on the Hyper-V host.'
                'Host'            = 'Hyper-V host that owns this VM.'
                'Domain'          = 'DNS domain of the machine (from Win32_ComputerSystem.Domain via WinRM).'
                'GroupName'       = 'Windows built-in local group this row belongs to (e.g. Administrators, Remote Desktop Users, Hyper-V Administrators). Collected via Get-LocalGroupMember -Group <name> or ADSI WinNT fallback.'
                'MemberName'      = 'DOMAIN\Username or DOMAIN\GroupName of the local group member. Unicode group names (e.g. names with en-dash) are preserved as-is from the API.'
                'ObjectClass'     = 'Object type: User or Group (from Get-LocalGroupMember.ObjectClass or ADSI Class property).'
                'PrincipalSource'  = 'Where the account was resolved: ActiveDirectory, Local, MicrosoftAccount, or ADSI (fallback path for WS2012/2008).'
                'Tier'            = 'Authorization status vs RequiredBuiltinMembers config in Config-OHDC.psd1: Required (expected mandatory member), Allowed (permitted but not required), Unexpected (not in either list), Unconfigured (no config for this group), Required-Missing (expected but not found).'
                'AlertLevel'      = 'Derived from Tier: OK (Required/Allowed/Unconfigured), Review (Unexpected), Missing (Required-Missing).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- S2D-Storage-Audit (v3.8.0 CR2) ----
            $tabNotes['S2D-Storage-Audit'] = @{
                'Cluster'           = 'Name of the S2D-enabled failover cluster this row belongs to (e.g. MHOHCLUHV).'
                'Section'           = 'Section of the S2D audit: Storage Pool, Virtual Disk, Physical Disk, Fault Domain, CSV, Storage Job, Storage QoS.'
                'Name'              = 'Friendly name of the object (pool name, virtual disk name, physical disk model, fault domain node, CSV name, job name, QoS policy name).'
                'HealthStatus'      = 'Health status from the storage subsystem: Healthy, Warning, or Unhealthy. Source: Get-StoragePool/Get-VirtualDisk/Get-PhysicalDisk .HealthStatus.'
                'OperationalStatus' = 'Operational state of the object (e.g. OK, Degraded, Lost Communication). Source: corresponding Get-Storage* .OperationalStatus.'
                'TotalGB'           = 'Total raw capacity in GB. For pools: Get-StoragePool.Size / 1GB. For VDs: Get-VirtualDisk.Size / 1GB. For PDs: Get-PhysicalDisk.Size / 1GB. For CSVs: Partition.Size / 1GB.'
                'AllocatedGB'       = 'Space allocated/used in GB. For pools: AllocatedSize / 1GB. For VDs: AllocatedSize / 1GB. For CSVs: UsedSpace / 1GB. For Storage Jobs: BytesProcessed / 1GB.'
                'FreeGB'            = 'Calculated: TotalGB - AllocatedGB.'
                'PercentUsed'       = 'Calculated: (AllocatedGB / TotalGB) * 100. Pools: warns at >85%, critical at >95%.'
                'NumberOfDisks'     = 'Number of physical disks in a storage pool (Get-StoragePool.NumberOfPhysicalDisks). Blank for other sections.'
                'ResiliencyDefault' = 'For pools: default provisioning type. For VDs: ResiliencySettingName (Mirror/Parity) + data copy count. For PDs: BusType | MediaType. For CSVs: filesystem.'
                'WriteCacheSizeGB'  = 'Size of the write cache tier for storage pools in GB (Get-StoragePool.WriteCacheSize / 1GB). Zero if no dedicated cache.'
                'ReadOnlyReason'    = 'For pools: reason the pool is read-only if applicable (Get-StoragePool.ReadOnlyReason). For QoS: MaxIOPS/MinIOPS values. For PDs: Usage (AutoSelect/ManualSelect/HotSpare/Retired).'
                'Version'           = 'Pool/VD version string. For PDs: wear indicator percentage from Get-StorageReliabilityCounter.Wear (NVMe/SSD only). For CSVs: block size. For QoS: MaxBandwidth in MB/s.'
                'Detail1'           = 'Additional context. For PDs: slot/enclosure/serial. For VDs: column count and footprint. For CSVs: volume path and owner node. For jobs: start time.'
                'Detail2'           = 'Supplemental detail. For PDs: read/write error counts and pool name. For VDs: DetachedReason. For CSVs: backup state.'
                'AlertLevel'        = 'Derived alert: Critical (Unhealthy/degraded health or <5% free on CSV), Warning (HealthStatus=Warning or >85% pool used or CSV Redirected), OK (Healthy), Info (S2D config rows, QoS policies).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- S2D-Config-Summary (v3.8.0 CR2) ----
            $tabNotes['S2D-Config-Summary'] = @{
                'Cluster'  = 'S2D-enabled cluster name.'
                'Section'  = 'Configuration section: S2D Configuration or Cluster Node.'
                'Item'     = 'Configuration item name (State, CacheState, CacheMode, CacheDeviceModel, or node name).'
                'Value'    = 'Current value of the item from Get-ClusterStorageSpacesDirect or Get-ClusterNode.'
                'Status'   = 'Derived status: OK (expected values), Info (informational only), Critical (node down or S2D disabled).'
                'Notes'    = 'Description of what the item represents and the source cmdlet/property.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- VM-IOPS-Summary (v3.8.7 Session 8d) ----
            $tabNotes['VM-IOPS-Summary'] = @{
                'Host'               = 'Hyper-V host that owns this VM.'
                'ClusterName'        = 'Failover cluster name if clustered; "Standalone" if not.'
                'VMName'             = 'VM display name from Get-VM.'
                'State'              = 'VM power state: Running / Off / Paused / Saved.'
                'MeteringEnabled'    = 'True/False -- whether Enable-VMResourceMetering is active on this VM. False means no IOPS data (counters show 0).'
                'AvgCPUMHz'          = 'Average CPU usage in MHz from Measure-VM.AvgCPU. Represents average processor time consumed over the metering period.'
                'AvgRAMMB'           = 'Average memory usage in MB from Measure-VM.AvgRAM.'
                'MaxRAMMB'           = 'Peak memory usage in MB from Measure-VM.MaxRAM.'
                'MinRAMMB'           = 'Minimum memory usage in MB from Measure-VM.MinRAM.'
                'NormalizedIOPS'     = 'Normalized IOPS from Measure-VM.AggregatedAverageNormalizedIOPS. Represents 8KB-normalized IO operations per second averaged over a 20-second sample window.'
                'AvgLatency'         = 'Average IO latency in NANOSECONDS from Measure-VM.AggregatedAverageLatency. To convert to milliseconds: divide by 1,000,000. Example: 10,497 ns / 1,000,000 = 0.0105 ms. Thresholds: <1,000,000 ns (1 ms) = Excellent; 1-5 ms = Good; 5-20 ms = Acceptable; >20 ms = Investigate. NVMe typically <10,000 ns (0.01 ms).'
                'TotalDiskReadMB'    = 'Total disk data read in MB from Measure-VM.AggregatedDiskDataRead over the metering period.'
                'TotalDiskWrittenMB' = 'Total disk data written in MB from Measure-VM.AggregatedDiskDataWritten over the metering period.'
                'ReadWriteRatio'     = 'Derived read/write percentage split (e.g. "70%/30%") calculated from TotalDiskReadMB vs TotalDiskWrittenMB.'
                'NetworkInMB'        = 'Total inbound network traffic in MB from Measure-VM.NetworkInbound. Returns 0 unless vSwitch bandwidth management is configured (Set-VMNetworkAdapter -MinimumBandwidthWeight or -MaximumBandwidth).'
                'NetworkOutMB'       = 'Total outbound network traffic in MB from Measure-VM.NetworkOutbound. Returns 0 unless vSwitch bandwidth management is configured.'
                'MeteringDurationSec' = 'Seconds since metering was enabled or last reset, from Measure-VM.MeteringDuration.TotalSeconds.'
                'MeteringDurationHrs' = 'Derived: MeteringDurationSec / 3600. Hours of data represented in the averages.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- VM-IOPS-PerDisk (v3.8.7 Session 8d) ----
            $tabNotes['VM-IOPS-PerDisk'] = @{
                'Host'           = 'Hyper-V host that owns the VM.'
                'ClusterName'    = 'Failover cluster name if clustered; "Standalone" if not.'
                'VMName'         = 'VM display name.'
                'VHDPath'        = 'Full path to the VHD/VHDX file from Measure-VM.HardDiskMetrics.VirtualHardDisk.Path.'
                'NormalizedIOPS' = 'Per-VHD normalized IOPS from HardDiskMetrics.AverageNormalizedIOPS. 8KB-normalized, 20-second sample window.'
                'AvgLatency'     = 'Per-VHD average IO latency in NANOSECONDS from HardDiskMetrics.AverageLatency. To convert to milliseconds: divide by 1,000,000. Example: 10,497 ns / 1,000,000 = 0.0105 ms. Values <1,000,000 ns (1 ms) indicate healthy storage performance.'
                'DiskReadMB'     = 'Data read from this VHD in MB from HardDiskMetrics.DataRead.'
                'DiskWrittenMB'  = 'Data written to this VHD in MB from HardDiskMetrics.DataWritten.'
                'ReadWriteRatio' = 'Derived read/write percentage split for this specific VHD.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Host-IOPS-Summary (v3.8.7 Session 8d) ----
            $tabNotes['Host-IOPS-Summary'] = @{
                'Host'               = 'Hyper-V host FQDN.'
                'ClusterName'        = 'Failover cluster name if clustered; "Standalone" if not.'
                'TotalVMs'           = 'Total VM count on this host.'
                'MeteredVMs'         = 'Count of VMs with ResourceMeteringEnabled = True.'
                'TotalNormalizedIOPS' = 'Sum of NormalizedIOPS across all metered VMs on this host.'
                'AvgIOPSPerVM'       = 'Derived: TotalNormalizedIOPS / MeteredVMs.'
                'MaxVMIOPS'          = 'Highest NormalizedIOPS among all VMs on this host.'
                'MaxVMIOPSName'      = 'Name of the VM generating the highest IOPS.'
                'TotalDiskReadMB'    = 'Sum of disk data read across all metered VMs.'
                'TotalDiskWrittenMB' = 'Sum of disk data written across all metered VMs.'
                'PhysicalDiskCount'  = 'Count of physical disks detected on this host via Get-PhysicalDisk (or Win32_DiskDrive fallback).'
                'SSDCount'           = 'Count of SSD/NVMe physical disks detected.'
                'HDDCount'           = 'Count of HDD (spinning) physical disks detected.'
                'DetectedStorage'    = 'Human-readable summary of detected physical disk types (e.g. "2x NVMe, 4x SAS").'
                'PerfReadIOPS'       = 'Real-time read IOPS from Hyper-V Virtual Storage Device perfmon counter (5-second average). "N/A" if counter collection failed.'
                'PerfWriteIOPS'      = 'Real-time write IOPS from Hyper-V Virtual Storage Device perfmon counter (5-second average).'
                'PerfReadLatencyMs'  = 'Real-time read latency in milliseconds from Hyper-V Virtual Storage Device perfmon counter.'
                'PerfWriteLatencyMs' = 'Real-time write latency in milliseconds (placeholder -- counter may not split read/write).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- IOPS-Recommendations (v3.8.7 Session 8d) ----
            $tabNotes['IOPS-Recommendations'] = @{
                'Target'              = 'Host FQDN (standalone) or cluster name (clustered).'
                'TargetType'          = '"Standalone Host" or "Cluster".'
                'StorageType'         = 'Detected or inferred storage type (e.g. "Local: 2x NVMe, 4x SAS", "Cluster: 31x SSD, 0x HDD").'
                'DiskCount'           = 'Total physical disk count for the target (sum across all nodes for clusters).'
                'SSDCount'            = 'SSD/NVMe disk count.'
                'HDDCount'            = 'HDD (spinning) disk count.'
                'CurrentTotalIOPS'    = 'Current aggregate NormalizedIOPS across all metered VMs on this target.'
                'EstCapacityIOPS'     = 'Estimated IOPS capacity based on physical disk count, type, and RAID penalty. Formula: SUM(per-disk baseline x 0.85 RAID factor) across all non-cache/non-retired disks.'
                'UtilizationPct'      = 'Derived: (CurrentTotalIOPS / EstCapacityIOPS) x 100. Percentage of estimated storage capacity in use.'
                'MinRecommendedIOPS'  = 'Derived: EstCapacityIOPS x 0.6. Below this = comfortable headroom.'
                'MaxRecommendedIOPS'  = 'Derived: EstCapacityIOPS x 0.8. Above this = capacity planning needed.'
                'AlertLevel'          = 'Derived: OK (<60%), Monitor (60-80%), Warning (80-90%), Critical (>90%).'
                'Recommendation'      = 'Actionable text: what to do based on current utilization vs capacity estimate.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- IOPS-Trends (v3.8.9.2 Session 8d-2) ----
            $tabNotes['IOPS-Trends'] = @{
                'Host'              = 'Hyper-V host short name from the collector data.'
                'Date'              = 'Calendar date (yyyy-MM-dd) for this daily aggregate row.'
                'Samples'           = 'Number of collector snapshots for this host on this date. At 15-min intervals, expect ~96/day.'
                'AvgIOPS'           = 'Average total NormalizedIOPS across all snapshots that day. Represents typical daily load.'
                'PeakIOPS'          = 'Maximum total NormalizedIOPS observed in any single snapshot that day. Represents burst demand.'
                'P95IOPS'           = '95th percentile total NormalizedIOPS. 95% of snapshots were at or below this value. Better than peak for capacity planning (filters outlier spikes).'
                'AvgVMCount'        = 'Average number of running/metered VMs across snapshots that day.'
                'TopVM'             = 'VM name with the highest single-snapshot IOPS that day.'
                'TopVMPeakIOPS'     = 'Peak IOPS value for the top VM (from the snapshot where it was highest).'
                'AvgPerfReadIOPS'   = 'Average host-level perfmon Read Operations/Sec across snapshots that day. "N/A" if perfmon was not collected.'
                'AvgPerfWriteIOPS'  = 'Average host-level perfmon Write Operations/Sec across snapshots that day. "N/A" if perfmon was not collected.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- IOPS-Heatmap (v3.8.9.2 Session 8d-2) ----
            $tabNotes['IOPS-Heatmap'] = @{
                'Host'       = 'Hyper-V host short name from the collector data.'
                'Hour'       = 'Hour of day label (e.g. "00:00", "13:00"). 24-hour format.'
                'HourNum'    = 'Numeric hour (0-23) for sorting.'
                'AvgIOPS'    = 'Average total IOPS across all collector snapshots that fell in this hour, aggregated over the entire lookback window (default 30 days).'
                'PeakIOPS'   = 'Maximum total IOPS observed in any single snapshot during this hour across the lookback window.'
                'Samples'    = 'Number of collector snapshots that fell in this hour. Higher = more statistical confidence.'
                'Intensity'  = 'Demand classification: "High" (>=1000 avg IOPS), "Medium" (>=500), "Low" (>=100), "Idle" (<100). Use to identify business-hours peaks and overnight maintenance windows.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- Disk-Format-Config (v3.9.0 Session 8f) ----
            $tabNotes['Disk-Format-Config'] = @{
                'Host'              = 'Hyper-V host the volume belongs to.'
                'ClusterName'       = 'Cluster name if the host is part of a failover cluster. Blank for standalone.'
                'DriveLetter'       = 'Drive letter (e.g. "C:", "D:"). Blank for mount-point-only or CSV volumes.'
                'MountPath'         = 'Primary display path for this volume. Drive letters show as C:. Mount points show the human-readable path (e.g. C:\HV). CSVs show as C:\ClusterStorage\<n>. Falls back to Volume GUID if no mount point is resolved.'
                'MountPointPath'    = 'Human-readable mount point path resolved from Get-Partition.AccessPaths (e.g. C:\HV, D:\Data). Blank for drive-letter-only volumes. This is the folder where the volume is mounted in the filesystem.'
                'VolumeRole'        = 'Classification: Boot/OS (contains SystemRoot), VM Storage (mount point or CSV where VMs are stored), Data (other volumes with drive letters). Helps identify which volumes are critical for VM operations.'
                'VolumeLabel'       = 'Volume label from Get-Volume.FileSystemLabel.'
                'VolumeType'        = 'Classification: Local (drive letter), CSV (Cluster Shared Volume), MountPoint (no drive letter, mounted to a folder path), or ERROR.'
                'FileSystem'        = 'Filesystem type from Get-Volume.FileSystem: NTFS, ReFS, CSVFS, exFAT, FAT32, or Unknown.'
                'PartitionStyle'    = 'Partition table format from Get-Disk.PartitionStyle: GPT (recommended) or MBR (legacy). GPT supports >2TB disks and UEFI boot.'
                'AllocationUnitKB'  = 'Filesystem cluster (allocation unit) size in KB from Get-Volume.AllocationUnitSize. Default: 4K for NTFS/ReFS. Recommended: 64K for SQL data volumes, Hyper-V VHD stores, and S2D CSVs.'
                'AllocationNote'    = 'Human-readable note on the allocation unit size: "Default (4K)", "64K (recommended for SQL/Hyper-V)", etc.'
                'CapacityGB'        = 'Total volume capacity in GB.'
                'FreeSpaceGB'       = 'Free space in GB.'
                'IsCSV'             = 'True if this volume is a Cluster Shared Volume.'
                'UseLargeFRS'       = 'NTFS only: whether the volume was formatted with UseLargeFRS (allows >900-char filenames, larger MFT records). Detected via fsutil fsinfo ntfsinfo. "N/A" for non-NTFS.'
                'ReFSIntegrity'     = 'ReFS/CSVFS only: whether integrity streams are enabled on the volume root via Get-FileIntegrity. "Enabled" or "Disabled". "N/A" for non-ReFS volumes.'
                'SSResiliency'      = 'Storage Spaces virtual disk resiliency type: Mirror (best IOPS), Parity (HIGH WRITE LATENCY -- not for IOPS-sensitive workloads), Simple (no redundancy), or N/A. From Get-VirtualDisk.ResiliencySettingName.'
                'SSColumns'         = 'Storage Spaces column count from Get-VirtualDisk.NumberOfColumns. Determines stripe width. 0 if not Storage Spaces.'
                'SSInterleaveKB'    = 'Storage Spaces interleave (stripe) size in KB from Get-VirtualDisk.Interleave. Default typically 256KB. 0 if not Storage Spaces.'
                'SSNote'            = 'Performance advisory: Parity volumes have significantly higher write latency than Mirror due to read-modify-write overhead. If users report slowness, convert to Mirror.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- TLS-Compliance (v3.9.0 Session 8e) ----
            $tabNotes['TLS-Compliance'] = @{
                'MachineName'        = 'Computer name of the host or VM being audited.'
                'MachineType'        = '"Host" (Hyper-V server) or "VM" (Windows guest OS checked via WinRM).'
                'Type'               = 'OPEN-67: Row scope -- Host (Hyper-V host) or VM (guest). Matches MachineType; added for cross-tab consistency.'
                'DataSource'         = 'Platform source: Hyper-V. Future: VMware, Nutanix, Active Directory.'
                'ParentHost'         = 'For VMs: the Hyper-V host this VM runs on. Blank for hosts.'
                'ClusterName'        = 'Cluster name if the host is part of a failover cluster. Blank for standalone.'
                'OSCaption'          = 'Full OS name from Win32_OperatingSystem.Caption (e.g. "Microsoft Windows Server 2019 Standard").'
                'OSBuild'            = 'OS build number from Win32_OperatingSystem.BuildNumber.'
                'SSL20_Disabled'     = 'PASS if SSL 2.0 is explicitly disabled in SChannel registry (both Server and Client subkeys: Enabled=0, DisabledByDefault=1). FAIL if not configured or enabled.'
                'SSL30_Disabled'     = 'PASS if SSL 3.0 is explicitly disabled in SChannel registry (both Server and Client). FAIL if not configured or enabled. SSL 3.0 is vulnerable to POODLE attack.'
                'TLS10_Disabled'     = 'PASS if TLS 1.0 is explicitly disabled in SChannel registry (both Server and Client). FAIL if not configured or enabled. Test application compatibility before disabling.'
                'TLS11_Disabled'     = 'PASS if TLS 1.1 is explicitly disabled in SChannel registry (both Server and Client). FAIL if not configured or enabled.'
                'TLS12_Enabled'      = 'PASS if TLS 1.2 is enabled or not explicitly disabled in SChannel registry (OS default on Server 2016+). FAIL only if explicitly disabled.'
                'TLS13_Enabled'      = 'PASS if TLS 1.3 is enabled or not explicitly disabled. PASS on older OS where TLS 1.3 registry keys do not exist (not supported = not a failure).'
                'SChannel_Status'    = 'Aggregate SChannel verdict: PASS (all legacy disabled + TLS 1.2 enabled), PARTIAL (TLS 1.2 OK but legacy not fully disabled), FAIL (TLS 1.2 not enabled).'
                'DotNet4_Compliant'  = 'PASS if .NET Framework v4 has SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 in both 64-bit and WOW6432Node registry paths. Required for .NET apps to default to TLS 1.2.'
                'DotNet2_Compliant'  = 'PASS if .NET Framework v2 has SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1. Only critical if legacy .NET 2.x/3.5 applications are in use.'
                'DotNet_Status'      = 'Aggregate .NET verdict: PASS (v4 + v2 both configured), PARTIAL (v4 OK, v2 not), FAIL (v4 not configured).'
                'WinHTTP_Compliant'  = 'PASS if WinHTTP DefaultSecureProtocols includes TLS 1.2 (bitmask 0x00000800) or is not configured (OS default on 2016+). Affects WSUS, SCCM client, and other WinHTTP-based apps.'
                'RDP_Compliant'      = 'PASS if RDP SecurityLayer=2 (TLS/SSL) and MinEncryptionLevel>=3 (High). FAIL if using RDP Security Layer (0) or Negotiate (1) without TLS.'
                'RDP_SecurityLayer'  = 'Human-readable RDP security mode: "TLS/SSL" (compliant), "Negotiate", "RDP (insecure)", or "Default" (not explicitly configured).'
                'LDAP_Compliant'     = 'For Domain Controllers: PASS if LdapEnforceChannelBinding>=1 and LDAPServerIntegrity>=1. N/A for non-DC machines.'
                'LDAP_IsDC'          = '"Yes" if the machine has DomainRole>=4 (Domain Controller). "No" otherwise. LDAP checks only apply to DCs.'
                'SMB_Encrypted'      = 'PASS if Set-SmbServerConfiguration EncryptData is $true. FAIL if not enabled. SMB encryption requires SMB 3.0+ clients.'
                'OverallStatus'      = 'Aggregate: COMPLIANT (zero failures), PARTIAL (1-2 failures), NON-COMPLIANT (3+ failures), ERROR (WinRM unreachable).'
                'FailedChecks'       = 'Semicolon-delimited list of specific failures (e.g. "SSL 2.0 not disabled; .NET4 strong crypto not set"). "None" if fully compliant.'
                'ErrorDetail'        = 'Error messages from collection (e.g. WinRM timeout, access denied). Blank if no errors.'
            }

            # ---- TLS-Recommendations (v3.9.0 Session 8e) ----
            $tabNotes['TLS-Recommendations'] = @{
                'MachineName'        = 'Computer name of the host or VM that needs remediation.'
                'MachineType'        = '"Host" or "VM".'
                'Type'               = 'OPEN-67: Row scope -- Host or VM. Matches MachineType; added for cross-tab consistency.'
                'DataSource'         = 'Platform source: Hyper-V. Future: VMware, Nutanix.'
                'Category'           = 'Remediation area: SChannel, .NET Framework, WinHTTP, RDP, LDAP, or SMB.'
                'Finding'            = 'Specific compliance failure description (e.g. "TLS 1.0 Disable required", ".NET4 strong crypto not configured").'
                'Severity'           = 'CRITICAL (immediate security risk), HIGH (should fix soon), MEDIUM (best practice improvement).'
                'RegistryPath'       = 'Exact registry key path or PowerShell command to apply the fix.'
                'RegistryAction'     = 'Specific values to set (e.g. "Set Enabled=0, DisabledByDefault=1").'
                'RemediationScript'  = 'Name of the universal Fix-*.ps1 script in the output folder that applies this fix.'
                'Priority'           = 'Numeric priority for remediation ordering: 1=fix first, 2=fix next, 3=nice to have.'
                'Notes'              = 'Additional context: application compatibility warnings, testing recommendations, GPO alternatives.'
            }

            # ---- RBAC-Compliance (v3.8.9 Session 8h) ----
            $tabNotes['RBAC-Compliance'] = @{
                'MachineName'         = 'Server hostname used for AD group name construction. v3.10.0: Uses guest OS computer name (WinRM $env:COMPUTERNAME or KVP FQDN) instead of Hyper-V display name. Example: "BALOH-BARTEND-1" (guest name) not "BALOH-Bartend-P01" (Hyper-V name). For hosts: hostname from the host itself.'
                'MachineType'         = '"Host" (Hyper-V server), "VM" (Windows guest), or "VM (Linux)" (Linux guest without WinRM access). Appliances (IPAM, FortiGate, etc.) are excluded entirely -- RBAC rules do not apply to non-domain devices.'
                'ParentHost'          = 'For VMs: the Hyper-V host this VM runs on. Blank for hosts.'
                'ClusterName'         = 'Cluster name if the host is part of a failover cluster. Blank for standalone.'
                'Domain'              = 'Domain the machine is joined to (e.g. ohdc.com, overheaddoor.com). Blank for workgroup/non-domain.'
                'ComputerInAD'        = '"Yes" if the computer object exists in Active Directory. "No" if not found (possibly decommissioned, renamed, or cross-domain). "N/A" for Linux VMs without WinRM access.'
                'BuiltinGroup'        = 'Windows local builtin group name being validated (e.g. Administrators, Remote Desktop Users). All 16 tracked groups are checked per machine. "(all)" for Linux summary rows.'
                'ExpectedADGroup'     = 'The AD security group name expected to be a member of this builtin group. Computed as: <ADGroupPrefix><MachineName>_<SuffixMap[BuiltinGroup]>. Example: ACL_BALOH-BARTEND-1_A for Administrators. "N/A" for Linux.'
                'ADGroupExists'       = '"Yes" if the expected AD group exists in the configured RBAC OU (or anywhere in AD via fallback lookup). "No" = group needs to be created by Deploy-RBACSecurityGroups.ps1. "N/A" for Linux.'
                'ADGroupMemberCount'  = 'Number of members in the AD group. 0 = empty group (orphan risk flag). Groups should contain the user/group accounts that need access to this builtin group on this server.'
                'ADGroupEmpty'        = '"Yes" if the AD group exists but has zero members (orphan risk -- group was created but never populated). "No" if it has members. Blank if group does not exist. "N/A" for Linux.'
                'InLocalBuiltin'      = '"Yes" if the expected AD group is a member of the local builtin group on this server. "No" = AD group exists but has not been applied to the server yet (Deploy-RBACSecurityGroups.ps1 or manual). "N/A" for Linux.'
                'CrossDomainCount'    = 'Number of accounts in this local builtin group that belong to a different domain than the machine. Cross-domain accounts cannot be automatically migrated into the AD group and need manual handling.'
                'CrossDomainAccounts' = 'Semicolon-delimited list of cross-domain account names found in this builtin group (e.g. "OVERHEADDOOR\jsmith; CREATIVE\svc_app"). Blank if none.'
                'Status'              = 'COMPLIANT: AD group exists, is in local builtin, has members, no issues. WARNING: minor issues (empty AD group, cross-domain accounts). NON-COMPLIANT: AD group missing or not in local builtin. LINUX: Linux VM that needs SSH access for validation.'
                'Issues'              = 'Semicolon-delimited list of specific compliance failures. "None" if fully compliant. For Linux: "Need to access Linux OS -- RBAC builtin group validation requires SSH or WinRM access." Examples: "AD group does not exist", "AD group exists but is not a member of local Administrators".'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- NTLM-Readiness (v3.8.9 Session 5e) ----
            $tabNotes['NTLM-Readiness'] = @{
                'Computer'           = 'Server hostname (host or VM) being audited for NTLM deprecation readiness.'
                'Host'               = 'Hyper-V host FQDN. For hosts, same as Computer. For VMs, the parent host.'
                'MachineType'        = '"Host" (Hyper-V server) or "VM" (Windows guest).'
                'NetBIOSStatus'      = '"Disabled" if all NIC interfaces have NetbiosOptions=2 in HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*. "Enabled" if any NIC uses Default(0) or Enabled(1). NetBIOS enables NTLM name resolution bypass.'
                'LLMNRStatus'        = '"Disabled" if HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0. "Enabled" otherwise. LLMNR (Link-Local Multicast Name Resolution) causes NTLM fallback on failed DNS lookups.'
                'WINSConfigured'     = '"Yes" if any NIC has a WINS primary or secondary server configured (Win32_NetworkAdapterConfiguration). "No" if none. WINS forces NetBIOS traffic which uses NTLM.'
                'LmCompatLevel'      = 'LAN Manager authentication level from HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel. Values: 0=Send LM+NTLM, 1=Send LM+NTLM use NTLMv2 if negotiated, 2=Send NTLM only, 3=Send NTLMv2 only, 4=Send NTLMv2 refuse LM, 5=Send NTLMv2 refuse LM+NTLM. Target: 5.'
                'LmCompatRisk'       = 'Human-readable risk assessment of the LmCompatibilityLevel value. CRITICAL (0-1), MEDIUM (2), OK (3), GOOD (4), BEST (5).'
                'RestrictSendNTLM'   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic. "Not Set"=default, "Allow all"=0, "Audit"=1, "Deny all"=2. Target: 2 (Deny all).'
                'RestrictReceiveNTLM'= 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic. "Not Set"=default, "Allow all"=0, "Audit domain"=1, "Deny domain"=2.'
                'NTLMMinClientSec'   = 'Minimum security negotiation flags for NTLM client sessions. Hex bitmask from MSV1_0\NTLMMinClientSec. Recommended: 0x20080000 (require NTLMv2 session security + 128-bit encryption).'
                'NTLMMinServerSec'   = 'Minimum security negotiation flags for NTLM server sessions. Hex bitmask from MSV1_0\NTLMMinServerSec. Recommended: 0x20080000.'
                'SMBv1Enabled'       = '"Enabled" if SMBv1 protocol is active (Get-SmbServerConfiguration.EnableSMB1Protocol). "Disabled" if off. SMBv1 is vulnerable to EternalBlue and forces NTLM negotiation.'
                'SMBSigningRequired' = 'SMB signing status. "Required (both)" = server and client require signing. "Server-only" or "Client-only" = partial. "Not required" = vulnerable to relay attacks.'
                'KerberosEncTypes'   = 'Supported Kerberos encryption types from HKLM:\...\Kerberos\Parameters\SupportedEncryptionTypes. Shows decoded types: DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1. Target: AES128+AES256 only.'
                'RC4Enabled'         = '"Yes" if RC4_HMAC_MD5 (bit 0x04) is in the supported Kerberos encryption types. RC4 is weak and should be disabled when all systems support AES.'
                'DESEnabled'         = '"Yes" if DES_CBC_CRC or DES_CBC_MD5 (bits 0x01/0x02) are in the supported Kerberos encryption types. DES is insecure and should always be disabled.'
                'DNSSuffixList'      = 'DNS suffix search order from HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SearchList. Missing or misconfigured suffixes can cause DNS resolution failures and NTLM fallback.'
                'OverallReadiness'   = 'Traffic-light score. "Ready" = all critical factors compliant (NetBIOS disabled, LLMNR disabled, LmCompat>=3, SMBv1 off, SMB signing required). "Needs-Work" = 1-3 non-critical issues. "Blocked" = critical factors prevent NTLM removal. "ERROR" = WinRM collection failed.'
                'BlockingFactors'    = 'Semicolon-delimited list of specific protocol configurations that block or impede NTLM deprecation. "None" if fully ready.'
                'RemediationCmds'    = 'Semicolon-delimited list of PowerShell/GPO commands to remediate each blocking factor. Apply via GPO for enterprise-wide consistency.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- SPN-ServiceAccounts (v3.8.9 Session 5f) ----
            $tabNotes['SPN-ServiceAccounts'] = @{
                'Domain'              = 'AD domain where the service account user object resides (e.g. ohdc.com, overheaddoor.com).'
                'AccountName'         = 'sAMAccountName of the AD user account that has SPNs registered.'
                'AccountDN'           = 'Distinguished Name of the account in Active Directory.'
                'AccountStatus'       = '"Active" = enabled and recently logged on. "Disabled" = account is disabled in AD. "Stale" = no logon in >90 days (configurable).'
                'StatusFlags'         = 'Semicolon-delimited flags: Disabled, Stale, Locked, PwdNeverExpires. Empty if no flags.'
                'Enabled'             = '"Yes" if the AD account is enabled. "No" if disabled. SPNs on disabled accounts are orphans that should be cleaned up.'
                'LastLogon'           = 'Date of the account last logon (yyyy-MM-dd). "Never" if no logon recorded. Stale accounts (>90d) may have orphaned SPNs.'
                'PasswordLastSet'     = 'Date the password was last changed. Service accounts with very old passwords are a security risk.'
                'Description'         = 'AD account Description field. Often contains the service purpose or ticket reference.'
                'SPN'                 = 'Full Service Principal Name string as registered on the account (e.g. HTTP/webserver.ohdc.com, MSSQLSvc/sqlserver.ohdc.com:1433).'
                'ServiceClass'        = 'Parsed service class from the SPN (e.g. HTTP, MSSQLSvc, WSMAN, HOST). Identifies the application protocol.'
                'SPNHostname'         = 'Parsed hostname from the SPN. Should resolve in DNS to the server where the service runs.'
                'SPNPort'             = 'Parsed port number from the SPN, if specified. Common: 1433 (SQL), 443 (HTTPS). Empty if no port in SPN.'
                'IsDuplicate'         = '"Yes" if this exact SPN string is also registered on a computer account in AD. Duplicate SPNs cause Kerberos authentication failures. "No" if unique.'
                'DuplicateWith'       = 'If IsDuplicate=Yes, lists the computer account(s) that also have this SPN registered. Resolve by removing the incorrect registration with setspn -D.'
                'MatchedServices'     = 'Running services from the inventory that use this account (DOMAIN\account as service LogOnAs). Shows up to 5 matches. Empty = no matching running service found (SPN may be orphaned or service not collected).'
                'MatchedServiceCount' = 'Count of running services in the inventory that use this account. 0 = potential orphan SPN.'
                'AlertLevel'          = '"Critical" = SPN on disabled account or duplicate SPN. "Warning" = SPN on stale account. "Info" = no matching running service found. "OK" = account active, SPN unique, service confirmed.'
                'Issues'              = 'Semicolon-delimited list of detected issues. "None" if no issues. Examples: "SPN registered on disabled account", "Duplicate with Computer: SERVER01", "No matching running service found".'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- v3.8.9.2: KCD-Validation tabNotes ----
            $tabNotes['KCD-Validation'] = @{
                'ComputerName'           = 'Server hostname (short name) of the computer object with Kerberos delegation configured.'
                'Domain'                 = 'AD domain where the computer object resides.'
                'FQDN'                   = 'Fully Qualified Domain Name of the computer.'
                'DelegationType'         = '"KCD" = traditional Kerberos Constrained Delegation (msDS-AllowedToDelegateTo). "RBCD" = Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity). "Unconstrained" = full delegation (TrustedForDelegation). "None" = no delegation configured.'
                'ProtocolTransition'     = '"Yes" = A2D2S (Any authentication to Delegated Service) enabled -- TrustedToAuthForDelegation is set. "No" = Kerberos-only authentication required. Protocol transition allows NTLM-to-Kerberos conversion.'
                'DelegationTargetSPN'    = 'Individual SPN string from msDS-AllowedToDelegateTo (one row per target SPN). For RBCD: shows the principal name allowed to act on behalf of this computer.'
                'TargetServiceClass'     = 'Parsed service class from the delegation target SPN (e.g. cifs, Microsoft Virtual System Migration Service). cifs = file share access. MVSMS = live migration.'
                'TargetHostname'         = 'Parsed hostname from the delegation target SPN. Should resolve in DNS.'
                'TargetDNSResolvable'    = '"Yes" = Resolve-DnsName succeeded for the target hostname. "No" = DNS lookup failed -- delegation will fail at runtime.'
                'TargetSPNRegistered'    = '"Yes" = the target SPN is actually registered on a computer account in AD. "No" = the SPN target does not exist -- Kerberos ticket request will fail.'
                'TargetComputerAccount'  = 'AD computer account that has the target SPN registered. Empty if SPN not found in AD.'
                'IsLiveMigrationSPN'     = '"Yes" = this SPN matches the live migration service class (Microsoft Virtual System Migration Service or cifs). "No" = other service type.'
                'LiveMigrationCoverage'  = 'For Hyper-V hosts: "Complete" = all cluster peer nodes are listed as delegation targets. "Partial" = some peers missing. "N/A" = not a Hyper-V host or not in a cluster.'
                'MissingLMTargets'       = 'Semicolon-delimited list of cluster peer hostnames that are NOT in this host delegation target list. These peers cannot receive live migrations from this host via Kerberos.'
                'RBCDPrincipals'         = 'For RBCD: semicolon-delimited list of principals (computer accounts) allowed to delegate to this computer. From msDS-AllowedToActOnBehalfOfOtherIdentity ACL.'
                'AlertLevel'             = '"Critical" = delegation target SPN not registered in AD or DNS unresolvable (delegation WILL fail). "Warning" = partial live migration coverage (some peers missing) or protocol transition enabled without justification. "OK" = all targets valid and reachable. "Info" = informational (RBCD or no delegation).'
                'Issues'                 = 'Semicolon-delimited list of validation findings. "None" if all checks pass. Examples: "Target SPN not registered in AD", "DNS lookup failed for target", "Missing LM targets: MHOH-HV-P03, MHOH-HV-P04".'
                'KCDConfigSteps'         = 'v3.10.12 OPEN-61: Traditional Kerberos Constrained Delegation remediation commands for this specific delegation gap. Copy-pasteable PowerShell that configures msDS-AllowedToDelegateTo on the SOURCE computer. For Unconstrained delegation: includes Step 1 (remove unconstrained) + Step 2 (set KCD). For missing SPNs: setspn command. For live migration gaps: adds the missing target SPNs. "No action needed" for OK entries. NOTE: KCD requires Domain Admin rights to modify the source computer delegation properties.'
                'RBCDConfigSteps'        = 'v3.10.12 OPEN-61: Resource-Based Constrained Delegation remediation commands (RECOMMENDED over KCD for Server 2012+). Copy-pasteable PowerShell that configures PrincipalsAllowedToDelegateToAccount on the DESTINATION computer. RBCD is preferred because: (1) configured on the destination, not the source; (2) does not require Domain Admin -- destination admin can set it; (3) works cross-domain without forest trust. For Unconstrained: includes removal + RBCD setup. For live migration: configures each missing target. "No action needed" for OK entries.'
                'KCDRemediationScript'   = 'OPEN-61 Part B: Full path to the auto-generated per-host KCD/RBCD remediation .ps1 in Remediation\KerberosDelegate\. One script per host covers ALL delegation gaps on that host. Blank for OK/Info rows. Review and run with -WhatIf first. Follow with Set-HyperVKerberosLiveMigration.ps1 (Step 2) to activate Kerberos live migration.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows.'
            }

            # ---- Cross-Domain-Auth (v3.9.0 CR54, v3.10.5 CR84: auth protocol + Kerberos diagnostics) ----
            $tabNotes['Cross-Domain-Auth'] = @{
                'VM'               = 'VM display name from Hyper-V.'
                'Host'             = 'Hyper-V host the VM runs on.'
                'ClusterName'      = 'Cluster name if host is clustered. Blank for standalone.'
                'Powerstate'       = 'VM power state: poweredOn / poweredOff.'
                'DetectedDomain'   = 'Domain FQDN resolved for this VM. Detection tiers: DNS (Tier 0, most reliable -- System.Net.Dns.GetHostEntry), KVP (Tier 1 -- Hyper-V Integration Services key-value pair), GuestOS (Tier 2 -- KVP OSName suffix), VMName (Tier 3 -- VM display name suffix). "unknown" if all tiers failed.'
                'DomainTier'       = 'Which detection tier succeeded: DNS, KVP, GuestOS, VMName, or none. DNS is most reliable and works even when integration services are broken.'
                'CredentialUsed'   = 'Username of the credential that successfully authenticated to this VM (e.g. ohdc1\svc_hypervreport or overheaddoor\mgeorge). For multi-credential-per-domain configs, shows which specific account worked. Blank if all credentials failed or VM was off.'
                'CredentialSource' = 'Domain key from DomainCredentials hashtable that provided the winning credential (e.g. ohdc.com, ohdc.com_2, overheaddoor.com, default). Useful when multiple credentials exist per domain.'
                'AuthMethod'       = 'v3.10.5: Authentication protocol that succeeded. Kerberos = default WinRM auth (preferred, most secure). Negotiate = NTLM fallback used because Kerberos failed (see KerberosFailReason). AllFailed = no credential or auth method worked. Blank = not attempted (VM off or unreachable).'
                'AuthProtocol'     = 'v3.10.5/v3.10.6: Human-readable auth protocol label. "Kerberos" = secure, no action needed. "Negotiate (NTLM)" = working but Kerberos should be fixed (see KerberosRemediation). "PSDirect (VMBus)" = collected via PowerShell Direct because network was unreachable. "AllFailed" = no access. "N/A (Off)" = VM powered off.'
                'WinRMStatus'      = 'WinRM service status from guest: Running, Unreachable, or N/A (Off).'
                'HasOSData'        = 'True if OS inventory data was successfully collected from this VM. False means WinRM connection failed.'
                'GuestComputerName' = 'Computer name reported by the guest OS. Blank if WinRM collection failed.'
                'FailReason'       = 'v3.9.8: Diagnostic explanation of why OS data collection failed. Examples: WinRM unreachable, all credentials failed (AccessDenied), non-domain appliance, domain unknown. Blank for OK and Off VMs.'
                'Remediation'      = 'v3.9.8: Actionable remediation steps specific to the failure reason. Includes verification commands (Invoke-Command, nltest, setspn, Enter-PSSession) and configuration guidance (firewall, trust, WinRM settings). Blank for OK and Off VMs.'
                'KerberosFailReason' = 'v3.10.5: When AuthProtocol is "Negotiate (NTLM)", this shows the specific Kerberos error that caused the fallback. Examples: "Cannot find the computer" (missing SPN), "0x80090322" (trust/clock skew), "does not allow the delegation" (delegation not configured), "Access is denied" (credential not authorized for Kerberos). Blank when Kerberos succeeded or VM was not accessed. v3.10.10 CR100: For PSDirect failures, this now shows a short category summary (e.g. "primary cat: NotAuthorized"); the FULL per-credential attempt log is in the new PSDirectFailReason column.'
                'KerberosRemediation' = 'v3.10.5: Actionable commands to fix the Kerberos failure so Negotiate is no longer needed. Pipe-delimited list. Examples: "SPN missing: setspn -S WSMAN/server.domain.com server$ | Verify: setspn -L server", "Check cross-domain trust: nltest /sc_query:domain.com | Verify trust: Get-ADTrust -Filter *", "Check time sync: w32tm /monitor /computers:server.domain.com". Blank when Kerberos succeeded. v3.10.10 CR100: For PSDirect failures, remediation text is now category-specific based on the classified error (NotAuthorized, InvalidCredential, GuestNotReady, LinuxGuest, VMNotReady, Timeout, NetworkError, IntegrationServices, etc.).'
                'PSDirectFailReason' = 'v3.10.10 CR100: Full untruncated PSDirect failure detail when AuthProtocol is AllFailed and PSDirect was attempted. Format: pipe-delimited list of per-credential attempts, each as "[N] username [source] -> Category: FullErrorMessage". Categories: NotAuthorized (service account lacks local admin in guest), InvalidCredential (wrong password), AccessDenied (guest firewall/GPO block), GuestNotReady (PSDirect not supported), IntegrationServices (integration components missing/old), LinuxGuest (non-PowerShell OS), VMNotReady (saved/paused), VMNotRunning, Timeout, NetworkError (VMBus issue), OtherError. Blank when PSDirect was not attempted (network reached VM normally) or when PSDirect succeeded.'
                'PSDirectAttempts'   = 'v3.10.10 CR100: Compact per-credential attempt log for PSDirect. Format: "[1] user1 [src1] -> Result:Category (DurationMs) | [2] user2 [src2] -> ... | ...". Shows EVERY credential that was tried in rotation order with the final result (Success or Failed), the classified error category, and the round-trip time in milliseconds. Useful for spotting which domain credential actually has permission vs. which just times out. Blank when PSDirect was not attempted.'
                'AlertLevel'       = 'Critical = powered on, no OS data, domain unknown (credential rotation had no domain to match). Warning = powered on, domain detected but no OS data (WinRM or auth issue). OK = OS data collected. N/A (Off) = VM powered off.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- DNS-Validation (v3.9.2 CR57) ----
            $tabNotes['DNS-Validation'] = @{
                'Name'             = 'Hyper-V VM display name (as shown in Hyper-V Manager). This may differ from the guest OS computer name -- see GuestOSDNSName column.'
                'GuestOSDNSName'   = 'The actual computer name from inside the guest OS. Sources in priority order: (1) WinRM $env:COMPUTERNAME, (2) KVP FullyQualifiedDomainName from Hyper-V Integration Services, (3) Hyper-V display name as fallback. DNS records are registered under this name, not the Hyper-V display name. Example: VM display name "BALOH-Bartend-P01" but guest OS name is "BALOH-BARTEND-1".'
                'NameMismatch'     = 'Yes = the Hyper-V VM display name (Name column) differs from the guest OS computer name (GuestOSDNSName). This is common when VMs are renamed inside the guest without updating the Hyper-V display name, or when naming conventions differ. DNS lookups use the guest OS name. N/A for hosts.'
                'Type'             = 'Host = Hyper-V hypervisor, VM = virtual machine.'
                'Host'             = 'Hyper-V host the target runs on. For hosts, same as Name.'
                'ClusterName'      = 'Failover cluster name if the host is clustered. Blank for standalone hosts.'
                'FQDN'             = 'Fully qualified domain name used for the DNS forward lookup. Constructed from GuestOSDNSName + detected domain. This is the name that should have an A record in DNS.'
                'Domain'           = 'Domain FQDN detected for this target. Detection tiers: DNS reverse lookup (Tier 0), KVP FullyQualifiedDomainName (Tier 1), host domain fallback.'
                'PrimaryIP'        = 'Primary IPv4 address from the VM NIC (first non-APIPA IP from GuestNetwork or KVP NetworkAddressIPv4). This is the expected IP that the DNS A record should resolve to. v3.9.5: KVP error strings filtered out (Msvm_KvpExchange errors no longer appear here).'
                'AllIPs'           = 'All IPv4 addresses on the target (semicolon-delimited). Multi-homed targets may have multiple valid IPs. A forward lookup matching ANY of these IPs is considered a match.'
                'DNSSource'        = 'How DNS was queried for this target domain: EfficientIP = SOLIDserver IPAM API (for ohdc.com where DCs do not host DNS), AD-DNS = Resolve-DnsName against a domain controller hosting DNS (for overheaddoor.com), System = default OS resolver as fallback.'
                'ForwardLookupIP'  = 'IP address(es) returned by the forward DNS lookup (A record query for the FQDN). Blank if no record found. For EfficientIP: queried via Get-EfficientIPByHostname. For AD-DNS: queried via Resolve-DnsName -Server <DC-IP> -Type A.'
                'ForwardMatch'     = 'Yes = forward lookup IP matches a NIC IP. Mismatch = A record exists but IP differs from NIC IP (stale DNS record, needs update). Missing = no A record found (Critical -- machine unreachable by name).'
                'ReverseLookupPTR' = 'Hostname(s) returned by the reverse DNS lookup (PTR record query for the PrimaryIP). Blank if no PTR record. PTR records enable reverse lookups (IP -> hostname) used by security tools and Kerberos.'
                'ReverseMatch'     = 'Yes = PTR record matches the FQDN. Mismatch = PTR points to a different hostname (stale or incorrect). Missing = no PTR record (Warning -- reverse lookups will fail).'
                'AlertLevel'       = 'Critical = no forward (A) record found (machine unreachable by hostname). Warning = IP mismatch, missing PTR, or PTR mismatch. OK = both forward and reverse DNS records are correct and match.'
                'Issues'           = 'Semicolon-delimited list of all findings. "None" if all checks pass. Includes: missing A records, IP mismatches, missing PTR records, VM display name vs guest OS name mismatches.'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- VM-Activity-Audit (v3.10.2 Session 14; CR93/CR95/CR96-99 in v3.10.9-v3.10.10) ----
            $tabNotes['VM-Activity-Audit'] = @{
                'Timestamp'        = 'Date/time the event occurred on the Hyper-V host (yyyy-MM-dd HH:mm:ss).'
                'VMName'           = 'VM name extracted from the event message. Event-ID-aware since v3.10.10 CR96: Event 20400 (VM Replication) uses targeted "for virtual machine X" regex; all other events use generic first-quoted-string with false-positive filter (CR95) rejecting disk paths, GUIDs, controllers. Blank if no VM name could be extracted.'
                'Host'             = 'Hyper-V host where the event occurred.'
                'ClusterName'      = 'Failover cluster name if the host is clustered. Blank for standalone.'
                'Activity'         = 'What happened: VM Started, VM Shutdown (guest-initiated), VM Powered Off, VM Powered Off (forced), VM Worker Crashed, Snapshot Created, Snapshot Deleted, VM Created.'
                'Trigger'          = 'WHO or WHAT caused the event. Categories: Human (interactive) = user action, Guest OS = shutdown from inside VM, Cluster (failover) = resource movement, Cluster (live migration), Host OS = host reboot/crash, Worker Crash = Hyper-V process failure, Service/Automation = service account action, Unknown = no correlated trigger found.'
                'TriggerDetail'    = 'Additional context about the trigger. Examples: "User OHDC1\mgeorge-adm via shutdown.exe", "Unexpected host shutdown (kernel power)", "Cluster resource movement (Event 1069)".'
                'UserAccount'      = 'User account associated with the event or correlated trigger event. From event UserId SID translated to NTAccount.'
                'ProcessName'      = 'Process name from User32 event 1074 (user-initiated shutdowns). Examples: shutdown.exe, wininit.exe, Explorer.EXE.'
                'EventSource'      = 'Windows event log source: VMMS-Admin (Hyper-V management), Worker-Admin (VM worker process), System (OS-level), FailoverClustering.'
                'EventID'          = 'Windows event ID number. Key IDs: 18501=guest shutdown, 18500/18502=power off, 12300=start, 18600=snapshot create, 1074=user shutdown, 41=unexpected power loss, 20400=VM replication.'
                'EventMessage'     = 'v3.10.10 CR97: Raw event message text truncated to 500 characters, with newlines collapsed to spaces. Lets the analyst see what the event actually said when the parser produces unexpected results (blank VMName, unusual Trigger, etc.). Full untruncated text is in the Windows event log on the originating host.'
                'ReplicaPartner'   = 'v3.10.10 CR98: Replica partner address extracted from Event 20400 (VM Replication) messages. Typically an IP or hostname of the paired replica server. Blank for all non-20400 events. Useful for identifying stuck/broken Hyper-V Replica relationships -- high counts of 20400 events pointing at the same partner suggest an orphaned or misconfigured replica config.'
                'ForensicNote'     = 'v3.10.9 CR95: Per-event-ID root-cause narrative explaining what the event means and common causes. Populated for 13+ critical events including 18500/18501/18502/18503/18504/18609 (VM power state), 12148/12582/12597 (storage/worker failures), 4092/14070/15140 (state transitions). Blank for events without a forensic mapping.'
                'CorrelatedEvents' = 'v3.10.9 CR93: Other events found within the correlation window (+/-30 seconds) that help identify the trigger. Descriptive labels like "User-initiated shutdown (1074)" or "Background disk merge started (19070)" instead of raw Source:ID.'
                'AlertLevel'       = 'Critical = forced power off, worker crash, unexpected host shutdown, or Event 20400 connection failure. Warning = cluster failover, unknown trigger on power-off, or Event 20400 authentication failure (CR99). Info = normal operation (guest shutdown, planned start, snapshot, successful replication).'
                'DataSource'       = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- VM-Offline-Disks (v3.10.4 CR83) ----
            $tabNotes['VM-Offline-Disks'] = @{
                'VMName'            = 'Hyper-V display name of the virtual machine containing the offline disk.'
                'Host'              = 'Hyper-V host where this VM runs.'
                'ClusterName'       = 'Failover cluster name if the host is clustered. Blank for standalone hosts.'
                'GuestOSDNSName'    = 'Guest OS computer name resolved via WinRM (GuestComputerName) or KVP integration services (FullyQualifiedDomainName hostname). May differ from the Hyper-V display name after renames or V2V migrations.'
                'DiskNumber'        = 'Windows disk number inside the guest OS (e.g. 0 = boot disk, 1 = first data disk). Corresponds to Disk Management Disk N.'
                'SizeGB'            = 'Total capacity of the disk in GB as reported by Get-Disk inside the guest OS.'
                'PartitionStyle'    = 'Partition table type: GPT (modern, required for >2TB), MBR (legacy), RAW (uninitialized). RAW disks have never been initialized in this OS.'
                'OperationalStatus' = 'Current operational state from Get-Disk. Online = normal. Offline = disk is not accessible to the OS. Values: Online, Offline, Missing, Failed, Unknown.'
                'HealthStatus'      = 'Physical health of the disk: Healthy, Warning (degraded), Unhealthy (failing), Unknown.'
                'IsOffline'         = 'True if the disk is offline. This is the primary alert indicator. Offline disks have no volumes mounted and applications cannot access their data.'
                'IsReadOnly'        = 'True if the disk is in read-only mode. Some V2V migrations set disks as read-only in addition to offline. Both conditions must be cleared for full access.'
                'OfflineReason'     = 'Windows reason code for why the disk is offline. Common values: Policy (SAN policy set it offline), Redundant Path (multipath), By User (manually taken offline), Collision (signature collision with another disk).'
                'BusType'           = 'Storage bus type visible inside the guest: SAS, SCSI, iSCSI, NVMe, Fibre Channel. Hyper-V virtual disks typically show as SAS or SCSI.'
                'SANPolicy'         = 'Current Windows SAN policy from diskpart.exe: OnlineAll (all disks come online automatically), OfflineShared (shared bus disks stay offline -- common after V2V), OfflineInternal (internal disks also stay offline). OfflineShared is the default for Windows Server and is the most common cause of this issue after V2V migrations.'
                'TotalGuestDisks'   = 'Total number of disks (online + offline) detected by Get-Disk inside this VM. Helps assess scope: a VM with 1 online + 3 offline disks needs more attention than 1 online + 1 offline.'
                'Remediation'       = 'PowerShell commands to bring the disk online: Set-Disk -Number N -IsOffline $false (and Set-Disk -Number N -IsReadOnly $false if read-only). If SANPolicy is not OnlineAll, includes Set-StorageSetting -NewDiskPolicy OnlineAll to prevent recurrence.'
                'DataSource'        = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # ---- LAPS-Usage (v3.10.11 CR102+CR103) ----

            # ---- AD-Info (v3.10.11) ----
            # AD Forest and Domain topology tab. Created by the orchestrator's
            # Step 5q: Get-ADForest + Get-ADDomain + Get-ADDomainController.
            $tabNotes['AD-Info'] = @{
                'Scope'                = 'Level of this row: "Forest" (top-level forest attributes) or "Domain" (per-domain attributes). The forest row shows cross-domain properties like SchemaMaster and DomainNamingMaster. Each domain row shows its own PDCEmulator, RIDMaster, InfrastructureMaster.'
                'Name'                 = 'Forest name (for Forest rows) or domain FQDN (for Domain rows). Source: Get-ADForest.Name / Get-ADDomain.DNSRoot.'
                'FunctionalLevel'      = 'Forest or domain functional level (e.g. Windows2012R2Forest, Windows2016Domain). Determines which AD features are available. Higher levels require all DCs to be at or above that OS version. Source: Get-ADForest.ForestMode / Get-ADDomain.DomainMode.'
                'SchemaMaster'         = 'FSMO role holder: Schema Master. The single DC in the forest that can modify the AD schema. Only populated on Forest rows. Source: Get-ADForest.SchemaMaster.'
                'DomainNaming'         = 'FSMO role holder: Domain Naming Master. The single DC in the forest that controls addition/removal of domains. Only populated on Forest rows. Source: Get-ADForest.DomainNamingMaster.'
                'PDCEmulator'          = 'FSMO role holder: PDC Emulator. Authoritative for time sync, password changes, and account lockout processing in this domain. Only populated on Domain rows. Source: Get-ADDomain.PDCEmulator.'
                'RIDMaster'            = 'FSMO role holder: RID Master. Allocates RID pools to DCs for creating new security principals. Only populated on Domain rows. Source: Get-ADDomain.RIDMaster.'
                'InfrastructureMaster' = 'FSMO role holder: Infrastructure Master. Handles cross-domain object references (phantom cleanup). Only populated on Domain rows. Source: Get-ADDomain.InfrastructureMaster.'
                'LAPSSchemaLevel'      = 'LAPS schema detection result: "WindowsLAPS-WS2025" (msLAPS-* attributes present in schema -- Server 2025 or manual schema extension), "LegacyLAPS" (ms-Mcs-AdmPwd attribute present), "Both" (both attribute sets present), or "None" (no LAPS schema extensions). Determines which LAPS backend the LAPS-Usage tab can query. Source: schema attribute existence check during Step 5p.'
                'Notes'                = 'Additional context: list of domains in the forest (Forest row), list of domain controllers (Domain row), trust relationships, or site/subnet information.'
            }

            # ---- SPN-Inventory-Full (v3.10.12 OPEN-66) ----
            # AD-wide SPN inventory: one row per SPN per account across all domains.
            # Created by Step 5s: Invoke-SPNInventoryFull queries Get-ADComputer and Get-ADUser
            # with -Filter 'ServicePrincipalName -like "*"'. Opt-in via IncludeSPNInventoryFull.
            $tabNotes['SPN-Inventory-Full'] = @{
                'AccountName'   = 'Computer name (sAMAccountName) or user account (sAMAccountName) that has this SPN registered. Source: Get-ADComputer.Name or Get-ADUser.SamAccountName.'
                'AccountType'   = '"Computer" for machine accounts (CN=Computers or OU=...). "User" for user/service-account objects. Computer accounts self-register HOST and WSMAN SPNs automatically. User accounts require explicit setspn registration.'
                'AccountScope'  = '"HyperV" if this computer account is also a Hyper-V host in the inventory (cross-reference with vHost tab). "ServiceAccount" for user-type accounts. "Other" for computers not in the Hyper-V inventory (file servers, SQL servers, etc.).'
                'Domain'        = 'AD domain FQDN this account belongs to. Source: the DomainCredentials server parameter used for the query.'
                'Enabled'       = 'True if the AD account is enabled. False = account is disabled. SPNs on disabled accounts are unreachable -- Kerberos ticket requests will fail immediately.'
                'IsStale'       = 'True if LastLogonDate is older than the StaleThresholdDays setting (default 90 days). Stale accounts often have SPNs that no longer point to any active service.'
                'OS'            = 'OperatingSystem attribute from AD (computer accounts only). Empty for user accounts. Useful for identifying old OS versions with SPNs still registered.'
                'SPN'           = 'Full SPN string as stored in AD (e.g. MSSQLSvc/sql01.ohdc.com:1433, HOST/server01, HTTP/intranet.ohdc.com). Source: servicePrincipalName attribute.'
                'ServiceClass'  = 'SPN service class prefix parsed from the SPN string (the portion before the first "/"). Common values: HOST, RestrictedKrbHost, WSMAN, HTTP, MSSQLSvc, TERMSRV, LDAP, GC, DNS, SMTP, NFS, RPC, CIFS. Non-standard values indicate custom service registrations.'
                'Hostname'      = 'Target hostname parsed from the SPN instance (the portion after the "/" with any ":port" suffix stripped). Useful for identifying which server this SPN points to, and whether that server still exists in DNS.'
                'Port'          = 'TCP port number parsed from the SPN instance (the ":port" suffix if present). Blank for SPNs without an explicit port (e.g. HOST, WSMAN). Common ports: 1433 (SQL), 443 (HTTPS), 3389 (RDP), 389 (LDAP).'
                'IsDuplicate'   = 'True if the same SPN string is registered on MORE THAN ONE account. Duplicate SPNs cause immediate Kerberos auth failures: the KDC cannot determine which account to issue a service ticket for. Critical alert -- requires immediate remediation.'
                'DuplicateOn'   = 'Comma-delimited list of OTHER account names that also hold this same SPN. Blank when IsDuplicate = False. Use setspn -X to verify and setspn -D to remove from the wrong account.'
                'AlertLevel'    = '"Critical" for duplicate SPNs (Kerberos auth WILL fail). "Warning" for SPNs on disabled accounts or stale accounts. "OK" for valid, unique, enabled registrations.'
                'AlertReason'   = 'Human-readable explanation of why AlertLevel was set. Includes the duplicate account names, or the stale/disabled status reason.'
                'Description'   = 'AD Description attribute of the account. Useful for identifying service accounts and understanding what each SPN is for.'
                'DataSource'    = 'Always "ACTIVE-DIRECTORY" for this tab. Source is the AD LDAP query, not Hyper-V WMI.'
            }

            $tabNotes['LAPS-Usage'] = @{
                'VM'                       = 'VM name or guest computer name. This is the machine whose LAPS posture is being audited.'
                'Host'                     = 'Hyper-V host running this VM.'
                'LAPSBackend'              = 'Which LAPS backend is active for this VM: AD-Legacy (ms-Mcs-AdmPwd attribute from Legacy LAPS MSI), AD-WindowsLAPS (msLAPS-* attributes from Windows LAPS built into Server 2019+/Win10/11), AD-Both (both backends configured -- migration in progress), None (LAPS not configured -- local admin password is unmanaged), NotDomainJoined (VM not found in AD), Error (AD query failed).'
                'LookupResult'             = 'Result of the LAPS metadata query: OK (LAPS data found and readable), NotEnabled (no LAPS attributes populated on the AD computer object), NoPermission (service account cannot read LAPS attributes -- permission issue), NotDomainJoined (VM not found in AD), Error (AD query exception).'
                'ManagedAccountName'       = 'Local account name that LAPS manages. Usually "Administrator" (Legacy LAPS always manages Administrator). Windows LAPS can manage a custom account name set by policy (msLAPS-ManagedPasswordAccountName attribute).'
                'PasswordAge'              = 'Estimated age of the current LAPS-managed password in days. For Legacy LAPS: calculated from expiration minus configured rotation interval. For Windows LAPS: calculated from the password expiration timestamp. Null if the information is not available. High values indicate password rotation is not occurring (possible GPO misconfiguration or LAPS service failure).'
                'PasswordExpiration'       = 'When the current password is scheduled to be rotated. For Legacy LAPS: ms-Mcs-AdmPwdExpirationTime (FileTime format converted to DateTime). For Windows LAPS: msLAPS-PasswordExpirationTime (DateTime). Past timestamps indicate the password is overdue for rotation.'
                'RotationDue'              = 'True if the password is due for rotation within the next 24 hours or is already overdue. False if the password is within its expected lifecycle.'
                'LegacyLAPSInstalled'      = 'True if the Legacy LAPS MSI ("Local Administrator Password Solution") was detected in the VM''s installed applications (from Applications-Windows tab). False does not mean LAPS is absent -- Windows LAPS is built-in and does not require an MSI.'
                'LegacyAttributePopulated' = 'True if the ms-Mcs-AdmPwd attribute on the VM''s AD computer object has a value. If LegacyLAPSInstalled=True but this is False, it indicates a GPO misconfiguration (LAPS MSI installed but not writing passwords to AD).'
                'WindowsLAPSConfigured'    = 'True if either msLAPS-Password (plaintext) or msLAPS-EncryptedPassword (encrypted) has a value on the AD computer object. This is the Windows LAPS indicator.'
                'WindowsLAPSEncrypted'     = 'True if the password is stored in the encrypted msLAPS-EncryptedPassword attribute (requires Server 2025 DC or Azure AD). False if using the plaintext msLAPS-Password attribute. Encrypted is more secure but requires newer infrastructure.'
                'MigrationStatus'          = 'LAPS migration posture: LegacyOnly (running Legacy LAPS MSI only), WindowsOnly (running Windows LAPS only -- migration complete for this VM), Both (both backends configured -- migration in progress), Unmanaged (no LAPS configured), NotDomainJoined (not in AD). Useful for tracking fleet-wide LAPS migration progress.'
                'AlertLevel'               = 'Info: LAPS managed and password within expected age. Warning: password age exceeds LAPSAgeWarningDays threshold or rotation due within 24h. Critical: LAPS not configured on a production VM (unmanaged local admin), password age exceeds LAPSAgeCriticalDays, or service account lacks permission to read LAPS attributes.'
                'AlertReason'              = 'Human-readable explanation of why the AlertLevel was set. Includes specific threshold values and remediation guidance.'
                'DataSource'               = 'Data platform source identifier. Currently HYPER-V for all rows.'
            }

            # ---- Permissions-Groups (v3.10.12 OPEN-60 / OPEN-67) ----
            $tabNotes['Permissions-Groups'] = @{
                'Computer'        = 'Machine name where the local group was queried. Can be a Hyper-V host or guest VM when AuditScope = HostsAndVMs.'
                'Type'            = 'OPEN-67: Row scope -- Host (Hyper-V host queried via WinRM) or VM (guest queried via WinRM, AuditScope=HostsAndVMs only).'
                'ParentHost'      = 'For VM rows: the Hyper-V host this VM runs on. Blank for host rows.'
                'ClusterName'     = 'Cluster name if the host/VM is part of a failover cluster. Blank for standalone.'
                'GroupName'       = 'Local security group name. Standard groups queried: Administrators, Hyper-V Administrators, Remote Desktop Users, Remote Management Users, Backup Operators, Event Log Readers, Distributed COM Users, Performance Monitor Users, Power Users, IIS_IUSRS. Groups that do not exist on a machine are silently skipped.'
                'MemberName'      = 'Domain\Username or COMPUTER\Username of the group member. Shows exactly who has access to this machine through this group.'
                'MemberSID'       = 'Security Identifier (SID) of the member. Orphaned SIDs (deleted AD accounts still in local groups) show as raw SID strings instead of DOMAIN\Username format.'
                'ObjectClass'     = 'Member type: "User" (individual account) or "Group" (nested group). Nested groups grant all their members the local group membership.'
                'PrincipalSource' = 'Where the member account comes from: "ActiveDirectory" (domain account), "Local" (local machine account), "MicrosoftAccount".'
                'AlertLevel'      = 'Info for most entries. Warning for local accounts in Administrators group (security risk -- domain accounts preferred for auditability).'
                'DataSource'      = 'Platform source: Hyper-V. Future: VMware, Nutanix, Active Directory.'
            }

            # ---- Permissions-Privileges (v3.10.12 OPEN-60 / OPEN-67) ----
            $tabNotes['Permissions-Privileges'] = @{
                'Computer'        = 'Machine name where user rights assignments were queried via secedit /export.'
                'Type'            = 'OPEN-67: Row scope -- Host or VM. VM rows appear when AuditScope = HostsAndVMs or Full.'
                'ParentHost'      = 'For VM rows: the Hyper-V host this VM runs on. Blank for host rows.'
                'ClusterName'     = 'Cluster name if clustered. Blank for standalone.'
                'PrivilegeName'   = 'Windows privilege constant name (e.g. SeBatchLogonRight, SeShutdownPrivilege). Programmatic name used in Group Policy and secedit.'
                'FriendlyName'    = 'Human-readable description: "Log on as a batch job", "Shut down the system", "Log on via Remote Desktop", etc.'
                'AssignedTo'      = 'DOMAIN\Username or BUILTIN\GroupName holding this privilege. Resolved from SID. Raw SID shown if resolution fails (orphaned account).'
                'RawSID'          = 'Raw SID as stored in local security policy. Format: *S-1-5-21-... S-1-5-32-544 = BUILTIN\Administrators.'
                'AlertLevel'      = 'Info for standard privileges. Warning for SeDebugPrivilege, SeTakeOwnershipPrivilege, SeTcbPrivilege (powerful -- should only be SYSTEM).'
                'DataSource'      = 'Platform source: Hyper-V. Future: VMware, Nutanix, Active Directory.'
            }

            # ---- Permissions-Security (OPEN-67 additions) ----
            $tabNotes['Permissions-Security'] = @{
                'Computer'     = 'Machine name where security options were queried via secedit /export /cfg.'
                'Type'         = 'OPEN-67: Row scope -- Host or VM.'
                'ParentHost'   = 'For VM rows: the Hyper-V host this VM runs on. Blank for host rows.'
                'ClusterName'  = 'Cluster name if clustered. Blank for standalone.'
                'Section'      = 'Policy section: "Account Policy / Interactive Logon" ([System Access]) or "Security Options" ([Registry Values]).'
                'PolicyKey'    = 'Raw policy key name from secedit .cfg (e.g. MinimumPasswordLength, MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel).'
                'FriendlyName' = 'Human-readable policy name matching gpedit.msc Security Options. Examples: "Minimum password length", "Network security: LAN Manager authentication level".'
                'Value'        = 'Configured value for this policy. For System Access: numeric (0/1 for bool, days/count for thresholds). For registry values: DWORD or string.'
                'DataSource'   = 'Platform source: Hyper-V. Collected via WinRM secedit /export, parsed [System Access] and [Registry Values] sections.'
            }

            $tabNotes['SCCM-Status'] = @{
                'ComputerName'      = 'Computer name as registered in SCCM (SMS_R_System.Name). This is the primary key for correlating SCCM clients with the Hyper-V VM inventory.'
                'HyperVMatch'       = 'Whether this SCCM client was matched to a VM in the Hyper-V inventory. "Yes" = matched by VM display name or guest computer name. "No" = SCCM client exists but is not a known Hyper-V VM (could be physical, VMware, Nutanix, or decommissioned). "Yes (No SCCM Client)" = VM is running in Hyper-V but has no SCCM client installed.'
                'HyperVHost'        = 'Hyper-V host running this VM. Blank if the SCCM client is not matched to Hyper-V inventory. "(self - HV Host)" for Hyper-V host machines themselves.'
                'ClusterName'       = 'Failover cluster name if the Hyper-V host is clustered. Blank for standalone hosts or non-Hyper-V machines.'
                'VMPowerState'      = 'Current VM power state from Hyper-V: poweredOn, poweredOff. Only populated for VMs matched to Hyper-V inventory.'
                'SCCMActive'        = 'SCCM client activity status. "Active" = client is communicating with the site server. "Inactive" = client has stopped communicating (stale, decommissioned, or network issue). "Missing Client" = VM is running in Hyper-V but has no SCCM client installed at all.'
                'ClientVersion'     = 'SCCM/MECM client version string (e.g. 5.00.9122.1010). Useful for identifying outdated clients that need updating.'
                'AssignedSite'      = 'SCCM site code(s) this client is assigned to (e.g. PS1). Multiple site codes indicate multi-site assignment.'
                'Domain'            = 'Active Directory domain or workgroup from SCCM (ResourceDomainORWorkgroup). Used for cross-domain correlation.'
                'ADSite'            = 'Active Directory site name from SCCM. Useful for geographic/network segmentation analysis.'
                'OperatingSystem'   = 'Operating system name and version as reported by SCCM hardware inventory. Format varies: "Microsoft Windows NT Server 10.0" for Server 2016+.'
                'IsVirtualMachine'  = 'SCCM detection of whether this client runs on a virtual machine. True/False. Useful for cross-referencing with Hyper-V inventory.'
                'LastLogon'         = 'Last logon timestamp from SCCM (SMS_R_System.LastLogonTimestamp). Stale values (>30 days) indicate the machine may be offline or decommissioned.'
                'DaysSinceLogon'    = 'Days since last logon. >30 = Warning (may be offline). >90 = Critical (likely decommissioned or abandoned). 0 = active today.'
                'HealthResult'      = 'Last client health evaluation result. "Healthy" = passed all checks. "Evaluation Failed" = client self-repair needed. "Not Yet Evaluated" = health eval has not run (new client or disabled).'
                'HealthStatus'      = 'Client state description from SMS_CH_ClientSummary. Provides detailed health context beyond the pass/fail result.'
                'LastHealthEval'    = 'Timestamp of the last client health evaluation. SCCM clients run health checks on a schedule (typically daily). Stale timestamps indicate the health evaluation task may be broken.'
                'LastPolicyRequest' = 'Timestamp of the last machine policy request. This shows when the client last asked the management point for new policies. Stale values indicate communication problems.'
                'LastHWScan'        = 'Timestamp of the last hardware inventory scan sent to the site server. Default cycle: 7 days. Stale values mean hardware data in SCCM is outdated.'
                'CollectionCount'   = 'Number of SCCM device collections this client belongs to. High counts may indicate over-targeting; zero (excluding built-in) may indicate the machine is not being managed.'
                'Collections'       = 'Semicolon-delimited list of SCCM device collection names. Includes both built-in (All Systems, All Desktop and Server Clients) and custom collections.'
                'IPAddresses'       = 'IP addresses reported by the SCCM client during hardware inventory. Useful for network correlation when DNS resolution fails.'
                'AlertLevel'        = 'Calculated alert level. OK = active and healthy. Warning = stale >30 days, health eval failed, or missing SCCM client. Critical = inactive, stale >90 days.'
                'DataSource'        = 'Data platform source identifier. Currently HYPER-V for all rows. Future modules will set: VMware, Nimble, NetApp, Isilon, SCCM, Forescout, Active Directory.'
            }

            # OPEN-50: Build Legend tab -- consolidated column definitions, color codes, alert levels.
            # Iterates $tabNotes dictionary and renders each tab's column descriptions as a structured table.
            # Tab position: after 01-Index (position 3), navy background to match navigation tabs.
            Write-HVLog "  OPEN-50: Building Legend tab..." -Level Info
            try {
                $legendWs = $pkg.Workbook.Worksheets.Add('Legend')
                $legendWs.TabColor = [System.Drawing.Color]::FromArgb(0x1F, 0x4E, 0x79)
                $lr = 1

                # Title row
                $legendWs.Cells[$lr, 1].Value = 'Hyper-V Inventory Report - Column Reference Legend'
                $legendWs.Cells[$lr, 1].Style.Font.Bold = $true
                $legendWs.Cells[$lr, 1].Style.Font.Size = 14
                $legendWs.Cells[$lr, 1, $lr, 3].Merge = $true
                $legendWs.Cells[$lr, 1].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $legendWs.Cells[$lr, 1].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0x1F, 0x4E, 0x79))
                $legendWs.Cells[$lr, 1].Style.Font.Color.SetColor([System.Drawing.Color]::White)
                $lr++
                $lr++

                # Color code legend
                $legendWs.Cells[$lr, 1].Value = 'Alert Level Color Codes (applied to data tabs)'
                $legendWs.Cells[$lr, 1].Style.Font.Bold = $true
                $legendWs.Cells[$lr, 1, $lr, 3].Merge = $true
                $lr++
                $colorCodes = @(
                    @{ Label = 'Critical'; BG = '#FFCCCC'; FG = '#9C0006'; Desc = 'Requires immediate attention. Security risk, broken chain, missing SPN, offline disk, etc.' }
                    @{ Label = 'Warning';  BG = '#FFEB9C'; FG = '#9C6500'; Desc = 'Should be reviewed. Elevated chain depth, stale password, NTLM not ready, etc.' }
                    @{ Label = 'Info / OK'; BG = '#C6EFCE'; FG = '#276221'; Desc = 'Healthy / informational. No action required.' }
                    @{ Label = 'N/A'; BG = '#E0E0E0'; FG = '#404040'; Desc = 'Not applicable for this row (e.g. LDAP check on non-DC, Linux VM in Windows-only audit).' }
                )
                foreach ($cc in $colorCodes) {
                    $legendWs.Cells[$lr, 1].Value = $cc.Label
                    $legendWs.Cells[$lr, 1].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $hex = $cc.BG.TrimStart('#')
                    $legendWs.Cells[$lr, 1].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb([Convert]::ToInt32($hex.Substring(0,2),16), [Convert]::ToInt32($hex.Substring(2,2),16), [Convert]::ToInt32($hex.Substring(4,2),16)))
                    $fghex = $cc.FG.TrimStart('#')
                    $legendWs.Cells[$lr, 1].Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb([Convert]::ToInt32($fghex.Substring(0,2),16), [Convert]::ToInt32($fghex.Substring(2,2),16), [Convert]::ToInt32($fghex.Substring(4,2),16)))
                    $legendWs.Cells[$lr, 2].Value = $cc.Desc
                    $legendWs.Cells[$lr, 2, $lr, 3].Merge = $true
                    $lr++
                }
                $lr++

                # Column definitions by tab -- sorted alphabetically
                $legendWs.Cells[$lr, 1].Value = 'Column Definitions by Tab'
                $legendWs.Cells[$lr, 1].Style.Font.Bold = $true
                $legendWs.Cells[$lr, 1, $lr, 3].Merge = $true
                $lr++

                # Column header row
                $legendWs.Cells[$lr, 1].Value = 'Tab'
                $legendWs.Cells[$lr, 2].Value = 'Column'
                $legendWs.Cells[$lr, 3].Value = 'Description'
                foreach ($c in 1..3) {
                    $legendWs.Cells[$lr, $c].Style.Font.Bold = $true
                    $legendWs.Cells[$lr, $c].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $legendWs.Cells[$lr, $c].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0xD9, 0xE1, 0xF2))
                }
                $lr++

                $sortedTabs = $tabNotes.Keys | Sort-Object
                $altRow = $false
                foreach ($tName in $sortedTabs) {
                    $cols = $tabNotes[$tName]
                    if (-not $cols -or $cols.Count -eq 0) { continue }
                    foreach ($colName in ($cols.Keys | Sort-Object)) {
                        $legendWs.Cells[$lr, 1].Value = $tName
                        $legendWs.Cells[$lr, 2].Value = $colName
                        $legendWs.Cells[$lr, 3].Value = $cols[$colName]
                        if ($altRow) {
                            foreach ($c in 1..3) {
                                $legendWs.Cells[$lr, $c].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                                $legendWs.Cells[$lr, $c].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0xF2, 0xF2, 0xF2))
                            }
                        }
                        $legendWs.Cells[$lr, 3].Style.WrapText = $true
                        $lr++
                        $altRow = -not $altRow
                    }
                }

                # Auto-fit columns 1 and 2; fix column 3 width for readability
                $legendWs.Column(1).Width = 28
                $legendWs.Column(2).Width = 24
                $legendWs.Column(3).Width = 80
                $legendWs.Column(3).Style.WrapText = $true

                # Freeze the header rows
                $legendWs.View.FreezePanes(7, 1)

                $legendColCount = ($tabNotes.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
                Write-HVLog "  OPEN-50: Legend tab built -- $legendColCount column entries across $($tabNotes.Keys.Count) tabs" -Level Info
            }
            catch {
                Write-HVLog "  OPEN-50: Legend tab build failed -- $($_.Exception.Message)" -Level Warning
            }

            # ---- Apply comments to all tabs ----
            $commentCount = 0
            Write-HVLog "  DEBUG: Starting header comments on $($tabNotes.Keys.Count) tabs..." -Level Info
            foreach ($tabName in $tabNotes.Keys) {
                $wsTarget = $pkg.Workbook.Worksheets[$tabName]
                if (-not $wsTarget) { continue }
                try {
                    & $applyHeaderComments $wsTarget $tabNotes[$tabName] $commentAuthor $titledTabs
                    $commentCount++
                }
                catch {
                    Write-HVLog "  DEBUG: Header comment FAILED on tab '$tabName': $($_.Exception.Message)" -Level Warning
                    Write-HVLog "  DEBUG: Error line: $($_.InvocationInfo.ScriptLineNumber) | Stack: $($_.ScriptStackTrace -replace '\r?\n',' | ')" -Level Warning
                }
            }
            # v3.8.9: Also apply comments to chunked tabs (e.g. Applications-Windows_1of2)
            foreach ($ws in $pkg.Workbook.Worksheets) {
                $wsName = $ws.Name
                if ($tabNotes.ContainsKey($wsName)) { continue }  # Already handled above
                if ($wsName -match '^(.+)_\d+of\d+$') {
                    $baseName = $Matches[1]
                    if ($tabNotes.ContainsKey($baseName)) {
                        try {
                            & $applyHeaderComments $ws $tabNotes[$baseName] $commentAuthor $titledTabs
                            $commentCount++
                        }
                        catch {
                            Write-HVLog "  DEBUG: Header comment FAILED on chunked tab '$wsName': $($_.Exception.Message)" -Level Warning
                            Write-HVLog "  DEBUG: Error line: $($_.InvocationInfo.ScriptLineNumber) | Stack: $($_.ScriptStackTrace -replace '\r?\n',' | ')" -Level Warning
                        }
                    }
                }
            }
            Write-HVLog "  Column header comments applied to $commentCount tab(s)" -Level Info

            # OPEN-51: Column header comment coverage audit.
            # Identify workbook tabs that have no matching tabNotes entry so gaps are visible in the log.
            $noNotesCount = 0
            $noNotesList  = [System.Collections.Generic.List[string]]::new()
            foreach ($ws in $pkg.Workbook.Worksheets) {
                $wsName = $ws.Name
                if ($tabNotes.ContainsKey($wsName)) { continue }
                # Chunked tabs: base name check
                if ($wsName -match '^(.+)_\d+of\d+$') {
                    $baseName2 = $Matches[1]
                    if ($tabNotes.ContainsKey($baseName2)) { continue }
                }
                # Structural tabs that intentionally have no column notes
                if ($wsName -in @('00-Executive-Summary', '01-Index', 'Legend')) { continue }
                $noNotesList.Add($wsName)
                $noNotesCount++
            }
            if ($noNotesCount -gt 0) {
                Write-HVLog "  OPEN-51 audit: $noNotesCount tab(s) have no tabNotes entry: $($noNotesList -join ', ')" -Level Warning
            } else {
                Write-HVLog "  OPEN-51 audit: All workbook tabs have tabNotes coverage." -Level Info
            }

            Close-ExcelPackage $pkg
            Write-HVLog "  Tab reorder + Executive Summary complete" -Level Info
        }
        catch {
            Write-HVLog "  Tab reorder/summary error: $($_.Exception.Message)" -Level Warning
            Write-HVLog "  Error location: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -Level Warning
            Write-HVLog "  Stack trace: $($_.ScriptStackTrace -replace '\r?\n',' | ')" -Level Warning
            # v3.10.8: Save whatever was built even if the Exec Summary hit an error.
            # Previously the catch swallowed the error and Close-ExcelPackage never ran,
            # causing the 00-Executive-Summary and 01-Index tabs to be lost entirely.
            try {
                if ($pkg) { Close-ExcelPackage $pkg }
                Write-HVLog "  Package saved despite error -- Exec Summary/Index may be partial" -Level Warning
            }
            catch {
                Write-HVLog "  Failed to save package after error: $($_.Exception.Message)" -Level Error
            }
        }

        Write-HVLog "Excel export complete ($ReportLevel level): $OutputPath" -Level Success

        # v3.10.9 CR100: Tab generation summary -- log which tabs were generated vs skipped
        # This helps troubleshoot runs where expected tabs are missing.
        try {
            $finalPkg = Open-ExcelPackage -Path $OutputPath
            $generatedTabs = @($finalPkg.Workbook.Worksheets | ForEach-Object { $_.Name })
            Close-ExcelPackage $finalPkg -NoSave
            Write-HVLog "  Tabs generated: $($generatedTabs.Count) total" -Level Info

            # Check key optional tabs and log skip reasons
            $optionalTabs = @{
                'S2D-Storage-Audit'    = 'S2D clusters found and accessible'
                'S2D-Config-Summary'   = 'S2D clusters found and accessible'
                'VM-IOPS-Summary'      = 'IOPS Collector data available (IOPSCollectorPath configured and accessible)'
                'VM-IOPS-PerDisk'      = 'IOPS Collector data available'
                'SCCM-Status'          = 'IncludeSCCM = $true in config and SCCM server accessible'
                'TLS-Compliance'       = 'EnableTLSAudit = $true in config'
                'TLS-Recommendations'  = 'EnableTLSAudit = $true and TLS issues found'
                'DNS-Validation'       = 'IncludeDNSValidation = $true in config (Advanced only)'
                'Disk-Format-Config'   = 'IncludeDiskFormatAudit = $true in config'
                'RBAC-Compliance'      = 'RBACBuiltinGroups.Enabled = $true in config'
                'VM-Offline-Disks'     = 'VMs with offline disks detected'
                'Host-NIC-Audit'       = 'Host NIC data collected (requires host access)'
                'LAPS-Usage'           = 'LAPSMode = Audit or Retrieve in config (default: Disabled)'
                'AD-Info'              = 'At least one domain credential configured and AD reachable'
                'SPN-Inventory-Full'   = 'IncludeSPNInventoryFull = $true in config (Advanced mode only)'
                'VHD-Chain'            = 'HyperVInventory-VHDChain.psm1 loaded and Advanced report level'
                'Permissions-Groups'   = 'IncludePermissionAudit = $true in config'
                'Permissions-Privileges' = 'IncludePermissionAudit = $true in config'
                'Permissions-Security' = 'IncludePermissionAudit = $true in config'
                'vIntegration'         = 'Advanced report level and Integration Services data collected'
                'vReplication'         = 'Advanced report level and VMs using Hyper-V Replica'
            }
            $missingOptional = @()
            foreach ($tab in $optionalTabs.Keys) {
                # VM-Activity-Audit chunks as "VM-Activity-Audit_1of4" etc. -- match on prefix
                $isPresent = if ($tab -eq 'VM-Activity-Audit') {
                    $generatedTabs | Where-Object { $_ -eq $tab -or $_ -match "^$([regex]::Escape($tab))_\d+of\d+$" }
                } else {
                    $generatedTabs -contains $tab
                }
                if (-not $isPresent) {
                    $reason = $optionalTabs[$tab]
                    # Add config key context where applicable
                    if ($tab -eq 'VM-Activity-Audit') { $reason = 'IncludeVMActivityAudit = $true in config' }
                    $missingOptional += "    $tab -- requires: $reason"
                }
            }
            if ($missingOptional.Count -gt 0) {
                Write-HVLog "  Optional tabs not generated ($($missingOptional.Count)):" -Level Info
                foreach ($msg in $missingOptional) {
                    Write-HVLog $msg -Level Info
                }
            }
        }
        catch {
            # Non-fatal -- don't let tab summary logging break the report
            Write-Verbose "Tab summary logging failed: $($_.Exception.Message)"
        }
    }
    catch {
        Write-HVLog "Error exporting to Excel: $($_.Exception.Message)" -Level Error
        throw
    }
}

Export-ModuleMember -Function 'Export-HyperVInventoryToExcel'
