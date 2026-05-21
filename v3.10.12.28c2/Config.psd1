<#
    Hyper-V Inventory Report - Configuration
    Version: 3.7.2
    Pre-filled for Overhead Door Corporation environment
    
    Test-SingleServer -Target rictx-dmzweb-p6.overheaddoor.com -CredFile "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml" -TestCredSSP
    Test-SingleServer -Target rictx-dmzweb-p6.overheaddoor.com -CredFile "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml" 
    Test-SingleServer -Target cdc-vmdc.creative.com -CredFile "C:\ProgramData\S\HyperV-Cred-creative.xml"


    Credential setup (one-time):
    Get-Credential -Message " admin"          | Export-Clixml "C:\ProgramData\S\HyperV-Cred.xml"
   
    Get-Credential -Message "admin HV REPORT"      | Export-Clixml "C:\ProgramData\S\HyperV-Cred-1.xml"

    Get-Credential -Message "admin HV REPORT Hosts"      | Export-Clixml "C:\ProgramData\S\HyperV-Cred-2.xml"

    Get-Credential -Message "admin"   | Export-Clixml "C:\ProgramData\S\HyperV-Cred-3.xml"
    
    Get-Credential -Message "admin"       | Export-Clixml "C:\ProgramData\S\HyperV-Cred-4.xml"


    Get-Credential -Message "Local"       | Export-Clixml 'C:\ProgramData\S\HyperV-Cred-LocalAdmin.xml'
            IsPrimary   = $false
#>
@{
    Version = '3.10.12'
    
    Credentials = @(
        @{
            Name        = 'Domain1_Cred'
            Type        = 'Domain'
            DomainFQDN  = 'uuuuuuu.com'
            Description = 'Primary AD domain (hypervisor hosts)'
            StoredPath  = 'C:\ProgramData\S\HyperV-Cred.xml'
            IsPrimary   = $true
        }
        @{
            Name        = 'Domain1_Cred'
            Type        = 'Domain'
            DomainFQDN  = 'wwwwwww.com'
            Description = 'Primary AD domain (hypervisor hosts)'
            StoredPath  = 'C:\ProgramData\S\HyperV-Cred-1.xml'
            IsPrimary   = $false
        }
        @{
            Name        = 'Domain1_Cred'
            Type        = 'Domain'
            DomainFQDN  = 'xxxxxx.com'
            Description = 'Primary AD domain (hypervisor hosts)'
            StoredPath  = 'C:\ProgramData\S\HyperV-Cred-2.xml'
            IsPrimary   = $false
        }
        
        @{
            Name        = 'Domain2_Cred'
            Type        = 'Domain'
            DomainFQDN  = 'yyyyy.com'
            Description = 'Overhead Door corporate domain (VMs)'
            StoredPath  = 'C:\ProgramData\S\HyperV-Cred-3.xml'
            IsPrimary   = $false
        }
        @{
            Name        = 'Domain3_Cred'
            Type        = 'Domain'
            DomainFQDN  = 'zzzzz.com'
            Description = 'Creative domain (decommissioning)'
            StoredPath  = 'C:\ProgramData\S\HyperV-Cred-4.xml'
            IsPrimary   = $false
        }
        @{
            Name        = 'LocalAdmin'
            Type        = 'Local'
            DomainFQDN  = ''
            Description = 'Default local administrator for non-domain VMs'
            StoredPath  = 'C:\ProgramData\S\HyperV-Cred-5.xml'
            IsPrimary   = $false
        }
    )
    
    OutputPath          = '\\script\log\Hyper-V'
    ReportLevel         = 'All'
    IncludeApplications = $true
    UseCredSSP          = $true
    MaxConcurrentJobs   = 10
    
    # VM Name Exclusion Patterns
    # Built-in: VMs starting with _ ... -- or containing (DO NOT DELETE) are always excluded.
    # Patterns below are additional -- use * wildcards.
    ExcludeVMPatterns   = @(
        'Template_*'        # Template VMs
        '*_OLD'             # Decommissioned VMs
        # Add patterns here to hide specific VMs from the report:
        # '(TESTING*'       # Exclude VMs whose names start with "(TESTING"
        # '*(NOT IN USE)*'  # Exclude VMs with (NOT IN USE) in the name
        # '*WAC*'           # Example: exclude WAC management VMs
        # '*GIT*'           # Example: exclude Git server from report
        # '*WEF*'           # Example: exclude Windows Event Forwarding servers
    )
    
    ExcludeHostNames = @('SV-server-001')

    # Missing VM History Dropoff (v3.3.1)
    # VMs absent for longer than this many days are dropped from the Missing-VMs tab
    # and permanently pruned from VM-History.json on the next run.
    # OHDC decom process: VM off 30 days -> deleted from host.
    #   90 days = 30-day hold + 60-day buffer (handles delayed deletions)
    #   0 = keep indefinitely (not recommended - history grows unbounded)
    MissingVMDropoffDays = 90
    
    # VM Guest Storage Tracking (v3.3.1)
    # Minimum hours between recorded snapshots (24 = one per day max).
    GuestStorageHistoryIntervalHours = 23
    # How guest storage deltas are calculated: 'Delta' (change since last run) or 'Snapshot' (point-in-time)
    GuestStorageTrackingMode = 'Delta'
    # Minimum hours between recorded tracking snapshots
    GuestStorageTrackingIntervalHours = 23
    # Include monthly growth columns (Jan_GrowthGB, Feb_GrowthGB, etc.) in VM-Guest-Storage tab.
    GuestStorageMonthlyColumns = $true
    # Collects Manufacturer, Model, SerialNumber, BIOSVersion from each host via WMI.
    # Works for Dell PowerEdge and Cisco UCS (via BIOS SMBIOS data).
    # No additional modules required -- uses Win32_ComputerSystem + Win32_BIOS.
    IncludeHardwareInfo = $true
    
    # --- Dell iDRAC Integration (optional -- enable when OpenManage is available) ---
    # IncludeDellIdrac   = $false
    # DellIdracMethod    = 'REST'    # 'OMSA' or 'REST' (iDRAC 7+ supports REST)
    # DellIdracCredPath  = 'C:\ProgramData\S\HyperV-Cred-iDRAC.xml'
    
    # SCCM Integration
    IncludeSCCM    = $true
    SCCMSiteServer = 'sccm-p01.domain.com'
    SCCMSiteCode   = '100'
    SCCMMethod     = 'WMI'

    # S2D Storage Audit filtering (v3.8.9 - Session 8g)
    # Only audit clusters whose nodes appear in the active Hyper-V host inventory.
    # Set to $false to probe ALL AD cluster objects (original behavior, slower).
    S2DOnlyActiveHVClusters = $true
    # Explicit exclude list: cluster names to NEVER attempt S2D audit on.
    # Use for SQL clusters, stale clusters, non-S2D clusters that waste time probing.
    S2DExcludeClusterNames = @(
        'SCVMMSOFS'          # SCVMM SOFS role -- not a separate S2D cluster
    )

    # AGListenerNames: SQL Always-On AG Listener virtual network names.
    # AG Listeners are virtual DNS names with IP addresses -- their AD computer
    # objects typically have NO SPNs registered on them (SPNs live on the replica
    # server accounts). This means SPN-based AG detection fails for them.
    # List them here so CR110 classifies them correctly as AG-Listener instead
    # of CNO. These names must also appear in S2DExcludeClusterNames above.
    AGListenerNames = @(
        'SQL-ADM'         # AG Listener for admin AG on SQLP03CLST
        'SQL-FGTS'        # AG Listener for FGTS AG on SQLP03CLST
        'SQL-INFOR'       # AG Listener for Infor AG on SQLP03CLST
        'SQL-USER'        # AG Listener for User AG on SQLP03CLST
    )
    
    # Services Collection Filter (v3.4.0)
    # CollectStartModes: only collect Auto-start services (reduces ~10k rows to ~3k).
    # Add 'Manual' if needed. 'Disabled' rarely useful.
    # ExcludeServiceNames: OHDC-specific noise services that are always stopped.
    ServicesFilter = @{
        CollectStartModes   = @('Auto')
        FlagStoppedAuto     = $true
        SystemAccounts      = @(
            'LocalSystem'
            'NT AUTHORITY\LocalService'
            'NT AUTHORITY\NetworkService'
            'NT AUTHORITY\Local Service'
            'NT AUTHORITY\Network Service'
        )
        ExcludeServiceNames = @(
            'edgeupdate'        # Edge auto-update - expected stopped on servers
            'DoSvc'             # Delivery Optimization - expected stopped on servers
            'MapsBroker'        # Windows Maps - not applicable to servers
            'wbengine'          # Windows Backup - stopped when no backup running
        )
        
        # Scheduled Tasks filter (v3.4.1 - S4b)
        IncludeScheduledTasks = $true    # Collect scheduled tasks from all VMs and hosts
        IncludeMicrosoftTasks = $false   # Exclude \Microsoft\ folder (reduces noise significantly)
        IncludeDisabledTasks  = $false   # Enabled/Ready only (set $true to include Disabled tasks)
    }

    # New config key (read in Get-HyperVInventory):
    AuditScope = 'HostsAndVMs'   # HostsOnly | HostsAndVMs | Full

    # Permissions Audit
     IncludePermissionAudit = $true

    # AD-Wide SPN Inventory (v3.10.12 OPEN-66)
    IncludeSPNInventoryFull = $true   # Pull all computer + user SPNs from ohdc.com + overheaddoor.com

    # AD Authentication Audit (v3.5.0 - S5a)
    IncludeADAuthAudit   = $true    # Audit delegation, SPNs, LAPS per machine from AD

    # Internal CA server for WinRM HTTPS certificate requests (v3.5.0 - S5b)
    # Used in the generated remediation script. Set to your issuing CA FQDN.
    CAServer = 'ca-p01.domain.com'

    # When true, generates individual per-machine .ps1 files in a PerMachine\ subfolder
    # alongside the master remediation script. Safe for isolated testing.
    # Set to $true when you want per-machine scripts, $false for master script only.
    SplitRemediationByMachine = $true

    # Roles and Features (v3.5.0 - S5a)
    IncludeRolesFeatures = $true    # Collect Windows features and .NET versions per VM/host

    # VM Resource Metering + IOPS Collection (v3.8.7 - Session 8d)
    # Auto-enables Enable-VMResourceMetering on all VMs during report run.
    # Collects Measure-VM data, per-VHD HardDiskMetrics, host perfmon counters.
    # Set to $false to skip resource metering entirely (saves ~5-10 sec per host).
    EnableResourceMetering = $true

    # Collect host-level Hyper-V Virtual Storage Device perfmon counters (5-second sample).
    # Provides real-time IOPS complement to metering averages. Adds ~5 sec per host.
    CollectIOPSPerfCounters = $true

    # IOPS-per-disk baselines for capacity estimation.
    # Override any value to match your specific hardware specs.
    # Units: IOPS per individual disk (except array-level entries like Nimble/NetApp).
    IOPSBaselines = @{
        SSD            = 75000    # Enterprise SATA/SAS SSD
        NVMe           = 200000   # NVMe SSD
        SAS10K         = 150      # 10K RPM SAS
        SAS15K         = 200      # 15K RPM SAS
        NLSAS          = 80       # 7.2K RPM NL-SAS / SATA
        NimbleAllFlash = 100000   # Nimble all-flash array (per-array)
        NimbleHybrid   = 50000    # Nimble hybrid array (per-array)
        NetApp         = 100000   # NetApp placeholder (per-array)
        Isilon         = 50000    # Dell Isilon/PowerScale placeholder (per-node)
    }

    # IOPS Collector -- standalone Collect-ServerIOPS.ps1 output (v3.8.9.2 Session 8d-2)
    # Set this path to enable IOPS-Trends and IOPS-Heatmap tabs.
    # The collector writes JSON Lines files to: <IOPSCollectorPath>\<hostname>\YYYY-MM.json
    IOPSCollectorPath    = '\\script\log\Hyper-V\IOPS-Collector'
    IOPSCollectorDaysBack = 30    # Number of days of collector history to analyze

    # TLS / Secure Channel Compliance Audit (v3.9.0 - Session 8e)
    # Audits SChannel protocols (SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3), .NET Framework
    # strong crypto, WinHTTP DefaultSecureProtocols, RDP security layer, LDAP channel
    # binding (on DCs), and SMB encryption on every host and Windows VM.
    # Produces TLS-Compliance and TLS-Recommendations tabs plus universal Fix-*.ps1 scripts.
    # Set to $false to skip entirely. Set TLSAuditIncludeVMs to $false for hosts only.
    EnableTLSAudit       = $true
    TLSAuditIncludeVMs   = $true     # Also check Windows VMs via WinRM (adds time per VM)

    # Cipher / Kerberos Encryption-Type Audit (v3.10.12.27 - OPEN-68)
    # Audits the runtime SCHANNEL / TLS cipher state and the AD
    # msDS-SupportedEncryptionTypes value on every host and VM (DCs included).
    # Produces Cipher-Audit, Kerberos-Etypes, Cipher-Interop, Cipher-Diagnostics
    # and Etype-Reference tabs. Diagnoses domain-trust / Netlogon secure-channel
    # / SMB file-share failures caused by Kerberos etype negotiation mismatches.
    EnableCipherAudit    = $true

    # Disk Format / Partition Audit (v3.9.0 - Session 8f)
    # Collects filesystem type (NTFS/ReFS/CSVFS), AllocationUnitSize, PartitionStyle (GPT/MBR),
    # UseLargeFRS (NTFS), and ReFS integrity streams from each host via WinRM.
    # Produces the Disk-Format-Config tab (Advanced level).
    IncludeDiskFormatAudit = $true

    # =========================================================================
    # DNS Record Validation (v3.9.2 - CR57)
    # =========================================================================
    # Validates forward (A) and reverse (PTR) DNS records for all VMs and hosts.
    # Auto-detects DNS source per domain:
    #   ohdc.com         -> EfficientIP (DCs do not host DNS)
    #   overheaddoor.com -> AD-integrated DNS (DCs host DNS)
    #   creative.com     -> AD-integrated DNS (DCs host DNS)
    IncludeDNSValidation = $true

    # VM Activity Audit (v3.10.2 Session 14) -- Advanced report only
    # Queries Hyper-V event logs on each host for VM lifecycle events
    # (shutdowns, power-on/off, snapshots, failovers) with trigger correlation.
    # Adds ~5-15 seconds per host depending on event log size.
    IncludeVMActivityAudit = $true
    VMActivityDaysBack     = 7        # Days of event history to collect (default: 7)

    # v3.10.12.9 CR-VMActivityCrash: VM Activity Audit export options
    # When $true, VM-Activity-Audit is exported to a SEPARATE xlsx file instead
    # of being appended to the main Advanced workbook. This avoids the EPPlus
    # Save() crash that occurs when adding 14K+ rows with long text columns and
    # conditional formatting to an already-large (~50 tab) xlsx. The crash
    # corrupts the entire main workbook (all prior tabs are lost).
    # Output file: HyperV-VMActivity_Advanced_<timestamp>.xlsx (same folder).
    # When $false (default), VM-Activity-Audit writes to the main workbook with
    # a pre-export backup (.vmactivity.bak) so a crash can be recovered.
    VMActivitySeparateFile = $false

    # v3.10.12.9: Maximum rows per VM-Activity-Audit worksheet tab.
    # When the event count exceeds this value, data is split across multiple
    # numbered tabs (e.g. VM-Activity-Audit_1of3, _2of3, _3of3).
    # Lower values = less EPPlus memory pressure during Save().
    # Default: 5000. Range: 1000-10000. Set to 0 to use default.
    VMActivityChunkSize    = 5000

    # v3.10.12.9 Debug: Enable forensic dump of VM-Activity-Audit data to JSON
    # before the Export-Excel call. Writes to _debug\VM-Activity-Audit.json
    # in the report output folder. Useful for offline analysis of crash data.
    # Can also be enabled per-run via: $env:HYPERVREPORT_DEBUG_DUMP = '1'
    DebugDumpFailedTabs    = $true

    # v3.10.4 CR83: VM Offline Disk Detection
    # When enabled, runs Get-Disk inside each reachable VM to detect disks with
    # IsOffline=$true or OperationalStatus != Online. Common after V2V migrations
    # from VMware where SAN policy carries over as OfflineShared.
    # Piggybacks on existing WinRM session -- minimal additional overhead.
    IncludeOfflineDiskCheck = $true

    # EfficientIP SOLIDserver connection for domains where DCs don't host DNS
    EfficientIPServer    = 'IPAM.domain.com'
    EfficientIPCredPath  = 'C:\ProgramData\S\efficientip-cred.xml'
    EfficientIPIgnoreSSL = $true

    # Optional: Override auto-detection per domain
    # Values: 'EfficientIP', 'AD-DNS', or omit for auto-detection
    # DNSSourceOverride = @{
    #     'domain.com'          = 'EfficientIP'
    #     'domain.com'  = 'AD-DNS'
    # }

    # =========================================================================
    # VM Guest Storage Alert Thresholds (v3.8.9.6 - CR53)
    # =========================================================================
    # Controls the Critical/Warning alert levels on the VM-Guest-Storage tab
    # and the Summary tab storage health metrics.
    #
    # GuestStorageCriticalPct - Drives below this % free = Critical alert (default: 5)
    # GuestStorageWarningPct - Drives below this % free = Warning alert (default: 10)
    # GuestStorageBufferPct  - Additional buffer % added to growth projections (default: 10)
    #
    # For large drives (5TB+), percentage thresholds may be too generous.
    # Future: MinimumGB and growth-based calculation modes (v4.x).
    GuestStorageCriticalPct = 5
    GuestStorageWarningPct  = 10
    GuestStorageBufferPct   = 10

    # Host-Storage-Risk thresholds (v3.9.8 CR69)
    # Controls the risk level classification on the Host-Storage-Risk tab.
    # PotentialPercent = (TotalMaxVHDSize / VolumeCapacity) * 100
    # Default: 90% CRITICAL, 75% HIGH, 60% MEDIUM, below 60% LOW
    StorageRiskCriticalPct      = 90
    StorageRiskHighPct          = 75
    StorageRiskMediumPct        = 60
    # Minimum GB floor: if a volume has at least this much free space in GB,
    # downgrade the risk level even if the percentage threshold is exceeded.
    # Example: A 20TB drive at 91% still has 1.8TB free -- with MinimumCriticalGB=500,
    # it downgrades from CRITICAL to MEDIUM because 1800 GB > 500 GB.
    # Set to 0 to disable (pure percentage mode).
    StorageRiskMinimumCriticalGB = 500
    StorageRiskMinimumWarningGB  = 200

    # RBAC Builtin Group Centralization (v3.8.9 - Session 8g)
    # Validates that each server has machine-specific AD security groups in the
    # corresponding local builtin groups. The expected AD group name is computed as:
    #   <ADGroupPrefix><ServerHostName>_<SuffixMap[BuiltinGroupName]>
    # Example: ACL_GRINE-PKLT-T01_A = required in GRINE-PKLT-T01's local Administrators
    #
    # The report checks: AD group exists, AD group is a local builtin member,
    # AD group has members (not empty), computer object exists in AD,
    # and flags cross-domain accounts for manual handling.
    RBACBuiltinGroups = @{
        Enabled        = $true
        ADGroupPrefix  = 'ACL_'
        ADGroupOU      = 'OU=Servers Access,OU=Role,OU=RBAC Structure,DC=domain,DC=com'

        # Builtin group name -> suffix abbreviation (admin-customizable)
        # Formula: <Prefix><HostName>_<Suffix>
        SuffixMap = @{
            'Administrators'                  = 'A'
            'Remote Desktop Users'            = 'RDU'
            'Remote Management Users'         = 'RMU'
            'Hyper-V Administrators'          = 'HVA'
            'Backup Operators'                = 'BO'
            'Event Log Readers'               = 'ELR'
            'Performance Monitor Users'       = 'PMU'
            'Performance Log Users'           = 'PLU'
            'Network Configuration Operators' = 'NCO'
            'Distributed COM Users'           = 'DCU'
            'IIS_IUSRS'                       = 'IIS'
            'Users'                           = 'U'
            'Power Users'                     = 'PU'
            'Print Operators'                 = 'PO'
            'Replicator'                      = 'R'
            'Guests'                          = 'G'
        }
    }

        # =========================================================================
    # LAPS Configuration (v3.10.11 CR102+CR103)
    # =========================================================================

    # Windows LAPS integration -- two-level opt-in
    # 'Disabled' = no LAPS activity (default). Module loaded but inactive.
    # 'Audit'    = Level 1: query LAPS metadata for ALL Windows domain-joined VMs.
    #              Populates LAPS-Usage tab with posture info. No passwords
    #              retrieved or used. Safe to enable broadly.
    # 'Retrieve' = Level 2: Level 1 audit PLUS tier-3 credential fallback for
    #              PSDirect when domain+local creds fail. Retrieves password and
    #              uses it for a single PSDirect attempt. Privileged operation.
    LAPSMode                = 'Retrieve'

    # LAPS backend detection: 'Auto' (detect per-VM), 'ADLAPS' (on-prem AD only),
    # 'EntraLAPS' (Azure AD / Entra only), 'Both' (try both)
    # Auto checks AD first, falls back to Entra if not found.
    LAPSBackend             = 'Auto'

    # For Entra LAPS (Azure AD): requires Microsoft.Graph module + app registration
    # with DeviceLocalCredential.ReadBasic.All (Audit) or
    # DeviceLocalCredential.Read.All (Retrieve).
    # Leave blank if not using Entra LAPS.
    LAPSEntraClientId       = ''
    LAPSEntraTenantId       = ''
    LAPSEntraCertThumbprint = ''

    # LAPS audit age thresholds (days) -- used for AlertLevel on LAPS-Usage tab
    # Warning: password age exceeds this value
    LAPSAgeWarningDays      = 25
    # Critical: password age exceeds this value
    LAPSAgeCriticalDays     = 40

    # Legacy LAPS password rotation interval (days).
    # Used to estimate password age from the expiration timestamp.
    # Match this to your Legacy LAPS GPO "Password Age (Days)" setting.
    LAPSLegacyRotationDays  = 30

    # =========================================================================
    # Backup-Stuck VM Detection (v3.10.11 CR104)
    # =========================================================================

    # Threshold (days) for flagging a backup-origin checkpoint as "stuck".
    # A backup checkpoint older than this is likely a failed/abandoned backup
    # that left a checkpoint behind, causing AVHDX chain growth and I/O storms.
    # Default: 3 days. Set higher if your backup schedule runs weekly.
    BackupCheckpointStaleDays = 3

    # Backup vendor name patterns for checkpoint detection (regex).
    # The report auto-detects Commvault, Veeam, Azure Backup, DPM, Altaro,
    # Nakivo, and Zerto from checkpoint names. Add custom patterns here if
    # your environment uses a vendor not in the default list.
    # Format: @('VendorName1:regex1', 'VendorName2:regex2')
    # Example: @('Rubrik:Rubrik.*Snapshot', 'Cohesity:Cohesity.*Protect')
    BackupVendorPatterns    = @()

    # CR105: VHD chain depth thresholds
    VHDChainWarningDepth        = 3
    VHDChainCriticalDepth       = 5
    VHDChainStaleCheckpointDays = 7

    # CR106: Generate per-VM repair scripts for stuck chains
    EnableRemediationScripts    = $true   # Critical/Warning VHD chains get a .ps1 script


    # ── Nimble Storage Integration (FUTURE - Session 10) ──────────────
    # HPE Nimble SAN health, volume, snapshot, and performance reporting.
    # REQUIRES: PowerShell 7 + HPENimblePowerShellToolkit module.
    # The report will launch a PS7 subprocess to run Nimble collection if enabled.
    # Credential: stored as encrypted XML (Export-Clixml) at the path below.
    #   To create:  Get-Credential | Export-Clixml -Path 'C:\ProgramData\S\nimble-cred.xml'
    # EnableNimble       = $false
    # NimbleArrays       = @(
    #     @{
    #         Name          = 'RICTX-Nimble-01'          # Friendly name for report tabs
    #         ArrayIP       = '10.91.1.174'                 # Management IP of the Nimble array
    #         CredentialPath = 'C:\ProgramData\S\nimble-cred.xml'
    #     }
    # )
    # NimblePS7Path      = 'C:\Program Files\PowerShell\7\pwsh.exe'   # Path to PS7 executable
    
    # Application Compliance (v3.2.9 - Session 3)
    AppCompliance = @{
        # Apps that must be removed from all servers
        AppsToRemove = @(
            'Zscaler'
            'McAfee Profiler'
        )
        
        # Apps required on every server
        AppsRequired = @(
            'Sentinel Agent'
            'Configuration Manager Client'
            'CyberArk Endpoint Privilege Manager Agent'
        )
        
        # Apps required on Server 2022 and earlier (not needed on 2025+)
        AppsRequiredPre2025 = @(
            'Local Administrator Password Solution'
        )
        
        # Known security tools (informational - tracked but not required/removed)
        SecurityTools = @(
            'CyberArk Endpoint Privilege Manager Agent'
            'gytpolClient x64'
        )
    }
    
    # Builtin Security Group Validation (v3.5.0 - domain-aware)
    # Structure: RequiredBuiltinMembers[DomainFQDN][GroupName][Required|Allowed]
    #
    # Domain matching: the VM's AD domain (from DNSHostName suffix or osInfo.Domain) is
    # compared against the keys below. 'Default' is the fallback when no domain matches.
    #
    # Required: must be present -- flag AlertLevel 'Missing' if absent
    # Allowed:  OK if present but not required -- wildcards (* ?) supported
    # Anything else = AlertLevel 'Review' (unexpected -- needs human review)
    #
    # Wildcard examples:
    #   'domain\OHD*'        matches any group starting with OHD in OHDC1 domain
    #   '*\Administrator'   matches any local built-in Administrator account
    RequiredBuiltinMembers = @{

        # -----------------------------------------------------------------------
        # domain.com -- Hyper-V hosts and primary infrastructure VMs
        # get-ADGroup -Identity 'OHD – Network Support Team'
        # -----------------------------------------------------------------------
        'ohdc.com' = @{
            Administrators = @{
                Required = @(
                    'domain\Domain Admins'       # Always required -- standard domain default
                    'domain\OHD – Network Support Team'
                    # - = Minus Key ALT+45   
                    # – = en dash -- or - space - space → – or ALT+0150
                    # — = em dash --- or ALT+0151

                    
                    'domain\OHD – Enterprise Security Team'
                    'domain\swom'                # swom admin account
                )
                Allowed = @(
                    'domain\Enterprise Admins'
                    'domain\ivoicesvc'
                    'AccountAdmin'
                    'domain\ServerAdmin$'        # Primary server admin gMSA (moved from Required v3.8.9.2)
                    'domain\MediaAdmin$'         # Media/IPAM admin gMSA (moved from Required v3.8.9.2)
                    'domain\mgeorge-adm'         # Michael George admin account (moved from Required v3.8.9.2)
                    'domain\OHD*'               # All OHD team groups
                    'domain\OHD - *'            # Explicit OHD team group format
                    '*\Administrator'          # Any local built-in Administrator
                    #'host-*\Administrator'    # BLRKA machine local admins
                    #'domain\*'               # Creative domain (cross-domain during decom)
                    #'domain\*'           # Domain (cross-domain)
                )
            }
            # Uncomment to audit Hyper-V Administrators on hosts:
            # 'Hyper-V Administrators' = @{
            #     Required = @('domain\OHD - System Admin Team')
            #     Allowed  = @('domain\OHD*')
            # }
            # Uncomment to audit Remote Management Users:
            # 'Remote Management Users' = @{
            #     Required = @('domain\OHD - System Admin Team')
            #     Allowed  = @('domain\OHD*')
            # }
        }

        # -----------------------------------------------------------------------
        # domain.com -- Corporate domain VMs (business applications)
        # -----------------------------------------------------------------------
        'domain.com' = @{
            Administrators = @{
                Required = @(
                    'domain\Domain Admins'    # Required on all  corporate VMs
                    #'domain\Domain Admins'            # (cross-domain mgmt)
                    #'domain\ServerAdmin$'             # Server admin gMSA (cross-domain)
                )
                Allowed = @(
                    'domain\*'               # Any domain group/account
                    #'domain\OHD*'                   #  team groups
                    #'domain\Enterprise Admins'
                    '*\Administrator'              # Local built-in Administrator
                )
            }
        }

        # -----------------------------------------------------------------------
        # domain.com -- Decommissioning domain (reduced requirements)
        # Servers in this domain are being wound down -- requirements are minimal.
        # -----------------------------------------------------------------------
        'domain.com' = @{
            Administrators = @{
                Required = @(
                    'domain\Domain Admins'        #  domain admins
                
                )
                Allowed = @(
                    'domain\*'                   # Any  domain account
                    '*\Administrator'              # Local built-in Administrator
                )
            }
        }

        # -----------------------------------------------------------------------
        # Default -- fallback for machines whose domain cannot be determined,
        # or for non-domain-joined machines
        # -----------------------------------------------------------------------
        'Default' = @{
            Administrators = @{
                Required = @(
                    'OHDC1\Domain Admins'           # Minimum expectation on any managed machine
                )
                Allowed = @(
                    'OHDC1\*'
                    '*\Administrator'
                )
            }
        }
    }
    # =========================================================================
    # Keys added to resolve CR112 config drift -- 2026-05-07
    # These keys are defined in Config.psd1 (public template) but were absent
    # from this deployed config. Added with OHDC-appropriate values.
    # =========================================================================

    # RBAC group provisioning -- used by Deploy-RBACSecurityGroups.ps1
    # Prefix and OU for auto-created AD access groups per server
    ADGroupPrefix  = 'ACL_'
    ADGroupOU      = 'OU=Servers Access,OU=Role,OU=RBAC Structure,DC=domain,DC=com'

    # Collection performance -- max parallel host inventory jobs
    # Set to match current Run_Report.ps1 parallelism. Increase with caution
    # (each job is a full PS runspace; 20 is safe on RICTX-SCRIPT-P2 with 16GB RAM)
    MaxHostJobParallelism = 20

    # WinRM timeout per host collection job (seconds)
    # Increase to 600 if slow hosts (SwingGear1, MHOH-SECVID-P1) frequently time out
    CollectionTimeoutSeconds = 7200 # 2 hours idle timeout -- matches IncludeApplications=true behaviour

    # v3.10.12.28 OPEN-70: Per-VM WinRM connect timeout.
    # VMs with names matching *-Clean or *-RESTORE are excluded via ExcludeVMPatterns
    # so they never reach this timeout. This value protects against any other VM that
    # silently drops WinRM packets (firewall DROP, isolated VLAN).
    # Root cause found 2026-05-19: RICTX-DEMAN-P01-Clean, RICTX-DEMAN-T01-Clean,
    # RICTX-SCRIP-P01-RESTORE on RICTX-UCSHV-P7 caused a 11-hour hang because
    # Invoke-Command had no timeout and the firewall was discarding packets silently.
    VMWinRMConnectTimeoutSec  = 120  # 2 minutes; sufficient for any reachable VM

    # Snapshot age thresholds -- used by Compliance-Issues and Exec Summary tabs
    # DefaultMaxSnapshotAgeDays: snapshots older than this are flagged as compliance issues
    # MaxSnapshotWarningAgeDays: snapshots older than this trigger Warning (below Default = Critical)
    DefaultMaxSnapshotAgeDays  = 7
    MaxSnapshotWarningAgeDays  = 3

    # Application compliance is configured in the AppCompliance = @{...} block above (line ~477).
    # AppsRequired, AppsToRemove, AppsRequiredPre2025, SecurityTools are sub-keys of AppCompliance.
    # The code reads $config.AppCompliance.AppsRequired etc. -- NOT top-level keys.
    # Do NOT add top-level AppsRequired/AppsToRemove/SecurityTools keys here.

    # ============================================================
    # ============================================================
    # Timezone Audit (v3.10.12.26 OPEN-NEW)
    # ============================================================
    # When IncludeTimezoneAudit = $true, the report collects:
    #   - TimeZoneId: Windows timezone ID from the guest (e.g. "Eastern Standard Time")
    #   - TimeOffsetSeconds: guest clock offset from its NTP server (w32tm /query /status)
    #   - ExpectedTimezone: derived by matching the VM primary NIC IP against SiteTimezones below
    #   - SiteNameMatch: the SiteName of the matching entry
    #   - TimezoneAlert: OK / Mismatch / Unknown
    # Adds ~1-3 seconds per Windows VM (WinRM required; Linux/offline VMs emit N/A).
    # Columns appear on vInfo tab (all report levels).
    IncludeTimezoneAudit = $true
    TimezoneOffsetWarningSeconds = 300   # flag NTP offset > 5 minutes as Warning

    # SiteTimezones: one entry per site. Array of hashtables, each with:
    #   Subnet   - CIDR notation (e.g. '10.42.36.0/24'). Any prefix length is supported.
    #              Use the most specific block that covers all VLANs at this site.
    #   SiteName - Human-readable label shown in the TimezoneAlert and ExpectedTimezone columns.
    #   Timezone - Windows timezone ID string. Use Get-TimeZone -ListAvailable | Select Id to find values.
    #
    # MATCHING RULE: The VM's primary NIC IP is tested against every entry.
    #   The entry with the LONGEST matching prefix wins (most specific subnet wins).
    #   Add a broad /16 or /8 entry as a catch-all for a region, then override specific
    #   sites with /24 entries -- the /24 will always beat the /16.
    #
    # TO ADD A SITE:       Add a new @{ Subnet='...'; SiteName='...'; Timezone='...' } line.
    # TO REMOVE A SITE:    Delete or comment out the entry (prefix the line with #).
    # TO CHANGE TIMEZONE:  Edit the Timezone value.
    # TO RENAME A SITE:    Edit the SiteName value (affects report display only).
    #
    # Valid Windows timezone IDs (all OHDC sites):
    #   'Eastern Standard Time'          US/Canada Eastern  (UTC-5 / UTC-4 DST)
    #   'Central Standard Time'          US/Canada Central  (UTC-6 / UTC-5 DST)
    #   'Mountain Standard Time'         US/Canada Mountain (UTC-7 / UTC-6 DST)
    #   'US Mountain Standard Time'      Arizona            (UTC-7, no DST)
    #   'Pacific Standard Time'          US/Canada Pacific  (UTC-8 / UTC-7 DST)
    #   'Canada Central Standard Time'   Saskatchewan       (UTC-6, no DST)
    #   'India Standard Time'            India              (UTC+5:30)
    #
    SiteTimezones = @(
        # ---- Eastern ------------------------------------------------
        @{ Subnet = '10.42.2.0/24';   SiteName = ' KY';   Timezone = 'Eastern Standard Time' }
        

        # ---- Central ------------------------------------------------
        @{ Subnet = '10.42.0.0/24';   SiteName = ' TX';                   Timezone = 'Central Standard Time' }
        

        # ---- Mountain -----------------------------------------------
        @{ Subnet = '10.42.7.0/24';   SiteName = ' AB Canada';           Timezone = 'Mountain Standard Time' }
        

        # ---- Pacific ------------------------------------------------
        @{ Subnet = '10.42.8.0/24';   SiteName = ' BC Canada';             Timezone = 'Pacific Standard Time' }
        

        # ---- Canada (no DST) ----------------------------------------
        @{ Subnet = '10.42.12.0/24';  SiteName = ' SK Canada';            Timezone = 'Canada Central Standard Time' }
        

        # ---- International ------------------------------------------
        @{ Subnet = '10.201.10.0/24'; SiteName = ' India';             Timezone = 'India Standard Time' }

        # ---- Datacenter Infrastructure ---
        # OPEN-69: The code now uses guest WinRM IPs (OSInfo.GuestNetwork) as a fallback
        # when Hyper-V IC doesn't report IPs -- so datacenter VM IPs WILL be matched against
        # entries here on the next run. Add the actual datacenter management subnets below.
        #
        # To find which subnets to add: after the next run, check the log for:
        #   "OPEN-69: N VMs had no matching SiteTimezones entry"
        # then open the Advanced workbook > vInfo tab, filter TimezoneAlert = "Unknown (no subnet match)"
        # and note the IPv4Addresses column values. Add a /24 entry for each unique prefix.
        #
        # Common datacenter subnet patterns to verify:
        # @{ Subnet = '10.91.0.0/16';   SiteName = ' Datacenter (verify range)'; Timezone = 'Central Standard Time' }
        # @{ Subnet = '10.92.0.0/16';   SiteName = ' Datacenter (verify range)';  Timezone = 'Eastern Standard Time' }

        # ---- Catch-alls (lowest priority -- /16 loses to any /24 above) ---
        # These fire only when no more-specific entry matches.
        @{ Subnet = '10.42.0.0/16';   SiteName = 'Site-Indexed Range (unmatched)'; Timezone = 'Central Standard Time' }
    )

}
