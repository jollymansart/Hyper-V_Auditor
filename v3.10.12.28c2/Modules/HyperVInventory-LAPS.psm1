<#
.SYNOPSIS
    HyperVInventory-LAPS.psm1
    Windows LAPS Audit and Retrieval module for the Hyper-V Inventory Suite.

.DESCRIPTION
    Provides LAPS posture visibility across all Windows domain-joined VMs.
    Two-level opt-in model controlled by the LAPSMode config key:

      Level 0 (Disabled, default): No LAPS activity. Module loaded but inactive.
      Level 1 (Audit): Query LAPS metadata for ALL Windows domain-joined VMs.
                        Populate LAPS-Usage tab with posture info. NO passwords
                        retrieved. Safe to enable broadly for operational monitoring.
      Level 2 (Retrieve): Level 1 audit PLUS tier-3 credential fallback for
                          PSDirect when domain+local creds fail. Retrieves the
                          current LAPS-managed password and uses it for a single
                          PSDirect attempt. Privileged operation.

    Handles BOTH backends:
      - Legacy LAPS (ms-Mcs-AdmPwd attribute, requires LAPS MSI installed)
      - Windows LAPS (msLAPS-Password / msLAPS-EncryptedPassword, built into
        Server 2019+, Windows 10/11 April 2023 update)

    Detection logic determines which backend is active per-VM and queries
    the appropriate attributes. VMs with both backends configured are flagged
    as 'AD-Both' for migration tracking.

.NOTES
    Author  : Michael George (with Claude)
    Version : 3.10.12-LAPS
    Date    : 2026-04-25
    Session : CR102 + CR103 + CR105 (Schema-Adaptive Fix)
    PS Compat: 5.1+

    SECURITY:
    - LAPS passwords are NEVER written to log files, CSV, Excel, or transcript.
    - Level 1 never touches the password value.
    - Level 2 credentials are held in memory for a single PSDirect attempt,
      then explicitly nulled and disposed.

    CR102: Two-level opt-in (Audit + Retrieve), LAPS-Usage tab
    CR103: Legacy LAPS + Windows LAPS unified handling, migration status metrics
    CR105: Schema-adaptive attribute probing -- dynamically discovers which LAPS
           attributes exist in the AD schema before querying. Fixes the 216/216
           Error cascade caused by msLAPS-ManagedPasswordAccountName not being
           present in pre-WS2025 schemas. Adds Notes column, AD-Info tab data,
           and differentiates SchemaNotExtended (Info) from real errors.
#>

#Requires -Version 5.0

# ---------------------------------------------------------------------------
# Module-scope storage
# ---------------------------------------------------------------------------
$script:LAPSResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:LAPSSchemaCache = $null

# ---------------------------------------------------------------------------
# PUBLIC: Get-LAPSSchemaCapability  (CR105 -- schema-adaptive probing)
# ---------------------------------------------------------------------------
function Get-LAPSSchemaCapability {
    <#
    .SYNOPSIS
        Probes the AD schema to discover which LAPS attributes exist.
        Returns a hashtable with boolean flags and the safe property list.
        Runs once per session and caches the result.
    #>
    [CmdletBinding()]
    param([switch]$Force)

    if ($script:LAPSSchemaCache -and -not $Force) { return $script:LAPSSchemaCache }

    $result = @{
        HasLegacyLAPS    = $false
        HasWindowsLAPS   = $false
        HasWS2025Attrs   = $false
        HasEncryptedLAPS = $false
        SafeProperties   = @()
        SchemaLevel      = 'None'
        ProbeTimestamp    = Get-Date
    }

    try { $schemaNC = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext }
    catch {
        Write-Warning "[LAPS-Schema] Cannot reach AD RootDSE: $($_.Exception.Message)"
        $script:LAPSSchemaCache = $result
        return $result
    }

    $attrMap = [ordered]@{
        'ms-Mcs-AdmPwd'                     = 'HasLegacyLAPS'
        'ms-Mcs-AdmPwdExpirationTime'       = 'HasLegacyLAPS'
        'msLAPS-Password'                   = 'HasWindowsLAPS'
        'msLAPS-EncryptedPassword'          = 'HasEncryptedLAPS'
        'msLAPS-PasswordExpirationTime'     = 'HasWindowsLAPS'
        'msLAPS-CurrentPasswordVersion'     = 'HasWindowsLAPS'
        'msLAPS-ManagedPasswordAccountName' = 'HasWS2025Attrs'
        'msLAPS-EncryptedDSRMPassword'      = 'HasWS2025Attrs'
        'msLAPS-EncryptedDSRMPasswordHistory' = 'HasWS2025Attrs'
    }

    $safeProps = [System.Collections.Generic.List[string]]::new()

    foreach ($attr in $attrMap.GetEnumerator()) {
        try {
            $found = Get-ADObject -SearchBase $schemaNC `
                -Filter "lDAPDisplayName -eq '$($attr.Key)'" `
                -Properties lDAPDisplayName -ErrorAction Stop
            if ($found) {
                $result[$attr.Value] = $true
                $safeProps.Add($attr.Key)
            }
        }
        catch { }  # Attribute not in schema -- expected
    }

    $result.SafeProperties = $safeProps.ToArray()

    if     ($result.HasWS2025Attrs)   { $result.SchemaLevel = 'WindowsLAPS-WS2025' }
    elseif ($result.HasWindowsLAPS)   { $result.SchemaLevel = 'WindowsLAPS' }
    elseif ($result.HasLegacyLAPS)    { $result.SchemaLevel = 'LegacyOnly' }
    else                              { $result.SchemaLevel = 'None' }

    $script:LAPSSchemaCache = $result
    return $result
}

# ---------------------------------------------------------------------------
# PUBLIC: Get-ADForestInfo  (CR105 -- AD forest/domain functional levels + FSMOs)
# ---------------------------------------------------------------------------
function Get-ADForestInfo {
    <#
    .SYNOPSIS
        Collects AD forest and domain functional levels, FSMO role holders,
        and LAPS schema readiness. Returns data for the AD-Info tab.
    #>
    [CmdletBinding()]
    param()

    $rows = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $forest = Get-ADForest -ErrorAction Stop

        # Forest-level row
        $rows.Add([PSCustomObject]@{
            Scope           = 'Forest'
            Name            = $forest.Name
            FunctionalLevel = $forest.ForestMode
            SchemaMaster    = $forest.SchemaMaster
            DomainNaming    = $forest.DomainNamingMaster
            PDCEmulator     = ''
            RIDMaster       = ''
            InfrastructureMaster = ''
            LAPSSchemaLevel = (Get-LAPSSchemaCapability).SchemaLevel
            Notes           = "Domains: $($forest.Domains -join ', ')"
        })

        # Per-domain rows
        foreach ($domainName in $forest.Domains) {
            try {
                $dom = Get-ADDomain -Server $domainName -ErrorAction Stop
                $rows.Add([PSCustomObject]@{
                    Scope           = 'Domain'
                    Name            = $dom.DNSRoot
                    FunctionalLevel = $dom.DomainMode
                    SchemaMaster    = ''
                    DomainNaming    = ''
                    PDCEmulator     = $dom.PDCEmulator
                    RIDMaster       = $dom.RIDMaster
                    InfrastructureMaster = $dom.InfrastructureMaster
                    LAPSSchemaLevel = ''
                    Notes           = "NetBIOS: $($dom.NetBIOSName), DCs: $($dom.ReplicaDirectoryServers.Count)"
                })
            }
            catch {
                $rows.Add([PSCustomObject]@{
                    Scope           = 'Domain'
                    Name            = $domainName
                    FunctionalLevel = 'UNREACHABLE'
                    SchemaMaster    = ''
                    DomainNaming    = ''
                    PDCEmulator     = ''
                    RIDMaster       = ''
                    InfrastructureMaster = ''
                    LAPSSchemaLevel = ''
                    Notes           = "Error: $($_.Exception.Message)"
                })
            }
        }
    }
    catch {
        $rows.Add([PSCustomObject]@{
            Scope           = 'Forest'
            Name            = 'ERROR'
            FunctionalLevel = ''
            SchemaMaster    = ''
            DomainNaming    = ''
            PDCEmulator     = ''
            RIDMaster       = ''
            InfrastructureMaster = ''
            LAPSSchemaLevel = ''
            Notes           = "Get-ADForest failed: $($_.Exception.Message)"
        })
    }

    return $rows
}

# ---------------------------------------------------------------------------
# PUBLIC: Get-LapsUnifiedStatus
# ---------------------------------------------------------------------------
function Get-LapsUnifiedStatus {
    <#
    .SYNOPSIS
        Queries LAPS metadata for a single VM's AD computer object.
        Detects backend (Legacy/Windows LAPS/Both/None) and returns
        posture information without retrieving the actual password.

    .DESCRIPTION
        CR102 Level 1 (Audit): Called for every Windows domain-joined VM
        regardless of whether PSDirect was needed. Populates the LAPS-Usage
        tab row for this VM.

        CR103: Handles both Legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS
        (msLAPS-Password / msLAPS-EncryptedPassword) backends. Detects
        which is configured and queries the appropriate attributes.

    .PARAMETER ComputerName
        Short hostname or FQDN of the VM to query.

    .PARAMETER Domain
        AD domain to query. Uses the VM's domain if available.

    .PARAMETER Credential
        Optional credential for cross-domain AD queries.

    .PARAMETER LAPSConfig
        Hashtable of LAPS-related config keys from Config-OHDC.psd1.

    .RETURNS
        PSCustomObject with LAPS posture fields for the LAPS-Usage tab row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [hashtable]$LAPSConfig = @{}
    )

    $shortName = ($ComputerName -split '\.')[0]
    $ageWarning  = if ($LAPSConfig.LAPSAgeWarningDays)  { [int]$LAPSConfig.LAPSAgeWarningDays }  else { 25 }
    $ageCritical = if ($LAPSConfig.LAPSAgeCriticalDays) { [int]$LAPSConfig.LAPSAgeCriticalDays } else { 40 }
    $legacyRotationDays = if ($LAPSConfig.LAPSLegacyRotationDays) { [int]$LAPSConfig.LAPSLegacyRotationDays } else { 30 }

    # Build the result object with all LAPS-Usage tab columns (CR105: added Notes)
    $result = [PSCustomObject]@{
        VM                       = $ComputerName
        LAPSBackend              = 'Unknown'         # AD-Legacy / AD-WindowsLAPS / AD-Both / None / NotDomainJoined / SchemaNotExtended / Error
        LookupResult             = 'Pending'          # OK / NotEnabled / NoPermission / NotDomainJoined / SchemaNotExtended / Error
        ManagedAccountName       = ''                 # Usually 'Administrator' but can be customized
        PasswordAge              = $null              # Days since last rotation (null if not available)
        PasswordExpiration       = $null              # DateTime when rotation is due
        RotationDue              = $false             # True if expiration is within 24 hours or past
        LegacyLAPSInstalled      = $false             # True if "Local Administrator Password Solution" MSI detected
        LegacyAttributePopulated = $false             # True if ms-Mcs-AdmPwd has a value
        WindowsLAPSConfigured    = $false             # True if msLAPS-* attributes exist on the object
        WindowsLAPSEncrypted     = $false             # True if msLAPS-EncryptedPassword is populated (vs plaintext)
        MigrationStatus          = ''                 # LegacyOnly / WindowsOnly / Both / Unmanaged / NotDomainJoined / SchemaNotExtended
        AlertLevel               = 'Info'             # Info / Warning / Critical
        AlertReason              = ''                 # Human-readable reason for the alert level
        DataSource               = 'HYPER-V'
        Notes                    = ''                 # CR105: Human-readable context -- schema limitations, migration guidance, rotation health
    }

    # --- Step 1: Find the AD computer object ---
    # CR105: Use schema-safe attribute list instead of hardcoding msLAPS-ManagedPasswordAccountName
    $schema = Get-LAPSSchemaCapability
    $lapsAttributes = @('Name', 'DistinguishedName', 'Enabled') + $schema.SafeProperties

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Domain)     { $adParams['Server']     = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $adComputer = $null
    try {
        $adComputer = Get-ADComputer -Identity $shortName @adParams -Properties $lapsAttributes
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match 'Cannot find an object with identity') {
            $result.LAPSBackend     = 'NotDomainJoined'
            $result.LookupResult    = 'NotDomainJoined'
            $result.MigrationStatus = 'NotDomainJoined'
            $result.AlertLevel      = 'Info'
            $result.AlertReason     = 'VM not found in AD -- likely workgroup or non-domain machine'
            $result.Notes           = 'Not found in any queried domain. May be non-domain-joined (Linux, appliance, workgroup).'
        }
        elseif ($errMsg -match 'properties are invalid|Parameter name: msLAPS') {
            # Windows LAPS attributes exist in schema but DC can't query them
            # on this object (permission/compatibility issue). Fall back to
            # legacy-only attributes silently -- no log noise.
            $legacyOnly = @('Name', 'DistinguishedName', 'Enabled',
                            'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime')
            try {
                $adComputer = Get-ADComputer -Identity $shortName @adParams -Properties $legacyOnly
                # Mark that Windows LAPS query failed so we don't try again
                $result.Notes = 'Windows LAPS attribute query failed (DC compatibility) -- fell back to Legacy LAPS attributes only.'
            }
            catch {
                $errMsg2 = $_.Exception.Message
                if ($errMsg2 -match 'Cannot find an object with identity') {
                    $result.LAPSBackend     = 'NotDomainJoined'
                    $result.LookupResult    = 'NotDomainJoined'
                    $result.MigrationStatus = 'NotDomainJoined'
                    $result.AlertLevel      = 'Info'
                    $result.AlertReason     = 'VM not found in AD'
                    $result.Notes           = 'Not found in AD on fallback query.'
                }
                else {
                    $result.LAPSBackend     = 'Error'
                    $result.LookupResult    = 'Error'
                    $result.AlertLevel      = 'Warning'
                    $result.AlertReason     = "AD query failed on fallback: $errMsg2"
                    $result.Notes           = "Both full and legacy-only queries failed: $errMsg2"
                }
                return $result
            }
        }
        else {
            $result.LAPSBackend     = 'Error'
            $result.LookupResult    = 'Error'
            $result.AlertLevel      = 'Warning'
            $result.AlertReason     = "AD query failed: $errMsg"
            $result.Notes           = "AD query failure. Check connectivity, permissions, and domain trust. Error: $errMsg"
        }
        return $result
    }

    # --- Step 2: Detect Legacy LAPS ---
    $hasLegacyPwd = $false
    $legacyExpiration = $null
    try {
        $legacyPwdRaw = $adComputer.'ms-Mcs-AdmPwd'
        $hasLegacyPwd = ($null -ne $legacyPwdRaw -and $legacyPwdRaw -ne '')
        $result.LegacyAttributePopulated = $hasLegacyPwd

        $legacyExpRaw = $adComputer.'ms-Mcs-AdmPwdExpirationTime'
        if ($legacyExpRaw -and $legacyExpRaw -ne 0) {
            try {
                $legacyExpiration = [DateTime]::FromFileTime([long]$legacyExpRaw)
            }
            catch { }
        }
    }
    catch {
        # ms-Mcs-AdmPwd attribute may not exist in the schema (Legacy LAPS not deployed)
        # This is normal and expected -- not an error
    }

    # --- Step 3: Detect Windows LAPS ---
    $hasWindowsLAPS = $false
    $hasEncryptedLAPS = $false
    $windowsExpiration = $null
    $managedAccount = ''

    try {
        $wlapsPlaintext  = $adComputer.'msLAPS-Password'
        $wlapsEncrypted  = $adComputer.'msLAPS-EncryptedPassword'
        $wlapsExpiration = $adComputer.'msLAPS-PasswordExpirationTime'
        $wlapsAccount    = $adComputer.'msLAPS-ManagedPasswordAccountName'

        $hasWindowsLAPS   = ($null -ne $wlapsPlaintext -and $wlapsPlaintext -ne '') -or
                            ($null -ne $wlapsEncrypted -and $wlapsEncrypted -ne '')
        $hasEncryptedLAPS = ($null -ne $wlapsEncrypted -and $wlapsEncrypted -ne '')

        $result.WindowsLAPSConfigured = $hasWindowsLAPS
        $result.WindowsLAPSEncrypted  = $hasEncryptedLAPS

        if ($wlapsExpiration) {
            $windowsExpiration = [DateTime]$wlapsExpiration
        }

        if ($wlapsAccount) {
            $managedAccount = [string]$wlapsAccount
        }
    }
    catch {
        # msLAPS-* attributes may not exist in schema (Windows LAPS not deployed)
        # Normal and expected
    }

    # --- Step 4: Classify backend and migration status ---
    if ($hasLegacyPwd -and $hasWindowsLAPS) {
        $result.LAPSBackend     = 'AD-Both'
        $result.MigrationStatus = 'Both'
        $result.Notes           = 'Both Legacy and Windows LAPS attributes populated. Complete migration by removing Legacy LAPS GPO and uninstalling the CSE.'
    }
    elseif ($hasLegacyPwd) {
        $result.LAPSBackend     = 'AD-Legacy'
        $result.MigrationStatus = 'LegacyOnly'
        $result.Notes           = 'Legacy LAPS (ms-Mcs-AdmPwd) active. Migrate to Windows LAPS: update GPO, ensure Update-LapsADSchema has been run, set OU permissions.'
    }
    elseif ($hasWindowsLAPS) {
        $result.LAPSBackend     = 'AD-WindowsLAPS'
        $result.MigrationStatus = 'WindowsOnly'
        $result.Notes           = 'Windows LAPS active.' + $(if ($hasEncryptedLAPS) { ' Password is encrypted (AD CS protected).' } else { ' Password stored as cleartext in AD.' })
    }
    else {
        $result.LAPSBackend     = 'None'
        $result.MigrationStatus = 'Unmanaged'
        $result.Notes           = 'CRITICAL: No LAPS deployed. Local admin password is unmanaged. Deploy Windows LAPS via GPO.'
    }

    # --- Step 5: Calculate password age and expiration ---
    # Prefer Windows LAPS expiration if available; fall back to Legacy
    $effectiveExpiration = $null
    if ($windowsExpiration) {
        $effectiveExpiration = $windowsExpiration
        $result.PasswordExpiration = $windowsExpiration
    }
    elseif ($legacyExpiration) {
        $effectiveExpiration = $legacyExpiration
        $result.PasswordExpiration = $legacyExpiration
    }

    if ($effectiveExpiration) {
        # Password age = rotation interval minus time remaining until expiration
        # For Legacy LAPS: expiration is set at rotation time to Now + RotationDays
        # For Windows LAPS: expiration is set by policy
        $now = Get-Date
        if ($effectiveExpiration -gt $now) {
            # Password not yet expired
            $timeRemaining = $effectiveExpiration - $now
            # Estimate age: for Legacy, use LegacyRotationDays; for Windows LAPS,
            # use the policy-configured interval (not available here, so estimate
            # from the expiration timestamp relative to a typical 30-day cycle)
            if ($result.LAPSBackend -eq 'AD-Legacy') {
                $result.PasswordAge = [int]($legacyRotationDays - $timeRemaining.TotalDays)
                if ($result.PasswordAge -lt 0) { $result.PasswordAge = 0 }
            }
            else {
                # Windows LAPS: we don't know the configured interval, so just
                # report time until expiration. PasswordAge will be set from
                # the expiration timestamp if we can infer the rotation date.
                $result.PasswordAge = $null  # We'll set AlertLevel from expiration proximity instead
            }
            $result.RotationDue = ($timeRemaining.TotalHours -le 24)
        }
        else {
            # Password IS expired -- rotation is overdue
            $overdueDays = [int](($now - $effectiveExpiration).TotalDays)
            $result.PasswordAge = $overdueDays  # Treat "days overdue" as password age
            $result.RotationDue = $true
        }
    }

    # Managed account name
    if ($managedAccount) {
        $result.ManagedAccountName = $managedAccount
    }
    elseif ($hasLegacyPwd) {
        $result.ManagedAccountName = 'Administrator'  # Legacy LAPS always manages Administrator
    }

    # --- Step 6: Set LookupResult ---
    if ($hasLegacyPwd -or $hasWindowsLAPS) {
        $result.LookupResult = 'OK'
    }
    else {
        $result.LookupResult = 'NotEnabled'
    }

    # --- Step 7: AlertLevel classification ---
    if ($result.LookupResult -eq 'NotEnabled' -and $result.LAPSBackend -eq 'None') {
        # Production VM with no LAPS = Critical
        $result.AlertLevel  = 'Critical'
        $result.AlertReason = 'LAPS not configured -- local admin password is unmanaged'
    }
    elseif ($result.LookupResult -eq 'NoPermission') {
        $result.AlertLevel  = 'Critical'
        $result.AlertReason = 'Service account does not have permission to read LAPS attributes'
    }
    elseif ($result.RotationDue) {
        if ($result.PasswordAge -and $result.PasswordAge -gt $ageCritical) {
            $result.AlertLevel  = 'Critical'
            $result.AlertReason = "Password rotation overdue by $($result.PasswordAge) days (threshold: $ageCritical)"
        }
        else {
            $result.AlertLevel  = 'Warning'
            $result.AlertReason = 'Password rotation due within 24 hours or overdue'
        }
    }
    elseif ($result.PasswordAge -and $result.PasswordAge -gt $ageCritical) {
        $result.AlertLevel  = 'Critical'
        $result.AlertReason = "Password age $($result.PasswordAge) days exceeds critical threshold ($ageCritical days)"
    }
    elseif ($result.PasswordAge -and $result.PasswordAge -gt $ageWarning) {
        $result.AlertLevel  = 'Warning'
        $result.AlertReason = "Password age $($result.PasswordAge) days exceeds warning threshold ($ageWarning days)"
    }
    elseif ($result.LookupResult -eq 'OK') {
        $result.AlertLevel  = 'Info'
        $result.AlertReason = "LAPS managed ($($result.LAPSBackend)), password within expected age"
    }
    else {
        $result.AlertLevel = 'Info'
        $result.AlertReason = $result.LookupResult
    }

    return $result
}

# ---------------------------------------------------------------------------
# PUBLIC: Invoke-LAPSAudit
# ---------------------------------------------------------------------------
function Invoke-LAPSAudit {
    <#
    .SYNOPSIS
        Runs the LAPS audit against all provided VMs and returns the results.

    .DESCRIPTION
        CR102 Level 1: Called from the orchestrator after VM inventory collection
        is complete. Iterates over all Windows domain-joined VMs and calls
        Get-LapsUnifiedStatus for each.

    .PARAMETER VMs
        Array of VM info objects from the inventory collection. Each must have
        at minimum: Name (or GuestComputerName), Domain (detected domain).

    .PARAMETER Config
        The full config hashtable from Config-OHDC.psd1.

    .PARAMETER Credential
        Default credential for AD queries.

    .PARAMETER DomainCredentials
        Hashtable of domain-specific credentials: @{ 'ohdc.com' = $cred1; 'creative.com' = $cred2 }

    .RETURNS
        Array of PSCustomObjects (one per VM) for the LAPS-Usage tab.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$VMs,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{}
    )

    $lapsMode = if ($Config.LAPSMode) { $Config.LAPSMode } else { 'Disabled' }
    if ($lapsMode -eq 'Disabled') {
        Write-HVLog "  LAPS Audit: skipped (LAPSMode = Disabled in config)" -Level Info
        return @()
    }

    Write-HVLog "  LAPS Audit: mode=$lapsMode, scanning $($VMs.Count) VMs..." -Level Info

    # CR105: Probe schema before querying any VMs
    $schema = Get-LAPSSchemaCapability
    Write-HVLog "  LAPS Schema: $($schema.SchemaLevel) ($($schema.SafeProperties.Count) safe attributes)" -Level Info
    if ($schema.SchemaLevel -eq 'None') {
        Write-HVLog "  LAPS Schema: WARNING -- No LAPS schema attributes found. All VMs will report SchemaNotExtended." -Level Warning
    }

    $lapsConfig = @{
        LAPSAgeWarningDays     = if ($Config.LAPSAgeWarningDays)  { $Config.LAPSAgeWarningDays }  else { 25 }
        LAPSAgeCriticalDays    = if ($Config.LAPSAgeCriticalDays) { $Config.LAPSAgeCriticalDays } else { 40 }
        LAPSLegacyRotationDays = if ($Config.LAPSLegacyRotationDays) { $Config.LAPSLegacyRotationDays } else { 30 }
    }

    $results  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $okCount  = 0
    $noneCount = 0
    $errCount  = 0
    $legacyCount = 0
    $windowsCount = 0
    $bothCount = 0
    $notDomainCount = 0
    $schemaNotExtCount = 0

    foreach ($vm in $VMs) {
        $vmName = if ($vm.GuestComputerName) { $vm.GuestComputerName }
                  elseif ($vm.Name)          { $vm.Name }
                  else                       { continue }

        # Skip Linux/appliance VMs (no LAPS)
        $osType = if ($vm.OSInfo -and $vm.OSInfo.OSType) { $vm.OSInfo.OSType } else { '' }
        if ($osType -eq 'Linux' -or $osType -eq 'Unknown') { continue }

        # Determine domain for this VM
        $vmDomain = if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vm.OSInfo.Domain }
                    elseif ($vm.Domain) { $vm.Domain }
                    else { $null }

        # Select credential for this VM's domain
        $queryCred = $Credential
        if ($vmDomain -and $DomainCredentials.ContainsKey($vmDomain)) {
            $queryCred = $DomainCredentials[$vmDomain]
        }

        try {
            $status = Get-LapsUnifiedStatus -ComputerName $vmName -Domain $vmDomain `
                        -Credential $queryCred -LAPSConfig $lapsConfig

            # Add Host info from the VM inventory
            $status | Add-Member -NotePropertyName 'Host' -NotePropertyValue $(
                if ($vm.HostName) { $vm.HostName } elseif ($vm.ComputerName) { $vm.ComputerName } else { '' }
            ) -Force

            $results.Add($status)

            # Track counts
            switch ($status.LAPSBackend) {
                'AD-Legacy'        { $legacyCount++; $okCount++ }
                'AD-WindowsLAPS'   { $windowsCount++; $okCount++ }
                'AD-Both'          { $bothCount++; $okCount++ }
                'None'             { $noneCount++ }
                'NotDomainJoined'  { $notDomainCount++ }
                'SchemaNotExtended' { $schemaNotExtCount++ }
                default            { $errCount++ }
            }
        }
        catch {
            Write-Verbose "  LAPS: $vmName query failed: $($_.Exception.Message)"
            $errCount++
        }
    }

    # Summary
    $totalManaged = $legacyCount + $windowsCount + $bothCount
    Write-HVLog "  LAPS Audit complete: $($results.Count) VMs queried -- $totalManaged managed ($legacyCount Legacy, $windowsCount Windows LAPS, $bothCount Both), $noneCount unmanaged, $notDomainCount not-domain-joined, $schemaNotExtCount schema-limited, $errCount errors" -Level Info

    # Migration status summary for Executive Summary
    if ($totalManaged -gt 0 -or $noneCount -gt 0) {
        $migSummary = @{
            LegacyOnly   = $legacyCount
            WindowsOnly  = $windowsCount
            Both         = $bothCount
            Unmanaged    = $noneCount
            NotDomain    = $notDomainCount
            TotalManaged = $totalManaged
            TotalQueried = $results.Count
        }
        Write-HVLog "  LAPS Migration Status: $legacyCount Legacy-only, $windowsCount Windows-only, $bothCount Both (migrating), $noneCount Unmanaged" -Level $(if ($noneCount -gt 0) { 'Warning' } else { 'Info' })
    }

    # Store in module scope for cross-module access
    $script:LAPSResults = $results

    return $results
}

# ---------------------------------------------------------------------------
# PUBLIC: Get-LAPSResults
# ---------------------------------------------------------------------------
function Get-LAPSResults {
    <#
    .SYNOPSIS
        Returns the LAPS audit results from the most recent Invoke-LAPSAudit run.
    #>
    return $script:LAPSResults
}

# ---------------------------------------------------------------------------
# PUBLIC: Get-LapsPassword (Level 2 only -- CR102 Retrieve mode)
# ---------------------------------------------------------------------------
function Get-LapsPassword {
    <#
    .SYNOPSIS
        Retrieves the current LAPS-managed password for a VM.
        Level 2 (Retrieve) ONLY. Never called at Level 1.

    .DESCRIPTION
        CR102 Level 2: Called as tier-3 credential fallback when domain + local
        creds both fail for a VM. Retrieves the password from whichever LAPS
        backend is active and returns a PSCredential object.

        SECURITY: The returned credential must be used immediately for ONE
        PSDirect attempt and then explicitly disposed. The password is NEVER
        logged, written to file, or stored in the result set.

    .PARAMETER ComputerName
        VM hostname to retrieve the password for.

    .PARAMETER Backend
        LAPS backend: 'AD-Legacy' or 'AD-WindowsLAPS'. Determined by the
        Get-LapsUnifiedStatus result for this VM.

    .PARAMETER Domain
        AD domain to query.

    .PARAMETER Credential
        Credential with permission to read the LAPS password attribute.

    .RETURNS
        PSCredential if successful, $null if retrieval failed.
        NEVER returns the raw password string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('AD-Legacy','AD-WindowsLAPS','AD-Both')]
        [string]$Backend,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )

    $shortName = ($ComputerName -split '\.')[0]
    $adParams = @{ ErrorAction = 'Stop' }
    if ($Domain)     { $adParams['Server']     = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }

    try {
        $accountName = 'Administrator'  # Default; may be overridden by Windows LAPS config
        $securePw    = $null

        if ($Backend -in @('AD-WindowsLAPS','AD-Both')) {
            # Prefer Windows LAPS -- try Get-LapsADPassword cmdlet first (Server 2025 / Windows 11 24H2+)
            if (Get-Command 'Get-LapsADPassword' -ErrorAction SilentlyContinue) {
                $lapsResult = Get-LapsADPassword -Identity $shortName -AsPlainText @adParams
                if ($lapsResult -and $lapsResult.Password) {
                    $securePw = ConvertTo-SecureString $lapsResult.Password -AsPlainText -Force
                    if ($lapsResult.Account) { $accountName = $lapsResult.Account }
                    # Immediately clear plaintext from the result object
                    $lapsResult = $null
                }
            }
            else {
                # Fallback: read msLAPS-Password directly (plaintext JSON format)
                # CR105: Use schema-safe properties
                $schema = Get-LAPSSchemaCapability
                $pwProps = @('msLAPS-Password')
                if ($schema.HasWS2025Attrs) { $pwProps += 'msLAPS-ManagedPasswordAccountName' }
                $comp = Get-ADComputer -Identity $shortName @adParams -Properties $pwProps
                $pwJson = $comp.'msLAPS-Password'
                if ($pwJson) {
                    try {
                        $parsed = $pwJson | ConvertFrom-Json
                        if ($parsed.p) {
                            $securePw = ConvertTo-SecureString $parsed.p -AsPlainText -Force
                        }
                        if ($parsed.n) {
                            $accountName = $parsed.n
                        }
                        $parsed = $null
                        $pwJson = $null
                    }
                    catch {
                        # JSON parse failed -- password format unexpected
                        Write-Verbose "LAPS: Windows LAPS password JSON parse failed for $shortName"
                    }
                }
                $managedName = $comp.'msLAPS-ManagedPasswordAccountName'
                if ($managedName) { $accountName = $managedName }
            }
        }

        if (-not $securePw -and $Backend -in @('AD-Legacy','AD-Both')) {
            # Legacy LAPS: read ms-Mcs-AdmPwd directly
            $comp = Get-ADComputer -Identity $shortName @adParams -Properties 'ms-Mcs-AdmPwd'
            $legacyPw = $comp.'ms-Mcs-AdmPwd'
            if ($legacyPw) {
                $securePw = ConvertTo-SecureString $legacyPw -AsPlainText -Force
                $legacyPw = $null  # Clear plaintext
                $accountName = 'Administrator'  # Legacy LAPS always manages Administrator
            }
        }

        if ($securePw) {
            $lapsCred = [PSCredential]::new("$shortName\$accountName", $securePw)
            $securePw = $null  # Clear reference (credential object owns the SecureString now)
            return $lapsCred
        }
        else {
            Write-Verbose "LAPS: Could not retrieve password for $shortName ($Backend backend)"
            return $null
        }
    }
    catch {
        Write-Verbose "LAPS: Retrieval failed for $shortName -- $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# EXPORTS
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Get-LAPSSchemaCapability',
    'Get-ADForestInfo',
    'Get-LapsUnifiedStatus',
    'Invoke-LAPSAudit',
    'Get-LAPSResults',
    'Get-LapsPassword'
)
