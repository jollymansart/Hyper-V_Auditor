<#
.SYNOPSIS
    Fix-LAPSCollection.ps1 - Drop-in replacement functions for the LAPS-Usage
    tab in the HyperV Inventory Report (v3.10.x+).

.DESCRIPTION
    Fixes three issues in the current LAPS collection:
      1. Get-ADComputer fails with "properties are invalid" because
         msLAPS-ManagedPasswordAccountName (WS2025-only) and/or
         msLAPS-Password (requires Update-LapsADSchema) are queried
         against domains where those schema attributes don't exist.
      2. No "Notes" column in the LAPS-Usage tab output.
      3. TerminatingError cascades -- one failed VM poisons the
         error message for all VMs in the same batch.

    INTEGRATION:
      Copy the three functions below into HyperVInventory-ADAuth.psm1
      (or a new HyperVInventory-LAPS.psm1 module) and replace the
      existing Step 5p call in HyperVInventory.psm1 orchestrator:

        # OLD:
        # $lapsData = Invoke-LAPSAudit -ComputerNames $vmNames -Mode Retrieve
        # NEW:
        $lapsData = Invoke-LAPSCollection -ComputerNames $vmNames `
                        -HostMap $hostMap `
                        -DomainCredentials $domainCredentials

.NOTES
    Author  : Michael George / Delzron
    Version : 3.10.12-LAPS-Fix
    Date    : 2026-04-25
    Tested  : PS 5.1 strict, ASCII-only, no external dependencies beyond RSAT-AD
#>

# ============================================================================
# FUNCTION 1: Schema Discovery (runs ONCE per forest, cached for session)
# ============================================================================
function Get-LAPSSchemaCapability {
    <#
    .SYNOPSIS
        Probes the AD schema to discover which LAPS attributes exist.
        Returns a hashtable with boolean flags and the safe property list.
        
        Runs once and caches in a script-scope variable for the session.
        Call with -Force to re-probe.

    .OUTPUTS
        [hashtable] with keys:
          HasLegacyLAPS       [bool]   - ms-Mcs-AdmPwd exists
          HasWindowsLAPS      [bool]   - msLAPS-Password exists
          HasWS2025Attrs      [bool]   - msLAPS-ManagedPasswordAccountName exists
          HasEncryptedLAPS    [bool]   - msLAPS-EncryptedPassword exists
          SafeProperties      [string[]] - attributes safe to pass to Get-ADComputer
          SchemaLevel         [string] - 'None', 'LegacyOnly', 'WindowsLAPS', 'WindowsLAPS-WS2025'
          ProbeTimestamp       [datetime]
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    # Return cached result if available
    if ($script:_LAPSSchemaCache -and -not $Force) {
        return $script:_LAPSSchemaCache
    }

    $result = @{
        HasLegacyLAPS    = $false
        HasWindowsLAPS   = $false
        HasWS2025Attrs   = $false
        HasEncryptedLAPS = $false
        SafeProperties   = @()
        SchemaLevel      = 'None'
        ProbeTimestamp   = Get-Date
        ProbeErrors      = @()
    }

    try {
        $schemaNC = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
    }
    catch {
        $result.ProbeErrors += "Cannot reach AD RootDSE: $($_.Exception.Message)"
        $script:_LAPSSchemaCache = $result
        return $result
    }

    # Attribute catalog: name -> flag key
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
        $attrName = $attr.Key
        $flagKey  = $attr.Value

        try {
            $found = Get-ADObject -SearchBase $schemaNC `
                -Filter "lDAPDisplayName -eq '$attrName'" `
                -Properties lDAPDisplayName `
                -ErrorAction Stop

            if ($found) {
                $result[$flagKey] = $true
                $safeProps.Add($attrName)
            }
        }
        catch {
            # Attribute not in schema -- this is expected, not an error
        }
    }

    $result.SafeProperties = $safeProps.ToArray()

    # Determine schema level
    if ($result.HasWS2025Attrs)   { $result.SchemaLevel = 'WindowsLAPS-WS2025' }
    elseif ($result.HasWindowsLAPS) { $result.SchemaLevel = 'WindowsLAPS' }
    elseif ($result.HasLegacyLAPS)  { $result.SchemaLevel = 'LegacyOnly' }
    else                            { $result.SchemaLevel = 'None' }

    # Cache for session
    $script:_LAPSSchemaCache = $result
    return $result
}


# ============================================================================
# FUNCTION 2: Per-VM LAPS Data Collection (schema-safe)
# ============================================================================
function Invoke-LAPSCollection {
    <#
    .SYNOPSIS
        Collects LAPS posture for a list of VM names.
        Uses schema-safe attribute list -- never queries attributes that
        don't exist in the AD schema.
        
        Returns an array of PSCustomObjects, one per VM, suitable for
        direct export to the LAPS-Usage tab.

    .PARAMETER ComputerNames
        Array of VM names (short or FQDN) to query.

    .PARAMETER HostMap
        Hashtable mapping VM name -> Hyper-V host FQDN (for the Host column).

    .PARAMETER DomainCredentials
        Optional hashtable of domain -> PSCredential for cross-domain lookups.

    .PARAMETER DataSource
        String for the DataSource column. Default: 'HYPER-V'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory=$false)]
        [hashtable]$HostMap = @{},

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{},

        [Parameter(Mandatory=$false)]
        [string]$DataSource = 'HYPER-V'
    )

    $rows = [System.Collections.Generic.List[PSObject]]::new()

    # ---- Step 1: Probe schema (cached after first call) ----
    $schema = Get-LAPSSchemaCapability
    Write-Host "  LAPS Schema: $($schema.SchemaLevel) ($($schema.SafeProperties.Count) safe attributes)" -ForegroundColor Gray

    if ($schema.SchemaLevel -eq 'None') {
        Write-Warning "[LAPS] No LAPS schema attributes found in AD. All VMs will report 'SchemaNotExtended'."
    }

    # ---- Step 2: Build the Get-ADComputer property list ----
    # Always include base properties; add LAPS properties only if schema supports them
    $baseProps = @('Name', 'DistinguishedName', 'OperatingSystem', 'Enabled')
    $adProperties = $baseProps + $schema.SafeProperties

    # ---- Step 3: Build domain probe list ----
    # Primary domain first (no -Server), then cross-domain entries
    $domainProbes = @(@{ Server = $null; Credential = $null; Label = 'PrimaryDomain' })
    foreach ($domName in $DomainCredentials.Keys) {
        $domainProbes += @{ Server = $domName; Credential = $DomainCredentials[$domName]; Label = $domName }
    }

    # ---- Step 4: Query each VM with per-VM try/catch ----
    $processed = 0
    $total = $ComputerNames.Count
    $errorCount = 0
    $managedCount = 0

    foreach ($vmName in $ComputerNames) {
        $processed++
        $shortName = ($vmName.Trim().ToUpper() -replace '\..*$', '')
        $hostFQDN = if ($HostMap.ContainsKey($shortName)) { $HostMap[$shortName] }
                    elseif ($HostMap.ContainsKey($vmName)) { $HostMap[$vmName] }
                    else { '' }

        $adObj      = $null
        $foundIn    = ''
        $queryError = ''

        # Try each domain in order until we find the computer
        foreach ($probe in $domainProbes) {
            try {
                $getParams = @{
                    Identity   = $shortName
                    Properties = $adProperties
                    ErrorAction = 'Stop'
                }
                if ($probe.Server)     { $getParams['Server']     = $probe.Server }
                if ($probe.Credential) { $getParams['Credential'] = $probe.Credential }

                $adObj = Get-ADComputer @getParams
                $foundIn = $probe.Label
                break   # Found it -- stop probing
            }
            catch {
                $msg = $_.Exception.Message
                # "Cannot find an object with identity" = not in this domain, try next
                if ($msg -match 'Cannot find an object') { continue }
                # "properties are invalid" = schema issue even after our probe
                if ($msg -match 'properties are invalid') {
                    $queryError = "Schema attribute missing: $msg"
                    break   # Don't try other domains, same schema applies
                }
                # Other AD error (permissions, connectivity)
                $queryError = "AD query failed: $msg"
                # Keep trying other domains
            }
        }

        # ---- Build the output row ----
        $row = ConvertTo-LAPSRow -ShortName $shortName `
                                  -ADObject $adObj `
                                  -QueryError $queryError `
                                  -SchemaCapability $schema `
                                  -HostFQDN $hostFQDN `
                                  -DataSource $DataSource `
                                  -FoundInDomain $foundIn

        $rows.Add($row)

        if ($row.AlertLevel -eq 'Critical' -or $row.AlertLevel -eq 'Warning') { $errorCount++ }
        if ($row.LAPSBackend -in @('Legacy','WindowsLAPS','Both')) { $managedCount++ }

        # Progress every 50 VMs
        if ($processed % 50 -eq 0) {
            Write-Host "    LAPS: $processed/$total VMs queried ($managedCount managed, $errorCount alerts)..." -ForegroundColor DarkGray
        }
    }

    Write-Host "  LAPS Audit complete: $total VMs queried -- $managedCount managed, $errorCount alerts" -ForegroundColor Gray
    return $rows
}


# ============================================================================
# FUNCTION 3: Row Builder (converts AD object to LAPS-Usage tab row)
# ============================================================================
function ConvertTo-LAPSRow {
    <#
    .SYNOPSIS
        Converts a single AD computer object (or error state) into a
        LAPS-Usage tab row with all 17 columns including Notes.
    #>
    [CmdletBinding()]
    param(
        [string]$ShortName,
        [object]$ADObject,           # $null if not found / error
        [string]$QueryError,
        [hashtable]$SchemaCapability,
        [string]$HostFQDN,
        [string]$DataSource,
        [string]$FoundInDomain
    )

    # Default values
    $lapsBackend           = 'None'
    $lookupResult          = 'NotFound'
    $managedAccountName    = ''
    $passwordAge           = $null
    $passwordExpiration    = $null
    $rotationDue           = $false
    $legacyLAPSInstalled   = $false
    $legacyAttrPopulated   = $false
    $windowsLAPSConfigured = $false
    $windowsLAPSEncrypted  = $false
    $migrationStatus       = ''
    $alertLevel            = 'Info'
    $alertReason           = ''
    $notes                 = ''

    # ---- Error path ----
    if ($QueryError) {
        $lapsBackend  = 'Error'
        $lookupResult = 'Error'
        $alertReason  = $QueryError

        # Classify the error for Notes and AlertLevel
        if ($QueryError -match 'Schema attribute missing|properties are invalid') {
            $alertLevel = 'Info'    # Not a real error -- known schema limitation
            if ($QueryError -match 'msLAPS-ManagedPasswordAccountName') {
                $notes = 'msLAPS-ManagedPasswordAccountName requires WS2025 AD schema. Not an error -- attribute does not exist in this forest.'
            }
            elseif ($QueryError -match 'msLAPS-Password') {
                $notes = 'msLAPS-Password attribute missing. Run Update-LapsADSchema (one-time, domain admin) to extend the schema for Windows LAPS.'
            }
            else {
                $notes = 'AD schema attribute not present. Check Update-LapsADSchema status.'
            }
            $lapsBackend  = 'SchemaNotExtended'
            $lookupResult = 'SchemaNotExtended'
        }
        elseif ($QueryError -match 'Cannot find an object') {
            $alertLevel = 'Info'
            $notes = 'Not found in any queried domain. May be non-domain-joined (Linux, appliance, workgroup).'
            $lapsBackend  = 'N/A'
            $lookupResult = 'NotDomainJoined'
        }
        else {
            $alertLevel = 'Warning'
            $notes = "AD query failure. Check connectivity and permissions. Error: $QueryError"
        }

        return [PSCustomObject]@{
            VM                     = $ShortName
            LAPSBackend            = $lapsBackend
            LookupResult           = $lookupResult
            ManagedAccountName     = $managedAccountName
            PasswordAge            = $passwordAge
            PasswordExpiration     = $passwordExpiration
            RotationDue            = $rotationDue
            LegacyLAPSInstalled    = $legacyLAPSInstalled
            LegacyAttributePopulated = $legacyAttrPopulated
            WindowsLAPSConfigured  = $windowsLAPSConfigured
            WindowsLAPSEncrypted   = $windowsLAPSEncrypted
            MigrationStatus        = $migrationStatus
            AlertLevel             = $alertLevel
            AlertReason            = $alertReason
            DataSource             = $DataSource
            Host                   = $HostFQDN
            Notes                  = $notes
        }
    }

    # ---- Not found (no AD object and no error = searched all domains, not found) ----
    if (-not $ADObject) {
        return [PSCustomObject]@{
            VM                     = $ShortName
            LAPSBackend            = 'N/A'
            LookupResult           = 'NotDomainJoined'
            ManagedAccountName     = ''
            PasswordAge            = $null
            PasswordExpiration     = $null
            RotationDue            = $false
            LegacyLAPSInstalled    = $false
            LegacyAttributePopulated = $false
            WindowsLAPSConfigured  = $false
            WindowsLAPSEncrypted   = $false
            MigrationStatus        = ''
            AlertLevel             = 'Info'
            AlertReason            = 'Computer not found in any queried AD domain.'
            DataSource             = $DataSource
            Host                   = $HostFQDN
            Notes                  = 'Not domain-joined or in an unqueried domain/forest.'
        }
    }

    # ---- Success path: AD object found, evaluate LAPS posture ----
    $lookupResult = 'Found'
    $now = Get-Date

    # Legacy LAPS (ms-Mcs-AdmPwd)
    $legacyPwd = $ADObject.'ms-Mcs-AdmPwd'
    $legacyExp = $ADObject.'ms-Mcs-AdmPwdExpirationTime'

    if ($legacyPwd) {
        $legacyLAPSInstalled = $true
        $legacyAttrPopulated = $true
    }
    elseif ($SchemaCapability.HasLegacyLAPS) {
        # Schema has the attribute but this machine's attribute is empty
        # Could still have the CSE installed -- just not populated
        $legacyLAPSInstalled = $false
        $legacyAttrPopulated = $false
    }

    # Windows LAPS (msLAPS-Password / msLAPS-EncryptedPassword)
    $winPwd    = $ADObject.'msLAPS-Password'
    $winEncPwd = $ADObject.'msLAPS-EncryptedPassword'
    $winExp    = $ADObject.'msLAPS-PasswordExpirationTime'
    $winVer    = $ADObject.'msLAPS-CurrentPasswordVersion'
    $winAcct   = $ADObject.'msLAPS-ManagedPasswordAccountName'

    if ($winPwd -or $winEncPwd) {
        $windowsLAPSConfigured = $true
        if ($winEncPwd) { $windowsLAPSEncrypted = $true }
    }

    if ($winAcct) { $managedAccountName = $winAcct }

    # Determine LAPS backend
    if ($windowsLAPSConfigured -and $legacyAttrPopulated) {
        $lapsBackend     = 'Both'
        $migrationStatus = 'Migrating (Legacy + Windows LAPS both active)'
        $notes           = 'Both Legacy and Windows LAPS attributes populated. Complete migration by removing Legacy LAPS GPO and uninstalling the CSE.'
    }
    elseif ($windowsLAPSConfigured) {
        $lapsBackend     = 'WindowsLAPS'
        $migrationStatus = 'Windows LAPS (current)'
        $notes           = 'Windows LAPS active.' + $(if ($windowsLAPSEncrypted) { ' Password is encrypted (AD CS protected).' } else { ' Password stored as cleartext in AD.' })
    }
    elseif ($legacyAttrPopulated) {
        $lapsBackend     = 'Legacy'
        $migrationStatus = 'Legacy LAPS (migrate to Windows LAPS)'
        $notes           = 'Legacy LAPS (ms-Mcs-AdmPwd) active. Migrate to Windows LAPS: update GPO, run Update-LapsADSchema, set OU permissions.'
        $alertLevel      = 'Warning'
        $alertReason     = 'Legacy LAPS deployed -- scheduled for deprecation. Migrate to Windows LAPS.'
    }
    else {
        $lapsBackend     = 'None'
        $migrationStatus = 'No LAPS'
        $alertLevel      = 'Critical'
        $alertReason     = 'No LAPS password management. Local admin password is static and shared.'
        $notes           = 'CRITICAL: No LAPS deployed. Local admin password is unmanaged. Deploy Windows LAPS via GPO.'
    }

    # Password age and expiration (prefer Windows LAPS, fall back to Legacy)
    $expirationFileTime = $null
    if ($winExp)     { $expirationFileTime = $winExp }
    elseif ($legacyExp) { $expirationFileTime = $legacyExp }

    if ($expirationFileTime) {
        try {
            $ft = [long]$expirationFileTime
            if ($ft -gt 0) {
                $expiryDate = [datetime]::FromFileTimeUtc($ft)
                $passwordExpiration = $expiryDate.ToString('yyyy-MM-dd HH:mm')

                # Password age = time since last rotation = expiry - policy_age
                # We can't know the policy age, so show days until expiry instead
                $daysUntilExpiry = ($expiryDate - $now).Days
                $rotationDue = ($daysUntilExpiry -le 0)

                if ($rotationDue) {
                    $passwordAge = "EXPIRED ($([math]::Abs($daysUntilExpiry)) days overdue)"
                    if ($alertLevel -ne 'Critical') {
                        $alertLevel  = 'Warning'
                        $alertReason = "LAPS password expired $([math]::Abs($daysUntilExpiry)) days ago. Rotation may be stuck."
                        $notes += " Password rotation overdue -- check LAPS GPO processing."
                    }
                }
                else {
                    $passwordAge = "$daysUntilExpiry days until rotation"
                }
            }
        }
        catch {
            $passwordAge = 'ParseError'
        }
    }

    return [PSCustomObject]@{
        VM                     = $ShortName
        LAPSBackend            = $lapsBackend
        LookupResult           = $lookupResult
        ManagedAccountName     = $managedAccountName
        PasswordAge            = $passwordAge
        PasswordExpiration     = $passwordExpiration
        RotationDue            = $rotationDue
        LegacyLAPSInstalled    = $legacyLAPSInstalled
        LegacyAttributePopulated = $legacyAttrPopulated
        WindowsLAPSConfigured  = $windowsLAPSConfigured
        WindowsLAPSEncrypted   = $windowsLAPSEncrypted
        MigrationStatus        = $migrationStatus
        AlertLevel             = $alertLevel
        AlertReason            = $alertReason
        DataSource             = $DataSource
        Host                   = $HostFQDN
        Notes                  = $notes
    }
}


# ============================================================================
# EXPORT TAB NOTES: Paste into $tabNotes in HyperVInventory-Export.psm1
# ============================================================================
<#
    'LAPS-Usage' = @{
        'VM'                       = 'VM display name (short hostname from Hyper-V).'
        'LAPSBackend'              = 'LAPS type detected: WindowsLAPS, Legacy, Both, None, SchemaNotExtended, N/A, or Error.'
        'LookupResult'             = 'AD query outcome: Found, NotDomainJoined, SchemaNotExtended, or Error.'
        'ManagedAccountName'       = 'msLAPS-ManagedPasswordAccountName value (WS2025+ only). Blank if schema does not support it.'
        'PasswordAge'              = 'Days until next password rotation, or EXPIRED with overdue count.'
        'PasswordExpiration'       = 'UTC timestamp when the LAPS-managed password is scheduled to expire and rotate.'
        'RotationDue'              = 'TRUE if the password expiration has passed and rotation may be stuck.'
        'LegacyLAPSInstalled'      = 'TRUE if the Legacy LAPS ms-Mcs-AdmPwd attribute was found populated for this machine.'
        'LegacyAttributePopulated' = 'TRUE if the ms-Mcs-AdmPwd attribute has a value (password is being managed by Legacy LAPS).'
        'WindowsLAPSConfigured'    = 'TRUE if msLAPS-Password or msLAPS-EncryptedPassword has a value.'
        'WindowsLAPSEncrypted'     = 'TRUE if the password is stored in msLAPS-EncryptedPassword (requires AD CS). FALSE = cleartext in AD.'
        'MigrationStatus'          = 'Human-readable migration state: Windows LAPS (current), Legacy LAPS (migrate), Both (migrating), No LAPS.'
        'AlertLevel'               = 'Critical (no LAPS at all), Warning (Legacy LAPS or expired password), Info (schema limitation or non-domain).'
        'AlertReason'              = 'Explanation for the AlertLevel. Schema errors are now Info-level, not Warning.'
        'DataSource'               = 'How this VM was discovered: HYPER-V (from host inventory) or SCCM.'
        'Host'                     = 'FQDN of the Hyper-V host running this VM.'
        'Notes'                    = 'Human-readable context: schema limitations, migration guidance, rotation health, or remediation steps.'
    }
#>
