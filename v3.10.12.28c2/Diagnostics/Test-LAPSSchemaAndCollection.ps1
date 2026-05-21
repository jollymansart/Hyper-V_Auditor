<#
.SYNOPSIS
    Test-LAPSSchemaAndCollection.ps1 - Diagnose and test the LAPS attribute
    query failures in the HyperV Inventory Report's LAPS-Usage tab.

.DESCRIPTION
    The LAPS-Usage tab shows 216/216 rows as Error with the message:
        "AD query failed: One or more properties are invalid.
         Parameter name: msLAPS-ManagedPasswordAccountName"

    ROOT CAUSE ANALYSIS
    ===================
    The Get-ADComputer cmdlet is being called with -Properties that include
    Windows LAPS attributes (msLAPS-ManagedPasswordAccountName, msLAPS-Password,
    etc.) but the AD schema on the target domain(s) has NOT been extended for
    Windows LAPS yet. These attributes literally do not exist in the schema,
    so Get-ADComputer throws a TerminatingError for EVERY VM.

    Two distinct error signatures appear in the log:
      1. "Parameter name: msLAPS-ManagedPasswordAccountName" (199 VMs)
         - The msLAPS-ManagedPasswordAccountName attribute was introduced in
           Windows Server 2025 / Windows 11 24H2 LAPS. This attribute does
           NOT exist if your DCs are WS2022 or earlier, even if you ran
           Update-LapsADSchema on WS2022.
      2. "Parameter name: msLAPS-Password" (17 VMs)
         - The msLAPS-Password attribute exists only after running
           Update-LapsADSchema. If the DCs queried for these 17 VMs are in
           a different domain or forest where the schema was never extended,
           this attribute won't exist either.

    FIX STRATEGY
    ============
    The collection script needs to:
      A. Probe the AD schema FIRST to discover which LAPS attributes actually
         exist, then only query for those that are present.
      B. Handle the TerminatingError gracefully with try/catch per-VM so one
         failure doesn't poison the entire dataset.
      C. Add a "Notes" column to the output for human-readable context.

    This test script validates all three conditions and provides the data
    needed to fix the collection module.

.PARAMETER SampleVMs
    Number of VMs to test. Default: 5. Use -1 for all.

.PARAMETER Domain
    Domain to query. Default: current domain (ohdc.com).

.NOTES
    Author  : Michael George / Delzron
    Date    : 2026-04-25
    Run from: RICTX-SCRIPT-P2 or any machine with RSAT-AD-PowerShell
#>

[CmdletBinding()]
param(
    [int]$SampleVMs = 5,
    [string]$Domain = ''
)

# ============================================================================
# TEST 1: Schema Attribute Discovery
# ============================================================================
Write-Host "`n============================================================" -ForegroundColor White
Write-Host " TEST 1: Windows LAPS Schema Attribute Discovery" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

$schemaNC = (Get-ADRootDSE).schemaNamingContext
Write-Host "  Schema NC: $schemaNC" -ForegroundColor Gray

# All possible LAPS-related attributes across legacy and Windows LAPS
$lapsAttributes = [ordered]@{
    # Legacy LAPS (Microsoft LAPS CSE)
    'ms-Mcs-AdmPwd'                     = 'Legacy LAPS password attribute'
    'ms-Mcs-AdmPwdExpirationTime'       = 'Legacy LAPS expiration timestamp'

    # Windows LAPS (WS2019+ with Update-LapsADSchema)
    'msLAPS-Password'                   = 'Windows LAPS password (JSON blob, cleartext-in-AD)'
    'msLAPS-EncryptedPassword'          = 'Windows LAPS encrypted password (requires AD CS)'
    'msLAPS-PasswordExpirationTime'     = 'Windows LAPS password expiration'
    'msLAPS-CurrentPasswordVersion'     = 'Windows LAPS password version counter'

    # Windows LAPS (WS2025 / 24H2+ only)
    'msLAPS-ManagedPasswordAccountName' = 'Windows LAPS auto-managed account name (WS2025+)'
    'msLAPS-EncryptedDSRMPassword'      = 'Windows LAPS encrypted DSRM password (WS2025+)'
    'msLAPS-EncryptedDSRMPasswordHistory' = 'Windows LAPS DSRM password history (WS2025+)'
}

$presentAttributes = @()
$missingAttributes = @()

foreach ($attr in $lapsAttributes.GetEnumerator()) {
    $attrName = $attr.Key
    $attrDesc = $attr.Value

    try {
        $found = Get-ADObject -SearchBase $schemaNC `
            -Filter "lDAPDisplayName -eq '$attrName'" `
            -Properties lDAPDisplayName `
            -ErrorAction Stop

        if ($found) {
            Write-Host "  [PRESENT] $attrName" -ForegroundColor Green
            Write-Host "            $attrDesc" -ForegroundColor DarkGray
            $presentAttributes += $attrName
        }
        else {
            Write-Host "  [MISSING] $attrName" -ForegroundColor Red
            Write-Host "            $attrDesc" -ForegroundColor DarkGray
            $missingAttributes += $attrName
        }
    }
    catch {
        Write-Host "  [MISSING] $attrName" -ForegroundColor Red
        Write-Host "            $attrDesc" -ForegroundColor DarkGray
        $missingAttributes += $attrName
    }
}

Write-Host ""
Write-Host "  Summary: $($presentAttributes.Count) present, $($missingAttributes.Count) missing" -ForegroundColor Cyan

# Determine LAPS generation
$hasLegacy      = $presentAttributes -contains 'ms-Mcs-AdmPwd'
$hasWindowsLAPS = $presentAttributes -contains 'msLAPS-Password'
$hasWS2025Attrs = $presentAttributes -contains 'msLAPS-ManagedPasswordAccountName'

Write-Host ""
if ($hasWS2025Attrs) {
    Write-Host "  LAPS Generation: Windows LAPS (WS2025 / 24H2+ full schema)" -ForegroundColor Green
}
elseif ($hasWindowsLAPS) {
    Write-Host "  LAPS Generation: Windows LAPS (WS2019-2022 schema)" -ForegroundColor Green
    Write-Host "  NOTE: msLAPS-ManagedPasswordAccountName is NOT available." -ForegroundColor Yellow
    Write-Host "        This is the attribute causing 199/216 errors in the report." -ForegroundColor Yellow
}
elseif ($hasLegacy) {
    Write-Host "  LAPS Generation: Legacy LAPS only (ms-Mcs-AdmPwd)" -ForegroundColor Yellow
    Write-Host "  NOTE: No Windows LAPS schema at all. Run Update-LapsADSchema to extend." -ForegroundColor Yellow
}
else {
    Write-Host "  LAPS Generation: NONE - No LAPS schema attributes found." -ForegroundColor Red
    Write-Host "  Neither Legacy nor Windows LAPS schema has been applied." -ForegroundColor Red
}

# ============================================================================
# TEST 2: Get-ADComputer Query With Safe Attribute List
# ============================================================================
Write-Host "`n============================================================" -ForegroundColor White
Write-Host " TEST 2: Get-ADComputer Query With Safe vs Unsafe Attributes" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

# Build the safe property list based on what actually exists
$safeProperties = @('Name', 'OperatingSystem', 'DistinguishedName')
if ($hasLegacy) {
    $safeProperties += 'ms-Mcs-AdmPwd'
    $safeProperties += 'ms-Mcs-AdmPwdExpirationTime'
}
if ($hasWindowsLAPS) {
    $safeProperties += 'msLAPS-Password'
    $safeProperties += 'msLAPS-EncryptedPassword'
    $safeProperties += 'msLAPS-PasswordExpirationTime'
    $safeProperties += 'msLAPS-CurrentPasswordVersion'
}
if ($hasWS2025Attrs) {
    $safeProperties += 'msLAPS-ManagedPasswordAccountName'
    $safeProperties += 'msLAPS-EncryptedDSRMPassword'
    $safeProperties += 'msLAPS-EncryptedDSRMPasswordHistory'
}

Write-Host "  Safe property list ($($safeProperties.Count) attributes):" -ForegroundColor Gray
$safeProperties | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

# Get sample VMs
$filter = "OperatingSystem -like '*Windows*Server*'"
$getParams = @{ Filter = $filter; Properties = 'Name' }
if ($Domain) { $getParams['Server'] = $Domain }

$allComputers = Get-ADComputer @getParams | Select-Object -ExpandProperty Name
$testVMs = if ($SampleVMs -eq -1) { $allComputers } else { $allComputers | Select-Object -First $SampleVMs }

Write-Host ""
Write-Host "  Testing $($testVMs.Count) VMs..." -ForegroundColor Cyan

# Test A: Unsafe query (reproduces the error)
Write-Host "`n  --- Test A: UNSAFE query (includes msLAPS-ManagedPasswordAccountName) ---" -ForegroundColor Yellow
$unsafeProps = $safeProperties + @('msLAPS-ManagedPasswordAccountName')
$unsafeProps = $unsafeProps | Select-Object -Unique

foreach ($vm in $testVMs) {
    try {
        $unsafeParams = @{ Identity = $vm; Properties = $unsafeProps; ErrorAction = 'Stop' }
        if ($Domain) { $unsafeParams['Server'] = $Domain }
        $null = Get-ADComputer @unsafeParams
        Write-Host "    [OK]    $vm - query succeeded" -ForegroundColor Green
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match 'properties are invalid') {
            Write-Host "    [ERROR] $vm - $($errMsg.Substring(0, [Math]::Min(80, $errMsg.Length)))" -ForegroundColor Red
        }
        else {
            Write-Host "    [ERROR] $vm - $errMsg" -ForegroundColor Red
        }
    }
}

# Test B: Safe query (only schema-validated attributes)
Write-Host "`n  --- Test B: SAFE query (schema-validated attributes only) ---" -ForegroundColor Green
foreach ($vm in $testVMs) {
    try {
        $safeParams = @{ Identity = $vm; Properties = $safeProperties; ErrorAction = 'Stop' }
        if ($Domain) { $safeParams['Server'] = $Domain }
        $result = Get-ADComputer @safeParams

        # Determine LAPS status
        $legacyPwd = $result.'ms-Mcs-AdmPwd'
        $winLAPSPwd = $result.'msLAPS-Password'
        $winLAPSEnc = $result.'msLAPS-EncryptedPassword'

        $status = 'No LAPS'
        if ($legacyPwd)                       { $status = 'Legacy LAPS (populated)' }
        if ($winLAPSPwd -or $winLAPSEnc)      { $status = 'Windows LAPS (populated)' }
        if ($legacyPwd -and ($winLAPSPwd -or $winLAPSEnc)) { $status = 'Both (migrating)' }

        Write-Host "    [OK]    $vm - $status" -ForegroundColor Green
    }
    catch {
        Write-Host "    [ERROR] $vm - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# TEST 3: Multi-Domain Schema Check
# ============================================================================
Write-Host "`n============================================================" -ForegroundColor White
Write-Host " TEST 3: Multi-Domain Schema Check" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

$forest = Get-ADForest
Write-Host "  Forest: $($forest.Name)" -ForegroundColor Gray
Write-Host "  Domains: $($forest.Domains -join ', ')" -ForegroundColor Gray
Write-Host ""

# Schema is forest-wide, so all domains share the same schema
Write-Host "  AD schema is forest-wide. If msLAPS-ManagedPasswordAccountName" -ForegroundColor Yellow
Write-Host "  is missing in the schema, it is missing for ALL domains." -ForegroundColor Yellow
Write-Host ""

# Check DC functional levels
foreach ($domainName in $forest.Domains) {
    try {
        $domInfo = Get-ADDomain -Server $domainName -ErrorAction Stop
        $fl = $domInfo.DomainMode
        Write-Host "  $domainName : DomainMode = $fl" -ForegroundColor Gray
    }
    catch {
        Write-Host "  $domainName : [UNREACHABLE] $($_.Exception.Message)" -ForegroundColor Red
    }
}

$forestFL = $forest.ForestMode
Write-Host ""
Write-Host "  ForestMode: $forestFL" -ForegroundColor Cyan
if ($forestFL -match '2016|2019|2022') {
    Write-Host "  msLAPS-ManagedPasswordAccountName requires WS2025 schema level." -ForegroundColor Yellow
    Write-Host "  Your forest is NOT at WS2025. This attribute cannot exist yet." -ForegroundColor Yellow
}

# ============================================================================
# RECOMMENDED FIX FOR THE COLLECTION SCRIPT
# ============================================================================
Write-Host "`n============================================================" -ForegroundColor White
Write-Host " RECOMMENDED FIX" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

Write-Host @"

  The collection script (Invoke-LAPSAudit or equivalent) needs these changes:

  1. SCHEMA PROBE FIRST: Before querying any VMs, run a schema discovery
     pass to determine which LAPS attributes exist. The code above in
     Test 1 shows exactly how to do this.

  2. DYNAMIC PROPERTY LIST: Build the Get-ADComputer -Properties list
     from only the attributes that passed the schema check. Never
     hardcode msLAPS-ManagedPasswordAccountName unless the schema probe
     confirmed it exists.

  3. PER-VM TRY/CATCH: Wrap each Get-ADComputer call in try/catch so
     one failure doesn't cascade to all 216 VMs as Error rows.

  4. ADD NOTES COLUMN: The LAPS-Usage tab is missing a "Notes" column.
     Add it to carry human-readable context like:
       - "Schema attribute msLAPS-ManagedPasswordAccountName not present (requires WS2025 schema)"
       - "Legacy LAPS password populated, rotation due in 12 days"
       - "No LAPS configured - remediation required"

  5. DIFFERENTIATE ERROR SOURCES: The current code lumps schema-missing
     errors and actual AD query failures into the same "Error" bucket.
     Separate them:
       - SchemaNotExtended  -> Warning, not Error (known limitation)
       - ADQueryFailed      -> Error (connectivity/permission issue)
       - NotDomainJoined    -> Info (expected for Linux/appliances)

"@ -ForegroundColor Gray

# ============================================================================
# OUTPUT: Generate the safe property list for copy/paste into the module
# ============================================================================
Write-Host "============================================================" -ForegroundColor White
Write-Host " COPY/PASTE: Safe LAPS Property List for This Environment" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host '  $lapsProperties = @(' -ForegroundColor White
foreach ($p in $safeProperties) {
    if ($p -notin @('Name','OperatingSystem','DistinguishedName')) {
        Write-Host "      '$p'" -ForegroundColor Green
    }
}
Write-Host '  )' -ForegroundColor White
Write-Host ""
Write-Host "  Use this list in your Get-ADComputer -Properties call." -ForegroundColor Gray
Write-Host "  It contains ONLY attributes confirmed present in your AD schema." -ForegroundColor Gray
Write-Host ""
