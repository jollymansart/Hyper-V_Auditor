<#
.SYNOPSIS
    Secure Boot & Windows Update Compliance Audit
    Scans all online servers (physical + virtual) across all configured AD domains.

.DESCRIPTION
    Queries Active Directory for all computer objects, tests reachability (ping + WinRM),
    then collects via a single Invoke-Command per server:

      1. Firmware mode (UEFI or Legacy BIOS)
      2. Secure Boot state (Enabled / Disabled / Not Supported)
      3. Secure Boot certificate details + expiry dates (AlertLevel: OK / Warning / Critical / Expired)
      4. Windows Update pending patches -- full list of missing KBs
      5. Specific required KB list status (per the $RequiredKBs table below)
      6. Recommendation: what to do for BIOS-mode machines

    Outputs:
      - Console summary during run
      - CSV:   SecureBoot-Audit_<timestamp>.csv   (one row per server)
      - XLSX:  SecureBoot-Audit_<timestamp>.xlsx  (formatted, conditional, three tabs:
                 Summary | PatchDetail | CertificateDetail)
      - Log:   SecureBoot-Audit_<timestamp>.log

.PARAMETER OutputFolder
    Where to write CSV, XLSX, and log. Defaults to script folder.

.PARAMETER MaxParallel
    Max concurrent background jobs. Default 20.

.PARAMETER PingTimeoutMs
    Ping timeout in milliseconds. Default 1000.

.PARAMETER WinRMTimeoutSec
    WinRM Invoke-Command timeout in seconds. Default 30.

.PARAMETER IncludeVMs
    Include virtual machines in addition to physical servers. Default $true.

.PARAMETER SkipPatchScan
    Skip the Windows Update pending patches scan (faster). Default $false.

.PARAMETER CertWarningDays
    Alert when a Secure Boot certificate expires within this many days. Default 180.

.PARAMETER CertCriticalDays
    Critical alert when a Secure Boot certificate expires within this many days. Default 60.

.EXAMPLE
    .\Get-SecureBootAudit.ps1

.EXAMPLE
    .\Get-SecureBootAudit.ps1 -OutputFolder "C:\Reports" -MaxParallel 30 -SkipPatchScan

.NOTES
    Credentials: Uses the same stored XML credential files as the HyperV Report.
    Requires: ImportExcel module (Install-Module ImportExcel -Scope CurrentUser)
    Run as: Domain admin or account with WinRM + remote WMI rights on all targets.
    Tested: PowerShell 5.1, Windows Server 2012R2 through 2025.
#>
[CmdletBinding()]
param(
    [string]$OutputFolder    = '\\rictx-script-p2\LOG\Server\SecureBoot',
    [int]$MaxParallel        = 20,
    [int]$PingTimeoutMs      = 1000,
    [int]$WinRMTimeoutSec    = 30,
    [bool]$IncludeVMs        = $true,
    [switch]$SkipPatchScan,
    [int]$CertWarningDays    = 180,
    [int]$CertCriticalDays   = 60
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# ============================================================
# CONFIGURATION
# ============================================================

# Domains to scan -- mirrors your HyperV Report domain structure.
# Add / remove entries to match your environment.
# SCOPE: ohdc.com and overheaddoor.com only.
# creative.com is decommissioning and explicitly excluded.
$DomainConfig = @(
    @{
        FQDN       = 'ohdc.com'
        CredPath   = 'C:\ProgramData\S\HyperV-Cred.xml'
        SearchBase = 'DC=ohdc,DC=com'
        Enabled    = $true
    }
    @{
        FQDN       = 'overheaddoor.com'
        CredPath   = 'C:\ProgramData\S\HyperV-Cred-overheaddoor.xml'
        SearchBase = 'DC=overheaddoor,DC=com'
        Enabled    = $true   # Enabled -- ensure credential XML is healthy before running
    }
    # creative.com intentionally excluded (decommissioning domain)
)

# Required KBs -- add any KBs that must be installed fleet-wide.
# Format: @{ KB = 'KB1234567'; Description = 'Why it is required'; Severity = 'Critical|Important|Moderate' }
# Common Secure Boot / UEFI / CVE patches:
$RequiredKBs = @(
    @{ KB = 'KB5012170';  Description = 'Secure Boot DBX Update (CVE-2022-21894 BootHole fix)';         Severity = 'Critical'  }
    @{ KB = 'KB4535680';  Description = 'Secure Boot DBX revocation list update';                        Severity = 'Critical'  }
    @{ KB = 'KB5025885';  Description = 'Secure Boot DBX update May 2023 (BlackLotus fix)';             Severity = 'Critical'  }
    @{ KB = 'KB5027070';  Description = 'Secure Boot DB/DBX cert chain update (June 2023)';             Severity = 'Important' }
    @{ KB = 'KB5036210';  Description = 'Windows Secure Boot Certificate Authority 2023 update';        Severity = 'Important' }
    @{ KB = 'KB3172729';  Description = 'Secure Boot allow list update (legacy -- 2012R2 onwards)';     Severity = 'Moderate'  }
    @{ KB = 'KB4524244';  Description = 'Secure Boot UEFI CA revocation (BootHole predecessor)';        Severity = 'Important' }
)

# Known Secure Boot certificate thumbprints that have been revoked or are expiring.
# Add to this list as Microsoft publishes new advisories.
# See: https://support.microsoft.com/kb/5012170 and UEFI working group advisories
$KnownRevokedThumbprints = @(
    # BootHole-related revocations (August 2020)
    '4E80511F43D1D7223FF97969C71D38EB4A0B7B6'
    # Add additional revoked thumbprints here as advisories are published
)

# ============================================================
# OUTPUT PATHS
# ============================================================
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputFolder) { $OutputFolder = $scriptDir }
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

$csvPath        = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.csv"
$xlsxPath       = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.xlsx"
$activityLog    = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.log"
$transcriptLog  = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.transcript"

# Start transcript immediately -- captures ALL console output from this point forward
try {
    Start-Transcript -Path $transcriptLog -Force | Out-Null
    Write-Host "[Transcript: $transcriptLog]" -ForegroundColor DarkGray
}
catch { Write-Warning "Could not start transcript: $($_.Exception.Message)" }

function Write-AuditLog {
    # Writes to the structured activity log (.log) and to the console.
    # The transcript captures console output separately -- no duplicate lines in the .log.
    param([string]$Message, [string]$Level = 'Info')
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $activityLog -Value $line -Encoding UTF8
    $color = switch ($Level) {
        'Error'   { 'Red'    }; 'Warning' { 'Yellow' }
        'Success' { 'Green'  }; 'WhatIf'  { 'Cyan'   }
        default   { 'Gray'   }
    }
    Write-Host $line -ForegroundColor $color
}

# Activity log header
@(
    "# ===================================================="
    "# SecureBoot Audit Activity Log"
    "# Started:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "# RunAs:      $($env:USERDOMAIN)\$($env:USERNAME)"
    "# Machine:    $($env:COMPUTERNAME)"
    "# Script:     $($MyInvocation.MyCommand.Path)"
    "# Params:     MaxParallel=$MaxParallel SkipPatchScan=$SkipPatchScan CertWarn=${CertWarningDays}d CertCrit=${CertCriticalDays}d"
    "# ActivityLog:  $activityLog"
    "# Transcript:   $transcriptLog"
    "# ===================================================="
) | Add-Content -Path $activityLog -Encoding UTF8
Write-AuditLog "===== Secure Boot & Patch Compliance Audit v1.0 =====" 'Info'
Write-AuditLog "Output: $xlsxPath" 'Info'
Write-AuditLog "Required KBs: $($RequiredKBs.Count) | CertWarning: ${CertWarningDays}d | CertCritical: ${CertCriticalDays}d" 'Info'

# ============================================================
# LOAD CREDENTIALS
# ============================================================
$domainCredentials = @{}
foreach ($dom in $DomainConfig) {
    if (-not $dom.Enabled) { continue }
    try {
        if (Test-Path $dom.CredPath) {
            $domainCredentials[$dom.FQDN] = Import-Clixml -Path $dom.CredPath -ErrorAction Stop
            Write-AuditLog "Loaded credential for $($dom.FQDN)" 'Info'
        }
        else {
            Write-AuditLog "Credential file not found for $($dom.FQDN): $($dom.CredPath)" 'Warning'
        }
    }
    catch {
        Write-AuditLog "Failed to load credential for $($dom.FQDN): $($_.Exception.Message)" 'Warning'
    }
}

# ============================================================
# DISCOVER COMPUTERS FROM AD
# ============================================================
Write-AuditLog "--- Phase 1: AD Computer Discovery ---" 'Info'
$allComputers = [System.Collections.Generic.List[hashtable]]::new()

foreach ($dom in $DomainConfig) {
    if (-not $dom.Enabled) {
        Write-AuditLog "Skipping disabled domain: $($dom.FQDN)" 'Info'
        continue
    }
    $cred = $domainCredentials[$dom.FQDN]
    $adParams = @{ SearchBase = $dom.SearchBase; Filter = '*'; Properties = @('Name','DNSHostName','OperatingSystem','OperatingSystemVersion','Enabled','LastLogonDate','Description','IPv4Address') }
    if ($cred) { $adParams['Credential'] = $cred; $adParams['Server'] = $dom.FQDN }

    try {
        $computers = Get-ADComputer @adParams | Where-Object {
            $_.Enabled -eq $true -and
            $_.OperatingSystem -match 'Windows Server|Windows.*Server' -and
            $_.Name -notmatch 'WSUS|SCCM-TMP|defunct' -and
            ($IncludeVMs -or $_.OperatingSystem -notmatch 'Virtual')
        }
        foreach ($c in $computers) {
            $fqdn = if ($c.DNSHostName) { $c.DNSHostName } else { "$($c.Name).$($dom.FQDN)" }
            $allComputers.Add(@{
                Name             = $c.Name.ToUpper()
                FQDN             = $fqdn
                Domain           = $dom.FQDN
                OperatingSystem  = if ($c.OperatingSystem)        { $c.OperatingSystem }        else { 'Unknown' }
                OSVersion        = if ($c.OperatingSystemVersion)  { $c.OperatingSystemVersion }  else { '' }
                LastLogonDate    = $c.LastLogonDate
                Description      = if ($c.Description)            { $c.Description }            else { '' }
                IPv4Address      = if ($c.IPv4Address)             { $c.IPv4Address }             else { '' }
                Credential       = $cred
            })
        }
        Write-AuditLog "  $($dom.FQDN): $($computers.Count) server computer objects found" 'Info'
    }
    catch {
        Write-AuditLog "  $($dom.FQDN): AD query failed -- $($_.Exception.Message)" 'Warning'
    }
}

# Deduplicate by Name
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# Deduplicate by computer name -- HashSet.Add returns bool; pipe through Out-Null prevents
# the True/False values from printing to console (PS 5.1 pipeline behaviour).
$seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueComputers = @($allComputers | Where-Object { $seenNames.Add($_.Name) })
Write-AuditLog "Total unique computer objects: $($uniqueComputers.Count)" 'Info'

# ============================================================
# PHASE 2: PING TEST
# ============================================================
Write-AuditLog "--- Phase 2: Reachability Test (ping) ---" 'Info'
$reachable   = [System.Collections.Generic.List[hashtable]]::new()
$unreachable = [System.Collections.Generic.List[hashtable]]::new()

foreach ($c in $uniqueComputers) {
    $ping = Test-Connection -ComputerName $c.FQDN -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $ping) {
        # Try short name if FQDN fails
        $ping = Test-Connection -ComputerName $c.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
    }
    if ($ping) {
        $reachable.Add($c)
    }
    else {
        $unreachable.Add($c)
        Write-Verbose "  OFFLINE: $($c.Name)"
    }
}

Write-AuditLog "Reachable: $($reachable.Count) / $($uniqueComputers.Count) (Offline: $($unreachable.Count))" 'Info'

# ============================================================
# REMOTE COLLECTION SCRIPTBLOCK
# ============================================================
$collectionSB = {
    param(
        [string[]]$RequiredKBList,
        [string[]]$RevokedThumbprints,
        [bool]$SkipPatches,
        [int]$CertWarnDays,
        [int]$CertCritDays
    )

    $r = @{
        Hostname             = $env:COMPUTERNAME
        FirmwareType         = 'Unknown'
        SecureBootEnabled    = $false
        SecureBootSupported  = $false
        SecureBootStatus     = 'Unknown'
        SecureBootRecommendation = ''
        TPMVersion           = 'Unknown'
        Manufacturer         = 'Unknown'
        Model                = 'Unknown'
        BIOSVersion          = 'Unknown'
        IsVirtual            = $false
        OSCaption            = ''
        OSBuildNumber        = ''
        # Patch data
        PendingPatchCount    = 0
        PendingPatches       = ''
        RequiredKBStatus     = ''
        MissingRequiredKBs   = ''
        MissingRequiredCount = 0
        # Certificate data
        SecureBootCerts      = ''
        CertAlertLevel       = 'N/A'
        CertExpiryDaysMin    = $null
        CertNearestExpiry    = ''
        RevokedCertsFound    = ''
        # Overall
        AlertLevel           = 'OK'
        Issues               = ''
        CollectionError      = ''
    }

    $issues = [System.Collections.Generic.List[string]]::new()

    # --- OS Info ---
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $r.OSCaption     = $os.Caption
        $r.OSBuildNumber = $os.BuildNumber
    }
    catch { }

    # --- Hardware Info ---
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $r.Manufacturer = $cs.Manufacturer
        $r.Model        = $cs.Model
        $r.IsVirtual    = $cs.Model -match 'Virtual|VMware|Hyper-V|Xen|KVM|VRTX'
    }
    catch { }

    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $r.BIOSVersion = $bios.SMBIOSBIOSVersion
    }
    catch { }

    # --- Firmware Type (UEFI vs Legacy BIOS) ---
    $r.FirmwareType = 'BIOS'  # assume Legacy until proven otherwise
    try {
        # Method 1: bcdedit -- most reliable
        $bcd = & bcdedit.exe /enum '{current}' 2>$null
        if ($bcd -match '\\EFI\\') { $r.FirmwareType = 'UEFI' }
    }
    catch { }

    if ($r.FirmwareType -eq 'BIOS') {
        # Method 2: EFI variable registry key
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') {
            $r.FirmwareType = 'UEFI'
        }
    }

    if ($r.FirmwareType -eq 'BIOS') {
        # Method 3: Check for EFI system partition in diskpart output
        try {
            $disk = Get-Partition | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' }
            if ($disk) { $r.FirmwareType = 'UEFI' }
        }
        catch { }
    }

    # --- Secure Boot State ---
    if ($r.FirmwareType -eq 'UEFI') {
        $r.SecureBootSupported = $true
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            $r.SecureBootEnabled = $sb
            $r.SecureBootStatus  = if ($sb) { 'Enabled' } else { 'Disabled (UEFI -- enable recommended)' }
            if (-not $sb) {
                $issues.Add('Secure Boot is supported but DISABLED. Enable in UEFI firmware settings.')
                $r.AlertLevel = 'Warning'
                $r.SecureBootRecommendation = 'Enable Secure Boot in UEFI/firmware settings. Ensure Microsoft UEFI CA certificate is present in DB (KB5036210). Then boot to verify OS still starts.'
            }
        }
        catch {
            $r.SecureBootStatus = 'Query failed'
            $r.SecureBootEnabled = $false
        }
    }
    else {
        $r.SecureBootSupported  = $false
        $r.SecureBootEnabled    = $false
        $r.SecureBootStatus     = 'Not Supported (Legacy BIOS mode)'
        $r.SecureBootRecommendation = 'LEGACY BIOS MODE DETECTED. Migrate to UEFI to enable Secure Boot. Steps: (1) Verify hardware supports UEFI (all modern servers do). (2) Convert OS disk from MBR to GPT using MBR2GPT.exe /convert /allowFullOS (no data loss). (3) Change firmware boot mode to UEFI. (4) Enable Secure Boot. (5) Validate boot succeeds. Note: VMs -- change VM generation or use Set-VMFirmware. Physical -- requires firmware configuration change and MBR2GPT conversion.'
        $issues.Add('Legacy BIOS mode -- Secure Boot not available. Migrate to UEFI.')
        if ($r.AlertLevel -eq 'OK') { $r.AlertLevel = 'Warning' }
    }

    # --- TPM ---
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmPresent) {
            try {
                $tpmWmi = Get-CimInstance -Namespace 'root\CIMv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
                $r.TPMVersion = if ($tpmWmi) { $tpmWmi.SpecVersion } else { 'Present (version unknown)' }
            }
            catch { $r.TPMVersion = 'Present (version unknown)' }
        }
        else { $r.TPMVersion = 'Not Present' }
    }
    catch { $r.TPMVersion = 'Not Available' }

    # --- Secure Boot Certificates ---
    $certRows = [System.Collections.Generic.List[string]]::new()
    $revokedFound = [System.Collections.Generic.List[string]]::new()
    $certMinDays = [int]::MaxValue

    if ($r.FirmwareType -eq 'UEFI') {
        $certStores = @(
            @{ StoreName = 'DB';  Path = 'Cert:\LocalMachine\Shielded VM Local Certificates' }
        )

        # Primary Secure Boot cert stores via Get-SecureBootUEFI
        $sbVars = @('db', 'dbx', 'KEK', 'PK')
        foreach ($varName in $sbVars) {
            try {
                $sbVar = Get-SecureBootUEFI -Name $varName -ErrorAction Stop
                if ($sbVar -and $sbVar.Bytes) {
                    # Parse the EFI_SIGNATURE_LIST structure to extract certificates
                    # The data is raw bytes; extract X.509 certs by looking for the DER header (30 82)
                    $bytes = $sbVar.Bytes
                    $i = 0
                    while ($i -lt ($bytes.Length - 4)) {
                        # Look for DER sequence start (0x30) followed by length bytes
                        if ($bytes[$i] -eq 0x30 -and ($bytes[$i+1] -eq 0x82 -or $bytes[$i+1] -eq 0x81)) {
                            try {
                                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]($bytes[$i..([Math]::Min($i+4096,$bytes.Length-1))]))
                                if ($cert -and $cert.Subject) {
                                    $daysLeft    = [int]($cert.NotAfter - (Get-Date)).TotalDays
                                    $thumbprint  = $cert.Thumbprint
                                    $isRevoked   = $RevokedThumbprints -icontains $thumbprint
                                    $certAlertLvl = if ($isRevoked)              { 'Revoked'  }
                                                    elseif ($daysLeft -lt 0)     { 'Expired'  }
                                                    elseif ($daysLeft -lt $CertCritDays)  { 'Critical' }
                                                    elseif ($daysLeft -lt $CertWarnDays)  { 'Warning'  }
                                                    else                                  { 'OK'       }

                                    $certRows.Add("[$varName] $($cert.Subject) | Expires: $($cert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days) | $certAlertLvl$(if($isRevoked){' *** REVOKED ***'})")

                                    if ($isRevoked) { $revokedFound.Add("[$varName] $($cert.Subject) ($thumbprint)") }
                                    # Only update certMinDays for ACTIONABLE certs.
                                    # Hyper-V static PK is always expired but never needs action --
                                    # including it would make every VM show a false cert emergency.
                                    $isHyperVStaticPKEntry = ($varName -eq 'PK' -and $cert.Subject -match 'Hyper-V Firmware')
                                    if (-not $isHyperVStaticPKEntry -and $daysLeft -lt $certMinDays) {
                                        $certMinDays = $daysLeft
                                    }
                                }
                                $i += [Math]::Max(1, $cert.RawData.Length)
                                continue
                            }
                            catch { }
                        }
                        $i++
                    }
                }
            }
            catch { }  # Variable not present -- normal on some configs
        }

        # Also check Windows certificate stores for Microsoft UEFI CA certs
        $uefiCaStores = @('CA', 'AuthRoot', 'Root')
        foreach ($storeName in $uefiCaStores) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'LocalMachine')
            try {
                $store.Open('ReadOnly')
                $msCerts = @($store.Certificates | Where-Object {
                    $_.Subject -match 'Microsoft.*UEFI|UEFI.*CA|Secure Boot|Windows.*Production|Microsoft.*Root.*CA'
                })
                foreach ($cert in $msCerts) {
                    $daysLeft   = [int]($cert.NotAfter - (Get-Date)).TotalDays
                    $thumbprint = $cert.Thumbprint
                    $isRevoked  = $RevokedThumbprints -icontains $thumbprint
                    $certAlertLvl = if ($isRevoked)              { 'Revoked'  }
                                    elseif ($daysLeft -lt 0)     { 'Expired'  }
                                    elseif ($daysLeft -lt $CertCritDays)  { 'Critical' }
                                    elseif ($daysLeft -lt $CertWarnDays)  { 'Warning'  }
                                    else                                  { 'OK'       }

                    $certRows.Add("[Store:$storeName] $($cert.Subject) | Expires: $($cert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days) | $certAlertLvl$(if($isRevoked){' *** REVOKED ***'})")
                    if ($isRevoked) { $revokedFound.Add("[Store:$storeName] $($cert.Subject) ($thumbprint)") }
                    if ($daysLeft -lt $certMinDays) { $certMinDays = $daysLeft }
                }
                $store.Close()
            }
            catch { try { $store.Close() } catch {} }
        }
    }

    $r.SecureBootCerts  = $certRows -join ' || '
    $r.RevokedCertsFound = $revokedFound -join ' || '

    if ($certMinDays -ne [int]::MaxValue) {
        $r.CertExpiryDaysMin = $certMinDays
        $r.CertNearestExpiry = (Get-Date).AddDays($certMinDays).ToString('yyyy-MM-dd')
        if ($revokedFound.Count -gt 0) {
            $r.CertAlertLevel = 'Revoked'
            $issues.Add("REVOKED Secure Boot certificate(s) found: $($revokedFound -join '; ')")
            $r.AlertLevel = 'Critical'
        }
        elseif ($certMinDays -lt 0) {
            $r.CertAlertLevel = 'Expired'
            $issues.Add("EXPIRED Secure Boot certificate -- nearest expiry was $($certMinDays * -1) days ago.")
            $r.AlertLevel = 'Critical'
        }
        elseif ($certMinDays -lt $CertCritDays) {
            $r.CertAlertLevel = 'Critical'
            $issues.Add("Secure Boot certificate expires in $certMinDays days (CRITICAL).")
            if ($r.AlertLevel -ne 'Critical') { $r.AlertLevel = 'Critical' }
        }
        elseif ($certMinDays -lt $CertWarnDays) {
            $r.CertAlertLevel = 'Warning'
            $issues.Add("Secure Boot certificate expires in $certMinDays days (Warning).")
            if ($r.AlertLevel -eq 'OK') { $r.AlertLevel = 'Warning' }
        }
        else {
            $r.CertAlertLevel = 'OK'
        }
    }

    # --- Patch Scan ---
    if (-not $SkipPatches) {
        try {
            # Get all installed hotfixes
            $installedKBs = @(Get-HotFix -ErrorAction Stop | ForEach-Object { $_.HotFixID.ToUpper() })

            # Required KB check
            $missingRequired = [System.Collections.Generic.List[string]]::new()
            $kbStatusLines   = [System.Collections.Generic.List[string]]::new()

            foreach ($req in $RequiredKBList) {
                # RequiredKBList is passed as "KB|Description|Severity" delimited strings
                $parts = $req -split '\|'
                $kb    = $parts[0].ToUpper()
                $desc  = if ($parts.Count -gt 1) { $parts[1] } else { '' }
                $sev   = if ($parts.Count -gt 2) { $parts[2] } else { 'Important' }
                $installed = $installedKBs -icontains $kb

                $kbStatusLines.Add("$kb : $(if($installed){'INSTALLED'}else{'MISSING'}) [$sev] $desc")
                if (-not $installed) {
                    $missingRequired.Add("$kb ($sev)")
                    if ($sev -eq 'Critical') {
                        $issues.Add("Missing CRITICAL patch: $kb -- $desc")
                        $r.AlertLevel = 'Critical'
                    }
                    elseif ($sev -eq 'Important' -and $r.AlertLevel -eq 'OK') {
                        $issues.Add("Missing Important patch: $kb -- $desc")
                        $r.AlertLevel = 'Warning'
                    }
                }
            }

            $r.RequiredKBStatus     = $kbStatusLines -join ' || '
            $r.MissingRequiredKBs   = $missingRequired -join ', '
            $r.MissingRequiredCount = $missingRequired.Count
            # Ensure OSBuildNumber is populated (needed for KB compatibility matching)
            if (-not $r.OSBuildNumber) { 
                try { $r.OSBuildNumber = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber } catch {} 
            }

            # Pending Windows Update patches (not yet installed)
            try {
                $updateSession    = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
                $updateSearcher   = $updateSession.CreateUpdateSearcher()
                $searchResult     = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
                $pendingUpdates   = @($searchResult.Updates)
                $r.PendingPatchCount = $pendingUpdates.Count
                $r.PendingPatches = ($pendingUpdates | Select-Object -First 50 | ForEach-Object {
                    $kbs = ($_.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
                    "$($_.Title) [$kbs]"
                }) -join ' || '
                if ($pendingUpdates.Count -gt 0 -and $r.AlertLevel -eq 'OK') {
                    $r.AlertLevel = 'Warning'
                }
            }
            catch {
                $r.PendingPatches = "Windows Update COM query failed (WuauServ may be disabled or WSUS redirect): $($_.Exception.Message)"
            }
        }
        catch {
            $r.RequiredKBStatus = "Get-HotFix failed: $($_.Exception.Message)"
        }
    }

    $r.Issues = $issues -join ' | '
    return $r
}

# Serialize RequiredKBs for remoting (hashtables don't cross job boundary cleanly)
$requiredKBSerial = @($RequiredKBs | ForEach-Object { "$($_.KB)|$($_.Description)|$($_.Severity)" })

# ============================================================
# PHASE 3: PARALLEL COLLECTION
# ============================================================
Write-AuditLog "--- Phase 3: Collecting from $($reachable.Count) reachable servers (MaxParallel=$MaxParallel) ---" 'Info'

$results   = [System.Collections.Generic.List[PSObject]]::new()
$jobs      = [System.Collections.Generic.List[hashtable]]::new()
$completed = 0
$total     = $reachable.Count

foreach ($computer in $reachable) {
    # Throttle
    while (@($jobs | Where-Object { $_.Job.State -eq 'Running' }).Count -ge $MaxParallel) {
        Start-Sleep -Milliseconds 500
        # Harvest completed jobs
        $done = @($jobs | Where-Object { $_.Job.State -ne 'Running' })
        foreach ($d in $done) {
            try {
                $jobResult = Receive-Job -Job $d.Job -ErrorAction SilentlyContinue
                if ($jobResult) {
                    $row = [PSCustomObject]$jobResult
                    $row | Add-Member -NotePropertyName 'ComputerName'    -NotePropertyValue $d.Computer.Name      -Force
                    $row | Add-Member -NotePropertyName 'FQDN'            -NotePropertyValue $d.Computer.FQDN      -Force
                    $row | Add-Member -NotePropertyName 'Domain'          -NotePropertyValue $d.Computer.Domain    -Force
                    $row | Add-Member -NotePropertyName 'OperatingSystem' -NotePropertyValue $d.Computer.OperatingSystem -Force
                    $row | Add-Member -NotePropertyName 'LastLogonDate'   -NotePropertyValue $d.Computer.LastLogonDate -Force
                    $results.Add($row)
                }
                else {
                    $results.Add([PSCustomObject]@{
                        ComputerName = $d.Computer.Name; FQDN = $d.Computer.FQDN; Domain = $d.Computer.Domain
                        OperatingSystem = $d.Computer.OperatingSystem; LastLogonDate = $d.Computer.LastLogonDate
                        AlertLevel = 'Error'; Issues = 'No data returned from job'
                        FirmwareType = 'Unknown'; SecureBootEnabled = $false; SecureBootStatus = 'Error'
                        CollectionError = 'No data'
                    })
                }
            }
            catch {
                $results.Add([PSCustomObject]@{
                    ComputerName = $d.Computer.Name; FQDN = $d.Computer.FQDN; Domain = $d.Computer.Domain
                    OperatingSystem = $d.Computer.OperatingSystem; AlertLevel = 'Error'
                    Issues = "Job error: $($_.Exception.Message)"; FirmwareType = 'Unknown'
                    SecureBootEnabled = $false; SecureBootStatus = 'Error'; CollectionError = $_.Exception.Message
                })
            }
            Remove-Job -Job $d.Job -Force -ErrorAction SilentlyContinue
            $jobs.Remove($d)
            $completed++
            if ($completed % 10 -eq 0 -or $completed -eq $total) {
                Write-AuditLog "  Progress: $completed / $total collected" 'Info'
            }
        }
    }

    # Launch job
    # IMPORTANT: ScriptBlock objects cannot be serialized across Start-Job process
    # boundaries in PowerShell 5.1.  The fix is to pass the scriptblock as a plain
    # string and reconstitute it inside the job using [ScriptBlock]::Create().
    $sbText   = $collectionSB.ToString()
    $fqdn     = $computer.FQDN
    $credObj  = $computer.Credential   # PSCredential serializes cleanly

    $job = Start-Job -ScriptBlock {
        param(
            [string]$TargetFQDN,
            [System.Management.Automation.PSCredential]$Cred,
            [string]$SBText,
            [string[]]$KBSerial,
            [string[]]$Revoked,
            [bool]$SkipPatches,
            [int]$WarnDays,
            [int]$CritDays
        )
        try {
            # Reconstitute the scriptblock from its text representation
            $remSB = [ScriptBlock]::Create($SBText)

            $icParams = @{
                ComputerName = $TargetFQDN
                ScriptBlock  = $remSB
                ArgumentList = @($KBSerial, $Revoked, $SkipPatches, $WarnDays, $CritDays)
                ErrorAction  = 'Stop'
            }
            if ($Cred) { $icParams['Credential'] = $Cred }

            $result = Invoke-Command @icParams
            return $result
        }
        catch {
            $primaryErr = $_.Exception.Message

            # ── CIM fallback for WS2008R2 / WS2012R2 ──────────────────────────────
            # WS2008R2 and WS2012R2 remote runspaces use .NET 2.0 which cannot
            # instantiate generic List<T> -- this causes "Method invocation failed"
            # errors. Fall back to CIM/DCOM which works on .NET 2.0 targets.
            $cimResult = $null
            $cimErr    = ''
            try {
                $cimOpts = New-CimSessionOption -Protocol Dcom
                $cimSess = if ($Cred) {
                    New-CimSession -ComputerName $TargetFQDN -SessionOption $cimOpts -Credential $Cred -ErrorAction Stop
                } else {
                    New-CimSession -ComputerName $TargetFQDN -SessionOption $cimOpts -ErrorAction Stop
                }

                $os      = Get-CimInstance -CimSession $cimSess -ClassName Win32_OperatingSystem -ErrorAction Stop
                $cs      = Get-CimInstance -CimSession $cimSess -ClassName Win32_ComputerSystem -ErrorAction Stop
                $bios    = Get-CimInstance -CimSession $cimSess -ClassName Win32_BIOS -ErrorAction Stop
                $hfList  = Get-CimInstance -CimSession $cimSess -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue
                $installedKBs = @($hfList | ForEach-Object { $_.HotFixID.ToUpper() })

                # Check required KBs via CIM
                $missingReq = [System.Collections.ArrayList]::new()
                $kbStatusArr = [System.Collections.ArrayList]::new()
                foreach ($kbEntry in $KBSerial) {
                    $parts = $kbEntry -split '\|'
                    $kb = $parts[0].ToUpper(); $desc = if ($parts.Count -gt 1) { $parts[1] } else { '' }
                    $sev = if ($parts.Count -gt 2) { $parts[2] } else { 'Important' }
                    $installed = $installedKBs -icontains $kb
                    [void]$kbStatusArr.Add("$kb : $(if($installed){'INSTALLED'}else{'MISSING'}) [$sev]")
                    if (-not $installed) { [void]$missingReq.Add("$kb ($sev)") }
                }

                # Detect firmware type via WMI (CIM)
                $fwType = 'BIOS'
                try {
                    $uefiCheck = Invoke-CimMethod -CimSession $cimSess -ClassName Win32_ComputerSystem -MethodName GetRelated -ErrorAction SilentlyContinue
                    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') { $fwType = 'UEFI' }
                } catch {}

                # Try Confirm-SecureBootUEFI via Invoke-Command with simple scriptblock (no List<T>)
                $sbEnabled = $false
                $sbStatus  = 'Unknown (CIM fallback mode)'
                try {
                    $simpleSB = { Confirm-SecureBootUEFI -ErrorAction SilentlyContinue }
                    $sbResult = Invoke-Command -ComputerName $TargetFQDN -ScriptBlock $simpleSB `
                        -Credential:$(if($Cred){$Cred}else{$null}) -ErrorAction SilentlyContinue
                    if ($null -ne $sbResult) {
                        $sbEnabled = [bool]$sbResult
                        $sbStatus  = if ($sbEnabled) { 'Enabled' } else { 'Disabled (UEFI -- enable recommended)' }
                        $fwType    = 'UEFI'
                    }
                } catch {}

                Remove-CimSession -CimSession $cimSess -ErrorAction SilentlyContinue

                $cimResult = @{
                    Hostname             = $TargetFQDN
                    FirmwareType         = $fwType
                    SecureBootEnabled    = $sbEnabled
                    SecureBootSupported  = ($fwType -eq 'UEFI')
                    SecureBootStatus     = $sbStatus
                    SecureBootRecommendation = if ($fwType -eq 'BIOS') { 'Legacy BIOS -- migrate to UEFI to enable Secure Boot' } else { '' }
                    TPMVersion           = 'N/A (CIM fallback)'
                    Manufacturer         = $cs.Manufacturer
                    Model                = $cs.Model
                    BIOSVersion          = $bios.SMBIOSBIOSVersion
                    IsVirtual            = ($cs.Model -match 'Virtual|VMware|Hyper-V|Xen|KVM')
                    OSCaption            = $os.Caption
                    OSBuildNumber        = $os.BuildNumber
                    PendingPatchCount    = 0
                    PendingPatches       = 'Skipped in CIM fallback mode'
                    RequiredKBStatus     = ($kbStatusArr -join ' || ')
                    MissingRequiredKBs   = ($missingReq -join ', ')
                    MissingRequiredCount = $missingReq.Count
                    SecureBootCerts      = ''
                    CertAlertLevel       = 'N/A (CIM fallback -- cert check requires WinRM)'
                    CertExpiryDaysMin    = $null
                    CertNearestExpiry    = ''
                    RevokedCertsFound    = ''
                    AlertLevel           = if ($missingReq.Count -gt 0) { 'Critical' } else { 'OK' }
                    Issues               = "Collected via CIM/DCOM fallback (WinRM scriptblock failed: $primaryErr)"
                    CollectionError      = "WinRM failed; CIM fallback used: $primaryErr"
                    DataSource           = 'CIM-FALLBACK'
                }
                return $cimResult
            }
            catch {
                $cimErr = $_.Exception.Message
            }

            # Both WinRM and CIM failed
            return @{
                CollectionError  = "WinRM: $primaryErr | CIM: $cimErr"
                AlertLevel       = 'Error'
                SecureBootStatus = 'WinRM+CIM Error'
                FirmwareType     = 'Unknown'
                Hostname         = $TargetFQDN
                DataSource       = 'FAILED'
            }
        }
    } -ArgumentList @(
        $fqdn,
        $credObj,
        $sbText,
        $requiredKBSerial,
        $KnownRevokedThumbprints,
        [bool]$SkipPatchScan,
        $CertWarningDays,
        $CertCriticalDays
    )

    $jobs.Add(@{ Job = $job; Computer = $computer })
}

# Drain remaining jobs
while ($jobs.Count -gt 0) {
    Start-Sleep -Milliseconds 800
    $done = @($jobs | Where-Object { $_.Job.State -ne 'Running' })
    foreach ($d in $done) {
        try {
            $jobResult = Receive-Job -Job $d.Job -ErrorAction SilentlyContinue
            if ($jobResult) {
                $row = [PSCustomObject]$jobResult
                $row | Add-Member -NotePropertyName 'ComputerName'    -NotePropertyValue $d.Computer.Name -Force
                $row | Add-Member -NotePropertyName 'FQDN'            -NotePropertyValue $d.Computer.FQDN -Force
                $row | Add-Member -NotePropertyName 'Domain'          -NotePropertyValue $d.Computer.Domain -Force
                $row | Add-Member -NotePropertyName 'OperatingSystem' -NotePropertyValue $d.Computer.OperatingSystem -Force
                $row | Add-Member -NotePropertyName 'LastLogonDate'   -NotePropertyValue $d.Computer.LastLogonDate -Force
                $results.Add($row)
            }
        }
        catch { }
        Remove-Job -Job $d.Job -Force -ErrorAction SilentlyContinue
        $jobs.Remove($d)
        $completed++
    }
}

Write-AuditLog "Collection complete: $($results.Count) servers" 'Info'

# ============================================================
# ADD OFFLINE SERVERS
# ============================================================
foreach ($c in $unreachable) {
    $results.Add([PSCustomObject]@{
        ComputerName     = $c.Name; FQDN = $c.FQDN; Domain = $c.Domain
        OperatingSystem  = $c.OperatingSystem; LastLogonDate = $c.LastLogonDate
        FirmwareType     = 'Offline'; SecureBootEnabled = $false
        SecureBootStatus = 'Offline -- could not connect'; AlertLevel = 'Offline'
        Issues = 'Server did not respond to ping'
        SecureBootRecommendation = ''; Hostname = $c.Name
        Manufacturer = ''; Model = ''; BIOSVersion = ''; IsVirtual = $false
        OSCaption = ''; OSBuildNumber = ''; TPMVersion = ''
        PendingPatchCount = 0; PendingPatches = ''; MissingRequiredKBs = ''
        MissingRequiredCount = 0; RequiredKBStatus = ''
        SecureBootCerts = ''; CertAlertLevel = 'N/A'
        CertExpiryDaysMin = $null; CertNearestExpiry = ''; RevokedCertsFound = ''
        CollectionError = 'Offline'
    })
}

# ============================================================
# PHASE 4: EXPORT
# ============================================================
Write-AuditLog "--- Phase 4: Exporting results ---" 'Info'

# Summary stats
$criticalCount  = @($results | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
$warningCount   = @($results | Where-Object { $_.AlertLevel -eq 'Warning'  }).Count
$okCount        = @($results | Where-Object { $_.AlertLevel -eq 'OK'       }).Count
$errorCount     = @($results | Where-Object { $_.AlertLevel -eq 'Error'    }).Count
$offlineCount   = @($results | Where-Object { $_.AlertLevel -eq 'Offline'  }).Count
$biosCount      = @($results | Where-Object { $_.FirmwareType -eq 'BIOS'   }).Count
$uefiNoSB       = @($results | Where-Object { $_.FirmwareType -eq 'UEFI' -and $_.SecureBootEnabled -eq $false -and $_.AlertLevel -ne 'Offline' -and $_.AlertLevel -ne 'Error' }).Count
$sbEnabled      = @($results | Where-Object { $_.SecureBootEnabled -eq $true }).Count

Write-AuditLog "===== RESULTS SUMMARY =====" 'Info'
Write-AuditLog "  Total servers:        $($results.Count)" 'Info'
Write-AuditLog "  Secure Boot Enabled:  $sbEnabled" 'Info'
Write-AuditLog "  BIOS mode (no SB):    $biosCount" 'Warning'
Write-AuditLog "  UEFI but SB disabled: $uefiNoSB" 'Warning'
Write-AuditLog "  Critical alerts:      $criticalCount" $(if($criticalCount -gt 0){'Error'}else{'Info'})
Write-AuditLog "  Warning alerts:       $warningCount" $(if($warningCount -gt 0){'Warning'}else{'Info'})
Write-AuditLog "  OK:                   $okCount" 'Info'
Write-AuditLog "  Errors/WinRM fail:    $errorCount" 'Info'
Write-AuditLog "  Offline:              $offlineCount" 'Info'

# CSV
$summaryColumns = @('AlertLevel','PriorityBucket','ComputerName','Domain','FirmwareType','IsVirtual',
    'SecureBootEnabled','SecureBootStatus',
    'CertAlertLevel','CertExpiryDaysMin','CertNearestExpiry',
    'MissingRequiredCount','MissingRequiredKBs','RequiredKBStatus',
    'PendingPatchCount','TPMVersion','Manufacturer','Model',
    'OperatingSystem','OSCaption','OSBuildNumber',
    'LastLogonDate','SecureBootRecommendation','Issues','CollectionError','DataSource')

# ── Priority bucket assignment ──────────────────────────────────────────────────
foreach ($row in $results) {
    $ft     = $row.FirmwareType
    $sb     = $row.SecureBootEnabled
    $virt   = $row.IsVirtual
    $al     = $row.AlertLevel
    $mcount = 0
    try { $mcount = [int]("$($row.MissingRequiredCount)" -replace '[^0-9]','') } catch {}

    $bucket = switch ($true) {
        ($al -eq 'Offline')                                                          { 'P9-Offline' }
        ($al -eq 'Error')                                                            { 'P8-WinRM/CIM Error' }
        ($ft -eq 'UEFI' -and -not $sb -and $virt -ne $true)                        { 'P1-CRITICAL: Physical UEFI, Secure Boot Disabled' }
        ($ft -eq 'UEFI' -and $sb -eq $true -and $virt -ne $true -and $mcount -gt 0) { 'P2-CRITICAL: Physical UEFI, SB On, Patches Missing' }
        ($ft -eq 'UEFI' -and $sb -eq $true -and $virt -eq $true -and $mcount -gt 0) { 'P3-HIGH: VM UEFI, SB On, Patches Missing' }
        ($ft -eq 'UEFI' -and -not $sb -and $virt -eq $true)                        { 'P4-MEDIUM: VM UEFI, Secure Boot Disabled' }
        ($ft -eq 'BIOS' -and $virt -ne $true)                                       { 'P5-PLAN: Physical Server -- BIOS mode, migrate to UEFI' }
        ($ft -eq 'BIOS' -and $virt -eq $true)                                       { 'P6-PLAN: VM -- BIOS mode (Gen1 or MBR disk)' }
        ($ft -eq 'UEFI' -and $sb -eq $true -and $mcount -eq 0)                     { 'P0-OK: UEFI + Secure Boot + Patches Current' }
        default { 'P7-Unknown' }
    }
    $row | Add-Member -NotePropertyName 'PriorityBucket'    -NotePropertyValue $bucket -Force
    $row | Add-Member -NotePropertyName 'DataSource'        -NotePropertyValue ($(if($row.PSObject.Properties.Name -contains 'DataSource'){$row.DataSource}else{'WinRM'})) -Force
    $row | Add-Member -NotePropertyName 'RequiredKBStatus'  -NotePropertyValue ($(if($row.PSObject.Properties.Name -contains 'RequiredKBStatus'){$row.RequiredKBStatus}else{''})) -Force
    $row | Add-Member -NotePropertyName 'OSBuildNumber'     -NotePropertyValue ($(if($row.PSObject.Properties.Name -contains 'OSBuildNumber'){$row.OSBuildNumber}else{''})) -Force
}

# ── Certificate detail rows ──────────────────────────────────────────────────────
# Parse SecureBootCerts into one structured row per cert with role, action, post-patch state.
$certDetailRows = [System.Collections.Generic.List[PSObject]]::new()

# Known cert thumbprint / CN -> post-patch guidance lookup
$certGuidance = @{
    'KEK_2011' = @{
        Role   = 'Key Exchange Key (KEK) 2011 -- Authorizes updates to the Secure Boot db and dbx. Used by Windows Update to push new allowed/revoked boot software lists.'
        Action = 'Install KB5036210 to add KEK 2023 replacement. KEK 2011 expires 2026-06-25. After expiry, Secure Boot database updates will be blocked until KEK 2023 is present.'
        PostPatch = 'KEK 2023 (CN=Microsoft Corporation KEK 2K CA 2023, valid to 2038-03-03) added alongside KEK 2011. KEK 2011 is NOT removed -- both coexist. KEK 2023 handles all future db/dbx authorizations.'
    }
    'KEK_2023' = @{
        Role   = 'Key Exchange Key (KEK) 2023 -- Replacement for KEK 2011. Authorizes Secure Boot database updates from 2023 onwards.'
        Action = 'No action required. KEK 2023 is the current replacement. This server is ready for post-2026 Secure Boot updates.'
        PostPatch = 'Already in target state. No change from patching.'
    }
    'PK_HyperV' = @{
        Role   = 'Platform Key (PK) -- Hyper-V Firmware PK. This is the top-level Secure Boot owner key embedded in the Hyper-V Gen2 virtual firmware. It controls who can update KEK/db/dbx.'
        Action = 'NO ACTION REQUIRED. This PK is expired by design. Hyper-V Gen2 VMs use a static historical PK that Microsoft has intentionally not renewed because the PK itself does not participate in the boot verification chain -- only the KEK and db certs matter for daily operation. Expiration of this key does NOT break Secure Boot and does NOT allow unauthorized boot software.'
        PostPatch = 'Unchanged by any Windows patch. This key is firmware-embedded in the Hyper-V virtual BIOS and cannot be updated by Windows Update.'
    }
    'DB_MsUefiCA' = @{
        Role   = 'Signature Database (db) -- Microsoft UEFI CA. Authorizes non-Microsoft UEFI drivers and bootloaders: Linux shim bootloader, Dell iDRAC virtual media, VMware tools UEFI components, and third-party UEFI option ROMs. Without this cert, only Microsoft-signed software can boot.'
        Action = 'Install KB5036210 to update to Microsoft UEFI CA 2023. The 2011 CA cert expired 2019-12-31 -- while Windows can still boot (bootmgr uses the Windows Production CA, not this one), third-party UEFI software may fail signature validation.'
        PostPatch = 'Microsoft UEFI CA 2023 (CN=Microsoft UEFI CA 2023) added to db. Existing expired CA remains. Third-party UEFI software signed with 2023 key will now be permitted.'
    }
    'DB_MsWin' = @{
        Role   = 'Signature Database (db) -- Microsoft Windows Production PCA. The PRIMARY cert that authorizes all Microsoft-signed bootloaders: bootmgr.efi, winload.efi, and the Windows kernel. If this cert expires and is not replaced, Windows WILL NOT BOOT with Secure Boot enabled. This is the most critical cert in the chain for day-to-day operation.'
        Action = 'VERIFY: Microsoft Windows Production PCA 2011 expires 2026-01-18. If this cert is present and has no 2023 replacement alongside it, apply the latest Windows Cumulative Update -- the PCA 2023 cert is delivered via monthly CU starting late 2024. Check: Get-SecureBootUEFI -Name db | ... should show both CN=Microsoft Windows Production PCA 2011 (expiring) and CN=Microsoft Windows Production PCA 2023 (valid to 2038). If only 2011 is present, install latest CU immediately.'
        PostPatch = 'After latest Windows Cumulative Update (late 2024+): Microsoft Windows Production PCA 2023 (valid to 2038-01-18) added to UEFI db alongside PCA 2011. Both coexist. PCA 2011 remains until firmware is next updated. Windows bootloaders signed with PCA 2023 key will be preferred.'
    }
    'DB_MsDriverPublisher' = @{
        Role   = 'Signature Database (db) -- Microsoft Windows UEFI Driver Publisher. Authorizes UEFI-mode device drivers: network adapters, storage controllers, GPU firmware. Commonly found in the db store of Nutanix AHV VMs and Dell PowerEdge R770 servers. Expired 2021-05-09.'
        Action = 'This cert being expired means new UEFI drivers signed after 2021 may not validate under Secure Boot. Apply the latest Windows Cumulative Update -- the replacement Driver Publisher cert is delivered via Windows Update. This does NOT prevent Windows from booting (bootmgr uses Production PCA, not this cert).'
        PostPatch = 'After latest Windows Cumulative Update: Microsoft Windows UEFI Driver Publisher 2023 cert (valid through 2038) added to db alongside the expired 2021 cert. New hardware drivers signed post-2021 will validate correctly.'
    }
    'DBX' = @{
        Role   = 'Revocation Database (dbx) -- The Secure Boot blocklist. Contains hashes and certificates of known-compromised bootloaders that must never be allowed to run, even if they bear a valid signature. Updated by BootHole and BlackLotus patches.'
        Action = 'Install KB5012170 (BootHole DBX update) AND KB5025885 (BlackLotus DBX update). After install, set registry key ApplyNewRevocationPolicy=1. DBX update activates on next reboot.'
        PostPatch = 'DBX updated with: (1) BootHole revocation entries -- prevents GRUB2 versions affected by CVE-2020-10713 from booting. (2) BlackLotus revocation entries -- blocks the 2023 UEFI bootkit exploit chain. Any bootloader matching these entries will be blocked at firmware level, before the OS loads.'
    }
    'STORE' = @{
        Role   = 'Windows Certificate Store -- UEFI-related cert in the Windows trust store (not the UEFI firmware variables). Used by Windows to validate UEFI component signatures from the OS side, independent of firmware-level Secure Boot variables.'
        Action = 'Updated automatically by Windows Update (root certificate updates). No manual action typically required.'
        PostPatch = 'Updated via standard Windows Update root certificate delivery.'
    }
}

foreach ($row in $results) {
    $certsStr = ''
    if ($row.PSObject.Properties.Name -contains 'SecureBootCerts') { $certsStr = $row.SecureBootCerts }
    if (-not $certsStr) { continue }

    $entries = @($certsStr -split ' \|\| ' | Where-Object { $_.Trim() })
    $hasKEK2011 = $false; $hasKEK2023 = $false

    foreach ($entry in $entries) {
        $varVal   = if ($entry -match '^\[([^\]]+)\]') { $matches[1] } else { 'Unknown' }
        $subject  = if ($entry -match '\] (.+?) \|') { $matches[1].Trim() } else { $entry.Substring(0,[Math]::Min(80,$entry.Length)) }
        $days     = if ($entry -match '\((-?\d+) days\)') { [int]$matches[1] } else { $null }
        $expiry   = if ($entry -match 'Expires: (\d{4}-\d{2}-\d{2})') { $matches[1] } else { '' }
        $cal      = if ($entry -match '\|\s*(OK|Warning|Critical|Expired|Revoked)') { $matches[1] } else { 'Unknown' }
        $isRevoked = ($entry -match 'REVOKED')

        $isHyperVPK   = ($varVal -eq 'PK' -and $subject -match 'Hyper-V Firmware')
        $isKEK2011    = ($varVal -eq 'KEK' -and $subject -match '2011')
        $isKEK2023    = ($varVal -eq 'KEK' -and $subject -match '2023')
        $isDBMsUefiCA        = ($varVal -eq 'db' -and $subject -match 'UEFI CA')
        $isDBMsWin2011       = ($varVal -eq 'db' -and $subject -match 'Windows Production' -and $subject -match '2011')
        $isDBMsWin2023       = ($varVal -eq 'db' -and $subject -match 'Windows Production' -and $subject -match '2023')
        $isDBMsWin           = ($varVal -eq 'db' -and $subject -match 'Windows Production')
        $isDBDriverPublisher = ($varVal -eq 'db' -and $subject -match 'UEFI Driver Publisher')
        $isDBX               = ($varVal -eq 'dbx')
        $isStore             = ($varVal -match '^Store:')

        if ($isKEK2011) { $hasKEK2011 = $true }
        if ($isKEK2023) { $hasKEK2023 = $true }

        $guide = switch ($true) {
            $isHyperVPK          { $certGuidance['PK_HyperV'] }
            $isKEK2011           { $certGuidance['KEK_2011'] }
            $isKEK2023           { $certGuidance['KEK_2023'] }
            $isDBMsUefiCA        { $certGuidance['DB_MsUefiCA'] }
            $isDBDriverPublisher { $certGuidance['DB_MsDriverPublisher'] }
            $isDBMsWin           { $certGuidance['DB_MsWin'] }
            $isDBX               { $certGuidance['DBX'] }
            $isStore             { $certGuidance['STORE'] }
            default              { @{ Role='Other UEFI certificate.'; Action='Review manually.'; PostPatch='Unknown.' } }
        }

        # Determine alert level for this specific cert
        $certAlertFinal = if ($isRevoked)                                { 'Revoked' }
                          elseif ($isHyperVPK -and $days -lt 0)         { 'Expected-Expired (safe)' }
                          elseif ($isDBDriverPublisher -and $days -lt 0) { 'Expired (non-boot, apply CU)' }
                          else                                           { $cal }

        # Build specific action text based on cert type + state
        $actionFinal = if ($isRevoked) {
            'CRITICAL: Revoked cert. Apply DBX update (KB5012170 + KB5025885) immediately.'
        } elseif ($isKEK2011 -and $days -lt 60 -and $days -ge 0) {
            "URGENT: KEK 2011 expires in $days days. Install KB5036210 NOW to add KEK 2023 replacement before expiry."
        } elseif ($isKEK2011 -and $days -lt 0) {
            'CRITICAL: KEK 2011 has EXPIRED. Secure Boot database updates are now blocked. Install KB5036210 immediately to add KEK 2023.'
        } elseif ($isDBMsWin2011 -and $days -lt 180 -and $days -ge 0) {
            "WARNING: Windows Production PCA 2011 expires in $days days (2026-01-18). If this expires while Secure Boot is enabled, Windows WILL NOT BOOT. Apply latest Windows Cumulative Update immediately to add PCA 2023."
        } elseif ($isDBMsWin2011 -and $days -lt 0) {
            'CRITICAL: Windows Production PCA 2011 has EXPIRED. If Secure Boot is enabled, Windows may fail to boot on next update. Apply latest Windows Cumulative Update to add PCA 2023, then verify both certs present in db.'
        } else { $guide.Action }

        $certDetailRows.Add([PSCustomObject]@{
            PriorityBucket      = $row.PriorityBucket
            ComputerName        = $row.ComputerName
            Domain              = $row.Domain
            IsVirtual           = $row.IsVirtual
            FirmwareType        = $row.FirmwareType
            SecureBootEnabled   = $row.SecureBootEnabled
            OperatingSystem     = $row.OperatingSystem
            CertVariable        = $varVal
            CertSubject         = $subject
            ExpiryDate          = $expiry
            DaysRemaining       = $days
            CertAlertLevel      = $certAlertFinal
            IsBootCritical      = ($isDBMsWin -or $isKEK2011 -or $isKEK2023)
            IsRevoked           = $isRevoked
            IsHyperVStaticPK    = $isHyperVPK
            ActionNeeded        = (-not $isHyperVPK -and ($isRevoked -or $certAlertFinal -notin @('OK','Expected-Expired (safe)')))
            CertRole            = $guide.Role
            ActionRequired      = $actionFinal
            PostPatchExpected   = $guide.PostPatch
        })
    }

    # Cross-reference: flag servers with KEK 2011 but missing KEK 2023
    if ($hasKEK2011 -and -not $hasKEK2023) {
        foreach ($cr in @($certDetailRows | Where-Object { $_.ComputerName -eq $row.ComputerName -and $_.CertVariable -eq 'KEK' -and $_.CertSubject -match '2011' })) {
            $cr.ActionRequired = 'KEK 2023 REPLACEMENT MISSING on this server. ' + $cr.ActionRequired
        }
    }
}

$results | Sort-Object { $_.PriorityBucket }, ComputerName |
    Select-Object $summaryColumns |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Command Export-Excel -ErrorAction SilentlyContinue) {
    $sortedResults = @($results | Sort-Object { $_.PriorityBucket }, ComputerName)

    # ── Tab 1: Priority Action Plan ──────────────────────────────────────────────
    # Sorted by PriorityBucket -- P1 (most critical) first, P9 (offline) last.
    # Filter this tab to P1-P4 for immediate action items.
    # Tab 1: Summary
    $summaryRows = $sortedResults | Select-Object $summaryColumns

    $excelParams = @{
        Path          = $xlsxPath
        WorksheetName = 'Summary'
        AutoSize      = $true
        FreezeTopRow  = $true
        BoldTopRow    = $true
        Title         = "Secure Boot & Patch Compliance Audit -- $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    }

    $summaryRows | Export-Excel @excelParams `
        -ConditionalText @(
            New-ConditionalText -Text 'Critical'  -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
            New-ConditionalText -Text 'Warning'   -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
            New-ConditionalText -Text 'Offline'   -BackgroundColor '#E0E0E0' -ConditionalTextColor '#757575'
            New-ConditionalText -Text 'Error'     -BackgroundColor '#FFE0B2' -ConditionalTextColor '#E65100'
            New-ConditionalText -Text 'OK'        -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
            New-ConditionalText -Text 'BIOS'      -BackgroundColor '#FFF8E1' -ConditionalTextColor '#F57F17'
            New-ConditionalText -Text 'True'      -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
            New-ConditionalText -Text 'False'     -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
            New-ConditionalText -Text 'Revoked'   -BackgroundColor '#FF0000' -ConditionalTextColor '#FFFFFF'
            New-ConditionalText -Text 'Expired'   -BackgroundColor '#FF0000' -ConditionalTextColor '#FFFFFF'
        )

    # Tab 2: Patch Detail (one row per server with full KB status)
    $patchRows = @($sortedResults | Where-Object { $_.RequiredKBStatus -or $_.PendingPatches } |
        Select-Object ComputerName, Domain, OperatingSystem, AlertLevel,
                      MissingRequiredCount, MissingRequiredKBs, RequiredKBStatus,
                      PendingPatchCount, PendingPatches)

    if ($patchRows.Count -gt 0) {
        $patchRows | Export-Excel -Path $xlsxPath -WorksheetName 'PatchDetail' `
            -AutoSize -FreezeTopRow -BoldTopRow `
            -Title 'Required KB Status + Pending Patches per Server' `
            -ConditionalText @(
                New-ConditionalText -Text 'MISSING'    -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                New-ConditionalText -Text 'INSTALLED'  -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                New-ConditionalText -Text 'Critical'   -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                New-ConditionalText -Text 'Warning'    -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
            )
    }

    # ── Tab 3: Certificate Detail ──────────────────────────────────────────────────
    # One row per certificate per server. Explains what each cert does, current status,
    # and what changes after patches are applied. Key cert explanations:
    #
    #  [PK]  Platform Key -- top-level Secure Boot owner. Hyper-V VMs have an EXPIRED
    #        static PK by design. This is SAFE AND EXPECTED -- no action required.
    #        CertAlertLevel shows 'Expected-Expired (safe)' for this cert.
    #
    #  [KEK] Key Exchange Key -- authorizes db/dbx updates. KEK 2011 expires 2026-06-25.
    #        KB5036210 adds KEK 2023 alongside it. Filter ActionNeeded=True for servers
    #        where KEK 2011 is present but KEK 2023 replacement is MISSING.
    #
    #  [db]  Signature Database -- lists allowed bootloaders (Windows + UEFI drivers).
    #        Microsoft UEFI CA cert expired 2019-12-31 -- Windows still boots because
    #        bootmgr uses the Windows Production CA, not the UEFI CA. Third-party
    #        UEFI drivers may fail. KB5036210 adds the 2023 UEFI CA.
    #
    #  [dbx] Revocation Database -- blocklist of compromised bootloaders.
    #        Must be updated by KB5012170 (BootHole) + KB5025885 (BlackLotus).
    #        Activates on next reboot after ApplyNewRevocationPolicy=1 is set.
    #
    #  [Store:*] Windows certificate store certs -- managed by Windows Update automatically.

    if ($certDetailRows.Count -gt 0) {
        $certDetailRows | Sort-Object PriorityBucket, ComputerName, CertVariable |
            Export-Excel -Path $xlsxPath -WorksheetName 'CertificateDetail' `
                -AutoSize -FreezeTopRow -BoldTopRow `
                -Title 'Secure Boot Certificate Analysis -- Role, Status, Action Required, Post-Patch Expected State' `
                -ConditionalText @(
                    New-ConditionalText -Text 'Revoked'              -BackgroundColor '#FF0000' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Critical'             -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'URGENT'               -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Expired'              -BackgroundColor '#FFDDC1' -ConditionalTextColor '#7B2D00'
                    New-ConditionalText -Text 'Expected-Expired'     -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    New-ConditionalText -Text 'Warning'              -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'OK'                   -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    New-ConditionalText -Text 'NO ACTION REQUIRED'   -BackgroundColor '#F3F3F3' -ConditionalTextColor '#555555'
                    New-ConditionalText -Text 'KEK 2023 REPLACEMENT MISSING' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'True'                 -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                )
        Write-AuditLog "  CertificateDetail: $($certDetailRows.Count) cert rows across $(($certDetailRows | Select-Object ComputerName -Unique).Count) servers" 'Info'
    } else {
        Write-AuditLog "  CertificateDetail: no cert data (SecureBootCerts only populated on UEFI servers with SB enabled)" 'Info'
    }

    # ── Tab 4: BIOS Migration Plan ───────────────────────────────────────────────────
    # Servers in Legacy BIOS mode.  Secure Boot cannot be enabled until UEFI migration.
    # IsVirtual=True -> Gen1 VM or Gen2 with MBR disk (use MBR2GPT or rebuild as Gen2).
    # IsVirtual=False -> Physical server (update firmware mode, run MBR2GPT, enable SB).
    $biosRows = @($sortedResults | Where-Object { $_.FirmwareType -eq 'BIOS' -and $_.AlertLevel -ne 'Offline' } |
        Select-Object PriorityBucket, ComputerName, Domain, OperatingSystem, IsVirtual,
                      Manufacturer, Model, BIOSVersion, OSBuildNumber,
                      SecureBootRecommendation, LastLogonDate)

    if ($biosRows.Count -gt 0) {
        $biosRows | Sort-Object IsVirtual, ComputerName |
            Export-Excel -Path $xlsxPath -WorksheetName 'BIOS-Migration' `
                -AutoSize -FreezeTopRow -BoldTopRow `
                -Title 'BIOS Mode Servers -- UEFI Migration Required.  Physical servers first; VMs via MBR2GPT or Gen2 rebuild.' `
                -ConditionalText @(
                    New-ConditionalText -Text 'False' -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'True'  -BackgroundColor '#E3F2FD' -ConditionalTextColor '#0D47A1'
                )
    }

    # ── Tab 5: KEK Certificate Cross-Reference ────────────────────────────────────
    # Focuses specifically on the KEK 2011 expiry issue (expires 2026-06-25).
    # Shows which servers have KEK 2011 without KEK 2023 replacement -- URGENT action.
    # Also confirms which servers already have KEK 2023 (post-patch state achieved).
    $kekRows = @($certDetailRows | Where-Object { $_.CertVariable -eq 'KEK' } |
        Select-Object PriorityBucket, ComputerName, Domain, IsVirtual, FirmwareType,
                      SecureBootEnabled, OperatingSystem, CertSubject, ExpiryDate,
                      DaysRemaining, CertAlertLevel, ActionRequired, PostPatchExpected)

    if ($kekRows.Count -gt 0) {
        $kekRows | Sort-Object DaysRemaining, ComputerName |
            Export-Excel -Path $xlsxPath -WorksheetName 'KEK-Cert-Status' `
                -AutoSize -FreezeTopRow -BoldTopRow `
                -Title 'KEK Certificate Status -- KEK 2011 expires 2026-06-25.  KB5036210 adds KEK 2023 replacement.' `
                -ConditionalText @(
                    New-ConditionalText -Text 'KEK 2023 REPLACEMENT MISSING' -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'URGENT'     -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text '2023'       -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                    New-ConditionalText -Text 'Critical'   -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                    New-ConditionalText -Text 'Warning'    -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                    New-ConditionalText -Text 'OK'         -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
                )
    }

    Write-AuditLog "XLSX written: $xlsxPath (5 tabs: Summary | PatchDetail | CertificateDetail | BIOS-Migration | KEK-Cert-Status)" 'Success'
}
else {
    Write-AuditLog "ImportExcel module not available -- CSV only. Install: Install-Module ImportExcel -Scope CurrentUser" 'Warning'
}

Write-AuditLog "CSV written:  $csvPath" 'Success'
Write-AuditLog "Log:          $logPath" 'Success'
Write-AuditLog "===== Audit Complete =====" 'Success'

Write-AuditLog "Activity log: $activityLog" 'Info'
Write-AuditLog "Transcript:   $transcriptLog" 'Info'
try { Stop-Transcript | Out-Null } catch {}
Write-Host "[Transcript stopped]" -ForegroundColor DarkGray
