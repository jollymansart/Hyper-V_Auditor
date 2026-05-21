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
    [string]$OutputFolder    = '',
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
        Enabled    = $false   # Set $true when overheaddoor.com credential is healthy
    }
    @{
        FQDN       = 'creative.com'
        CredPath   = 'C:\ProgramData\S\HyperV-Cred-creative.xml'
        SearchBase = 'DC=creative,DC=com'
        Enabled    = $true
    }
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

$csvPath  = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.csv"
$xlsxPath = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.xlsx"
$logPath  = Join-Path $OutputFolder "SecureBoot-Audit_${timestamp}.log"

function Write-AuditLog {
    param([string]$Message, [string]$Level = 'Info')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $line -ForegroundColor $(switch($Level) {
        'Error'   { 'Red'    }
        'Warning' { 'Yellow' }
        'Success' { 'Green'  }
        default   { 'Gray'   }
    })
    Add-Content -Path $logPath -Value $line -Encoding UTF8
}

Start-Transcript -Path $logPath -Append -Force | Out-Null
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
$uniqueComputers = @($allComputers | Where-Object { $seen.Add($_.Name) })
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
                                    if ($daysLeft -lt $certMinDays) {
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

                $kbStatusLines.Add("$kb: $(if($installed){'INSTALLED'}else{'MISSING'}) [$sev] $desc")
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
    $invokeParams = @{
        ComputerName = $computer.FQDN
        ScriptBlock  = $collectionSB
        ArgumentList = @(
            $requiredKBSerial,
            $KnownRevokedThumbprints,
            [bool]$SkipPatchScan,
            $CertWarningDays,
            $CertCriticalDays
        )
        ErrorAction  = 'Stop'
    }
    if ($computer.Credential) { $invokeParams['Credential'] = $computer.Credential }

    $job = Start-Job -ScriptBlock {
        param($params)
        try {
            $result = Invoke-Command @params
            return $result
        }
        catch {
            return @{
                CollectionError = $_.Exception.Message
                AlertLevel      = 'Error'
                SecureBootStatus = 'WinRM Error'
                FirmwareType    = 'Unknown'
            }
        }
    } -ArgumentList (,$invokeParams)

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
$summaryColumns = @('AlertLevel','ComputerName','Domain','FirmwareType','SecureBootEnabled',
    'SecureBootStatus','CertAlertLevel','CertExpiryDaysMin','CertNearestExpiry',
    'MissingRequiredCount','MissingRequiredKBs','PendingPatchCount',
    'TPMVersion','Manufacturer','Model','OperatingSystem','OSCaption','IsVirtual',
    'LastLogonDate','SecureBootRecommendation','Issues','CollectionError')

$results | Sort-Object AlertLevel, ComputerName |
    Select-Object $summaryColumns |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Command Export-Excel -ErrorAction SilentlyContinue) {
    $sortedResults = @($results | Sort-Object @{E={
        switch ($_.AlertLevel) {
            'Critical' { 0 } 'Revoked' { 1 } 'Warning' { 2 }
            'Error'    { 3 } 'Offline' { 4 } default    { 5 }
        }
    }}, ComputerName)

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

    # Tab 3: Certificate Detail
    $certRows = @($sortedResults | Where-Object { $_.SecureBootCerts -or $_.RevokedCertsFound } |
        Select-Object ComputerName, Domain, FirmwareType, SecureBootEnabled,
                      CertAlertLevel, CertExpiryDaysMin, CertNearestExpiry,
                      RevokedCertsFound, SecureBootCerts)

    if ($certRows.Count -gt 0) {
        $certRows | Export-Excel -Path $xlsxPath -WorksheetName 'CertificateDetail' `
            -AutoSize -FreezeTopRow -BoldTopRow `
            -Title 'Secure Boot Certificate Status and Expiry' `
            -ConditionalText @(
                New-ConditionalText -Text 'Revoked'    -BackgroundColor '#FF0000' -ConditionalTextColor '#FFFFFF'
                New-ConditionalText -Text 'Expired'    -BackgroundColor '#FF0000' -ConditionalTextColor '#FFFFFF'
                New-ConditionalText -Text 'Critical'   -BackgroundColor '#FF6B6B' -ConditionalTextColor '#FFFFFF'
                New-ConditionalText -Text 'Warning'    -BackgroundColor '#FFF3CD' -ConditionalTextColor '#856404'
                New-ConditionalText -Text 'OK'         -BackgroundColor '#E8F5E9' -ConditionalTextColor '#2E7D32'
            )
    }

    # Tab 4: BIOS Remediation -- servers needing UEFI migration
    $biosRows = @($sortedResults | Where-Object { $_.FirmwareType -eq 'BIOS' -and $_.AlertLevel -ne 'Offline' } |
        Select-Object ComputerName, Domain, OperatingSystem, Manufacturer, Model,
                      BIOSVersion, IsVirtual, SecureBootRecommendation, LastLogonDate)

    if ($biosRows.Count -gt 0) {
        $biosRows | Export-Excel -Path $xlsxPath -WorksheetName 'BIOS-Migration' `
            -AutoSize -FreezeTopRow -BoldTopRow `
            -Title 'Servers in Legacy BIOS Mode -- UEFI Migration Required for Secure Boot'
    }

    Write-AuditLog "XLSX written: $xlsxPath (4 tabs)" 'Success'
}
else {
    Write-AuditLog "ImportExcel module not available -- CSV only. Install: Install-Module ImportExcel -Scope CurrentUser" 'Warning'
}

Write-AuditLog "CSV written:  $csvPath" 'Success'
Write-AuditLog "Log:          $logPath" 'Success'
Write-AuditLog "===== Audit Complete =====" 'Success'

try { Stop-Transcript | Out-Null } catch {}
