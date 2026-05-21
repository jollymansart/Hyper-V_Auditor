<#
.SYNOPSIS
    Hyper-V Inventory Report Launcher v3.2.0
    
.DESCRIPTION
    Config-driven launcher for the Hyper-V Inventory module.
    Reads Config.psd1 for credential definitions, output paths, and report options.
    No company-specific variables -- fully portable across environments.
    
.NOTES
    Prerequisites:
    1. CredSSP enabled (if UseCredSSP = $true in config):
       Enable-WSManCredSSP -Role Client -DelegateComputer "*.yourdomain.com" -Force
    2. Credentials saved via Export-Clixml (see Config.psd1 for paths)
    3. ImportExcel module: Install-Module -Name ImportExcel -Scope CurrentUser
    
    First-time setup:
    1. Edit Config.psd1 with your domain info and credential paths
    2. For each credential slot:
       Get-Credential -Message "Description" | Export-Clixml "C:\ProgramData\S\HyperV-Cred.xml"
    3. Run this script

    $env:HYPERVREPORT_DEBUG_DUMP = '1'
#>

$env:HYPERVREPORT_DEBUG_DUMP = '1'

# Determine script location
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# --- Early Transcript: capture everything from first line ---
# Start a temporary transcript immediately so that Configuration, Pre-requisites,
# Module Check, Preflight Gate, and Credential validation are all captured in the log.
# Once the output path is resolved below, this temp log is moved into the report folder.
$earlyTimestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$tempTranscript  = Join-Path $env:TEMP "HyperV-Report_${earlyTimestamp}_startup.log"
$earlyTranscriptStarted = $false
try {
    Start-Transcript -Path $tempTranscript -Force | Out-Null
    $earlyTranscriptStarted = $true
}
catch {
    Write-Host "[WARNING] Could not start early transcript: $($_.Exception.Message)" -ForegroundColor Yellow
    $tempTranscript = $null
}

# --- Load Configuration ---
Write-Host "===== Configuration =====" -ForegroundColor Cyan

$configPath = Join-Path $scriptDir "Config-OHDC.psd1"
if (-not (Test-Path $configPath)) {
    Write-Host "Config file not found: $configPath" -ForegroundColor Red
    Write-Host "Copy Config.psd1 template to: $scriptDir" -ForegroundColor Yellow
    return
}

$config = Import-PowerShellDataFile -Path $configPath
Write-Host "Loaded config v$($config.Version) from: $configPath" -ForegroundColor Gray

# --- Pre-requisites Validation ---
Write-Host "===== Pre-requisites =====" -ForegroundColor Cyan

# Check and install required modules/features
$prereqFailed = $false

# 1. ImportExcel module (required for report export)
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "  [INSTALL] ImportExcel module not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module -Name ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
        Write-Host "  [OK] ImportExcel installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] Failed to install ImportExcel: $($_.Exception.Message)" -ForegroundColor Red
        $prereqFailed = $true
    }
}
else {
    Write-Host "  [OK] ImportExcel module" -ForegroundColor Gray
}

# 2. ActiveDirectory module (required for host/VM discovery and AD enrichment)
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "  [INSTALL] ActiveDirectory module not found. Installing RSAT..." -ForegroundColor Yellow
    try {
        # Windows Server: Install as feature
        if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) {
            Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
        }
        else {
            # Windows 10/11: Install as capability
            Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop | Out-Null
        }
        Write-Host "  [OK] ActiveDirectory RSAT installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] Failed to install AD RSAT: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         Manual: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Yellow
        $prereqFailed = $true
    }
}
else {
    Write-Host "  [OK] ActiveDirectory module" -ForegroundColor Gray
}

# 3. FailoverClusters module (required for cluster inventory)
if (-not (Get-Module -ListAvailable -Name FailoverClusters)) {
    Write-Host "  [INSTALL] FailoverClusters module not found. Installing..." -ForegroundColor Yellow
    try {
        if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) {
            Install-WindowsFeature RSAT-Clustering-PowerShell -ErrorAction Stop | Out-Null
        }
        else {
            Add-WindowsCapability -Online -Name "Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0" -ErrorAction Stop | Out-Null
        }
        Write-Host "  [OK] FailoverClusters RSAT installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARN] FailoverClusters not available. Cluster inventory will use host-side data only." -ForegroundColor DarkYellow
    }
}
else {
    Write-Host "  [OK] FailoverClusters module" -ForegroundColor Gray
}

# 4. Hyper-V PowerShell module (optional - used for connectivity testing)
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Write-Host "  [INSTALL] Hyper-V PowerShell module not found. Installing..." -ForegroundColor Yellow
    try {
        if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) {
            Install-WindowsFeature RSAT-Hyper-V-Tools, Hyper-V-PowerShell -ErrorAction Stop | Out-Null
        }
        else {
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart -ErrorAction Stop | Out-Null
        }
        Write-Host "  [OK] Hyper-V PowerShell installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARN] Hyper-V module not available locally. Host testing uses remote commands." -ForegroundColor DarkYellow
    }
}
else {
    Write-Host "  [OK] Hyper-V PowerShell module" -ForegroundColor Gray
}

# 5. CredSSP client configuration check
if ($config.UseCredSSP) {
    $credSSPState = Get-WSManCredSSP -ErrorAction SilentlyContinue 2>&1
    if ($credSSPState -match 'not configured to allow delegating') {
        Write-Host "  [WARN] CredSSP client delegation not enabled. Run:" -ForegroundColor DarkYellow
        Write-Host "         Enable-WSManCredSSP -Role Client -DelegateComputer '*.ohdc.com' -Force" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] CredSSP client enabled" -ForegroundColor Gray
    }
}

# 6. PowerShell version check
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "  [ERROR] PowerShell 5.1+ required. Current: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    $prereqFailed = $true
}
else {
    Write-Host "  [OK] PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Gray
}

# 7. WinRM service check
$winrm = Get-Service WinRM -ErrorAction SilentlyContinue
if (-not $winrm -or $winrm.Status -ne 'Running') {
    Write-Host "  [WARN] WinRM service not running. Starting..." -ForegroundColor DarkYellow
    try { Start-Service WinRM -ErrorAction Stop; Write-Host "  [OK] WinRM started" -ForegroundColor Green }
    catch { Write-Host "  [ERROR] Cannot start WinRM: $($_.Exception.Message)" -ForegroundColor Red; $prereqFailed = $true }
}
else {
    Write-Host "  [OK] WinRM service running" -ForegroundColor Gray
}

if ($prereqFailed) {
    Write-Host "`n  [FATAL] One or more required prerequisites failed. Cannot continue." -ForegroundColor Red
    Write-Host "  Fix the issues above and re-run the script." -ForegroundColor Yellow
    return
}

# Unblock files from network share
if (Test-Path "$scriptDir\Pre-Requisite\Unblock-DF.ps1") {
    . "$scriptDir\Pre-Requisite\Unblock-DF.ps1"
    Unblock-DF -Path $scriptDir -Recurse
}

# Import module (prefer PSD1 manifest for version tracking)
$psd1Path = Join-Path $scriptDir "HyperVInventory.psd1"
$psm1Path = Join-Path $scriptDir "HyperVInventory.psm1"
if (Test-Path $psd1Path) {
    Write-Host "Loading module: $psd1Path" -ForegroundColor Gray
    Import-Module $psd1Path -Force -Verbose
}
elseif (Test-Path $psm1Path) {
    Write-Host "Loading module: $psm1Path (no manifest)" -ForegroundColor Yellow
    Import-Module $psm1Path -Force -Verbose
}

# --- Load Credentials from Config ---
Write-Host "===== Credentials =====" -ForegroundColor Cyan

$primaryCred = $null
$domainCredentials = @{}

foreach ($credDef in $config.Credentials) {
    $credName = $credDef.Name
    $credPath = $credDef.StoredPath
    $credDomain = $credDef.DomainFQDN
    $credDesc = $credDef.Description
    $isPrimary = $credDef.IsPrimary
    
    # Skip entries with no domain configured (unless primary)
    if ((-not $credDomain -or $credDomain -eq '') -and -not $isPrimary) {
        Write-Host "  [SKIP] $credName - no DomainFQDN configured" -ForegroundColor DarkGray
        continue
    }
    
    if (-not (Test-Path $credPath)) {
        if ($isPrimary) {
            Write-Host "No saved credential for primary ($credDesc). Creating now..." -ForegroundColor Yellow
            Get-Credential -Message "Enter credentials for: $credDesc" | Export-Clixml $credPath
        }
        else {
            Write-Host "  [SKIP] $credName ($credDesc) - credential file not found: $credPath" -ForegroundColor Yellow
            Write-Host "         To create: Get-Credential | Export-Clixml '$credPath'" -ForegroundColor Yellow
            continue
        }
    }
    
    try {
        $cred = Import-Clixml $credPath
        Write-Host "  [OK] $credName : $($cred.UserName) ($credDesc)" -ForegroundColor Gray
        
        if ($isPrimary) {
            $primaryCred = $cred
        }
        
        # v3.8.1: Domain credential map now supports MULTIPLE credentials per domain.
        # The first/primary credential for each domain claims the base key (e.g. 'ohdc.com').
        # Additional credentials for the same domain are stored under synthetic keys
        # (e.g. 'ohdc.com_2', 'ohdc.com_3') so the fallback logic in Test-HyperVHost and
        # Get-VMOperatingSystemInfo can iterate them all.
        # IsPrimary entries always claim the base domain key; if one was already there,
        # the displaced credential is demoted to a synthetic key.
        if ($credDomain -and $credDomain -ne '') {
            $domLower = $credDomain.ToLower()
            if ($isPrimary -or -not $domainCredentials.ContainsKey($domLower)) {
                # If primary is replacing an existing entry, demote the old one
                if ($isPrimary -and $domainCredentials.ContainsKey($domLower)) {
                    $existingCred = $domainCredentials[$domLower]
                    $idx = 2
                    while ($domainCredentials.ContainsKey("${domLower}_$idx")) { $idx++ }
                    $domainCredentials["${domLower}_$idx"] = $existingCred
                }
                $domainCredentials[$domLower] = $cred
            }
            else {
                # Additional credential for this domain -- store under synthetic key
                $idx = 2
                while ($domainCredentials.ContainsKey("${domLower}_$idx")) { $idx++ }
                $domainCredentials["${domLower}_$idx"] = $cred
            }
        }
    }
    catch {
        Write-Host "  [ERROR] Failed to load $credName from $credPath : $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $primaryCred) {
    Write-Host "No primary credential loaded. Cannot proceed." -ForegroundColor Red
    return
}

# Check primary account lockout (if AD module available)
if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
    try {
        $adUser = Get-ADUser ($primaryCred.GetNetworkCredential().UserName) -Properties LockedOut -ErrorAction SilentlyContinue
        if ($adUser -and $adUser.LockedOut) {
            Write-Host "Primary account is locked out. Waiting for unlock..." -ForegroundColor Yellow
            do {
                Start-Sleep -Seconds 30
                $adUser = Get-ADUser ($primaryCred.GetNetworkCredential().UserName) -Properties LockedOut
            } while ($adUser.LockedOut)
            Write-Host "Account unlocked!" -ForegroundColor Green
        }
        Write-Host "Primary: $($primaryCred.UserName) | Locked: $($adUser.LockedOut)" -ForegroundColor Gray
    }
    catch {
        Write-Host "Could not check AD lockout status (continuing): $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# v3.8.1: Show all loaded credentials including fallback entries
$uniqueDomains = @($domainCredentials.Keys | ForEach-Object { ($_ -replace '_\d+$','') } | Sort-Object -Unique)
$totalCreds    = $domainCredentials.Count
Write-Host "Domain credentials loaded: $($uniqueDomains -join ', ') ($totalCreds credential(s) total)" -ForegroundColor Cyan

# --- Credential Precheck ---
# v3.8.1: Three-phase validation for each credential BEFORE starting the inventory run:
#   Test 1: AD connectivity   -- Get-ADDomain (ADWS), falls back to LDAP for Server 2003 DCs
#   Test 2: Kerberos TGT      -- Validates the credential can obtain/has a valid TGT from the KDC
#   Test 3: WinRM connectivity -- Test-WSMan against domain DCs
# A failed credential here means those VMs/hosts will show no data in the report.
Write-Host "===== Credential Precheck =====" -ForegroundColor Cyan

$credPrecheckFailed = $false

foreach ($credDef in $config.Credentials) {
    $credDomain = $credDef.DomainFQDN
    $credName   = $credDef.Name
    $credPath   = $credDef.StoredPath
    $isPrimary  = $credDef.IsPrimary

    if (-not $credDomain -or $credDomain -eq '') { continue }
    if (-not (Test-Path $credPath)) { continue }

    try { $cred = Import-Clixml $credPath } catch { continue }

    $adOk    = $false
    $winrmOk = $false
    $adErr   = ''
    $winrmErr = ''

    # Test 1: AD connectivity -- try ADWS first (Get-ADDomain), fall back to LDAP for Server 2003 DCs
    $adMethod = 'ADWS'
    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
        try {
            $adParams = @{ Server = $credDomain; ErrorAction = 'Stop' }
            if (-not $isPrimary) { $adParams['Credential'] = $cred }
            $null = Get-ADDomain @adParams
            $adOk = $true
        }
        catch {
            $adErr = $_.Exception.Message -replace '
?
.*',''
            # ADWS unavailable (Server 2003 / AD Web Services not running) -- try LDAP bind
            if ($adErr -match 'Unable to contact|9389|not.*running|does not exist|cannot be contacted') {
                $adMethod = 'LDAP'
                try {
                    if ($cred -and -not $isPrimary) {
                        $de = New-Object System.DirectoryServices.DirectoryEntry(
                            "LDAP://$credDomain", $cred.UserName, $cred.GetNetworkCredential().Password)
                    } else {
                        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$credDomain")
                    }
                    $null = $de.Name
                    $de.Dispose()
                    $adOk  = $true
                    $adErr = 'Server 2003 DC (no ADWS) -- AD audit data will be limited'
                }
                catch { $adErr = "ADWS+LDAP both failed: $($_.Exception.Message -replace '
?
.*','')" }
            }
        }
    } else {
        $adOk = $true   # AD module not available -- skip this test
    }

    # Test 2: Kerberos TGT validation (v3.8.1)
    # Verifies the credential can obtain a Kerberos TGT from the KDC.
    # Catches: expired passwords, clock skew, disabled accounts, missing pre-auth,
    # and accounts that pass LDAP bind but cannot get service tickets for WSMAN/HOST SPNs.
    # Primary credential: runs klist in the current session.
    # Non-primary: runs klist inside an Invoke-Command -ComputerName localhost with
    # the credential, which forces a new logon session and TGT request.
    $krbOk    = $false
    $krbErr   = ''
    $krbLabel = ''
    $krbRealm = $credDomain.ToUpper()

    try {
        if ($isPrimary) {
            # Primary credential: TGT is already in the current logon session
            $klistOutput = & klist 2>&1 | Out-String
            if ($klistOutput -match "krbtgt/$krbRealm" -or $klistOutput -match "krbtgt/\S+\s*@\s*$krbRealm") {
                $krbOk = $true
                # Parse ticket expiry if present
                if ($klistOutput -match "End Time\s*:\s*(\d+/\d+/\d+\s+\d+:\d+:\d+)") {
                    $krbExpiry = $Matches[1]
                    try {
                        $krbExpiryDT = [datetime]::Parse($krbExpiry)
                        $krbMinLeft  = [math]::Round(($krbExpiryDT - (Get-Date)).TotalMinutes)
                        if ($krbMinLeft -lt 60) {
                            $krbLabel = "Krb: OK (TGT expires in ${krbMinLeft}min -- consider klist purge + fresh logon)"
                        }
                        elseif ($krbMinLeft -lt 0) {
                            $krbOk    = $false
                            $krbErr   = "TGT expired $([math]::Abs($krbMinLeft)) minutes ago"
                            $krbLabel = "Krb: EXPIRED"
                        }
                        else {
                            $krbLabel = "Krb: OK"
                        }
                    }
                    catch { $krbLabel = "Krb: OK" }
                }
                else {
                    $krbLabel = "Krb: OK"
                }
            }
            elseif ($klistOutput -match 'Cached Tickets: \(0\)' -or $klistOutput -notmatch 'krbtgt') {
                $krbErr   = "No TGT found in current session for $krbRealm (klist shows 0 tickets or no krbtgt)"
                $krbLabel = "Krb: NO TGT"
            }
            else {
                # Has tickets but not for this realm
                $krbErr   = "TGT present but not for realm $krbRealm"
                $krbLabel = "Krb: WRONG REALM"
            }
        }
        else {
            # Non-primary: create a logon session with the credential via localhost Invoke-Command.
            # This forces Windows to request a TGT from the KDC for this credential.
            # If the TGT request fails (bad password, expired, locked, etc.), the Invoke-Command
            # itself will throw an authentication error -- that IS the Kerberos test.
            #
            # v3.8.3: Cross-domain credentials (credential domain != machine domain) cannot create
            # a local logon session via Invoke-Command localhost -- the DC for the foreign domain
            # won't accept a local logon on this machine. For cross-domain creds, we skip the
            # localhost test and rely on the AD connectivity test (which already validated the
            # credential can bind to the foreign domain's AD).
            $machineDomain = try {
                ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name.ToLower()
            } catch { $env:USERDNSDOMAIN.ToLower() }
            $isCrossDomain = $credDomain.ToLower() -ne $machineDomain

            if ($isCrossDomain) {
                # Cross-domain: localhost Kerberos test not applicable.
                # AD test already confirmed the credential can authenticate to the foreign domain.
                if ($adOk) {
                    $krbOk    = $true
                    $krbLabel = "Krb: SKIP (cross-domain -- validated via AD bind)"
                }
                else {
                    $krbErr   = "Cross-domain credential -- AD bind also failed"
                    $krbLabel = "Krb: SKIP (AD FAIL)"
                }
            }
            else {
            # Same-domain non-primary: test via localhost Invoke-Command
            try {
                $krbTestResult = Invoke-Command -ComputerName localhost -Credential $cred -ErrorAction Stop -ScriptBlock {
                    $out = & klist 2>&1 | Out-String
                    return $out
                }
                if ($krbTestResult -match 'krbtgt') {
                    $krbOk    = $true
                    $krbLabel = "Krb: OK"
                    # Check expiry in the remote session output
                    if ($krbTestResult -match "End Time\s*:\s*(\d+/\d+/\d+\s+\d+:\d+:\d+)") {
                        try {
                            $krbExpiryDT = [datetime]::Parse($Matches[1])
                            $krbMinLeft  = [math]::Round(($krbExpiryDT - (Get-Date)).TotalMinutes)
                            if ($krbMinLeft -lt 60 -and $krbMinLeft -gt 0) {
                                $krbLabel = "Krb: OK (TGT expires in ${krbMinLeft}min)"
                            }
                        }
                        catch {}
                    }
                }
                else {
                    # Logon succeeded (Invoke-Command didn't throw) but no krbtgt in klist
                    # This can happen with NTLM fallback -- still counts as auth OK
                    $krbOk    = $true
                    $krbLabel = "Krb: OK (NTLM)"
                }
            }
            catch {
                $krbErr = $_.Exception.Message -replace '\r?\n.*',''
                # Classify the Kerberos failure
                if ($krbErr -match 'password.*expired|0x80090327') {
                    $krbLabel = "Krb: PASSWORD EXPIRED"
                }
                elseif ($krbErr -match 'account.*disabled|0x80090345') {
                    $krbLabel = "Krb: ACCOUNT DISABLED"
                }
                elseif ($krbErr -match 'account.*locked|0x80090346') {
                    $krbLabel = "Krb: ACCOUNT LOCKED"
                }
                elseif ($krbErr -match 'clock skew|0x80090324') {
                    $krbLabel = "Krb: CLOCK SKEW"
                }
                elseif ($krbErr -match '0x80090322|unknown security error') {
                    # Same self-loopback issue as WinRM -- credential may still work on remote hosts
                    $krbOk    = $true
                    $krbLabel = "Krb: OK** (self-loopback)"
                }
                elseif ($krbErr -match 'Access is denied|0x80090311|Logon failure') {
                    $krbLabel = "Krb: AUTH FAIL"
                }
                else {
                    $krbLabel = "Krb: FAIL"
                }
            }
            }  # end same-domain else block
        }
    }
    catch {
        $krbErr   = $_.Exception.Message -replace '\r?\n.*',''
        $krbLabel = "Krb: ERROR"
    }

    # Test 3: WinRM connectivity -- for the primary domain, try each DC returned by DNS
    # until one responds.  This handles DCs that are offline or have restrictive firewall rules.
    # For cross-domain credentials, test against the domain name (DC auto-resolved by DNS);
    # error 0x8009030e is a known cross-domain false alarm and is classified as OK*.
    try {
        $winrmTestTargets = @()

        if ($isPrimary) {
            # Resolve all DCs for this domain via DNS SRV record (_ldap._tcp.<domain>)
            # nslookup -type=SRV returns the DC list AD publishes; we just need their hostnames.
            try {
                $srvRecords = Resolve-DnsName -Name "_ldap._tcp.$credDomain" -Type SRV -ErrorAction SilentlyContinue
                if ($srvRecords) {
                    $winrmTestTargets = @($srvRecords |
                        Where-Object { $_.Type -eq 'SRV' -and $_.NameTarget } |
                        Select-Object -ExpandProperty NameTarget -Unique)
                }
            } catch {}

            # Fallback: try the domain name itself (let DNS round-robin to a DC)
            if ($winrmTestTargets.Count -eq 0) { $winrmTestTargets = @($credDomain) }
        }
        else {
            $winrmTestTargets = @($credDomain)
        }

        $winrmOk  = $false
        $winrmErr = ''
        foreach ($target in $winrmTestTargets) {
            try {
                $wsParams = @{ ComputerName = $target; ErrorAction = 'Stop' }
                if (-not $isPrimary -and $cred) {
                    $wsParams['Credential']     = $cred
                    $wsParams['Authentication'] = 'Negotiate'
                }
                $null = Test-WSMan @wsParams
                $winrmOk = $true
                break   # First DC that responds is enough
            }
            catch {
                $winrmErr = $_.Exception.Message -replace '\r?\n.*',''
                # Don't stop on one DC failure -- try the next
            }
        }
    }
    catch { $winrmErr = $_.Exception.Message -replace '\r?\n.*','' }

    # Classify WinRM result -- 0x8009030e is a false alarm for cross-domain DC targeting
    # v3.8.1: 0x80090322 on same-domain non-primary credentials is typically a self-loopback
    # Negotiate/CredSSP issue when testing from the script host against a DC (the credential
    # is still valid for remote hosts). Since Test-HyperVHost now has credential fallback,
    # these credentials will be tried automatically during Step 2.
    $winrmFalseAlarm = $winrmErr -match '0x8009030e|8009030e|logon session does not exist'
    $winrmSelfLoopback = (-not $isPrimary) -and ($winrmErr -match '0x80090322|80090322|unknown security error')
    $winrmEffectiveOk = $winrmOk -or $winrmFalseAlarm -or $winrmSelfLoopback

    # v3.10.9 CR92: Test 4 -- Live Remote Credential Validation
    # Tests 1-3 can pass with a stale cached Kerberos TGT even after a password change.
    # The cached TGT (10-hour default lifetime) lets the current session authenticate to DCs,
    # but background jobs (Start-Job) create NEW sessions that must request fresh TGTs --
    # which fail with the old password. This test catches that scenario by forcing a fresh
    # WinRM session to a remote host using the stored credential object (not the cached TGT).
    $liveTestOk    = $false
    $liveTestLabel = ''
    $liveTestErr   = ''

    if ($isPrimary -and $adOk -and $krbOk -and $winrmEffectiveOk) {
        $liveTestTarget = $null
        try {
            $srvDCs = @()
            try {
                $srvRecords = Resolve-DnsName -Name "_ldap._tcp.$credDomain" -Type SRV -ErrorAction SilentlyContinue
                $srvDCs = @($srvRecords | Where-Object { $_.Type -eq 'SRV' -and $_.NameTarget } |
                    Select-Object -ExpandProperty NameTarget -Unique)
            } catch {}
            $localHost = $env:COMPUTERNAME
            foreach ($dc in $srvDCs) {
                if (($dc -split '\.')[0] -ne $localHost) { $liveTestTarget = $dc; break }
            }
            if (-not $liveTestTarget -and $srvDCs.Count -gt 0) { $liveTestTarget = $srvDCs[0] }
        } catch {}

        if ($liveTestTarget) {
            try {
                $null = Invoke-Command -ComputerName $liveTestTarget -Credential $cred -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
                $liveTestOk = $true
                $liveTestLabel = 'Live: OK'
            }
            catch {
                $liveTestErr = $_.Exception.Message -replace '\r?\n.*',''
                if ($liveTestErr -match 'user name or password is incorrect|Logon failure') {
                    $liveTestLabel = 'Live: STALE PASSWORD'
                }
                elseif ($liveTestErr -match '0x80090322|unknown security error') {
                    $liveTestOk = $true
                    $liveTestLabel = 'Live: OK (Negotiate)'
                }
                else {
                    $liveTestLabel = "Live: WARN"
                    $liveTestOk = $true   # Non-password error -- don't block
                }
            }
        }
        else {
            $liveTestOk = $true
            $liveTestLabel = ''
        }
    }
    else {
        $liveTestOk = $true
        $liveTestLabel = ''
    }

    $adLabel = if ($adOk)  { "AD: OK$(if ($adMethod -eq 'LDAP') { ' [LDAP]' })" } else { "AD: FAIL" }
    $wmLabel = if ($winrmOk) { "WinRM: OK" } elseif ($winrmFalseAlarm) { "WinRM: OK*" } elseif ($winrmSelfLoopback) { "WinRM: OK**" } else { "WinRM: FAIL" }

    # Overall pass: AD OK + Kerberos OK (or OK**) + WinRM OK (or OK*/OK**) + Live OK
    $allOk = $adOk -and $krbOk -and $winrmEffectiveOk -and $liveTestOk

    if ($allOk) {
        $labels = "[$adLabel] [$krbLabel] [$wmLabel]"
        if ($liveTestLabel -and $liveTestLabel -ne '') { $labels += " [$liveTestLabel]" }
        Write-Host "  [OK] $credName ($($cred.UserName)) -> $credDomain  $labels" -ForegroundColor Green
        if ($adMethod -eq 'LDAP') {
            Write-Host "         Server 2003 DC: delegation/SPN/LAPS audit skipped. OS inventory runs per-VM." -ForegroundColor DarkYellow }
        if ($winrmFalseAlarm) {
            Write-Host "         WinRM*: cross-domain DC restriction (0x8009030e) -- normal for foreign domain, VMs connect directly." -ForegroundColor DarkGreen }
        if ($winrmSelfLoopback) {
            Write-Host "         WinRM**: self-loopback Negotiate issue (0x80090322) -- credential is valid, will be used as fallback for remote hosts." -ForegroundColor DarkGreen }
        if ($krbLabel -match 'self-loopback') {
            Write-Host "         Krb**: self-loopback issue -- credential will be validated on first remote host contact." -ForegroundColor DarkGreen }
        if ($krbLabel -match 'expires in') {
            Write-Host "         TGT nearing expiry -- consider: klist purge ; then re-run or re-logon to refresh tickets." -ForegroundColor DarkYellow }
    }
    elseif ($adOk -and $krbOk -and $winrmEffectiveOk -and -not $liveTestOk) {
        # v3.10.9 CR92: All cached tests passed but live remote credential test FAILED
        # This means the Kerberos TGT is cached from before a password change.
        Write-Host "  [FAIL] $credName ($($cred.UserName)) -> $credDomain  [$adLabel] [$krbLabel] [$wmLabel] [$liveTestLabel]" -ForegroundColor Red
        Write-Host "         STALE CREDENTIAL DETECTED: Tests 1-3 passed using cached Kerberos TGT," -ForegroundColor Red
        Write-Host "         but the stored password no longer works for new sessions (background jobs)." -ForegroundColor Red
        Write-Host "         This will cause 'user name or password is incorrect' errors on most hosts." -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host "         FIX: Re-export the credential with the new password:" -ForegroundColor Yellow
        Write-Host "              Get-Credential -Message '$($cred.UserName)' | Export-Clixml '$credPath'" -ForegroundColor Yellow
        Write-Host "         Then run:  klist purge   (clears stale TGTs)" -ForegroundColor Yellow
        Write-Host "         Then re-run this report." -ForegroundColor Yellow
        $credPrecheckFailed = $true
    }
    elseif ($adOk -and $krbOk) {
        Write-Host "  [WARN] $credName ($($cred.UserName)) -> $credDomain  [$adLabel] [$krbLabel] [WinRM: FAIL]" -ForegroundColor Yellow
        Write-Host "         WinRM: $winrmErr" -ForegroundColor DarkYellow
        Write-Host "         OS data collection for $credDomain VMs may fail" -ForegroundColor DarkYellow
    }
    elseif ($adOk -and -not $krbOk) {
        # AD OK but Kerberos FAILED -- this is the key new diagnostic
        Write-Host "  [WARN] $credName ($($cred.UserName)) -> $credDomain  [$adLabel] [$krbLabel] [$wmLabel]" -ForegroundColor Yellow
        Write-Host "         Kerberos: $krbErr" -ForegroundColor DarkYellow
        if ($krbLabel -match 'EXPIRED') {
            Write-Host "         FIX: Password expired. Reset password and re-export credential:" -ForegroundColor Yellow
            Write-Host "              Get-Credential | Export-Clixml '$credPath'" -ForegroundColor Yellow
        }
        elseif ($krbLabel -match 'LOCKED') {
            Write-Host "         FIX: Account locked out. Unlock via AD Users and Computers or:" -ForegroundColor Yellow
            Write-Host "              Unlock-ADAccount -Identity '$($cred.GetNetworkCredential().UserName)'" -ForegroundColor Yellow
        }
        elseif ($krbLabel -match 'CLOCK SKEW') {
            Write-Host "         FIX: Time difference between this machine and the KDC exceeds 5 minutes." -ForegroundColor Yellow
            Write-Host "              Run: w32tm /resync /force" -ForegroundColor Yellow
        }
        elseif ($krbLabel -match 'NO TGT') {
            Write-Host "         FIX: No TGT in current session. Try: klist purge then re-logon, or:" -ForegroundColor Yellow
            Write-Host "              runas /user:$($cred.UserName) powershell  (then re-run from that session)" -ForegroundColor Yellow
        }
        elseif ($krbLabel -match 'AUTH FAIL') {
            Write-Host "         FIX: Credential rejected by KDC. Verify password and re-export:" -ForegroundColor Yellow
            Write-Host "              Get-Credential -Message '$($cred.UserName)' | Export-Clixml '$credPath'" -ForegroundColor Yellow
        }
        Write-Host "         This credential will be skipped for host fallback until Kerberos is fixed." -ForegroundColor DarkYellow
    }
    elseif ($winrmEffectiveOk) {
        Write-Host "  [WARN] $credName ($($cred.UserName)) -> $credDomain  [AD: FAIL] [$krbLabel] [$wmLabel]" -ForegroundColor Yellow
        Write-Host "         AD: $adErr" -ForegroundColor DarkYellow
        Write-Host "         AD Auth audit for $credDomain machines may show errors" -ForegroundColor DarkYellow
    }
    else {
        Write-Host "  [FAIL] $credName ($($cred.UserName)) -> $credDomain  [AD: FAIL] [$krbLabel] [WinRM: FAIL]" -ForegroundColor Red
        Write-Host "         AD:       $adErr" -ForegroundColor Red
        if ($krbErr) {
            Write-Host "         Kerberos: $krbErr" -ForegroundColor Red }
        Write-Host "         WinRM:    $winrmErr" -ForegroundColor Red
        Write-Host "         VMs in $credDomain will show no OS data. Check credential file: $credPath" -ForegroundColor Red
        if (-not $isPrimary) { $credPrecheckFailed = $true }
    }
}

if ($credPrecheckFailed) {
    Write-Host "" 
    Write-Host "  One or more domain credentials failed. VMs in those domains will have no OS data." -ForegroundColor Yellow
    $response = Read-Host "  Continue anyway? (Y to proceed, N to abort)"
    if ($response -notmatch '^[Yy]') {
        Write-Host "Aborted by user. Fix credentials and re-run." -ForegroundColor Red
        return
    }
    Write-Host "  Continuing with partial credentials..." -ForegroundColor Yellow
}
else {
    Write-Host "  All credentials validated successfully." -ForegroundColor Green
}

# --- Verify Module ---
Write-Host "===== Module Check =====" -ForegroundColor Cyan
# Filter to ONLY modules loaded from THIS script's directory -- ignores older versions in other folders
$loadedModules = Get-Module HyperVInventory* | Where-Object { $_.Path -like "*$scriptDir*" } | Sort-Object Name
$loadedModules | Format-Table Name, Version, Path -AutoSize

# Quick version alignment check (compare only modules from this folder)
$mainMod = $loadedModules | Where-Object { $_.Name -eq 'HyperVInventory' } | Select-Object -First 1
if ($mainMod) {
    $expectedVer = $mainMod.Version
    # Sub-modules use the base version (3.10.12); the orchestrator adds a patch suffix (3.10.12.12).
    # Compare only the first three version components so sub-modules don't false-alarm.
    $expectedBase = "$($expectedVer.Major).$($expectedVer.Minor).$($expectedVer.Build)"
    $mismatched = $loadedModules | Where-Object {
        $_.Name -ne 'HyperVInventory' -and
        "$($_.Version.Major).$($_.Version.Minor).$($_.Version.Build)" -ne $expectedBase
    }
    if ($mismatched) {
        Write-Host "  [WARNING] Version mismatches detected (sub-modules vs base $expectedBase):" -ForegroundColor Yellow
        foreach ($m in $mismatched) {
            Write-Host "    $($m.Name) v$($m.Version) (expected base v$expectedBase)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  [OK] All modules at base v$expectedBase (orchestrator v$($mainMod.Version))" -ForegroundColor Green
    }
}

# --- CR113: Module Preflight Gate ---
# Validates that every required module file is physically present on disk before
# starting the 4-hour run. A missing .psm1 will silently skip features
# (VHD-Chain, SPN-Inventory, Remediation, etc.) rather than producing an error.
# This gate catches deployment gaps immediately at startup.
Write-Host ""
Write-Host "===== Module Preflight Gate (CR113) =====" -ForegroundColor Cyan

$cr113RequiredModules = @(
    @{ Name = 'HyperVInventory-Core';           Critical = $true  }
    @{ Name = 'HyperVInventory-Cluster';         Critical = $true  }
    @{ Name = 'HyperVInventory-Security';        Critical = $true  }
    @{ Name = 'HyperVInventory-OS';              Critical = $true  }
    @{ Name = 'HyperVInventory-Storage';         Critical = $true  }
    @{ Name = 'HyperVInventory-Analysis';        Critical = $true  }
    @{ Name = 'HyperVInventory-Export';          Critical = $true  }
    @{ Name = 'HyperVInventory-ADAuth';          Critical = $true  }
    @{ Name = 'HyperVInventory-LiveMigration';   Critical = $true  }
    @{ Name = 'HyperVInventory-S2D';             Critical = $true  }
    @{ Name = 'HyperVInventory-ResourceMetering'; Critical = $false }
    @{ Name = 'HyperVInventory-TLS';             Critical = $false }
    @{ Name = 'HyperVInventory-VMActivity';      Critical = $false }
    @{ Name = 'HyperVInventory-SCCM';            Critical = $false }
    @{ Name = 'HyperVInventory-LAPS';            Critical = $false }
    @{ Name = 'HyperVInventory-DNS';             Critical = $false }
    @{ Name = 'HyperVInventory-Permissions';     Critical = $false }
    @{ Name = 'HyperVInventory-VHDChain';        Critical = $false }
    @{ Name = 'HyperVInventory-Remediation';     Critical = $false }
)

$modulesDir = Join-Path $scriptDir 'Modules'
$preflightFailed = $false
$optionalMissing = @()

foreach ($mod in $cr113RequiredModules) {
    $psm1 = Join-Path $modulesDir "$($mod.Name).psm1"
    $psd1 = Join-Path $modulesDir "$($mod.Name).psd1"
    $psm1Exists = Test-Path $psm1
    $psd1Exists = Test-Path $psd1

    if ($psm1Exists -and $psd1Exists) {
        Write-Host "  [OK]   $($mod.Name)" -ForegroundColor $(if ($mod.Critical) { 'Gray' } else { 'DarkGray' })
    }
    elseif ($psm1Exists -and -not $psd1Exists) {
        Write-Host "  [WARN] $($mod.Name) -- .psm1 found but .psd1 missing (version tracking disabled)" -ForegroundColor Yellow
    }
    elseif ($mod.Critical) {
        Write-Host "  [FAIL] $($mod.Name) -- REQUIRED module not found in Modules\ folder" -ForegroundColor Red
        $preflightFailed = $true
    }
    else {
        $optionalMissing += $mod.Name
        Write-Host "  [SKIP] $($mod.Name) -- optional module not found (feature will be skipped)" -ForegroundColor Yellow
    }
}

if ($optionalMissing.Count -gt 0) {
    Write-Host ""
    Write-Host "  $($optionalMissing.Count) optional module(s) missing -- features will be skipped:" -ForegroundColor Yellow
    Write-Host "  $($optionalMissing -join ', ')" -ForegroundColor Yellow
    Write-Host "  Copy the missing .psm1 and .psd1 files from the release zip to resolve." -ForegroundColor Yellow
}

if ($preflightFailed) {
    Write-Host ""
    Write-Host "  [FATAL] One or more REQUIRED modules are missing. Cannot start report run." -ForegroundColor Red
    Write-Host "  Copy the missing files from the release zip into: $modulesDir" -ForegroundColor Yellow
    try { Stop-Transcript | Out-Null } catch {}
    # Save the startup log to the script folder so the preflight failure is captured
    if ($tempTranscript -and (Test-Path $tempTranscript)) {
        $failLog = Join-Path $scriptDir "HyperV-Report_${earlyTimestamp}_preflight-fail.log"
        Move-Item -Path $tempTranscript -Destination $failLog -Force -ErrorAction SilentlyContinue
        Write-Host "  Startup log saved to: $failLog" -ForegroundColor Yellow
    }
    return
}

Write-Host "  Module preflight passed." -ForegroundColor Green
Write-Host ""
# Reuse the timestamp from the early transcript so the folder name matches the log name
$timestamp = $earlyTimestamp

if ($config.OutputPath -and $config.OutputPath -ne '') {
    $outputBase = $config.OutputPath
}
else {
    $outputBase = [Environment]::GetFolderPath("Desktop")
}

$outputPath = Join-Path $outputBase "HyperV-Report_$timestamp\HyperV-Inventory.xlsx"
$historyPath = Join-Path $outputBase "VM-History.json"

# --- Transcript (run log): move temp startup log into report folder ---
# Stop the early transcript, move it into the report folder, then restart to the final path.
# This ensures Configuration, Pre-requisites, Credentials, Module Check, and Preflight Gate
# are all captured -- not just the report execution phase.
$reportFolder = Split-Path $outputPath -Parent
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder -Force | Out-Null
}
$transcriptPath = Join-Path $reportFolder "HyperV-Report_$timestamp.log"

# Stop early transcript and move it so the startup content is at the top of the final log
if ($earlyTranscriptStarted -and $tempTranscript -and (Test-Path $tempTranscript)) {
    try { Stop-Transcript | Out-Null } catch {}
    try {
        # Move the startup log content into the final path
        Move-Item -Path $tempTranscript -Destination $transcriptPath -Force
    }
    catch {
        Write-Host "[WARNING] Could not move startup transcript: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
elseif (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder -Force | Out-Null
}

# Restart transcript appending to the final path (picks up where the startup log left off)
try {
    Start-Transcript -Path $transcriptPath -Append -Force | Out-Null
    Write-Host "Transcript: $transcriptPath" -ForegroundColor Gray
}
catch {
    Write-Host "[WARNING] Could not start transcript: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Console output will not be saved to file." -ForegroundColor Yellow
}

# --- Run Report ---
Write-Host "===== Running Report =====" -ForegroundColor Cyan
Write-Host "Output: $outputPath" -ForegroundColor Gray
Write-Host "History: $historyPath" -ForegroundColor Gray

$reportParams = @{
    OutputPath        = $outputPath
    Credential        = $primaryCred
    DomainCredentials = $domainCredentials
    HistoryPath       = $historyPath
}

if ($config.UseCredSSP)              { $reportParams['UseCredSSP'] = $true }
if ($config.IncludeApplications)     { $reportParams['IncludeApplications'] = $true }
if ($config.MaxConcurrentJobs)       { $reportParams['MaxConcurrentJobs'] = $config.MaxConcurrentJobs }
if ($config.ReportLevel)             { $reportParams['ReportLevel'] = $config.ReportLevel }
if ($config.ExcludeVMPatterns)       { $reportParams['ExcludeVMPatterns'] = $config.ExcludeVMPatterns }
if ($null -ne $config.MissingVMDropoffDays)                { $reportParams['MissingVMDropoffDays']                = $config.MissingVMDropoffDays }
if ($null -ne $config.GuestStorageTrackingMode)            { $reportParams['GuestStorageTrackingMode']            = $config.GuestStorageTrackingMode }
if ($null -ne $config.GuestStorageTrackingIntervalHours)   { $reportParams['GuestStorageTrackingIntervalHours']   = $config.GuestStorageTrackingIntervalHours }
if ($null -ne $config.GuestStorageMonthlyColumns)          { $reportParams['GuestStorageMonthlyColumns']          = $config.GuestStorageMonthlyColumns }
if ($config.ServicesFilter)                                { $reportParams['ServicesFilter']                      = $config.ServicesFilter }
if ($config.RequiredBuiltinMembers)                        { $reportParams['RequiredBuiltinMembers']              = $config.RequiredBuiltinMembers }

# AD Authentication Audit (S5a)
if ($null -ne $config.IncludeADAuthAudit)   { $reportParams['IncludeADAuthAudit']   = [bool]$config.IncludeADAuthAudit }
if ($null -ne $config.IncludeRolesFeatures) { $reportParams['IncludeRolesFeatures'] = [bool]$config.IncludeRolesFeatures }

# SCCM Integration (optional)
if ($config.IncludeSCCM) {
    $reportParams['IncludeSCCM'] = $true
    if ($config.SCCMSiteServer) { $reportParams['SCCMSiteServer'] = $config.SCCMSiteServer }
    if ($config.SCCMSiteCode)   { $reportParams['SCCMSiteCode'] = $config.SCCMSiteCode }
    if ($config.SCCMMethod)     { $reportParams['SCCMMethod'] = $config.SCCMMethod }
}

Get-HyperVInventory @reportParams -Verbose

# --- Stop Transcript ---
try { Stop-Transcript | Out-Null } catch {}
