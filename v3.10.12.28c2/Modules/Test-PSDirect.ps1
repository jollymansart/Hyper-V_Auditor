<#
.SYNOPSIS
    Test-PSDirect.ps1 - Diagnose PowerShell Direct connectivity for cross-domain VMs
    
.DESCRIPTION
    This script tests every component of the PowerShell Direct pipeline used by the
    Hyper-V Inventory Report v3.10.12. It validates:
    
    1. VM domain detection (4-tier: DNS, KVP, GuestOS, VMName)
    2. Credential selection (domain-match lookup from Config-OHDC.psd1)
    3. Network connectivity (FQDN, short name, IP)
    4. WinRM + Kerberos authentication
    5. WinRM + Negotiate (NTLM) fallback
    6. PowerShell Direct via VMBus (Invoke-Command -VMId)
    7. Multi-credential PSDirect rotation
    
    Run this from RICTX-SCRIPT-P2 as mgeorge-adm to simulate exact report conditions.
    
.PARAMETER HostName
    Hyper-V host FQDN (e.g., RICTX-UCSHV-P2.ohdc.com)
    
.PARAMETER VMName
    Specific VM display name to test. If omitted, tests ALL running VMs on the host.

.PARAMETER CredentialPaths
    Hashtable of domain -> credential XML path (same format as Config-OHDC.psd1).
    If omitted, loads from Config-OHDC.psd1 in the script directory.

.PARAMETER ShowAll
    Show results for all VMs, not just failures/PSDirect candidates.
    
.EXAMPLE
    # Test a specific cross-domain VM
    .\Test-PSDirect.ps1 -HostName RICTX-UCSHV-P2.ohdc.com -VMName DMZSFTP-01
    
.EXAMPLE
    # Test all running VMs on a host
    .\Test-PSDirect.ps1 -HostName RICTX-UCSHV-P2.ohdc.com -ShowAll
    
.EXAMPLE
    # Test with explicit credentials
    .\Test-PSDirect.ps1 -HostName RICTX-UCSHV-P2.ohdc.com -VMName DMZSFTP-01 `
        -CredentialPaths @{
            'ohdc.com'          = 'C:\ProgramData\S\HyperV-Cred.xml'
            'overheaddoor.com'  = 'C:\ProgramData\S\HyperV-Cred-overheaddoor.xml'
            'creative.com'     = 'C:\ProgramData\S\HyperV-Cred-creative.xml'
        }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    
    [Parameter(Mandatory = $false)]
    [string]$VMName,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$CredentialPaths,
    
    [switch]$ShowAll
)

$ErrorActionPreference = 'Continue'

# --- Color helpers ---
function Write-Status { param($Label, $Status, $Detail, $Color)
    $pad = ' ' * [math]::Max(0, 25 - $Label.Length)
    Write-Host "  $Label$pad" -NoNewline
    Write-Host "[$Status]" -ForegroundColor $Color -NoNewline
    if ($Detail) { Write-Host " $Detail" -ForegroundColor Gray }
    else { Write-Host "" }
}

# ===== STEP 0: Load Credentials =====
Write-Host "`n===== Step 0: Credential Loading =====" -ForegroundColor Cyan

$credLookup = @{}

if (-not $CredentialPaths) {
    # Try loading from Config-OHDC.psd1
    $configPath = Join-Path $PSScriptRoot 'Config-OHDC.psd1'
    if (-not (Test-Path $configPath)) {
        $configPath = Join-Path (Split-Path $PSScriptRoot) 'Config-OHDC.psd1'
    }
    if (Test-Path $configPath) {
        Write-Host "  Loading config: $configPath" -ForegroundColor Gray
        $config = Import-PowerShellDataFile $configPath
        foreach ($credDef in $config.Credentials) {
            if ($credDef.DomainFQDN -and $credDef.StoredPath -and (Test-Path $credDef.StoredPath)) {
                try {
                    $cred = Import-Clixml $credDef.StoredPath
                    $domain = $credDef.DomainFQDN.ToLower()
                    $credLookup[$domain] = $cred
                    Write-Status $domain "OK" "$($cred.UserName)" Green
                } catch {
                    Write-Status $credDef.DomainFQDN "FAIL" "Cannot load $($credDef.StoredPath)" Red
                }
            }
        }
    } else {
        Write-Host "  Config not found. Use -CredentialPaths parameter." -ForegroundColor Yellow
    }
} else {
    foreach ($domain in $CredentialPaths.Keys) {
        $path = $CredentialPaths[$domain]
        if (Test-Path $path) {
            try {
                $cred = Import-Clixml $path
                $credLookup[$domain.ToLower()] = $cred
                Write-Status $domain "OK" "$($cred.UserName)" Green
            } catch {
                Write-Status $domain "FAIL" "Cannot load $path" Red
            }
        } else {
            Write-Status $domain "MISSING" "$path not found" Yellow
        }
    }
}

if ($credLookup.Count -eq 0) {
    Write-Host "`n  No credentials loaded. Cannot continue." -ForegroundColor Red
    return
}

# Set primary credential (ohdc.com or first available)
$primaryCred = if ($credLookup.ContainsKey('ohdc.com')) { $credLookup['ohdc.com'] }
               else { $credLookup[($credLookup.Keys | Select-Object -First 1)] }

# ===== STEP 1: Connect to Host =====
Write-Host "`n===== Step 1: Host Connectivity =====" -ForegroundColor Cyan

try {
    $null = Test-WSMan -ComputerName $HostName -ErrorAction Stop
    Write-Status "WinRM to Host" "OK" $HostName Green
} catch {
    Write-Status "WinRM to Host" "FAIL" $_.Exception.Message Red
    Write-Host "  Cannot connect to host. Verify hostname and credentials." -ForegroundColor Red
    return
}

# ===== STEP 2: Get VMs from Host =====
Write-Host "`n===== Step 2: VM Inventory from Host =====" -ForegroundColor Cyan

$vmFilter = if ($VMName) { "Name='$VMName'" } else { "State=2" }  # State=2 = Running
try {
    $vms = Invoke-Command -ComputerName $HostName -Credential $primaryCred -ErrorAction Stop -ScriptBlock {
        param($filter)
        # Get VMs with KVP data and network adapters
        $vmList = Get-VM | Where-Object { $_.State -eq 'Running' }
        if ($filter -match "Name='(.+)'") { $vmList = $vmList | Where-Object { $_.Name -eq $Matches[1] } }
        
        foreach ($vm in $vmList) {
            # Get KVP exchange data
            $kvpData = @{}
            try {
                $kvpItems = $vm | Get-VMIntegrationService -Name 'Key-Value Pair Exchange' -ErrorAction SilentlyContinue
                if ($kvpItems -and $kvpItems.Enabled) {
                    $kvpXml = (Get-WmiObject -Namespace "root\virtualization\v2" -Query `
                        "SELECT GuestExchangeItems FROM Msvm_KvpExchangeComponent WHERE SystemName='$($vm.Id)'" `
                        -ErrorAction SilentlyContinue).GuestExchangeItems
                    if ($kvpXml) {
                        foreach ($item in $kvpXml) {
                            $xml = [xml]$item
                            $kvpData[$xml.INSTANCE.PROPERTY[0].VALUE] = $xml.INSTANCE.PROPERTY[1].VALUE
                        }
                    }
                }
            } catch {}
            
            # Get network adapter IPs
            $nics = @($vm | Get-VMNetworkAdapter -ErrorAction SilentlyContinue | ForEach-Object {
                @{ Name = $_.Name; IPs = @($_.IPAddresses); MacAddress = $_.MacAddress }
            })
            
            [PSCustomObject]@{
                Name          = $vm.Name
                VMId          = $vm.Id.ToString()
                State         = $vm.State.ToString()
                GuestOS       = try { ($vm | Get-VMIntegrationService -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Guest Service Interface' }).PrimaryStatusDescription } catch { '' }
                KVP           = $kvpData
                NetworkAdapters = $nics
                Generation    = $vm.Generation
                IntSvcEnabled = try { ($vm | Get-VMIntegrationService -ErrorAction SilentlyContinue | Where-Object { $_.OperationalStatus -eq 'Ok' }).Count } catch { 0 }
            }
        }
    } -ArgumentList $vmFilter
} catch {
    Write-Host "  Failed to get VMs from $HostName : $($_.Exception.Message)" -ForegroundColor Red
    return
}

$vmCount = @($vms).Count
Write-Host "  Found $vmCount running VM(s)" -ForegroundColor $(if ($vmCount -gt 0) { 'Green' } else { 'Yellow' })
if ($vmCount -eq 0) {
    if ($VMName) { Write-Host "  VM '$VMName' not found or not running on $HostName" -ForegroundColor Yellow }
    return
}

# ===== STEP 3: Test Each VM =====
Write-Host "`n===== Step 3: Per-VM Connectivity Analysis =====" -ForegroundColor Cyan
Write-Host "  Testing domain detection, credential selection, network, WinRM, and PSDirect...`n" -ForegroundColor Gray

$results = @()

foreach ($vm in $vms) {
    $vmTarget = $vm.Name
    $result = [ordered]@{
        VMName         = $vmTarget
        VMId           = $vm.VMId
        Domain         = 'unknown'
        DomainSource   = 'none'
        Credential     = '(none)'
        CredDomain     = 'none'
        FQDN           = $vmTarget
        FQDNSource     = 'VMName'
        HasIP          = $false
        VMIPAddress    = ''
        CanPing        = $false
        PingTarget     = ''
        WinRM_Kerberos = 'Not Tested'
        WinRM_Negotiate = 'Not Tested'
        PSDirect       = 'Not Tested'
        PSDirect_MultiCred = 'Not Tested'
        WinningMethod  = 'None'
        WinningCred    = '(none)'
        GuestHostname  = ''
        GuestDomain    = ''
        ErrorDetails   = ''
    }
    
    # --- 3a: Domain Detection (4-tier) ---
    # Tier 0: DNS
    try {
        $dnsResult = [System.Net.Dns]::GetHostEntry($vmTarget)
        if ($dnsResult -and $dnsResult.HostName -match '\.(.+\..+)$') {
            $result.Domain = $Matches[1].ToLower()
            $result.DomainSource = 'DNS'
        }
    } catch {}
    
    # Tier 1: KVP
    if ($result.Domain -eq 'unknown' -and $vm.KVP -and $vm.KVP['FullyQualifiedDomainName']) {
        $kvpFqdn = [string]$vm.KVP['FullyQualifiedDomainName']
        if ($kvpFqdn -match '\.(.+\..+)$') {
            $result.Domain = $Matches[1].ToLower()
            $result.DomainSource = 'KVP'
        }
    }
    
    # Tier 2: GuestOS string
    if ($result.Domain -eq 'unknown' -and $vm.GuestOS -and $vm.GuestOS -match '\.(\w+\.\w+)$') {
        $result.Domain = $Matches[1].ToLower()
        $result.DomainSource = 'GuestOS'
    }
    
    # Tier 3: VM name contains FQDN
    if ($result.Domain -eq 'unknown' -and $vmTarget -match '\.(.+\..+)$') {
        $result.Domain = $Matches[1].ToLower()
        $result.DomainSource = 'VMName'
    }
    
    # --- 3b: Credential Selection ---
    $vmCred = $null
    if ($result.Domain -ne 'unknown' -and $credLookup.ContainsKey($result.Domain)) {
        $vmCred = $credLookup[$result.Domain]
        $result.Credential = $vmCred.UserName
        $result.CredDomain = $result.Domain
    } elseif ($credLookup.ContainsKey('ohdc.com')) {
        $vmCred = $credLookup['ohdc.com']
        $result.Credential = $vmCred.UserName
        $result.CredDomain = 'ohdc.com (default)'
    }
    
    # --- 3c: FQDN Resolution (4-source) ---
    # Source 1: DNS
    try {
        $dnsEntry = [System.Net.Dns]::GetHostEntry($vmTarget)
        if ($dnsEntry -and $dnsEntry.HostName -match '\.') {
            $result.FQDN = $dnsEntry.HostName
            $result.FQDNSource = 'DNS'
        }
    } catch {}
    
    # Source 2: KVP FQDN
    if ($result.FQDNSource -eq 'VMName' -and $vm.KVP -and $vm.KVP['FullyQualifiedDomainName']) {
        $kvpFqdn = [string]$vm.KVP['FullyQualifiedDomainName']
        if ($kvpFqdn -match '\.') {
            $result.FQDN = $kvpFqdn
            $result.FQDNSource = 'KVP'
        }
    }
    
    # Source 3: Constructed
    if ($result.FQDNSource -eq 'VMName' -and $result.Domain -ne 'unknown') {
        $result.FQDN = "$vmTarget.$($result.Domain)"
        $result.FQDNSource = 'Constructed'
    }
    
    # Source 4: IP from NIC
    $vmIP = $null
    if ($vm.NetworkAdapters) {
        foreach ($nic in $vm.NetworkAdapters) {
            if ($nic.IPs) {
                $ipv4 = @($nic.IPs | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -ne '127.0.0.1' })
                if ($ipv4.Count -gt 0) { $vmIP = $ipv4[0]; break }
            }
        }
    }
    $result.HasIP = [bool]$vmIP
    $result.VMIPAddress = if ($vmIP) { $vmIP } else { '' }
    
    # --- 3d: Ping Test ---
    $canReach = $false
    $reachTarget = $result.FQDN
    
    $canReach = Test-Connection -ComputerName $result.FQDN -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $canReach -and $result.FQDN -ne $vmTarget) {
        $canReach = Test-Connection -ComputerName $vmTarget -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($canReach) { $reachTarget = $vmTarget }
    }
    if (-not $canReach -and $vmIP) {
        $canReach = Test-Connection -ComputerName $vmIP -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($canReach) { $reachTarget = $vmIP }
    }
    $result.CanPing = $canReach
    $result.PingTarget = if ($canReach) { $reachTarget } else { 'UNREACHABLE' }
    
    # --- 3e: WinRM Test (Kerberos then Negotiate) ---
    if ($canReach -and $vmCred) {
        # Kerberos
        try {
            $krbResult = Invoke-Command -ComputerName $reachTarget -Credential $vmCred -ErrorAction Stop -ScriptBlock {
                @{ Hostname = $env:COMPUTERNAME; Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
            }
            $result.WinRM_Kerberos = 'OK'
            $result.WinningMethod = 'Kerberos (WinRM)'
            $result.WinningCred = $vmCred.UserName
            $result.GuestHostname = $krbResult.Hostname
            $result.GuestDomain = $krbResult.Domain
        } catch {
            $result.WinRM_Kerberos = "FAIL: $($_.Exception.Message -replace '\r?\n.*','' -replace '.{80}$','')"
            
            # Try Negotiate
            try {
                $negResult = Invoke-Command -ComputerName $reachTarget -Credential $vmCred -Authentication Negotiate -ErrorAction Stop -ScriptBlock {
                    @{ Hostname = $env:COMPUTERNAME; Domain = (Get-CimInstance Win32_ComputerSystem).Domain }
                }
                $result.WinRM_Negotiate = 'OK'
                $result.WinningMethod = 'Negotiate (WinRM)'
                $result.WinningCred = $vmCred.UserName
                $result.GuestHostname = $negResult.Hostname
                $result.GuestDomain = $negResult.Domain
            } catch {
                $result.WinRM_Negotiate = "FAIL: $($_.Exception.Message -replace '\r?\n.*','' -replace '.{80}$','')"
            }
        }
    } elseif (-not $canReach) {
        $result.WinRM_Kerberos = 'SKIP (unreachable)'
        $result.WinRM_Negotiate = 'SKIP (unreachable)'
    } elseif (-not $vmCred) {
        $result.WinRM_Kerberos = 'SKIP (no credential)'
        $result.WinRM_Negotiate = 'SKIP (no credential)'
    }
    
    # --- 3f: PowerShell Direct Test (primary credential) ---
    if ($vm.VMId -and $vmCred -and $result.WinningMethod -eq 'None') {
        try {
            $psdResult = Invoke-Command -ComputerName $HostName -Credential $primaryCred -ErrorAction Stop -ScriptBlock {
                param($vmId, $guestCred)
                try {
                    $r = Invoke-Command -VMId ([guid]$vmId) -Credential $guestCred -ErrorAction Stop -ScriptBlock {
                        @{ 
                            Hostname = $env:COMPUTERNAME
                            Domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
                            OS = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                        }
                    }
                    @{ Success = $true; Data = $r; Error = '' }
                } catch {
                    @{ Success = $false; Data = $null; Error = $_.Exception.Message }
                }
            } -ArgumentList $vm.VMId, $vmCred
            
            if ($psdResult.Success) {
                $result.PSDirect = "OK (guest: $($psdResult.Data.Hostname))"
                $result.WinningMethod = 'PSDirect (VMBus)'
                $result.WinningCred = $vmCred.UserName
                $result.GuestHostname = $psdResult.Data.Hostname
                $result.GuestDomain = $psdResult.Data.Domain
            } else {
                $result.PSDirect = "FAIL: $($psdResult.Error -replace '\r?\n.*','' -replace '.{80}$','')"
            }
        } catch {
            $result.PSDirect = "FAIL (host-level): $($_.Exception.Message -replace '\r?\n.*','')"
        }
    } elseif ($result.WinningMethod -ne 'None') {
        $result.PSDirect = "SKIP (WinRM succeeded)"
    } elseif (-not $vm.VMId) {
        $result.PSDirect = "SKIP (no VMId)"
    }
    
    # --- 3g: Multi-Credential PSDirect Rotation ---
    # If primary PSDirect failed, try ALL available credentials
    # This is the KEY FIX for v3.10.9 -- the current code only tries $vmCred
    if ($result.WinningMethod -eq 'None' -and $vm.VMId) {
        $triedCreds = @()
        if ($vmCred) { $triedCreds += $vmCred.UserName }
        
        foreach ($credDomain in ($credLookup.Keys | Sort-Object)) {
            $tryCred = $credLookup[$credDomain]
            if ($triedCreds -contains $tryCred.UserName) { continue }
            $triedCreds += $tryCred.UserName
            
            try {
                $psdResult2 = Invoke-Command -ComputerName $HostName -Credential $primaryCred -ErrorAction Stop -ScriptBlock {
                    param($vmId, $guestCred)
                    try {
                        $r = Invoke-Command -VMId ([guid]$vmId) -Credential $guestCred -ErrorAction Stop -ScriptBlock {
                            @{ 
                                Hostname = $env:COMPUTERNAME
                                Domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
                            }
                        }
                        @{ Success = $true; Data = $r; Error = '' }
                    } catch {
                        @{ Success = $false; Data = $null; Error = $_.Exception.Message }
                    }
                } -ArgumentList $vm.VMId, $tryCred
                
                if ($psdResult2.Success) {
                    $result.PSDirect_MultiCred = "OK with $($tryCred.UserName) (guest: $($psdResult2.Data.Hostname))"
                    $result.WinningMethod = "PSDirect (VMBus) [$credDomain]"
                    $result.WinningCred = $tryCred.UserName
                    $result.GuestHostname = $psdResult2.Data.Hostname
                    $result.GuestDomain = $psdResult2.Data.Domain
                    break
                } else {
                    $result.PSDirect_MultiCred = "FAIL with $($tryCred.UserName): $($psdResult2.Error -replace '\r?\n.*','' -replace '.{60}$','')"
                }
            } catch {
                $result.PSDirect_MultiCred = "FAIL (host-level) with $($tryCred.UserName)"
            }
        }
        
        if ($result.WinningMethod -eq 'None') {
            $result.PSDirect_MultiCred = "ALL FAILED (tried: $($triedCreds -join ', '))"
        }
    }
    
    $results += [PSCustomObject]$result
}

# ===== STEP 4: Display Results =====
Write-Host "`n===== Step 4: Results =====" -ForegroundColor Cyan

$psdCandidates = @($results | Where-Object { $_.WinningMethod -match 'PSDirect|None' })
$winrmOk       = @($results | Where-Object { $_.WinningMethod -match 'Kerberos|Negotiate' })
$allFailed     = @($results | Where-Object { $_.WinningMethod -eq 'None' })

Write-Host "  WinRM OK:         $($winrmOk.Count) VMs" -ForegroundColor Green
Write-Host "  PSDirect OK:      $(@($results | Where-Object { $_.WinningMethod -match 'PSDirect' }).Count) VMs" -ForegroundColor Cyan
Write-Host "  All Failed:       $($allFailed.Count) VMs" -ForegroundColor $(if ($allFailed.Count -gt 0) { 'Red' } else { 'Green' })

Write-Host ""

foreach ($r in $results) {
    # Skip WinRM-OK VMs unless ShowAll
    if (-not $ShowAll -and $r.WinningMethod -match 'Kerberos|Negotiate') { continue }
    
    $color = switch -Regex ($r.WinningMethod) {
        'Kerberos|Negotiate' { 'Green' }
        'PSDirect'           { 'Cyan' }
        'None'               { 'Red' }
    }
    
    Write-Host "  --- $($r.VMName) ---" -ForegroundColor $color
    Write-Host "    Domain:         $($r.Domain) (via $($r.DomainSource))" -ForegroundColor Gray
    Write-Host "    Credential:     $($r.Credential) [from $($r.CredDomain)]" -ForegroundColor Gray
    Write-Host "    FQDN:           $($r.FQDN) (via $($r.FQDNSource))" -ForegroundColor Gray
    Write-Host "    IP:             $(if ($r.HasIP) { $r.VMIPAddress } else { '(none from Hyper-V adapter)' })" -ForegroundColor Gray
    Write-Host "    Ping:           $(if ($r.CanPing) { "OK -> $($r.PingTarget)" } else { 'UNREACHABLE' })" -ForegroundColor $(if ($r.CanPing) { 'Green' } else { 'Yellow' })
    Write-Host "    WinRM Kerberos: $($r.WinRM_Kerberos)" -ForegroundColor $(if ($r.WinRM_Kerberos -eq 'OK') { 'Green' } elseif ($r.WinRM_Kerberos -match 'SKIP') { 'DarkGray' } else { 'Yellow' })
    Write-Host "    WinRM Negotiate:$($r.WinRM_Negotiate)" -ForegroundColor $(if ($r.WinRM_Negotiate -eq 'OK') { 'Green' } elseif ($r.WinRM_Negotiate -match 'SKIP') { 'DarkGray' } else { 'Yellow' })
    Write-Host "    PSDirect:       $($r.PSDirect)" -ForegroundColor $(if ($r.PSDirect -match '^OK') { 'Cyan' } elseif ($r.PSDirect -match 'SKIP') { 'DarkGray' } else { 'Yellow' })
    if ($r.PSDirect_MultiCred -ne 'Not Tested') {
        Write-Host "    PSD MultiCred:  $($r.PSDirect_MultiCred)" -ForegroundColor $(if ($r.PSDirect_MultiCred -match '^OK') { 'Cyan' } else { 'Yellow' })
    }
    Write-Host "    Winner:         $($r.WinningMethod) -> $($r.WinningCred)" -ForegroundColor $color
    if ($r.GuestHostname) {
        Write-Host "    Guest:          $($r.GuestHostname).$($r.GuestDomain)" -ForegroundColor Gray
    }
    Write-Host ""
}

# ===== STEP 5: Root Cause Summary =====
Write-Host "`n===== Step 5: Root Cause Summary =====" -ForegroundColor Cyan

$domainGroups = $results | Group-Object Domain
foreach ($dg in $domainGroups) {
    $failed = @($dg.Group | Where-Object { $_.WinningMethod -eq 'None' })
    $psd    = @($dg.Group | Where-Object { $_.WinningMethod -match 'PSDirect' })
    $winrm  = @($dg.Group | Where-Object { $_.WinningMethod -match 'Kerberos|Negotiate' })
    Write-Host "  Domain: $($dg.Name)" -ForegroundColor White
    Write-Host "    WinRM OK: $($winrm.Count)  |  PSDirect OK: $($psd.Count)  |  Failed: $($failed.Count)" -ForegroundColor Gray
    
    if ($failed.Count -gt 0) {
        # Diagnose WHY
        $noCred = @($failed | Where-Object { $_.Credential -eq '(none)' })
        $noPing = @($failed | Where-Object { -not $_.CanPing -and $_.Credential -ne '(none)' })
        $noAuth = @($failed | Where-Object { $_.CanPing -and $_.Credential -ne '(none)' })
        
        if ($noCred.Count -gt 0) {
            Write-Host "    [!] $($noCred.Count) VM(s) have NO credential for domain '$($dg.Name)'" -ForegroundColor Red
            Write-Host "        FIX: Add a Credentials entry for '$($dg.Name)' in Config-OHDC.psd1" -ForegroundColor Yellow
        }
        if ($noPing.Count -gt 0) {
            Write-Host "    [!] $($noPing.Count) VM(s) unreachable by network AND PSDirect failed" -ForegroundColor Red
            Write-Host "        Check: Integration Services, guest OS PowerShell, credential local admin rights" -ForegroundColor Yellow
        }
        if ($noAuth.Count -gt 0) {
            Write-Host "    [!] $($noAuth.Count) VM(s) reachable but ALL auth methods failed" -ForegroundColor Red
            Write-Host "        Check: WinRM listeners, firewall rules, credential permissions" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Export results for analysis
$exportPath = Join-Path $PSScriptRoot "PSDirect-Test_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
Write-Host "  Results exported to: $exportPath" -ForegroundColor Green
Write-Host ""
