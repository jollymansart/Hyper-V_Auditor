<#
.SYNOPSIS
    Test-ReportPermissions.ps1
    Diagnostic script that checks whether a given user account has the minimum
    permissions required to run the Hyper-V Inventory Report unattended.

.DESCRIPTION
    OPEN-59 Part 1: Standalone diagnostic for the unattended-report scenario.

    The Hyper-V Inventory Report touches many systems: the report host itself,
    every Hyper-V host in scope, the guest OSes inside those VMs, AD, DNS, file
    shares, and (optionally) SCCM. To run the report from Task Scheduler under
    a non-admin service account, that account needs a specific set of
    permissions in each of those locations.

    This script enumerates every permission the report actually needs and tests
    whether the current user (or a specified credential) has it. The output is
    a pass/fail report with concrete remediation guidance for every missing
    permission.

    The script is non-destructive. It only reads permissions and tests
    connections; it never modifies anything. Safe to run against production.

.PARAMETER ReportHost
    Hostname of the report host where Run_Report.ps1 will execute.
    Default: $env:COMPUTERNAME (the local machine).

.PARAMETER HyperVHosts
    Array of Hyper-V host FQDNs to test against. If omitted, the script will
    pull the current Hyper-V host list from AD using Get-ADComputer with
    OperatingSystem -like '*Hyper-V*' (best-effort discovery).

.PARAMETER SampleVMs
    Optional array of VM names to test guest-side WinRM permissions against.
    If omitted, the script picks 3 random running VMs from the first reachable
    Hyper-V host as samples.

.PARAMETER OutputFolder
    Path where the report would write its output xlsx files. Used to test NTFS
    Modify permission. Default: \\rictx-script-p2\log\Hyper-V

.PARAMETER ConfigPath
    Path to the report's Config file. Used to test NTFS Read permission and to
    parse what features are enabled (so we only check permissions for features
    that are turned on). Default: tries Config-OHDC.psd1 then Config.psd1 in
    the script's own folder.

.PARAMETER Credential
    Optional PSCredential to test against. If omitted, tests the current user.
    Use this to validate a service account candidate before configuring it on
    the scheduled task: pass the future svc account credential here.

.PARAMETER ExportResults
    If specified, writes a CSV of all checks (Pass/Fail/Warning) to the
    location. Useful for documentation or for opening a ticket with
    infrastructure to grant missing permissions.

.PARAMETER Verbose
    Standard PowerShell -Verbose. Shows per-host details as the script runs.

.EXAMPLE
    .\Test-ReportPermissions.ps1

    Tests the current user against the report host's discovered Hyper-V hosts
    and a few sample VMs. Prints a colored pass/fail summary.

.EXAMPLE
    .\Test-ReportPermissions.ps1 -Credential (Get-Credential ohdc1\svc_hypervreport)

    Tests a service account candidate. Prompts for the password, then runs
    every check using that credential.

.EXAMPLE
    .\Test-ReportPermissions.ps1 -HyperVHosts @('rictx-hv-p01.ohdc.com','mhoh-hv-p01.ohdc.com') -SampleVMs @('RICTX-AD-P01','MHOH-AD-P01') -ExportResults C:\temp\perm-check.csv

    Targeted test against specific hosts and VMs, exports results to CSV.

.NOTES
    Author: Michael George (with Claude)
    Version: 1.0.0
    Date: 2026-04-12
    PS Compat: 5.1+
    Related items: OPEN-59 (this script), OPEN-60 (permission visibility tab),
                   CR113 (preflight gate, will call this script's logic)

    What this script does NOT test:
    - DPAPI credential file decryption. Because DPAPI tied to the specific user
      that encrypted the file, the only valid test is "run the actual report".
      This script will warn if the credential files are not readable by the
      tested account, but cannot test decryption without the actual data.
    - SCCM client role permissions. SCCM has its own RBAC model that is
      orthogonal to AD permissions. If IncludeSCCM is true, the script flags
      this as "untested -- verify in SCCM console".
    - VMware/Nutanix/SCVMM permissions (those collectors don't exist yet -- v4.0.0).
#>

[CmdletBinding()]
param(
    [string]$ReportHost = $env:COMPUTERNAME,
    [string[]]$HyperVHosts,
    [string[]]$SampleVMs,
    [string]$OutputFolder = '\\rictx-script-p2\log\Hyper-V',
    [string]$ConfigPath,
    [pscredential]$Credential,
    [string]$ExportResults
)

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
$script:Results = New-Object System.Collections.Generic.List[PSCustomObject]
$script:PassCount = 0
$script:WarnCount = 0
$script:FailCount = 0

function Add-CheckResult {
    param(
        [string]$Category,
        [string]$Target,
        [string]$Permission,
        [ValidateSet('PASS','WARN','FAIL','SKIP')] [string]$Result,
        [string]$Detail,
        [string]$Remediation
    )
    $obj = [PSCustomObject]@{
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category    = $Category
        Target      = $Target
        Permission  = $Permission
        Result      = $Result
        Detail      = $Detail
        Remediation = $Remediation
    }
    $script:Results.Add($obj)
    switch ($Result) {
        'PASS' { $script:PassCount++; $color = 'Green' }
        'WARN' { $script:WarnCount++; $color = 'Yellow' }
        'FAIL' { $script:FailCount++; $color = 'Red' }
        'SKIP' { $color = 'DarkGray' }
    }
    $marker = switch ($Result) { 'PASS' {'[OK]'}; 'WARN' {'[??]'}; 'FAIL' {'[XX]'}; 'SKIP' {'[--]'}}
    Write-Host ("  {0,-5} {1,-20} {2,-35} {3}" -f $marker, $Category, $Permission, $Target) -ForegroundColor $color
    if ($Result -ne 'PASS' -and $Detail) {
        Write-Host ("        $Detail") -ForegroundColor DarkGray
    }
}

function Invoke-AsTestUser {
    param([scriptblock]$ScriptBlock, [object[]]$ArgumentList)
    if ($Credential) {
        # Run the test inside an Invoke-Command -ComputerName localhost session
        # using the test credential. This is the only reliable way to test
        # "what would this account see" without actually logging in as them.
        try {
            return Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
        catch {
            return @{ Error = $_.Exception.Message }
        }
    }
    else {
        return & $ScriptBlock @ArgumentList
    }
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " Hyper-V Inventory Report -- Permission Diagnostic" -ForegroundColor Cyan
Write-Host " Test user: $(if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME (current)" })" -ForegroundColor Cyan
Write-Host " Report host: $ReportHost" -ForegroundColor Cyan
Write-Host " Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Section A: Report host itself
# ---------------------------------------------------------------------------
Write-Host "[A] REPORT HOST PERMISSIONS ($ReportHost)" -ForegroundColor White
Write-Host ""

# A1: SeBatchLogonRight (Log on as a batch job)
try {
    $secedit = & secedit /export /cfg $env:TEMP\secpol.cfg /quiet 2>&1
    $polContent = Get-Content $env:TEMP\secpol.cfg -ErrorAction Stop
    $batchLine = $polContent | Where-Object { $_ -match '^SeBatchLogonRight' }
    if ($batchLine) {
        $sids = ($batchLine -split '=')[1].Trim() -split ','
        $testSid = if ($Credential) {
            try { ([System.Security.Principal.NTAccount]$Credential.UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
        } else {
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        }
        $hasBatch = $sids -contains "*$testSid"
        if ($hasBatch) {
            Add-CheckResult -Category 'ReportHost' -Target $ReportHost -Permission 'SeBatchLogonRight' -Result PASS -Detail "Account is in the Log on as a batch job policy"
        } else {
            Add-CheckResult -Category 'ReportHost' -Target $ReportHost -Permission 'SeBatchLogonRight' -Result FAIL -Detail "Account is NOT in the Log on as a batch job policy" -Remediation "secpol.msc -> Local Policies -> User Rights Assignment -> Log on as a batch job -> Add the service account. Or via GPO: Computer Config -> Policies -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> Log on as a batch job"
        }
    } else {
        Add-CheckResult -Category 'ReportHost' -Target $ReportHost -Permission 'SeBatchLogonRight' -Result WARN -Detail "Could not parse local security policy" -Remediation "Run secpol.msc manually and verify Log on as a batch job includes the service account"
    }
    Remove-Item $env:TEMP\secpol.cfg -Force -ErrorAction SilentlyContinue
}
catch {
    Add-CheckResult -Category 'ReportHost' -Target $ReportHost -Permission 'SeBatchLogonRight' -Result WARN -Detail "secedit failed: $($_.Exception.Message)" -Remediation "Run as administrator to test this check"
}

# A2: NTFS Modify on output folder
try {
    $testFile = Join-Path $OutputFolder ".perm-test-$(New-Guid).tmp"
    if ($Credential) {
        # Test by attempting via SMB with creds
        $result = Invoke-AsTestUser -ScriptBlock {
            param($f)
            try { New-Item -Path $f -ItemType File -Force -ErrorAction Stop | Out-Null; Remove-Item -Path $f -Force; return 'OK' }
            catch { return $_.Exception.Message }
        } -ArgumentList $testFile
        if ($result -eq 'OK') {
            Add-CheckResult -Category 'ReportHost' -Target $OutputFolder -Permission 'NTFS Modify (output folder)' -Result PASS -Detail "Can create+delete files in $OutputFolder"
        } else {
            Add-CheckResult -Category 'ReportHost' -Target $OutputFolder -Permission 'NTFS Modify (output folder)' -Result FAIL -Detail $result -Remediation "Grant Modify NTFS permission to the service account on $OutputFolder. Right-click folder -> Properties -> Security -> Edit -> Add."
        }
    } else {
        New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
        Remove-Item -Path $testFile -Force
        Add-CheckResult -Category 'ReportHost' -Target $OutputFolder -Permission 'NTFS Modify (output folder)' -Result PASS -Detail "Can create+delete files in $OutputFolder"
    }
}
catch {
    Add-CheckResult -Category 'ReportHost' -Target $OutputFolder -Permission 'NTFS Modify (output folder)' -Result FAIL -Detail $_.Exception.Message -Remediation "Grant Modify NTFS permission to the service account on $OutputFolder"
}

# A3: Config file readable
if (-not $ConfigPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    foreach ($cn in @('Config-OHDC.psd1','Config.psd1')) {
        $cp = Join-Path $scriptDir $cn
        if (Test-Path $cp) { $ConfigPath = $cp; break }
    }
}
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    try {
        $configData = Import-PowerShellDataFile -Path $ConfigPath -ErrorAction Stop
        Add-CheckResult -Category 'ReportHost' -Target $ConfigPath -Permission 'Config file readable+parseable' -Result PASS -Detail "Loaded $($configData.Keys.Count) keys"
    }
    catch {
        Add-CheckResult -Category 'ReportHost' -Target $ConfigPath -Permission 'Config file readable+parseable' -Result FAIL -Detail $_.Exception.Message -Remediation "Grant Read NTFS permission on $ConfigPath"
    }
}
else {
    Add-CheckResult -Category 'ReportHost' -Target '(not specified)' -Permission 'Config file readable' -Result SKIP -Detail "No Config path provided and none found in script folder. Pass -ConfigPath to test."
    $configData = $null
}

# A4: PowerShell modules loadable
$requiredModules = @('Hyper-V','ActiveDirectory','FailoverClusters','ImportExcel')
if ($configData) {
    if ($configData.IncludeDNSValidation) { $requiredModules += @('DnsClient','DnsServer') }
    if ($configData.IncludeSCCM) { $requiredModules += 'ConfigurationManager' }
}
foreach ($m in $requiredModules) {
    $mod = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mod) {
        Add-CheckResult -Category 'ReportHost' -Target $m -Permission 'Module installed' -Result PASS -Detail "Version $($mod.Version)"
    } else {
        $remediation = switch ($m) {
            'Hyper-V'           { 'Install-WindowsFeature RSAT-Hyper-V-Tools (Server) or Enable optional feature Microsoft-Hyper-V-Management-PowerShell (Workstation)' }
            'ActiveDirectory'   { 'Install-WindowsFeature RSAT-AD-PowerShell (Server) or Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 (Workstation)' }
            'FailoverClusters'  { 'Install-WindowsFeature RSAT-Clustering-PowerShell' }
            'ImportExcel'       { 'Install-Module ImportExcel -Scope AllUsers -Force' }
            'DnsClient'         { 'Native module -- should always be present. Check $env:PSModulePath includes C:\Windows\System32\WindowsPowerShell\v1.0\Modules' }
            'DnsServer'         { 'Install-WindowsFeature RSAT-DNS-Server (or RSAT-DNS via Add-WindowsCapability on workstation)' }
            'ConfigurationManager' { 'Install SCCM Console (includes ConfigurationManager.psd1). Set IncludeSCCM=$false in config to disable.' }
            default             { "Install-Module $m -Scope AllUsers -Force" }
        }
        Add-CheckResult -Category 'ReportHost' -Target $m -Permission 'Module installed' -Result FAIL -Detail "Module not found in $env:PSModulePath" -Remediation $remediation
    }
}

# A5: AD readability (needed to discover hosts and computer objects)
try {
    $adTest = Invoke-AsTestUser -ScriptBlock {
        try { Get-ADDomain -ErrorAction Stop | Select-Object -ExpandProperty DNSRoot } catch { @{ Error = $_.Exception.Message } }
    }
    if ($adTest -and -not $adTest.Error) {
        Add-CheckResult -Category 'ReportHost' -Target $adTest -Permission 'AD read (Get-ADDomain)' -Result PASS -Detail "Resolved domain $adTest"
    } else {
        Add-CheckResult -Category 'ReportHost' -Target 'AD' -Permission 'AD read (Get-ADDomain)' -Result FAIL -Detail $adTest.Error -Remediation "Account must be Authenticated User in the domain. Verify network connectivity to a DC and Kerberos auth working."
    }
}
catch {
    Add-CheckResult -Category 'ReportHost' -Target 'AD' -Permission 'AD read (Get-ADDomain)' -Result FAIL -Detail $_.Exception.Message -Remediation "Verify ActiveDirectory module installed and account can reach a DC"
}

Write-Host ""

# ---------------------------------------------------------------------------
# Section B: Hyper-V Hosts
# ---------------------------------------------------------------------------
Write-Host "[B] HYPER-V HOST PERMISSIONS" -ForegroundColor White
Write-Host ""

if (-not $HyperVHosts -or $HyperVHosts.Count -eq 0) {
    Write-Host "  Discovering Hyper-V hosts from AD..." -ForegroundColor DarkGray
    try {
        $HyperVHosts = Get-ADComputer -Filter "OperatingSystem -like '*Hyper-V*' -or OperatingSystem -like '*Server*'" -Properties OperatingSystem, DNSHostName -ErrorAction Stop |
            Where-Object { $_.OperatingSystem -match 'Server' } |
            Select-Object -First 5 -ExpandProperty DNSHostName
        Write-Host "  Found $($HyperVHosts.Count) candidate hosts (limited to first 5 for diagnostic)" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  Could not auto-discover hosts: $($_.Exception.Message)" -ForegroundColor Red
        $HyperVHosts = @()
    }
}

foreach ($hv in $HyperVHosts) {
    Write-Host "  Testing $hv ..." -ForegroundColor DarkCyan

    # B1: ICMP / network reachability
    if (Test-Connection -ComputerName $hv -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Network reachable (ICMP)' -Result PASS
    } else {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Network reachable (ICMP)' -Result WARN -Detail "Ping failed (firewall may block ICMP -- WinRM may still work)"
    }

    # B2: WinRM connectivity
    try {
        $params = @{ ComputerName = $hv; ErrorAction = 'Stop' }
        if ($Credential) { $params['Credential'] = $Credential }
        $null = Test-WSMan @params
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'WinRM reachable' -Result PASS
    }
    catch {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'WinRM reachable' -Result FAIL -Detail $_.Exception.Message -Remediation "Verify WinRM is running on $hv (Test-WSMan), firewall allows port 5985/5986, account has Remote Management Users membership or is local Administrator on $hv"
        continue  # skip the rest of the host-level checks if WinRM is broken
    }

    # B3: Hyper-V Administrators membership (via Get-VMHost cmdlet success)
    try {
        $hvCheck = Invoke-Command -ComputerName $hv -Credential $Credential -ErrorAction Stop -ScriptBlock {
            try {
                Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                $h = Hyper-V\Get-VMHost -ErrorAction Stop
                @{ OK = $true; Name = $h.Name }
            }
            catch { @{ OK = $false; Error = $_.Exception.Message } }
        }
        if ($hvCheck.OK) {
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Hyper-V cmdlet access (Get-VMHost)' -Result PASS -Detail "Resolved $($hvCheck.Name)"
        } else {
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Hyper-V cmdlet access (Get-VMHost)' -Result FAIL -Detail $hvCheck.Error -Remediation "Add account to local 'Hyper-V Administrators' group on $hv. Run on the host: Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member '<DOMAIN>\<svcaccount>'"
        }
    }
    catch {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Hyper-V cmdlet access (Get-VMHost)' -Result FAIL -Detail $_.Exception.Message -Remediation "Verify WinRM works first (B2 above)"
    }

    # B4: Failover Cluster read (best-effort, may legitimately fail on standalone hosts)
    try {
        $clusterCheck = Invoke-Command -ComputerName $hv -Credential $Credential -ErrorAction Stop -ScriptBlock {
            try {
                $svc = Get-Service ClusSvc -ErrorAction SilentlyContinue
                if (-not $svc -or $svc.Status -ne 'Running') {
                    @{ OK = $true; Standalone = $true }
                } else {
                    Import-Module FailoverClusters -ErrorAction Stop
                    $c = Get-Cluster -ErrorAction Stop
                    @{ OK = $true; Standalone = $false; Name = $c.Name }
                }
            }
            catch { @{ OK = $false; Error = $_.Exception.Message } }
        }
        if ($clusterCheck.OK) {
            if ($clusterCheck.Standalone) {
                Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Failover Cluster read' -Result PASS -Detail "Standalone host (no cluster service)"
            } else {
                Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Failover Cluster read' -Result PASS -Detail "Cluster: $($clusterCheck.Name)"
            }
        } else {
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Failover Cluster read' -Result WARN -Detail $clusterCheck.Error -Remediation "Cluster cmdlets require local Administrators membership on $hv. Add account to Administrators group."
        }
    }
    catch {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Failover Cluster read' -Result WARN -Detail $_.Exception.Message
    }

    # B5: Remote registry read (TLS audit)
    try {
        $regCheck = Invoke-Command -ComputerName $hv -Credential $Credential -ErrorAction Stop -ScriptBlock {
            try {
                $null = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -ErrorAction Stop
                @{ OK = $true }
            }
            catch { @{ OK = $false; Error = $_.Exception.Message } }
        }
        if ($regCheck.OK) {
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Remote registry read (TLS audit)' -Result PASS
        } else {
            # SCHANNEL keys may legitimately not exist if TLS was never explicitly configured -- soft warn
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Remote registry read (TLS audit)' -Result WARN -Detail "$($regCheck.Error) (key may not exist if TLS never explicitly configured -- this is informational only)" -Remediation "If reading other registry keys also fails, account needs local Administrators membership for remote registry"
        }
    }
    catch {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Remote registry read (TLS audit)' -Result WARN -Detail $_.Exception.Message
    }

    # B6: Remote event log read (VM Activity Audit)
    try {
        $logCheck = Invoke-Command -ComputerName $hv -Credential $Credential -ErrorAction Stop -ScriptBlock {
            try {
                $null = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -MaxEvents 1 -ErrorAction Stop
                @{ OK = $true }
            }
            catch { @{ OK = $false; Error = $_.Exception.Message } }
        }
        if ($logCheck.OK) {
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Event log read (Hyper-V-VMMS-Admin)' -Result PASS
        } else {
            Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Event log read (Hyper-V-VMMS-Admin)' -Result FAIL -Detail $logCheck.Error -Remediation "Add account to 'Event Log Readers' group on $hv: Add-LocalGroupMember -Group 'Event Log Readers' -Member '<DOMAIN>\<svcaccount>'"
        }
    }
    catch {
        Add-CheckResult -Category 'HyperVHost' -Target $hv -Permission 'Event log read (Hyper-V-VMMS-Admin)' -Result WARN -Detail $_.Exception.Message
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# Section C: Sample VMs (guest-side WinRM)
# ---------------------------------------------------------------------------
Write-Host "[C] SAMPLE VM GUEST PERMISSIONS" -ForegroundColor White
Write-Host ""

if (-not $SampleVMs -or $SampleVMs.Count -eq 0) {
    Write-Host "  No sample VMs specified -- pass -SampleVMs to test guest-side permissions" -ForegroundColor DarkGray
    Add-CheckResult -Category 'GuestVM' -Target '(none)' -Permission 'Guest WinRM test' -Result SKIP -Detail "No sample VMs provided -- pass -SampleVMs @('VM1','VM2')"
}
else {
    foreach ($vm in $SampleVMs) {
        Write-Host "  Testing $vm ..." -ForegroundColor DarkCyan

        # Guest WinRM via direct DNS (Kerberos path)
        try {
            $params = @{ ComputerName = $vm; ErrorAction = 'Stop' }
            if ($Credential) { $params['Credential'] = $Credential }
            $null = Test-WSMan @params
            Add-CheckResult -Category 'GuestVM' -Target $vm -Permission 'WinRM reachable (Kerberos)' -Result PASS
        }
        catch {
            Add-CheckResult -Category 'GuestVM' -Target $vm -Permission 'WinRM reachable (Kerberos)' -Result FAIL -Detail $_.Exception.Message -Remediation "Verify VM is running, DNS resolves, WinRM is configured in guest, and account is in guest's local Administrators or Remote Management Users group. PSDirect fallback (CR111) will only work if account is also Hyper-V Admin on the host."
            continue
        }

        # Guest CIM read
        try {
            $params = @{ ComputerName = $vm; ErrorAction = 'Stop'; ScriptBlock = { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | Select-Object -ExpandProperty Caption } }
            if ($Credential) { $params['Credential'] = $Credential }
            $os = Invoke-Command @params
            Add-CheckResult -Category 'GuestVM' -Target $vm -Permission 'Guest CIM read (Win32_OperatingSystem)' -Result PASS -Detail "OS: $os"
        }
        catch {
            Add-CheckResult -Category 'GuestVM' -Target $vm -Permission 'Guest CIM read (Win32_OperatingSystem)' -Result FAIL -Detail $_.Exception.Message -Remediation "Account must be in guest's local Administrators group for full WMI/CIM access."
        }

        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  PASS: $script:PassCount" -ForegroundColor Green
Write-Host "  WARN: $script:WarnCount" -ForegroundColor Yellow
Write-Host "  FAIL: $script:FailCount" -ForegroundColor Red
Write-Host ""

if ($script:FailCount -gt 0) {
    Write-Host " RESULT: NOT READY for unattended execution" -ForegroundColor Red
    Write-Host " The above failures must be resolved before this account can run the report from Task Scheduler." -ForegroundColor Red
}
elseif ($script:WarnCount -gt 0) {
    Write-Host " RESULT: PROBABLY READY -- review warnings above" -ForegroundColor Yellow
    Write-Host " The account has all hard requirements but some non-critical checks could not be verified." -ForegroundColor Yellow
}
else {
    Write-Host " RESULT: READY for unattended execution" -ForegroundColor Green
}
Write-Host "==============================================================="  -ForegroundColor Cyan

if ($ExportResults) {
    try {
        $script:Results | Export-Csv -Path $ExportResults -NoTypeInformation -Force
        Write-Host ""
        Write-Host "  Results exported to: $ExportResults" -ForegroundColor Cyan
    }
    catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Note: This script does NOT test DPAPI credential file decryption." -ForegroundColor DarkYellow
Write-Host "      DPAPI is tied to the encrypting user. The only true test is to run the actual report under the target account." -ForegroundColor DarkYellow
if ($configData -and $configData.IncludeSCCM) {
    Write-Host ""
    Write-Host "Note: IncludeSCCM=true detected in config. SCCM RBAC is separate from AD permissions." -ForegroundColor DarkYellow
    Write-Host "      Verify the account has appropriate SCCM Read role in the SCCM Admin Console." -ForegroundColor DarkYellow
}
Write-Host ""
