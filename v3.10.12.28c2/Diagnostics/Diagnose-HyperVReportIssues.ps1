<#
.SYNOPSIS
    Diagnostic script for Hyper-V Inventory Report issues found in v3.10.0-v3.10.2 runs.
    
.DESCRIPTION
    Targeted troubleshooting for 7 known issues. Run from RICTX-SCRIPT-P2 as mgeorge-adm.
    Each section can be run independently by uncommenting/commenting the $RunDiagnostics array.

.NOTES
    Author: Michael George / Claude
    Date: 2026-03-28
    Context: Issues identified from v3.10.0, v3.10.1, v3.10.2 run analysis
#>

#Requires -Version 5.1

param(
    [string]$OutputFolder = "\\rictx-script-p2\log\Hyper-V\Diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Which diagnostics to run (comment out any you want to skip)
$RunDiagnostics = @(
    'Issue1_VMActivityAudit_ZeroEvents'
    'Issue2_OpAdditionBug'
    'Issue3_CrossDomain68Warning'
    'Issue4_DNS161Critical'
    'Issue5_UCSHVP3_Stuck'
    'Issue6_S2D_FaultDomains'
    'Issue7_CreativeCom_ADWS'
)

New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
$logFile = Join-Path $OutputFolder "Diagnostics.log"
function Log { param($Msg) $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; "$ts  $Msg" | Tee-Object -FilePath $logFile -Append }

Log "=========================================="
Log "Hyper-V Report Diagnostics -- $(Get-Date)"
Log "Running as: $env:USERDOMAIN\$env:USERNAME"
Log "Output: $OutputFolder"
Log "=========================================="

# ============================================================
# ISSUE 1: VM Activity Audit returned 0 events across all 38 hosts
# Root cause hypothesis: Event log name mismatch or XPath filter too restrictive
# ============================================================
if ($RunDiagnostics -contains 'Issue1_VMActivityAudit_ZeroEvents') {
    Log ""
    Log "=== ISSUE 1: VM Activity Audit -- 0 Events ==="
    Log "Testing event log queries on a few representative hosts..."
    
    $testHosts = @(
        'RICTX-UCSHV-P1.ohdc.com'    # UCS blade, many VMs
        'MHOH-HV-P01.ohdc.com'       # MHOH cluster node
        'MATMX-HV-P01.ohdc.com'      # MATMX host (has offline disk VM)
    )
    
    $results = @()
    foreach ($h in $testHosts) {
        Log "  Testing $h ..."
        try {
            $data = Invoke-Command -ComputerName $h -ScriptBlock {
                $out = @{ Host = $env:COMPUTERNAME; Errors = @() }
                
                # Test 1: Do the expected event log names exist?
                $expectedLogs = @(
                    'Microsoft-Windows-Hyper-V-VMMS-Admin'
                    'Microsoft-Windows-Hyper-V-Worker-Admin'
                    'System'
                    'Microsoft-Windows-FailoverClustering/Operational'
                )
                $out.LogExists = @{}
                foreach ($logName in $expectedLogs) {
                    try {
                        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                        $out.LogExists[$logName] = @{
                            Exists      = $true
                            RecordCount = $log.RecordCount
                            MaxSizeKB   = [math]::Round($log.MaximumSizeInBytes / 1KB, 0)
                            IsEnabled   = $log.IsEnabled
                            LastWrite   = if ($log.LastWriteTime) { $log.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }
                        }
                    }
                    catch {
                        $out.LogExists[$logName] = @{ Exists = $false; Error = $_.Exception.Message }
                    }
                }
                
                # Test 2: Raw event count for last 7 days (no XPath filter -- just count everything)
                $since = (Get-Date).AddDays(-7)
                $out.RawEventCounts = @{}
                foreach ($logName in $expectedLogs) {
                    try {
                        $events = Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction SilentlyContinue |
                            Where-Object { $_.TimeCreated -ge $since }
                        $out.RawEventCounts[$logName] = $events.Count
                    }
                    catch {
                        $out.RawEventCounts[$logName] = -1
                    }
                }
                
                # Test 3: Specific VMMS event IDs that the module looks for
                $vmmsEventIDs = @(18500, 18501, 18502, 18504, 18506, 12300, 18600, 18602, 18503, 13002)
                $out.VMSEventsByID = @{}
                try {
                    $allVmmsEvents = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -MaxEvents 500 -ErrorAction SilentlyContinue |
                        Where-Object { $_.TimeCreated -ge $since }
                    foreach ($id in $vmmsEventIDs) {
                        $out.VMSEventsByID[$id] = @($allVmmsEvents | Where-Object { $_.Id -eq $id }).Count
                    }
                    $out.TotalVMMSLast7Days = $allVmmsEvents.Count
                    # Show a sample of what event IDs ARE in the log
                    $out.TopVMMSEventIDs = $allVmmsEvents | Group-Object Id | Sort-Object Count -Descending |
                        Select-Object -First 10 @{N='EventID';E={$_.Name}}, Count
                }
                catch {
                    $out.TotalVMMSLast7Days = -1
                    $out.Errors += "VMMS query failed: $($_.Exception.Message)"
                }
                
                # Test 4: Check if the XPath query from the module works
                $xpathTest = "*[System[TimeCreated[@SystemTime >= '$(($since).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z'))']]]"
                try {
                    $xpathEvents = Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -FilterXPath $xpathTest -MaxEvents 10 -ErrorAction Stop
                    $out.XPathWorks = $true
                    $out.XPathSampleCount = $xpathEvents.Count
                }
                catch {
                    $out.XPathWorks = $false
                    $out.XPathError = $_.Exception.Message
                }
                
                # Test 5: Try FilterHashtable instead of XPath
                try {
                    $hashEvents = Get-WinEvent -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Hyper-V-VMMS-Admin'
                        StartTime = $since
                    } -MaxEvents 10 -ErrorAction Stop
                    $out.FilterHashWorks = $true
                    $out.FilterHashCount = $hashEvents.Count
                    $out.FilterHashSample = $hashEvents | Select-Object -First 3 Id, TimeCreated, Message
                }
                catch {
                    $out.FilterHashWorks = $false
                    $out.FilterHashError = $_.Exception.Message
                }
                
                $out
            } -ErrorAction Stop
            
            $results += $data
            
            Log "    Log exists: $($data.LogExists.Keys -join ', ')"
            foreach ($k in $data.LogExists.Keys) {
                $v = $data.LogExists[$k]
                if ($v.Exists) {
                    Log "      $k : Records=$($v.RecordCount), Enabled=$($v.IsEnabled), LastWrite=$($v.LastWrite)"
                } else {
                    Log "      $k : NOT FOUND -- $($v.Error)"
                }
            }
            Log "    Raw event counts (last 7d): $($data.RawEventCounts | ConvertTo-Json -Compress)"
            Log "    Total VMMS events (last 7d): $($data.TotalVMMSLast7Days)"
            if ($data.TopVMMSEventIDs) {
                Log "    Top VMMS Event IDs: $(($data.TopVMMSEventIDs | ForEach-Object { "$($_.EventID):$($_.Count)" }) -join ', ')"
            }
            Log "    XPath works: $($data.XPathWorks) $(if (-not $data.XPathWorks) { "-- $($data.XPathError)" })"
            Log "    FilterHashtable works: $($data.FilterHashWorks) $(if (-not $data.FilterHashWorks) { "-- $($data.FilterHashError)" })"
            if ($data.FilterHashSample) {
                foreach ($evt in $data.FilterHashSample) {
                    Log "      Sample: ID=$($evt.Id) Time=$($evt.TimeCreated) Msg=$($evt.Message.Substring(0, [Math]::Min(120, $evt.Message.Length)))..."
                }
            }
        }
        catch {
            Log "    FAILED to connect: $($_.Exception.Message)"
        }
    }
    
    $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputFolder "Issue1_VMActivity_EventLogs.json") -Encoding UTF8
    Log "  Results saved to Issue1_VMActivity_EventLogs.json"
}

# ============================================================
# ISSUE 2: op_Addition bug in Exec Summary (v3.10.2)
# This is a code bug -- just documenting the repro pattern here
# ============================================================
if ($RunDiagnostics -contains 'Issue2_OpAdditionBug') {
    Log ""
    Log "=== ISSUE 2: op_Addition Bug (Code-Level) ==="
    Log "  This is a PowerShell array concatenation bug in the Export module."
    Log "  The issueItems array is defined as @(...) which creates [System.Object[]]."
    Log "  When code later does issueItems += @{...}, it fails in some scopes."
    Log "  Fix: Change the initial array to [System.Collections.Generic.List[object]]"
    Log "  or define as [System.Collections.ArrayList]."
    Log ""
    Log "  Repro pattern (simplified):"
    Log '    $issueItems = @( @{Label="A"; Val=1}, @{Label="B"; Val=2} )'
    Log '    # This works in global scope but can fail inside try/catch or pipeline:'
    Log '    $issueItems += @{Label="C"; Val=3}  # op_Addition error'
    Log ""
    Log "  Affected: Exec Summary issues block when DNS Critical or Offline Disk entries are appended."
    Log "  Impact: Non-fatal. Reports generate but some issue rows may be missing from Exec Summary."
    Log "  Will be fixed in next version."
}

# ============================================================
# ISSUE 3: 68 Warning VMs on Cross-Domain-Auth (OS-Inventory stuck at ~188)
# Gather the specific VMs and their domains for CR84 validation
# ============================================================
if ($RunDiagnostics -contains 'Issue3_CrossDomain68Warning') {
    Log ""
    Log "=== ISSUE 3: 68 Cross-Domain Warning VMs ==="
    Log "  These are VMs where domain was detected but OS collection failed."
    Log "  v3.10.5 CR84 (Negotiate fallback) should fix most of these."
    Log "  Gathering the specific VMs from the Advanced xlsx..."
    
    # Quick test: try Negotiate on a known overheaddoor.com VM
    $testVMs = @(
        @{ Name = 'RICTX-DMZWEB-P6'; Domain = 'overheaddoor.com'; CredFile = 'C:\ProgramData\S\HyperV-Cred-overheaddoor.xml' }
    )
    
    foreach ($vm in $testVMs) {
        Log "  Testing $($vm.Name) ($($vm.Domain))..."
        
        $cred = $null
        if (Test-Path $vm.CredFile) {
            try { $cred = Import-Clixml $vm.CredFile } catch { Log "    Cannot load credential: $_" }
        }
        
        if ($cred) {
            # Test 1: Default auth (Kerberos)
            Log "    Attempt 1: Default (Kerberos)..."
            try {
                $result = Invoke-Command -ComputerName $vm.Name -Credential $cred -ScriptBlock { hostname } -ErrorAction Stop
                Log "    Kerberos: SUCCESS -- hostname=$result"
            }
            catch {
                $krbErr = $_.Exception.Message -replace '\r?\n.*',''
                Log "    Kerberos: FAILED -- $krbErr"
                
                # Test 2: Negotiate auth
                Log "    Attempt 2: Negotiate (NTLM fallback)..."
                try {
                    $result = Invoke-Command -ComputerName $vm.Name -Credential $cred -Authentication Negotiate -ScriptBlock { hostname } -ErrorAction Stop
                    Log "    Negotiate: SUCCESS -- hostname=$result"
                    Log "    >> This VM will be fixed by v3.10.5 CR84"
                }
                catch {
                    Log "    Negotiate: ALSO FAILED -- $($_.Exception.Message -replace '\r?\n.*','')"
                }
            }
        }
        else {
            Log "    No credential available for $($vm.Domain)"
        }
    }
    
    Log ""
    Log "  To test more VMs, run:"
    Log '    $cred = Import-Clixml "C:\ProgramData\S\HyperV-Cred-overheaddoor.xml"'
    Log '    Invoke-Command -ComputerName "VMNAME" -Credential $cred -Authentication Negotiate -ScriptBlock { hostname }'
}

# ============================================================
# ISSUE 4: DNS Validation -- 161 Critical (missing forward lookups)
# Check if the EfficientIP scope bug from v3.9.2 is still present
# ============================================================
if ($RunDiagnostics -contains 'Issue4_DNS161Critical') {
    Log ""
    Log "=== ISSUE 4: DNS Validation -- 161 Critical ==="
    Log "  Checking if EfficientIP API returns data for ohdc.com lookups..."
    
    # Test direct DNS resolution for a few known VMs
    $testNames = @(
        'RICTX-DC-P10.ohdc.com'
        'MHOH-HV-P01.ohdc.com'
        'RICTX-UCSHV-P1.ohdc.com'
    )
    
    foreach ($name in $testNames) {
        Log "  $name :"
        try {
            $dns = Resolve-DnsName $name -ErrorAction Stop | Select-Object -First 1
            Log "    Resolve-DnsName: $($dns.IPAddress) (Type=$($dns.Type))"
        }
        catch {
            Log "    Resolve-DnsName: FAILED -- $($_.Exception.Message)"
        }
        
        try {
            $dotnet = [System.Net.Dns]::GetHostEntry($name)
            $ips = ($dotnet.AddressList | ForEach-Object { $_.IPAddressToString }) -join ', '
            Log "    .NET GetHostEntry: $ips"
        }
        catch {
            Log "    .NET GetHostEntry: FAILED -- $($_.Exception.Message)"
        }
    }
    
    # Test EfficientIP connectivity
    Log ""
    Log "  Testing EfficientIP SOLIDserver connectivity..."
    $eipServer = 'RICTX-IPAM-P01.ohdc.com'
    try {
        $ping = Test-Connection -ComputerName $eipServer -Count 1 -Quiet
        Log "    Ping $eipServer : $ping"
    }
    catch { Log "    Ping failed: $_" }
    
    # Check if the Test-EfficientIPConnection.ps1 script exists
    $testScript = '\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\Test-EfficientIPConnection.ps1'
    if (Test-Path $testScript) {
        Log "    Test script found: $testScript"
        Log "    Run it manually: & '$testScript'"
    }
    else {
        Log "    Test script not found at $testScript"
    }
}

# ============================================================
# ISSUE 5: RICTX-UCSHV-P3 consistently stuck (7200+ seconds)
# ============================================================
if ($RunDiagnostics -contains 'Issue5_UCSHVP3_Stuck') {
    Log ""
    Log "=== ISSUE 5: RICTX-UCSHV-P3 Stuck Pattern ==="
    
    $slowHost = 'RICTX-UCSHV-P3.ohdc.com'
    Log "  Testing WinRM responsiveness on $slowHost..."
    
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-Command -ComputerName $slowHost -ScriptBlock {
            @{
                Hostname   = hostname
                VMCount    = (Get-VM).Count
                RunningVMs = (Get-VM | Where-Object State -eq 'Running').Count
                Uptime     = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                CPULoad    = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
                FreeMemGB  = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
                TotalMemGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
            }
        } -ErrorAction Stop
        $sw.Stop()
        
        Log "    WinRM response: $($sw.ElapsedMilliseconds)ms"
        Log "    Hostname: $($result.Hostname)"
        Log "    VMs: $($result.VMCount) total, $($result.RunningVMs) running"
        Log "    Uptime: $([math]::Round($result.Uptime.TotalDays, 1)) days"
        Log "    CPU: $($result.CPULoad)%"
        Log "    Memory: $($result.FreeMemGB)GB free / $($result.TotalMemGB)GB total"
        
        if ($result.VMCount -gt 30) {
            Log "    >> HIGH VM DENSITY: $($result.VMCount) VMs may explain slow collection"
        }
    }
    catch {
        Log "    FAILED: $($_.Exception.Message)"
    }
    
    # Test if the slow behavior is in the OS collection (per-VM WinRM) or the host inventory
    Log "  Testing per-VM WinRM from $slowHost (sample 3 VMs)..."
    try {
        $vms = Invoke-Command -ComputerName $slowHost -ScriptBlock {
            Get-VM | Where-Object State -eq 'Running' | Select-Object -First 3 Name
        }
        foreach ($vm in $vms) {
            $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $hostname = Invoke-Command -ComputerName $vm.Name -ScriptBlock { hostname } -ErrorAction Stop
                $sw2.Stop()
                Log "    $($vm.Name): ${hostname} -- $($sw2.ElapsedMilliseconds)ms"
            }
            catch {
                $sw2.Stop()
                Log "    $($vm.Name): FAILED ($($sw2.ElapsedMilliseconds)ms) -- $($_.Exception.Message -replace '\r?\n.*','')"
            }
        }
    }
    catch {
        Log "    Could not enumerate VMs on $slowHost : $($_.Exception.Message)"
    }
}

# ============================================================
# ISSUE 6: S2D MHOHCLUHV FaultDomains null expression
# ============================================================
if ($RunDiagnostics -contains 'Issue6_S2D_FaultDomains') {
    Log ""
    Log "=== ISSUE 6: S2D FaultDomains Null Expression ==="
    
    $s2dHost = 'MHOH-HV-P01.ohdc.com'
    Log "  Testing S2D FaultDomain query on $s2dHost..."
    
    try {
        $data = Invoke-Command -ComputerName $s2dHost -ScriptBlock {
            $out = @{}
            
            # Test Get-StorageFaultDomain
            try {
                $fd = Get-StorageFaultDomain -ErrorAction Stop
                $out.FaultDomainCount = $fd.Count
                $out.FaultDomainTypes = ($fd | Group-Object FaultDomainType | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ', '
            }
            catch {
                $out.FaultDomainError = $_.Exception.Message
            }
            
            # Test Get-ClusterStorageSpacesDirect
            try {
                $s2d = Get-ClusterStorageSpacesDirect -ErrorAction Stop
                $out.S2DState = $s2d.State
                $out.S2DCacheState = $s2d.CacheState
            }
            catch {
                $out.S2DError = $_.Exception.Message
            }
            
            # Test Get-PhysicalDisk
            try {
                $pd = Get-PhysicalDisk -ErrorAction Stop
                $out.PhysicalDiskCount = $pd.Count
                $out.DiskTypes = ($pd | Group-Object MediaType | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ', '
            }
            catch {
                $out.PhysicalDiskError = $_.Exception.Message
            }
            
            $out
        } -ErrorAction Stop
        
        foreach ($k in $data.Keys | Sort-Object) {
            Log "    $k : $($data[$k])"
        }
    }
    catch {
        Log "    FAILED: $($_.Exception.Message)"
    }
}

# ============================================================
# ISSUE 7: creative.com AD Web Services unreachable
# ============================================================
if ($RunDiagnostics -contains 'Issue7_CreativeCom_ADWS') {
    Log ""
    Log "=== ISSUE 7: creative.com AD Web Services ==="
    
    Log "  Testing creative.com domain controller connectivity..."
    
    # Find creative.com DCs via DNS
    try {
        $dcs = Resolve-DnsName -Name '_ldap._tcp.dc._msdcs.creative.com' -Type SRV -ErrorAction Stop
        Log "  Found $($dcs.Count) DC SRV records:"
        foreach ($dc in $dcs) {
            $dcName = $dc.NameTarget
            Log "    $dcName (port $($dc.Port), priority $($dc.Priority))"
            
            # Test LDAP (389)
            $tcpLDAP = Test-NetConnection -ComputerName $dcName -Port 389 -WarningAction SilentlyContinue
            Log "      LDAP (389): $($tcpLDAP.TcpTestSucceeded)"
            
            # Test ADWS (9389) -- this is what fails
            $tcpADWS = Test-NetConnection -ComputerName $dcName -Port 9389 -WarningAction SilentlyContinue
            Log "      ADWS (9389): $($tcpADWS.TcpTestSucceeded)"
            
            if (-not $tcpADWS.TcpTestSucceeded) {
                Log "      >> ADWS not running. Server 2003 DCs do not have ADWS."
                Log "      >> This is expected and not fixable without upgrading to Server 2008 R2+."
                Log "      >> Impact: KCD validation and some AD queries skip creative.com."
            }
            
            # Check OS version via WMI
            try {
                $os = Get-WmiObject Win32_OperatingSystem -ComputerName $dcName -ErrorAction Stop
                Log "      OS: $($os.Caption) (Build $($os.BuildNumber))"
            }
            catch {
                Log "      OS query failed: $($_.Exception.Message -replace '\r?\n.*','')"
            }
        }
    }
    catch {
        Log "  Could not resolve creative.com SRV records: $($_.Exception.Message)"
    }
}

# ============================================================
# SUMMARY
# ============================================================
Log ""
Log "=========================================="
Log "DIAGNOSTICS COMPLETE"
Log "Output folder: $OutputFolder"
Log "Log file: $logFile"
Log "=========================================="

Write-Host ""
Write-Host "Results saved to: $OutputFolder" -ForegroundColor Green
Write-Host "Open the log: notepad `"$logFile`"" -ForegroundColor Cyan
