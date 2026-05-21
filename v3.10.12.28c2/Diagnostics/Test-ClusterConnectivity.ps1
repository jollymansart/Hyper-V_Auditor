<#
.SYNOPSIS
    Diagnose Hyper-V Cluster Connectivity and VM Enumeration
    
.DESCRIPTION
    Tests connectivity to clusters and enumerates VMs on cluster nodes
    
.EXAMPLE
    .\Test-ClusterConnectivity.ps1 -Credential (Get-Credential)
#>

param(
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Cluster Connectivity Diagnostic" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Write-Host "[STEP 1] Discovering clusters from Active Directory..." -ForegroundColor Yellow
Write-Host ""

try {
    $clusterObjects = Get-ADComputer -Filter {ServicePrincipalName -like "MSClusterVirtualServer/*"} `
        -Properties ServicePrincipalName, CN, DNSHostName, Description, LastLogonDate
    
    Write-Host "  [OK] Found $($clusterObjects.Count) cluster objects" -ForegroundColor Green
    Write-Host ""
    
    foreach ($cno in $clusterObjects) {
        $clusterName = $cno.DNSHostName
        Write-Host "----------------------------------------" -ForegroundColor Gray
        Write-Host "Cluster: $clusterName" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
        
        # Test 1: Get-Cluster WITHOUT -Domain parameter
        Write-Host "  [TEST 1] Get-Cluster without -Domain..." -NoNewline
        try {
            $cluster = Get-Cluster -Name $clusterName -ErrorAction Stop
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "    Cluster: $($cluster.Name)" -ForegroundColor Gray
            Write-Host "    Domain: $($cluster.Domain)" -ForegroundColor Gray
        }
        catch {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # Test 2: Get-Cluster WITH -Domain parameter
        Write-Host "  [TEST 2] Get-Cluster with -Domain..." -NoNewline
        try {
            $cluster = Get-Cluster -Name $clusterName -Domain "ohdc.com" -ErrorAction Stop
            Write-Host " [PASS]" -ForegroundColor Green
            Write-Host "    Cluster: $($cluster.Name)" -ForegroundColor Gray
            Write-Host "    Domain: $($cluster.Domain)" -ForegroundColor Gray
            
            # Get nodes
            $nodes = Get-ClusterNode -Cluster $clusterName -ErrorAction Stop
            Write-Host "    Nodes: $($nodes.Count)" -ForegroundColor Gray
            foreach ($node in $nodes) {
                Write-Host "      - $($node.Name) [$($node.State)]" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host " [FAIL]" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # Test 3: Enumerate VMs on cluster nodes
        Write-Host "  [TEST 3] Enumerating VMs on cluster nodes..." -ForegroundColor Yellow
        try {
            $nodes = Get-ClusterNode -Cluster $clusterName -Domain "ohdc.com" -ErrorAction Stop
            $totalVMs = 0
            
            foreach ($node in $nodes) {
                Write-Host "    Node: $($node.Name)..." -NoNewline
                try {
                    if ($Credential) {
                        $vms = Invoke-Command -ComputerName $node.Name -Credential $Credential -ScriptBlock {
                            Get-VM | Select-Object Name, State, CPUUsage, @{N='Host';E={$env:COMPUTERNAME}}
                        } -ErrorAction Stop
                    }
                    else {
                        $vms = Get-VM -ComputerName $node.Name -ErrorAction Stop
                    }
                    
                    Write-Host " $($vms.Count) VMs" -ForegroundColor Green
                    $totalVMs += $vms.Count
                    
                    foreach ($vm in ($vms | Select-Object -First 3)) {
                        Write-Host "        - $($vm.Name) [$($vm.State)]" -ForegroundColor Gray
                    }
                    if ($vms.Count -gt 3) {
                        Write-Host "        ... and $($vms.Count - 3) more" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Host " [ERROR]" -ForegroundColor Red
                    Write-Host "        Error: $($_.Exception.Message)" -ForegroundColor Gray
                }
            }
            
            Write-Host "    TOTAL: $totalVMs VMs across $($nodes.Count) nodes" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  [FAIL] Could not enumerate cluster nodes" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        Write-Host ""
    }
}
catch {
    Write-Host "[ERROR] Failed to query Active Directory" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "STEP 2: Checking Hyper-V Hosts from AD" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

try {
    $hvHosts = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} `
        -Properties OperatingSystem, ServicePrincipalName, DNSHostName |
        Where-Object { $_.ServicePrincipalName -like "Microsoft Virtual Console Service/*" -or
                       $_.ServicePrincipalName -like "Microsoft Virtual System Migration Service/*" }
    
    Write-Host "Total Hyper-V hosts found: $($hvHosts.Count)" -ForegroundColor White
    Write-Host ""
    
    # Group by cluster membership
    $standaloneHosts = @()
    $clusterNodes = @()
    
    foreach ($host in $hvHosts) {
        try {
            # Check if this host is a cluster node
            $clusterNode = Get-ClusterNode -Name $host.Name -ErrorAction SilentlyContinue
            if ($clusterNode) {
                $clusterNodes += [PSCustomObject]@{
                    Name = $host.Name
                    FQDN = $host.DNSHostName
                    Cluster = $clusterNode.Cluster
                }
            }
            else {
                $standaloneHosts += [PSCustomObject]@{
                    Name = $host.Name
                    FQDN = $host.DNSHostName
                }
            }
        }
        catch {
            $standaloneHosts += [PSCustomObject]@{
                Name = $host.Name
                FQDN = $host.DNSHostName
            }
        }
    }
    
    Write-Host "Standalone Hosts: $($standaloneHosts.Count)" -ForegroundColor Yellow
    foreach ($host in $standaloneHosts | Select-Object -First 10) {
        Write-Host "  - $($host.FQDN)" -ForegroundColor Gray
    }
    if ($standaloneHosts.Count -gt 10) {
        Write-Host "  ... and $($standaloneHosts.Count - 10) more" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Cluster Nodes: $($clusterNodes.Count)" -ForegroundColor Yellow
    foreach ($node in $clusterNodes | Select-Object -First 10) {
        Write-Host "  - $($node.FQDN) [Cluster: $($node.Cluster)]" -ForegroundColor Gray
    }
    if ($clusterNodes.Count -gt 10) {
        Write-Host "  ... and $($clusterNodes.Count - 10) more" -ForegroundColor Gray
    }
}
catch {
    Write-Host "[ERROR] Failed to enumerate Hyper-V hosts" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "FINDINGS:" -ForegroundColor White
Write-Host "  1. If TEST 1 fails but TEST 2 passes, add -Domain parameter" -ForegroundColor Gray
Write-Host "  2. If TEST 3 shows VMs, cluster nodes are accessible" -ForegroundColor Gray
Write-Host "  3. Compare standalone vs cluster node counts" -ForegroundColor Gray
Write-Host ""
