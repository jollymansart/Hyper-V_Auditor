<#
.SYNOPSIS
    Identify Which Hyper-V Hosts are Cluster Nodes vs Standalone
    
.DESCRIPTION
    Analyzes your Hyper-V inventory to show which hosts are actually cluster nodes
    and identifies cluster TYPES (Hyper-V, SQL, WAC, etc.)
    
.EXAMPLE
    .\Identify-ClusterNodes.ps1
#>

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Cluster Node vs Standalone Host Analysis" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Write-Host "[STEP 1] Discovering Hyper-V hosts from AD..." -ForegroundColor Yellow
Write-Host ""

try {
    # Get all Hyper-V hosts
    $hvHosts = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} `
        -Properties OperatingSystem, ServicePrincipalName, DNSHostName |
        Where-Object { $_.ServicePrincipalName -like "Microsoft Virtual Console Service/*" -or
                       $_.ServicePrincipalName -like "Microsoft Virtual System Migration Service/*" }
    
    Write-Host "Total Hyper-V hosts found: $($hvHosts.Count)" -ForegroundColor White
    Write-Host ""
    
    # Get all clusters
    Write-Host "[STEP 2] Discovering ALL clusters from AD..." -ForegroundColor Yellow
    Write-Host ""
    
    $clusterObjects = Get-ADComputer -Filter {ServicePrincipalName -like "MSClusterVirtualServer/*"} `
        -Properties ServicePrincipalName, CN, DNSHostName
    
    Write-Host "Total cluster objects found: $($clusterObjects.Count)" -ForegroundColor White
    Write-Host ""
    
    # For each cluster, get its nodes and determine type
    $allClusterNodes = @()
    $hyperVClusters = @()
    $sqlClusters = @()
    $wacClusters = @()
    $otherClusters = @()
    
    Write-Host "[STEP 3] Identifying cluster types and nodes..." -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($cno in $clusterObjects) {
        $clusterName = $cno.DNSHostName
        Write-Verbose "Processing cluster: $clusterName"
        
        try {
            # Try to connect to cluster
            $domain = if ($clusterName -match '\.') {
                $clusterName -replace '^[^\.]+\.', ''
            } else {
                "ohdc.com"
            }
            
            # Try without -Domain first, then with -Domain
            try {
                $cluster = Get-Cluster -Name $clusterName -ErrorAction Stop
            }
            catch {
                $cluster = Get-Cluster -Name $clusterName -Domain $domain -ErrorAction Stop
            }
            
            $nodes = Get-ClusterNode -Cluster $clusterName -ErrorAction Stop
            
            # Determine cluster type based on nodes
            $hvNodesInCluster = @()
            $clusterType = "Unknown"
            
            foreach ($node in $nodes) {
                if ($hvHosts.Name -contains $node.Name) {
                    $hvNodesInCluster += $node.Name
                    $allClusterNodes += [PSCustomObject]@{
                        NodeName = $node.Name
                        ClusterName = $cluster.Name
                        ClusterFQDN = $clusterName
                        State = $node.State
                    }
                }
            }
            
            # Determine cluster type
            if ($hvNodesInCluster.Count -gt 0) {
                # Determine specific type based on cluster name
                if ($cluster.Name -like "*SCVMM*" -or $cluster.Name -like "*VMM*") {
                    $clusterType = "System Center VMM (Hyper-V Management)"
                }
                else {
                    $clusterType = "Hyper-V Cluster"
                }
                
                $hyperVClusters += [PSCustomObject]@{
                    ClusterName = $cluster.Name
                    ClusterFQDN = $clusterName
                    NodeCount = $nodes.Count
                    HyperVNodeCount = $hvNodesInCluster.Count
                    Nodes = $hvNodesInCluster -join ', '
                    Type = $clusterType
                }
                Write-Host "  [HV] $($cluster.Name): $($hvNodesInCluster.Count) Hyper-V node(s) [$clusterType]" -ForegroundColor Green
            }
            elseif ($cluster.Name -like "*SQL*" -or $cluster.Name -like "*MSMQ*" -or $cluster.Name -like "*AGL*") {
                $clusterType = "SQL/Database Cluster"
                $sqlClusters += [PSCustomObject]@{
                    ClusterName = $cluster.Name
                    ClusterFQDN = $clusterName
                    NodeCount = $nodes.Count
                    Nodes = ($nodes | Select-Object -ExpandProperty Name) -join ', '
                    Type = $clusterType
                }
                Write-Host "  [SQL] $($cluster.Name): SQL/Database cluster" -ForegroundColor Gray
            }
            elseif ($cluster.Name -like "*WAC*") {
                $clusterType = "Windows Admin Center Cluster"
                $wacClusters += [PSCustomObject]@{
                    ClusterName = $cluster.Name
                    ClusterFQDN = $clusterName
                    NodeCount = $nodes.Count
                    Nodes = ($nodes | Select-Object -ExpandProperty Name) -join ', '
                    Type = $clusterType
                }
                Write-Host "  [WAC] $($cluster.Name): Windows Admin Center cluster" -ForegroundColor Cyan
            }
            else {
                $clusterType = "Other Cluster"
                $otherClusters += [PSCustomObject]@{
                    ClusterName = $cluster.Name
                    ClusterFQDN = $clusterName
                    NodeCount = $nodes.Count
                    Nodes = ($nodes | Select-Object -ExpandProperty Name) -join ', '
                    Type = $clusterType
                }
                Write-Host "  [???] $($cluster.Name): Other/Unknown cluster type" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Verbose "  Could not connect to $clusterName : $($_.Exception.Message)"
        }
    }
    
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "ANALYSIS RESULTS" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Identify standalone vs cluster nodes
    $standaloneHosts = $hvHosts | Where-Object { 
        $allClusterNodes.NodeName -notcontains $_.Name 
    }
    
    Write-Host "HYPER-V CLUSTERS: $($hyperVClusters.Count)" -ForegroundColor Yellow
    Write-Host ""
    foreach ($cluster in $hyperVClusters | Sort-Object ClusterName) {
        Write-Host "  Cluster: $($cluster.ClusterName)" -ForegroundColor White
        Write-Host "    FQDN: $($cluster.ClusterFQDN)" -ForegroundColor Gray
        Write-Host "    Nodes: $($cluster.Nodes)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "CLUSTER NODES (Hyper-V): $($allClusterNodes.Count)" -ForegroundColor Yellow
    Write-Host ""
    foreach ($node in $allClusterNodes | Sort-Object NodeName) {
        Write-Host "  $($node.NodeName) -> $($node.ClusterName) [$($node.State)]" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "STANDALONE HYPER-V HOSTS: $($standaloneHosts.Count)" -ForegroundColor Yellow
    Write-Host ""
    foreach ($hostObj in $standaloneHosts | Sort-Object Name) {
        Write-Host "  $($hostObj.DNSHostName)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "SQL/DATABASE CLUSTERS: $($sqlClusters.Count)" -ForegroundColor Gray
    foreach ($cluster in $sqlClusters | Sort-Object ClusterName | Select-Object -First 5) {
        Write-Host "  $($cluster.ClusterName)" -ForegroundColor Gray
    }
    if ($sqlClusters.Count -gt 5) {
        Write-Host "  ... and $($sqlClusters.Count - 5) more" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "WINDOWS ADMIN CENTER CLUSTERS: $($wacClusters.Count)" -ForegroundColor Cyan
    foreach ($cluster in $wacClusters | Sort-Object ClusterName) {
        Write-Host "  $($cluster.ClusterName): $($cluster.Nodes)" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Total Hyper-V Hosts: $($hvHosts.Count)" -ForegroundColor White
    Write-Host "  - Cluster Nodes: $($allClusterNodes.Count)" -ForegroundColor Cyan
    Write-Host "  - Standalone Hosts: $($standaloneHosts.Count)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Cluster Breakdown:" -ForegroundColor White
    Write-Host "  - Hyper-V Clusters: $($hyperVClusters.Count)" -ForegroundColor Green
    Write-Host "  - SQL/DB Clusters: $($sqlClusters.Count)" -ForegroundColor Gray
    Write-Host "  - WAC Clusters: $($wacClusters.Count)" -ForegroundColor Cyan
    Write-Host "  - Other Clusters: $($otherClusters.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "CRITICAL NOTES:" -ForegroundColor Red
    Write-Host "  1. ALL $($hvHosts.Count) Hyper-V hosts should appear in your inventory" -ForegroundColor White
    Write-Host "     (both standalone AND cluster nodes)" -ForegroundColor White
    Write-Host ""
    Write-Host "  2. Check your latest inventory report - if it shows fewer than" -ForegroundColor White
    Write-Host "     $($hvHosts.Count) hosts, some hosts are MISSING!" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "[ERROR] Failed to enumerate hosts/clusters" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
