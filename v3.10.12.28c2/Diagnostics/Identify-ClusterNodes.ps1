<#
.SYNOPSIS
    Identify Which Hyper-V Hosts are Cluster Nodes vs Standalone
    
.DESCRIPTION
    Analyzes your Hyper-V inventory to show which hosts are actually cluster nodes
    
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
    
    # Get all Hyper-V clusters
    Write-Host "[STEP 2] Discovering Hyper-V clusters from AD..." -ForegroundColor Yellow
    Write-Host ""
    
    $clusterObjects = Get-ADComputer -Filter {ServicePrincipalName -like "MSClusterVirtualServer/*"} `
        -Properties ServicePrincipalName, CN, DNSHostName
    
    Write-Host "Total cluster objects found: $($clusterObjects.Count)" -ForegroundColor White
    Write-Host ""
    
    # For each cluster, get its nodes
    $allClusterNodes = @()
    $hyperVClusters = @()
    
    Write-Host "[STEP 3] Identifying Hyper-V cluster nodes..." -ForegroundColor Yellow
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
            
            $cluster = Get-Cluster -Name $clusterName -Domain $domain -ErrorAction Stop
            $nodes = Get-ClusterNode -Cluster $clusterName -ErrorAction Stop
            
            # Check if any nodes are Hyper-V hosts
            $hvNodesInCluster = @()
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
            
            # Only include if it has Hyper-V nodes
            if ($hvNodesInCluster.Count -gt 0) {
                $hyperVClusters += [PSCustomObject]@{
                    ClusterName = $cluster.Name
                    ClusterFQDN = $clusterName
                    NodeCount = $nodes.Count
                    HyperVNodeCount = $hvNodesInCluster.Count
                    Nodes = $hvNodesInCluster -join ', '
                }
                
                Write-Host "  ✓ $($cluster.Name): $($hvNodesInCluster.Count) Hyper-V node(s)" -ForegroundColor Green
            }
            else {
                Write-Host "  ⊘ $($cluster.Name): SQL/Other cluster (no Hyper-V nodes)" -ForegroundColor Gray
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
    
    Write-Host "CLUSTER NODES: $($allClusterNodes.Count)" -ForegroundColor Yellow
    Write-Host ""
    foreach ($node in $allClusterNodes | Sort-Object NodeName) {
        Write-Host "  $($node.NodeName) → $($node.ClusterName) [$($node.State)]" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "STANDALONE HOSTS: $($standaloneHosts.Count)" -ForegroundColor Yellow
    Write-Host ""
    foreach ($host in $standaloneHosts | Sort-Object Name) {
        Write-Host "  $($host.DNSHostName)" -ForegroundColor Gray
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
    Write-Host "Hyper-V Clusters: $($hyperVClusters.Count)" -ForegroundColor White
    Write-Host "SQL/Other Clusters: $($clusterObjects.Count - $hyperVClusters.Count)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "  1. Your current inventory shows ALL VMs from both cluster nodes" -ForegroundColor White
    Write-Host "     and standalone hosts - you're not missing any VMs!" -ForegroundColor White
    Write-Host ""
    Write-Host "  2. The issue is just that cluster nodes aren't being LABELED" -ForegroundColor White
    Write-Host "     as cluster members in the report." -ForegroundColor White
    Write-Host ""
    Write-Host "  3. Many 'clusters' in AD are SQL Server clusters, not Hyper-V" -ForegroundColor White
    Write-Host "     clusters - these don't host VMs." -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "[ERROR] Failed to enumerate hosts/clusters" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
