# Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)]
    [string]$LogDirectory = "C:\PreformanceLogs",

    [Parameter(Mandatory=$false)]
    [string]$BackupTarget = $null # Optional parameter for yearly backup location
)

# ==============================================
# 1. CORE SETUP FUNCTIONS
# ==============================================

function Invoke-Setup {
    Write-Host "--- Initializing Monitoring System ---" -ForegroundColor Yellow
    try {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory | Out-Null
            Write-Host "Created log directory: $LogDirectory" -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to create log directory. Check permissions."
        exit 1
    }

    # Define the path for daily logs (better organization)
    $DailyLogPath = Join-Path -Path $LogDirectory -ChildPath "PerformanceData"
    if (-not (Test-Path $DailyLogPath)) {
        New-Item -Path $DailyLogPath -ItemType Directory | Out-Null
    }

    Write-Host "Setup complete. Logging will occur in $DailyLogPath" -ForegroundColor Green
}


# ==============================================
# 2. DATA COLLECTION ENGINE (Runs every 5 minutes)
# ==============================================

function Collect-PerformanceData {
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFileName = Join-Path -Path $LogDirectory -ChildPath "$($Timestamp).json"
    
    Write-Host "`n[$(Get-Date)] Collecting performance data..." -ForegroundColor Cyan

    try {
        # --- PERFORMANCE METRICS COLLECTION ---
        
        # 1. CPU Utilization & Cycles (Requires Get-Counter)
        $CPUMetrics = @{
            'System Total Processor Time %' = "Processor(_Total)\% Processor Time"
            'System Idle Process Time %'  = "Processor(_Total)\% Idle Time"
        }

        # 2. Memory Utilization
        $MemoryMetrics = @{
            'Available Bytes' = "\Memory\Bytes Available" # Free RAM
            'Committed Bytes' = "\Memory\Commit Bytes"     # Total committed memory
        }
        
        # 3. Disk I/O & Space (Requires performance counters)
        $DiskMetrics = @{
            'Total Read KB/sec'  = "\PhysicalDisk(_Total)\Avg. Disk sec/Write" # Example: Write latency
            'Total Write KB/sec' = "\PhysicalDisk(_Total)\Disk Writes/sec"
        }

        # --- Collect all data points into a structured array ---
        $CounterList = @("System Total Processor Time", "Processor(_Total)\% Idle Time", 
                           "\Memory\Bytes Available", "\Memory\Commit Bytes", 
                           "\PhysicalDisk(_Total)\Avg. Disk sec/Write")

        # Use Get-Counter for efficient collection of multiple metrics
        $Counters = Get-Counter -Counter $CounterList -SampleInterval 1 -MaxSamples 1 | Select-Object -ExpandProperty CounterSamples

        # Structure the collected data into a comprehensive PS Object
        [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            CPU_Total_Pct = $Counters | Where-Object { $_.Path -like "*Processor(_Total)*" } | Select-Object -ExpandProperty CookedValue 
            CPU_Idle_Pct  = $Counters | Where-Object { $_.Path -like "*Processor(_Total)*" } | Select-Object -ExpandProperty CookedValue
            RAM_Available = ($MemoryMetrics['Available Bytes'] | Get-Counter -SampleInterval 1 -MaxSamples 1).CookedValue # Simplified counter call
            Disk_IO_Metric = $Counters[-1].CookedValue                                                   # Use the last collected value as a general indicator

            # Add more specific calculated metrics here (e.g., CPU Cycle Rate, etc.)
        } | Out-File $OutputFileName -Encoding UTF8 # Write object to JSON file
        
        Write-Host "Data successfully logged to: $OutputFileName" -ForegroundColor Green
    } catch {
        Write-Error "Failed to collect performance data. Error: $($_.Exception.Message)"
    }
}


# ==============================================
# 3. DATA MANAGEMENT AND CLEANUP (Runs daily/weekly)
# ==============================================

function Cleanup-OldLogs {
    param(
        [string]$MaxDaysToKeep = "366"
    )
    Write-Host "`n--- Running Log Cleanup ---" -ForegroundColor Yellow
    
    $CutoffDate = (Get-Date).AddDays(-[int]$MaxDaysToKeep)
    $OldFiles = Get-ChildItem -Path $LogDirectory -Filter "*.json" | Where-Object { 
        $_.LastWriteTime -lt $CutoffDate
    }

    if ($OldFiles.Count -gt 0) {
        Write-Host "Found $($OldFiles.Count) old files older than $MaxDaysToKeep days." -ForegroundColor Yellow
        # IMPORTANT: Uncomment the line below ONLY when you are sure you want to delete data!
        # Remove-Item -Path $OldFiles.FullName -Force -Confirm:$false
        Write-Host "Cleanup simulated. No files deleted." -ForegroundColor Gray 
    } else {
        Write-Host "No old logs found requiring cleanup." -ForegroundColor Green
    }
}

# ==============================================
# 4. ANNUAL ANALYTICS SUMMARY (Runs Year End)
# ==============================================

function Generate-YearlySummary {
    param(
        [string]$StartDate, # e.g., "2023-01-01"
        [string]$EndDate    # e.g., "2023-12-31"
    )
    Write-Host "`n--- Generating Yearly Summary ($StartDate to $EndDate) ---" -ForegroundColor Magenta

    $LogFiles = Get-ChildItem -Path (Join-Path $LogDirectory -ChildPath "PerformanceData") | Where-Object { 
        $_.LastWriteTime -ge (Get-DateFromString($StartDate)) -and $_.LastWriteTime -le (Get-DateFromString($EndDate))
    }

    if (-not $LogFiles) {
        Write-Warning "No log files found for the specified year."
        return
    }

    # Load all data and process it (Example: Calculating Average CPU usage)
    $Data = @()
    foreach ($File in $LogFiles) {
        try {
            $Content = Get-Content $File.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($Content) {
                # Assuming the object structure defined in Collect-PerformanceData is used
                [PSCustomObject]@{
                    Timestamp   = $Content.Timestamp;
                    CPU_Total_Pct = [double]$Content.CPU_Total_Pct;
                    RAM_Available = [double]$Content.RAM_Available
                } | Out-Null # Add to the array collection ($Data)
            }
        } catch {} # Ignore corrupted files

    }

    # Calculation Logic (Example: Average CPU Usage for the Year)
    $AverageCPU = $Data | Measure-Object -Property CPU_Total_Pct -Average | Select-Object -ExpandProperty Average
    $PeakRAM = $Data | Sort-Object RAM_Available -Descending | Select-Object -First 1 -ExpandProperty RAM_Available

    $SummaryReport = @{
        YearlyPeriod = "$StartDate to $EndDate"
        TotalRecordsProcessed = $Data.Count
        AverageCPUUtilizationPct = [math]::Round($AverageCPU, 2)
        PeakRAMAvailabilityGB = [math]::Round(($PeakRAM / 1GB), 2)
    } | ConvertTo-Json

    $SummaryPath = Join-Path -Path (Join-Path $LogDirectory -ChildPath "YearlySummaries") -ChildPath "$($StartDate)_Summary.json"
    Write-Host "Annual summary report generated successfully: $SummaryPath" -ForegroundColor Green
    # Set the data structure to JSON for easy reading
    $SummaryReport | Out-File $SummaryPath -Encoding UTF8 
}

# ==============================================
# 5. BACKUP FUNCTIONALITY (Manual Trigger)
# ==============================================

function Backup-Data {
    param(
        [string]$SourceDir, # e.g., C:\PreformanceLogs\PerformanceData
        [Parameter(Mandatory=$true)]
        [string]$TargetMachineName # Used to name the backup folder
    )
    Write-Host "`n--- Starting Backup Process ---" -ForegroundColor Yellow

    $BackupDest = Join-Path -Path $PSScriptRoot -ChildPath "Backups\$($TargetMachineName)_$(Get-Date -Format yyyyMMdd)"
    if (-not (Test-Path $BackupDest)) {
        New-Item -Path $BackupDest -ItemType Directory | Out-Null
        Write-Host "Created backup directory: $BackupDest" -ForegroundColor Green
    }

    # Copy the entire data folder contents
    Copy-Item -Path "$SourceDir\*" -Destination $BackupDest -Recurse -Force
    
    Write-Host "✅ Backup complete for machine '$($TargetMachineName)' to $BackupDest" -ForegroundColor Green
}


# ==============================================
# MAIN EXECUTION BLOCK (HOW TO CALL THE SCRIPT)
# ==============================================

if ($PSCmdlet.ShouldProcess("Initialize Monitoring", "Setting up the logging directory.")) {
    Invoke-Setup
}

Write-Host "`nScript is ready. To run continuously, this must be scheduled." -ForegroundColor Yellow

# --- EXAMPLE USAGE PARAMETERS ---

# 1. To Run Data Collection (The main loop logic)
Collect-PerformanceData # This should be called repeatedly by a scheduler

# 2. Example: Running Yearly Analysis for 2023 data
# Generate-YearlySummary -StartDate "2023-01-01" -EndDate "2023-12-31"

# 3. Example: Manual Backup of the entire year's data to a specific location
# $CurrentMachineName = [System.Net.Machine]::ComputerName
# Backup-Data -SourceDir (Join-Path C:\PreformanceLogs\PerformanceData) -TargetMachineName $CurrentMachineName

