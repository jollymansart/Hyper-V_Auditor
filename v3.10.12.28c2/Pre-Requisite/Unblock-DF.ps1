function Unblock-DF
{
    <#
    .SYNOPSIS
        Automatically unblock all PowerShell files in a directory
    
    .DESCRIPTION
        Recursively unblocks all .ps1, .psm1, and .psd1 files in the specified directory.
        Useful for unblocking files downloaded from the internet.
    
    .PARAMETER Path
        The directory path to unblock files in (default: current directory)
    
    .PARAMETER Recurse
        If specified, unblocks files in all subdirectories too
    
    .EXAMPLE
        .\Unblock-DownloadedFiles.ps1
        Unblocks all PowerShell files in current directory
    
    .EXAMPLE
        .\Unblock-DownloadedFiles.ps1 -Path "C:\Downloads\Scripts" -Recurse
        Unblocks all PowerShell files in Downloads\Scripts and subdirectories
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path = (Get-Location).Path,
    
        [Parameter()]
        [switch]$Recurse
    )

    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Auto-Unblock PowerShell Files" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""

    # Get all PowerShell files
    $fileExtensions = @('*.ps1', '*.psm1', '*.psd1')
    $files = @()

    foreach ($ext in $fileExtensions) {
        if ($Recurse) {
            $files += Get-ChildItem -Path $Path -Filter $ext -Recurse -ErrorAction SilentlyContinue
        } else {
            $files += Get-ChildItem -Path $Path -Filter $ext -ErrorAction SilentlyContinue
        }
    }

    if ($files.Count -eq 0) {
        Write-Host "[INFO] No PowerShell files found in: $Path" -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }

    Write-Host "[INFO] Found $($files.Count) PowerShell file(s)" -ForegroundColor White
    Write-Host ""

    $unblocked = 0
    $alreadyUnblocked = 0
    $errors = 0

    foreach ($file in $files) {
        try {
            # Check if file is blocked
            $zone = Get-Content -Path $file.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
        
            if ($zone) {
                # File is blocked - unblock it
                Unblock-File -Path $file.FullName -ErrorAction Stop
                Write-Host "  [UNBLOCKED] $($file.Name)" -ForegroundColor Green
                $unblocked++
            } else {
                # File is not blocked
                Write-Host "  [OK] $($file.Name)" -ForegroundColor Gray
                $alreadyUnblocked++
            }
        }
        catch {
            Write-Host "  [ERROR] $($file.Name): $($_.Exception.Message)" -ForegroundColor Red
            $errors++
        }
    }

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Total files: $($files.Count)" -ForegroundColor White
    Write-Host "Unblocked: $unblocked" -ForegroundColor Green
    Write-Host "Already unblocked: $alreadyUnblocked" -ForegroundColor Gray
    Write-Host "Errors: $errors" -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Gray' })
    Write-Host ""
}