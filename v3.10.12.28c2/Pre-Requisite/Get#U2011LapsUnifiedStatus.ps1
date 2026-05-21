function Get-LapsUnifiedStatus {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [string]$VMName,
        [string]$VMId,
        [string]$HyperVHost   # FIXED: no longer "Host"
    )

    $Timestamp = Get-Date
    $AccountName = "Administrator"
    $DataSource = "None"
    $LookupResult = "NotAttempted"
    $PSDirectResult = "NotAttempted"
    $PasswordAge = $null
    $RotationDue = $null
    $Backend = "None"
    $Password = $null

    try {
        $ad = Get-ADComputer $ComputerName -Properties * -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Timestamp      = $Timestamp
            VMName         = $VMName
            VMId           = $VMId
            HyperVHost     = $HyperVHost
            Backend        = "AD"
            AccountName    = $AccountName
            LookupResult   = "ADLookupFailed"
            PSDirectResult = $PSDirectResult
            PasswordAge    = $PasswordAge
            RotationDue    = $RotationDue
            DataSource     = "None"
        }
    }

    # ---------------------------
    # LEGACY LAPS DETECTION
    # ---------------------------
    $LegacyPwd = $ad.'ms-Mcs-AdmPwd'
    $LegacyExp = $ad.'ms-Mcs-AdmPwdExpirationTime'

    if ($LegacyPwd) {
        $DataSource = "LegacyLAPS"
        $Backend = "AD-Legacy"
        $Password = $LegacyPwd
        $LookupResult = "Success"

        if ($LegacyExp) {
            $RotationDue = [datetime]::FromFileTime($LegacyExp)
            $PasswordAge = (Get-Date) - ($RotationDue.AddDays(-30))
        }
    }

    # ---------------------------
    # WINDOWS LAPS DETECTION
    # ---------------------------
    if ($DataSource -eq "None") {
        try {
            $laps = Get-LapsADPassword -Identity $ComputerName -AsPlainText -ErrorAction Stop

            if ($laps.Password) {
                $DataSource = "WindowsLAPS"
                $Backend = "AD-WindowsLAPS"
                $Password = $laps.Password
                $LookupResult = "Success"
                $PasswordAge = (Get-Date) - $laps.PasswordUpdateTime
                $RotationDue = $laps.ExpirationTime
            }
        }
        catch {
            if ($_.Exception.Message -like "*access*denied*") {
                $LookupResult = "AccessDenied"
            }
            elseif ($_.Exception.Message -like "*encrypted*") {
                $LookupResult = "EncryptedPasswordNoRights"
            }
            else {
                $LookupResult = "WindowsLAPSLookupFailed"
            }
        }
    }

    # ---------------------------
    # PS DIRECT VALIDATION
    # ---------------------------
    if ($Password -and $VMName) {
        try {
            $session = New-PSSession -VMName $VMName -ErrorAction Stop
            Invoke-Command -Session $session -ScriptBlock { "Test" } -ErrorAction Stop
            $PSDirectResult = "Validated"
            Remove-PSSession $session
        }
        catch {
            $PSDirectResult = "Failed"
        }
    }

    # ---------------------------
    # OUTPUT RECORD
    # ---------------------------
    return [pscustomobject]@{
        Timestamp      = $Timestamp
        VMName         = $VMName
        VMId           = $VMId
        HyperVHost     = $HyperVHost
        Backend        = $Backend
        AccountName    = $AccountName
        LookupResult   = $LookupResult
        PSDirectResult = $PSDirectResult
        PasswordAge    = $PasswordAge
        RotationDue    = $RotationDue
        DataSource     = $DataSource
        Password       = $Password
    }
}