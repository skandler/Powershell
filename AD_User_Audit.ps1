# Get all domains in the forest automatically
$DomainList = (Get-ADForest).Domains  
# Or define manually:
# $DomainList = @("corp.example.com", "child.example.com")

$LastLoggedOnDate = (Get-Date) - (New-TimeSpan -Days 180)
$PasswordStaleDate = (Get-Date) - (New-TimeSpan -Days 180)

$ADLimitedProperties = @(
    "Name","Enabled","SAMAccountname","DisplayName","LastLogonDate","PasswordLastSet",
    "PasswordNeverExpires","PasswordNotRequired","PasswordExpired","SmartcardLogonRequired",
    "AccountExpirationDate","AdminCount","Created","Modified","LastBadPasswordAttempt",
    "badpwdcount","mail","CanonicalName","DistinguishedName","ServicePrincipalName",
    "SIDHistory","PrimaryGroupID","UserAccountControl","DoesNotRequirePreAuth","ObjectCategory","ObjectClass"
)

$BaseOutputFolder = "C:\Temp\AD_Audit_MultiDomain"
if (!(Test-Path $BaseOutputFolder)) { New-Item -Path $BaseOutputFolder -ItemType Directory | Out-Null }

foreach ($Domain in $DomainList) {
    Write-Host "`n--- Scanning domain: $Domain ---"

    $OutputFolder = Join-Path $BaseOutputFolder $Domain
    if (!(Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory | Out-Null }

    # Get all users from the domain
    [array]$DomainUsers = Get-ADUser -Server $Domain -Filter * -Property $ADLimitedProperties
    [array]$DomainEnabledUsers = $DomainUsers | Where-Object {$_.Enabled -eq $True}
    [array]$DomainEnabledInactiveUsers = $DomainEnabledUsers | Where-Object {
        ($_.LastLogonDate -le $LastLoggedOnDate) -and ($_.PasswordLastSet -le $PasswordStaleDate)
    }

    # Risky account checks (enabled only)
    [array]$DomainUsersWithReversibleEncryptionPasswordArray = $DomainEnabledUsers | Where-Object {
        $_.UserAccountControl -band 0x0080
    }

    # Password Not Required - EXCLUDE domain trusts & computer accounts
    [array]$DomainUserPasswordNotRequiredArray = $DomainEnabledUsers | Where-Object {
        ($_.PasswordNotRequired -eq $True) -and
        ($_.ObjectCategory -eq "person") -and
        ($_.ObjectClass -eq "user") -and
        (-not $_.SamAccountName.EndsWith('$'))
    }

    [array]$DomainUserPasswordNeverExpiresArray = $DomainEnabledUsers | Where-Object {$_.PasswordNeverExpires -eq $True}
    [array]$DomainKerberosDESUsersArray = $DomainEnabledUsers | Where-Object {
        $_.UserAccountControl -band 0x200000
    }
    [array]$DomainUserDoesNotRequirePreAuthArray = $DomainEnabledUsers | Where-Object {$_.DoesNotRequirePreAuth -eq $True}
    [array]$DomainUsersWithSIDHistoryArray = $DomainEnabledUsers | Where-Object {$_.SIDHistory -like "*"}

	    # --- NEW: krbtgt password reset check ---
    try {
        $Krbtgt = Get-ADUser -Server $Domain -Identity "krbtgt" -Properties PasswordLastSet
        $KrbtgtPasswordAgeDays = (New-TimeSpan -Start $Krbtgt.PasswordLastSet -End (Get-Date)).Days
        $KrbtgtPasswordRecentlyReset = $KrbtgtPasswordAgeDays -le 180
    } catch {
        Write-Warning "Could not query krbtgt account in $Domain"
        $KrbtgtPasswordRecentlyReset = $null
    }

    # Console summary
    Write-Host "Total Users: $($DomainUsers.Count)"
    Write-Host "Enabled Users: $($DomainEnabledUsers.Count)"
    Write-Host "Inactive Enabled Users: $($DomainEnabledInactiveUsers.Count)"
    Write-Host "Reversible Encryption Password: $($DomainUsersWithReversibleEncryptionPasswordArray.Count)"
    Write-Host "Password Not Required (filtered): $($DomainUserPasswordNotRequiredArray.Count)"
    Write-Host "Password Never Expires: $($DomainUserPasswordNeverExpiresArray.Count)"
    Write-Host "Kerberos DES: $($DomainKerberosDESUsersArray.Count)"
    Write-Host "No Kerberos Pre-Auth: $($DomainUserDoesNotRequirePreAuthArray.Count)"
    Write-Host "SID History: $($DomainUsersWithSIDHistoryArray.Count)"
	    if ($KrbtgtPasswordRecentlyReset -ne $null) {
        if ($KrbtgtPasswordRecentlyReset) {
            Write-Host "krbtgt password was reset in last 180 days  (Age: $KrbtgtPasswordAgeDays days)"
        } else {
            Write-Host "krbtgt password NOT reset in last 180 days  (Age: $KrbtgtPasswordAgeDays days)"
        }
    }
	
    # Export CSVs with LastLogonDate & PasswordLastSet
    $DomainEnabledInactiveUsers |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\Enabled_Inactive_Users.csv" -NoTypeInformation

    $DomainUsersWithReversibleEncryptionPasswordArray |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\Reversible_Encryption.csv" -NoTypeInformation

    $DomainUserPasswordNotRequiredArray |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\Password_Not_Required.csv" -NoTypeInformation

    $DomainUserPasswordNeverExpiresArray |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\Password_Never_Expires.csv" -NoTypeInformation

    $DomainKerberosDESUsersArray |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\Kerberos_DES.csv" -NoTypeInformation

    $DomainUserDoesNotRequirePreAuthArray |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\No_Kerberos_Preauth.csv" -NoTypeInformation

    $DomainUsersWithSIDHistoryArray |
        Select-Object SAMAccountName,DisplayName,PasswordLastSet,LastLogonDate,DistinguishedName |
        Export-Csv "$OutputFolder\SID_History.csv" -NoTypeInformation

    Write-Host "Detailed lists saved to $OutputFolder"
}

Write-Host "`nMulti-domain audit completed. Results in: $BaseOutputFolder"
