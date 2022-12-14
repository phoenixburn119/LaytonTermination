$Global:TermUsername = $null
$Global:DelegateInput = $null
$Global:DelegateInput2 = @()
$Global:DeletionDate = $null
$Global:AdminStatus = $null
$Global:DateToday = $(get-date).ToString("MM-dd-yyyy")

#Draws the main menue for the program.
Function Show-Menu {
    Write-Host "
     _______  _             _______                      _                _               
    |__   __|| |           |__   __|                    (_)              | |              
       | |   | |__    ___     | |  ___  _ __  _ __ ___   _  _ __    __ _ | |_  ___   _ __ 
       | |   | '_ \  / _ \    | | / _ \| '__|| '_ ` _ \ | || '_ \  / _` || __|/ _ \ | '__|
       | |   | | | ||  __/    | ||  __/| |   | | | | | || || | | || (_| || |_| (_) || |   
       |_|   |_| |_| \___|    |_| \___||_|   |_| |_| |_||_||_| |_| \__,_| \__|\___/ |_|   
                                                                                          
     " -NoNewLine -ForeGroundColor Blue
    Write-Host ""
    Write-Warning "Debug Information:"
    Write-Host "Term User : $($Global:TermUsername)"
    Write-Host "Admin Account : $($Global:SystemCredentials.UserName)"
    Write-Host "Todays Date : $($Global:DateToday)"
    Write-Host ""
    Write-Host "1: Start Termination"
    Write-Host "2: Start Abnormal Termination (No Forward User)"
    Write-Host "4: List Accounts In Disabled Users OU"
    Write-Host "7: Audit Log Review"
    Write-Host "8: Teams User Lookup"
    Write-Host "9: Change AD Admin User"
    # Write-Host "3: Change MFA Status : Does Not Work"
    Write-Host "Q: Press 'Q' to quit." -ForeGroundColor Red
}
#Prints any errors in a unified way.
Function PrintError($err) {
    #Used for return of standardized formated errors throughout the program.
    write-host $err -ForeGroundColor Red
}
function Write-Log {
    Param(
        $Message,$Path = ".\AuditLog\Audit-Log $($env:username) $($Global:DateToday).txt"
    )

    function TS {Get-Date -Format 'hh:mm:ss'}
    "[$(TS)]$Message" | Tee-Object -FilePath $Path -Append | Write-Verbose
}
Function ExchangeConnect {
        Write-Host "Checking connection to ExchangeOnline..." -BackgroundColor DarkGray
        $getsessions = Get-PSSession | Select-Object -Property State, Name
        $isconnected = (@($getsessions) -like '@{State=Opened; Name=ExchangeOnlineInternalSession*').Count -gt 0
        If ($isconnected -ne "True") {
            Write-Warning "Connecting to ExchangeOnline...Please follow the popup"
            Connect-ExchangeOnline -ShowProgress $true
            Write-Log "EXCHANGE-Connect: User signed into Exchange."
        } Else{
            Write-Host "Thanks for connecting before ;)"
            Write-Log "EXCHANGE-Connect: User was already signed into Exchange."
        }
}
Function MicrosoftTeamsConnect {
    Write-Host "Checking connection to MicrosoftTeams..." -BackgroundColor DarkGray
    Try{
        # Uses our spam account to verify Teams is connected correctly.
        Get-CsOnlineUser -Identity jzinger2@laytonconstruction.com | Out-null
        Write-Host "Thanks for connecting to MicrosoftTeams prior ;)"
        Write-Log "TEAMS-Connect: User was already signed into MicrosoftTeams."
    } Catch{
        Write-Warning "Connecting to MicrosoftTeams...Please follow the popup"
        Connect-MicrosoftTeams
        Write-Log "TEAMS-Connect: User signed into MicrosoftTeams."
    }
}
Function AzureADConnect {
    Write-Host "Checking connection to AzureAD..." -BackgroundColor DarkGray
    Try{
        Get-AzureADTenantDetail | Out-null
        Write-Host "Thanks for connecting to AzureAD prior ;)"
        Write-Log "AzureAD-Connect: User was already signed into AzureAD."
    } Catch{
        Write-Warning "Connecting to AzureAD...Please follow the popup"
        Connect-AzureAD
        Write-Log "AzureAD-Connect: User signed into AzureAD."
    }
}
#Checks if the modules are installed and connects to Exchange Online.
Function ModuleChecker {
    Write-Host "        Module Checker Initiated        " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Log "$($env:username) initiated The Terminator startup."
    #Checks if the required modules are installed.
    Write-Host "    Checking for required modules...    " -BackgroundColor DarkGray
    If ((Get-InstalledModule -Name ExchangeOnlineManagement).Name -eq "ExchangeOnlineManagement") { #Checks for the install of ExchagneOnlineManagement
        Write-Host "ExchangeOnlineManagement...Passed" -ForegroundColor Green
    }
    Else {
        Write-Warning "Please run the following command in elevated powershell:"
        Write-Host "Install-Module ExchangeOnlineManagement"
        Pause
        Exit
    }
    If ((Get-InstalledModule -Name MicrosoftTeams).Name -eq "MicrosoftTeams") { #Checks for the install of MicrosoftTeams
        Write-Host "MicrosoftTeams...Passed" -ForegroundColor Green
    }
    Else {
        Write-Warning "Please run the following command in elevated powershell:"
        Write-Host "Install-Module MicrosoftTeams"
        Pause
        Exit
    }
    If ((Get-InstalledModule -Name AzureAD).Name -eq "AzureAD") { #Checks for the install of AzureAD
        Write-Host "AzureAD...Passed" -ForegroundColor Green
    }
    Else {
        Write-Warning "Please run the following command in elevated powershell:"
        Write-Host "Install-Module AzureAD"
        Pause
        Exit
    }
    #Checks if you are connected to the STO domain.
    Write-Host "  Checking connection to the domain...  " -BackgroundColor DarkGray
    If((Test-ComputerSecureChannel -Server laytutahdc01 -erroraction 'silentlycontinue') -eq $True) {
        Write-Host "Connection to the domain...Passed" -ForeGroundColor Green
    }
    Else{
        Write-Warning "Please connect to the domain or connect to the VPN."
        PrintError $_
        Pause
        Exit
    }
    #Checks if Python is installed.
    Write-Host "     Checking Python installation...    " -BackgroundColor DarkGray
    $PyVer = python --version
    If($PyVer -eq "Python was not found; run without arguments to install from the Microsoft Store, or disable this shortcut from Settings > Manage App Execution Aliases.") {
        Write-Warning "Please install Python on your computer from https://www.python.org/"
        Pause
        Exit
    }
    Write-Host "Python successfully...Passed" -ForegroundColor Green
    MicrosoftTeamsConnect
    ExchangeConnect
    AzureADConnect
    Import-Module ExchangeOnlineManagement
    Write-Host "Connection to ExchangeOnline was successful" -ForeGroundColor Green
    Write-Host "        Continuing to program...        " -ForegroundColor Black -BackgroundColor Green
    Write-Log "$($env:username) has finished The Terminator startup procedure."
    Start-Sleep -seconds 1
}
# Captures the Y account credentials to perform all AD commands.
Function ActiveDirectoryLogin {
    If ((Get-Content -Path ".\Content\AuthorizedUsers.txt") -contains $env:USERNAME) {
        Write-Host "User is already authorized to make AD changes."
        $Global:SystemCredentials = $env:username
        $Global:AdminStatus = $true
    } Else {
        $Global:SystemCredentials = Get-Credential -Message "Enter your Y account credentials to make AD changes"
        Write-Log "Account: $($Global:SystemCredentials.UserName) was used to gain AD permissions."
        $Global:AdminStatus = $false
    }
    # Possible might want to have a test to double check if it's correct. It'll cause problems later if not.
}
# Used to look at the disabled users OU and pull whoevers in there.
Function DisabledUsersLookup {
    Try{
        Write-Host "With Admin"
        Get-ADUser -filter * -Properties * -SearchBase "OU=Disabled Users,OU=Disabled Accounts,OU=Layton,DC=sto,DC=com" | Format-Table Name,Description,Enabled,DistinguishedName -Credential $Global:SystemCredentials
    } Catch{
        Get-ADUser -filter * -Properties * -SearchBase "OU=Disabled Users,OU=Disabled Accounts,OU=Layton,DC=sto,DC=com" | Format-Table Name,Description,Enabled,DistinguishedName
    }
    Pause
}
# Resets the AD password for the terminated user to the default.
Function ADPasswordReset {
    If($Global:AdminStatus -eq $false) {
        Try {
            Set-ADAccountPassword -Identity $Global:TermUsername -Credential $Global:SystemCredentials -Server laytutahdc01 -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "RANDOMP@ssword!@#$" -Force)
            Write-Host "Password Reset" -ForegroundColor Green
            Write-Log "CHANGE-AD: Reset the password of $($Global:TermUsername) to the default term password."
        } Catch {
            Write-Error "FAIL-AD: Password reset of $($Global:TermUsername) failed. Error: $_"
            Write-Log "FAIL-AD: Password reset of $($Global:TermUsername) failed. Error: $_"
            Start-Sleep -second 3
        }
    } Else {
        Try {
            # This sets a static password but a possible randomizer or a user input would be great options for the future.
            Set-ADAccountPassword -Identity $Global:TermUsername -Server laytutahdc01 -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "RANDOMP@ssword!@#$" -Force)
            Write-Host "Password Reset" -ForegroundColor Green
            Write-Log "CHANGE-AD: Reset the password of $($Global:TermUsername) to the default term password."
        } Catch {
            Write-Error "FAIL-AD: Password reset of $($Global:TermUsername) failed. Error: $_"
            Write-Log "FAIL-AD: Password reset of $($Global:TermUsername) failed. Error: $_"
            Start-Sleep -second 3
        }
    }
}
# Updates the Description and Disabled status of the account.
Function ADPropertyEditor {
    $Global:TermUsernameProp | Format-Table Name,Description,DistinguishedName
    If($Global:AdminStatus -eq $false) {
        # Edits the description of the users account to have the termination date.
        Try{
            Set-ADUser -Identity $Global:TermUsername -Credential $Global:SystemCredentials -Server laytutahdc01 -Description "Termination Remove $($Global:DeletionDate)"
            Write-Host "CHANGE-AD: $($Global:TermUsername) description was changed to (Termination Remove $($Global:DeletionDate)) prior was ($($Global:TermUsernameProp.Description))"
            Write-Log "CHANGE-AD: $($Global:TermUsername) description was changed to (Termination Remove $($Global:DeletionDate)) prior was ($($Global:TermUsernameProp.Description))"
        } Catch{
            Write-Error "FAIL-AD: AD description update failed for user $($Global:TermUsername). Error: $_"
            Write-Log "FAIL-AD: AD description update failed for user $($Global:TermUsername). Error: $_"
        }
        # Change account to disabled
        Try{
            Disable-ADAccount -Identity $Global:TermUsername -Credential $Global:SystemCredentials -Server laytutahdc01
            Write-Host "CHANGE-AD: $($Global:TermUsername) account was set to disabled"
            Write-Log "CHANGE-AD: $($Global:TermUsername) account was set to disabled"
        } Catch{
            Write-Error "FAIL-AD: Edit of disabled property of user $($Global:TermUsername) failed. ERROR: $_"
            Write-Log "FAIL-AD: Edit of disabled property of user $($Global:TermUsername) failed. ERROR: $_"
        }
    } Else {
        # Edits the description of the users account to have the termination date.
        Try{
            Set-ADUser -Identity $Global:TermUsername -Server laytutahdc01 -Description "Termination Remove $($Global:DeletionDate)" 
            Write-Host "CHANGE-AD: $($Global:TermUsername) description was changed to (Termination Remove $($Global:DeletionDate)) prior was ($($Global:TermUsernameProp.Description))"
            Write-Log "CHANGE-AD: $($Global:TermUsername) description was changed to (Termination Remove $($Global:DeletionDate)) prior was ($($Global:TermUsernameProp.Description))"
        } Catch{
            Write-Error "FAIL-AD: AD description update failed for user $($Global:TermUsername). Error: $_"
            Write-Log "FAIL-AD: AD description update failed for user $($Global:TermUsername). Error: $_"
        }
        # Change account to disabled
        Try{
            Disable-ADAccount -Identity $Global:TermUsername -Server laytutahdc01
            Write-Host "CHANGE-AD: $($Global:TermUsername) account was set to disabled"
            Write-Log "CHANGE-AD $($Global:TermUsername) account was set to disabled"
        } Catch{
            Write-Error "FAIL-AD: Edit of disabled property of user $($Global:TermUsername) failed. ERROR: $_"
            Write-Log "FAIL-AD: Edit of disabled property of user $($Global:TermUsername) failed. ERROR: $_"
        }
    }

}
# Sets the users OU to the DisabledUsers OU in AD.
Function ADOUEditor {
    If($Global:AdminStatus -eq $false) {
        Try{
            Move-ADObject -Identity $Global:TermUsernameProp.DistinguishedName -TargetPath "OU=Disabled Users,OU=Disabled Accounts,OU=Layton,DC=sto,DC=com" -Credential $Global:SystemCredentials -Server laytutahdc01
            Write-Host "CHANGE-AD: User $($Global:TermUsername) was moved to Layton\Disabled Accounts\Disabled Users."
            Write-Log "CHANGE-AD: User $($Global:TermUsername) was moved to Layton\Disabled Accounts\Disabled Users."
        } Catch{
            Write-Host "FAIL-AD: Unable to edit the OU path of $($Global:TermUsername). Error: $_"
            Write-Log "FAIL-AD: Unable to edit the OU path of $($Global:TermUsername). Error: $_"
        }
    } Else{
        Try{
            Move-ADObject -Identity $Global:TermUsernameProp.DistinguishedName -TargetPath "OU=Disabled Users,OU=Disabled Accounts,OU=Layton,DC=sto,DC=com" -Server laytutahdc01
            Write-Host "CHANGE-AD: User $($Global:TermUsername) was moved to Layton\Disabled Accounts\Disabled Users."
            Write-Log "CHANGE-AD: User $($Global:TermUsername) was moved to Layton\Disabled Accounts\Disabled Users."
        } Catch{
            Write-Host "FAIL-AD: Unable to edit the OU path of $($Global:TermUsername). Error: $_"
            Write-Log "FAIL-AD: Unable to edit the OU path of $($Global:TermUsername). Error: $_"
        }
    }
}
Function AzureADRemoveLicenseGroup {
    Try{
        # Removes from the Layton License-LCC-Premium-Calling-Plan Group.
        $GroupID = Get-AzureADUser -ObjectId $Global:TermUsernameProp.UserPrincipalName
        Remove-AzureADGroupMember -ObjectId 4a45b386-68ba-4217-ab0e-660a7529f91f -MemberId $GroupID.ObjectId
        Write-Host "CHANGE-AZURE: User $($Global:TermUsername) was removed from the licensing group (License-LCC-Premium-Calling-Plan)."
        Write-Log "CHANGE-AZURE: User $($Global:TermUsername) was removed from the licensing group (License-LCC-Premium-Calling-Plan)."
    } Catch{
        Write-Host "FAIL-AZURE: License group (License-LCC-Premium-Calling-Plan) update for user $($Global:TermUsername) failed. Error: $_"
        Write-Log "FAIL-AZURE: License group (License-LCC-Premium-Calling-Plan) update for user $($Global:TermUsername) failed. Error: $_"
    }
}
Function ExchangeAutoReply {
    Try{
        $StoredReply = "Thank you for contacting Layton Construction. We regret to inform you that $($Global:TermUsernameProp.name) is no longer with the organization. Please direct this and any future correspondence to $($Global:DelegateProp.name) at $($Global:DelegateProp.EmailAddress).
        Best Regards
        This is an automated reply. This mailbox is not monitored or forwarded."
        Set-MailboxAutoReplyConfiguration -Identity $Global:TermUsernameProp.EmailAddress -AutoReplyState Enabled -ExternalMessage $StoredReply -ExternalAudience All -InternalMessage $StoredReply

        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
    } Catch{
        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
    }
}
Function ExchangeAutoReplyNoForward {
    Try{
        $StoredReply = "Thank you for contacting Layton Construction. We regret to inform you that $($Global:TermUsernameProp.name) is no longer with the organization.
        Best Regards
        This is an automated reply. This mailbox is not monitored or forwarded."
        Set-MailboxAutoReplyConfiguration -Identity $Global:TermUsernameProp.EmailAddress -AutoReplyState Enabled -ExternalMessage $StoredReply -ExternalAudience All -InternalMessage $StoredReply

        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
    } Catch{
        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
    }
}
Function ExchangeAutoReplyTwoForward {
    Try{
        $StoredReply = "Thank you for contacting Layton Construction. We regret to inform you that $($Global:TermUsernameProp.name) is no longer with the organization. Please direct this and any future correspondence to $($Global:DelegateProp.name) at $($Global:DelegateProp.EmailAddress).
        Best Regards
        This is an automated reply. This mailbox is not monitored or forwarded."
        Set-MailboxAutoReplyConfiguration -Identity $Global:TermUsernameProp.EmailAddress -AutoReplyState Enabled -ExternalMessage $StoredReply -ExternalAudience All -InternalMessage $StoredReply
        Write-Host $StoredReply

        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
    } Catch{
        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
    }
}
Function ExchangeAutoReplyExperimental {
    $TempData = @()
    Try {
        For($idx = 0; $idx -lt $Global:DelegateInput2.Count; $idx++) {
            $UserData = Get-aduser -Identity $Global:DelegateInput2[$idx] -Properties *
            $TempData += "$($UserData.Name) at $($UserData.UserPrincipalName)"
        }
        $StoredReply = "Thank you for contacting Layton Construction. We regret to inform you that $($Global:TermUsernameProp.name) is no longer with the organization. Please direct this and any future correspondence to the following users.
        $($TempData | Out-String)
        Best Regards,
        This is an automated reply. This mailbox is not monitored or forwarded."
        Set-MailboxAutoReplyConfiguration -Identity $Global:TermUsernameProp.EmailAddress -AutoReplyState Enabled -ExternalMessage $StoredReply -ExternalAudience All -InternalMessage $StoredReply

        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox succeeded."
    }Catch {
        Write-Host "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
        Write-Log "CHANGE-Exchange: Autoreply Message of $($Global:TermUsername)'s mailbox failed. Error: $_"
    }

}
# Delegates the users Exchange mailbox to another user
Function ExchangeDelegation {
    Try{
        Add-MailboxPermission -Identity $Global:TermUsername -User $Global:DelegateProp.UserPrincipalName -AccessRights FullAccess -AutoMapping $true
        Write-Host "CHANGE-Exchange: Delegation of $($Global:TermUsername)'s mailbox succeeded."
        Write-Log "CHANGE-Exchange: Delegation of $($Global:TermUsername)'s mailbox succeeded."
    } Catch{
        Write-Host "FAIL-Exchange: Delegation of $($Global:TermUsername)'s mailbox failed. Error: $_"
        Write-Log "FAIL-Exchange: Delegation of $($Global:TermUsername)'s mailbox failed. Error: $_"
    }
}
Function ExchangeDelegationExperimental {
    For($idx = 0; $idx -lt $Global:DelegateInput2.Count; $idx++) {
        Try{
            $DelegateProp = Get-aduser -Identity $Global:DelegateInput2[$idx] -Properties *
            Add-MailboxPermission -Identity $Global:TermUsername -User $DelegateProp.UserPrincipalName -AccessRights FullAccess -AutoMapping $true
            Write-Host "CHANGE-Exchange: Delegation of $($Global:TermUsername)'s mailbox to $($Global:DelegateInput2[$idx]) succeeded."
            Write-Log "CHANGE-Exchange: Delegation of $($Global:TermUsername)'s mailbox to $($Global:DelegateInput2[$idx]) succeeded."
        } Catch{
            Write-Host "FAIL-Exchange: Delegation of $($Global:TermUsername)'s mailbox to $($Global:DelegateInput2[$idx]) failed. Error: $_"
            Write-Log "FAIL-Exchange: Delegation of $($Global:TermUsername)'s mailbox to $($Global:DelegateInput2[$idx]) failed. Error: $_"
        }
    }
}
# A short command to wipe the users future meetings so they do not annoy/become broken when the user object is delted.
Function ExchangeCancelMeetings {
    Try{
        Remove-CalendarEvents -Identity $Global:TermUsernameProp.UserPrincipalName -CancelOrganizedMeetings -QueryStartDate $Global:DateToday -QueryWindowInDays 1825 -Confirm:$false
        Write-Host "CHANGE-Exchange: Cancelation of $($Global:TermUsername)'s future meetings succeeded."
        Write-Log "CHANGE-Exchange: Cancelation of $($Global:TermUsername)'s future meetings succeeded."
    } Catch{
        Write-Host "CHANGE-Exchange: Cancelation of $($Global:TermUsername)'s future meetings failed. Error: $_"
        Write-Log "CHANGE-Exchange: Cancelation of $($Global:TermUsername)'s future meetings failed. Error: $_"
    }
}
# Blocks the signin of all methods for Exchange.
Function ExchangeSignInBlocked {
    Try{
        Set-CASMailbox -Identity $Global:TermUsername -ImapEnabled $false -PopEnabled $false -MAPIEnabled $false -EwsEnabled $false -ActiveSyncEnabled $false
        Write-Host "CHANGE-Exchange: Update of $($Global:TermUsername)'s sign in methods succeeded."
        Write-Log "CHANGE-Exchange: Update of $($Global:TermUsername)'s sign in methods succeeded."
        # Get-CASMailbox -Identity $Global:TermUsername | Format-Table
    } Catch{
        Write-Host "FAIL-Exchange: Update of $($Global:TermUsername)'s sign in methods fails. Error: $_"
        Write-Log "FAIL-Exchange: Update of $($Global:TermUsername)'s sign in methods fails. Error: $_"
    }
}
# Converts the Exchange mailbox to a shared mailbox.
Function ExchangeConvertToSharedMailbox {
    $MailboxInput = Read-Host "Do you want to convert $($Global:TermUsername)'s exchange to a shared mailbox? Y or N : "
    If($MailboxInput -eq "Y" -or $MailboxInput -eq "Yes") {
        Try{
            Set-Mailbox -Identity $($Global:TermUsernameProp).UserPrincipalName -Type shared
            Start-Sleep -Seconds 4
            Get-Mailbox -Identity $($Global:TermUsernameProp).UserPrincipalName | Format-Table Identity,RecipientTypeDetails
            Write-Host "CHANGE-Exchange: Update of $($Global:TermUsername)'s mailbox to a shared mailbox succeeded."
            Write-Log "CHANGE-Exchange: Update of $($Global:TermUsername)'s mailbox to a shared mailbox succeeded."
        } Catch{
            Write-Host "FAIL-Exchange: Update of $($Global:TermUsername)'s mailbox to a shared mailbox fails. Error: $_"
            Write-Log "FAIL-Exchange: Update of $($Global:TermUsername)'s mailbox to a shared mailbox fails. Error: $_"
        }
    }Else {
        Write-Host "FAIL-Exchange: Operator denied conversion of $($Global:TermUsername)'s mailbox to a shared mailbox."
        Write-Log "FAIL-Exchange: Operator denied conversion of $($Global:TermUsername)'s mailbox to a shared mailbox."
    }
}
# Wipes the users EnterpriseVoiceEnabled, HostedVoicemail, and LineURI to false and null.
Function TeamsUserWipe {
    Try{
        # Beginning logging of old info and DID list update instructions.
        $OldStoredInfo = Get-CsOnlineUser -Identity ($Global:TermUsernameProp).UserPrincipalName
        Write-Warning "Old user info listed below"
        $OldStoredInfo | Format-List DisplayName,SipAddress,LineURI,EnterpriseVoiceEnabled,HostedVoicemail,OnlineVoiceRoutingPolicy
        Write-Host "Please update the DID list for user $($Global:TermUsername) at DID $($OldStoredInfo.LineURI)" -ForegroundColor Yellow
        Write-Log "STATUS-Teams: User $($Global:TermUsername) account info prior to wipe. LineURI: $($OldStoredInfo.LineURI) , EnterpriseVoiceEnabled: $($OldStoredInfo.EnterpriseVoiceEnabled) , HostedVoicemail: $($OldStoredInfo.HostedVoicemail)"

        Remove-CsPhoneNumberAssignment -Identity ($Global:TermUsernameProp).UserPrincipalName -RemoveAll
        Write-Warning "Five second sleep started..."
        Start-Sleep -second 5

        Write-Host "New user info listed below" -ForeGroundColor Green
        $NewStoredInfo = Get-CsOnlineUser -Identity ($Global:TermUsernameProp).UserPrincipalName
        $NewStoredInfo | Format-List DisplayName,SipAddress,LineURI,EnterpriseVoiceEnabled,HostedVoicemail,OnlineVoiceRoutingPolicy
        Write-Log "CHANGE-Teams: User $($Global:TermUsername) account info after wipe. LineURI: $($OldStoredInfo.LineURI) , EnterpriseVoiceEnabled: $($OldStoredInfo.EnterpriseVoiceEnabled) , HostedVoicemail: $($OldStoredInfo.HostedVoicemail)"
    } Catch{
        Write-Log "FAIL-Teams: Account wipe of user $($Global:TermUsername) has failed. Error: $_"
    }
}
# Retrieves the users EnterpriseVoiceEnabled, HostedVoicemail, and LineURI info.


# The main function that starts the termination.



ModuleChecker
ActiveDirectoryLogin
#Main Loop for the program.
while ($true) {
    Clear-Host
    Show-Menu
    $Selection = Read-Host "Please make a selection"
    switch ($Selection) {
        '1' { TermFramework }
        '2' { TermFrameworkNoForward }
        '3' { TermFrameworkTwoForward }
        '4' { DisabledUsersLookup }
        '5' { FunctionTesting }
        '7' { AuditLookup }
        '8' { GetTeamsUserInfo }
        '9' { ActiveDirectoryLogin }
        'q' {
            write-Host "Hope we could help!" -ForegroundColor Blue
            If($(Read-Host -Prompt 'Do you want to disconnect from ExchangeOnline?(y/N)') -eq "y") {
                Disconnect-ExchangeOnline -Confirm:$false
                Disconnect-MicrosoftTeams -Confirm:$false
                Disconnect-AzureAD -Confirm:$false
                Write-Log "EXCHANGE-Disconnect: Disconnected from Exchange."
                Write-Log "$($env:username) quit the terminator."
            }
            Return
        }
    }
}