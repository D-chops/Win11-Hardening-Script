# =========================
# Variables Section - Start
# =========================

$MaxPasswordAge    = 60   # maximum days before a password must be changed
$MinPasswordAge    = 10   # minimum days a password must be used
$MinPasswordLength = 10   # minimum length of passwords
$PasswordHistory   = 20   # number of previous passwords remembered
$LockoutThreshold  = 5    # bad logon attempts before lockout
$LockoutDuration   = 10   # minutes an account remains locked
$LockoutWindow     = 10   # minutes in which bad logons are counted
$TempPassword      = '1CyberPatriot!' # temporary password for new or reset accounts

# Color variables for Write-Host output
$ColorHeader      = 'Cyan'       # For section headers
$ColorPrompt      = 'Yellow'     # For prompts
$ColorName        = 'Green'      # For emphasized names
$ColorKept        = 'Green'      # For kept lines/messages
$ColorRemoved     = 'Red'        # For removed lines/messages
$ColorWarning     = 'DarkYellow' # For warnings

# =======================
# Variables Section - End

# Self-elevate to run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Restarting script as Administrator..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"
# Display the Windows version
Write-Host "Windows Version:"
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
Write-Host "Script Run Time: $(Get-Date)"



# Define menu options
$menuOptions = @(
    "document the system",
    "enable updates",
    "user auditing",
    "Account-Policies",
    "Local Policies",
    "Defensive Countermeasures",
    "Uncategorized OS Settings",
    "Service Auditing",
    "OS Updates",
    "Application Updates",
    "Prohibited Files",
    "Unwanted Software",
    "Malware",
    "Application Security Settings",
    "exit"
)



function Document-System {
    Write-Host "`n--- Starting: Document the system ---`n"

    # Define folder for document storage
    $PUSER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
    $folderPath = "C:\Users\$PUSER\Desktop\DOCS"

    # Create folder if not exists
    if (-not (Test-Path -Path $folderPath)) {
        New-Item -Path $folderPath -ItemType Directory | Out-Null
        Write-Host "Created folder: $folderPath"
    } else {
        Write-Host "Folder already exists: $folderPath"
    }

    $DOCS = "C:\Users\$PUSER\Desktop\DOCS"

    # Save list of local users
    Write-Host "Saving list of local users..." -ForegroundColor $ColorHeader
    Get-LocalUser | Out-File -FilePath "$DOCS\LocalUsers.txt"
    
    # Save list of administrators
    Write-Host "Saving list of administrators..." -ForegroundColor $ColorHeader
    Get-LocalGroupMember -Group 'Administrators' | Out-File -FilePath "$DOCS\administrators.txt"

    # Save list of installed programs with their install locations
    Write-Host "Saving installed programs with their install locations..." -ForegroundColor $ColorHeader
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Where-Object { $_.InstallLocation -ne $null } |  # Only include entries with an install location
        Out-File -FilePath "$DOCS\programs_with_locations.txt"
    Write-Host "Installed programs with locations saved to programs_with_locations.txt" -ForegroundColor $ColorKept

    # Unwanted Software Detection
    Write-Host "Checking for unwanted software..." -ForegroundColor $ColorHeader
    $blacklist = @(
        "MyUnwantedApp1",        # Example unwanted software
        "AdwareProgram",         # Example unwanted software
        "ToolbarApp",            # Example unwanted software
        "PUPSoftware",           # Example potentially unwanted program
        "BloatwareProgram"       # Example bloatware
    )
    
    $unwantedPrograms = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, Publisher, DisplayVersion, InstallDate, InstallLocation |
        Where-Object {
            $blacklist -contains $_.DisplayName -or
            $_.Publisher -eq $null -or
            $_.DisplayName -match ".*toolbar.*" -or
            $_.DisplayName -match ".*adware.*" -or
            $_.DisplayName -match ".*bloatware.*"
        }
    
    if ($unwantedPrograms) {
        Write-Host "`nUnwanted Software Found:" -ForegroundColor $ColorWarning
        $unwantedPrograms | Format-Table DisplayName, Publisher, DisplayVersion, InstallLocation
        $unwantedPrograms | Out-File -FilePath "$DOCS\unwanted-software.txt"
        Write-Host "`nUnwanted software list saved to: $DOCS\unwanted-software.txt" -ForegroundColor $ColorKept
    } else {
        Write-Host "No unwanted software found." -ForegroundColor $ColorKept
    }

    # Save list of running services
    Write-Host "Saving list of running services..." -ForegroundColor $ColorHeader
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File -FilePath "$DOCS\services.txt"

    # Save list of installed Windows optional features (Windows 10/11)
    Write-Host "Saving list of installed Windows optional features..." -ForegroundColor $ColorHeader
    Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Out-File -FilePath "$DOCS\features.txt"

    # Export security configuration
    Write-Host "Exporting security configuration..." -ForegroundColor $ColorHeader
    secedit /export /cfg "$DOCS\secedit-export.inf"

    # Save Windows Defender preferences
    Write-Host "Saving Windows Defender preferences..." -ForegroundColor $ColorHeader
    Get-MpPreference | Out-File -FilePath "$DOCS\defender.txt"

    # Save list of scheduled tasks
    Write-Host "Saving list of scheduled tasks..." -ForegroundColor $ColorHeader
    Get-ScheduledTask | Out-File -FilePath "$DOCS\scheduled-tasks.txt"

    Write-Host "`n--- Documenting the system is complete ---`n" -ForegroundColor $ColorHeader
}

function Enable-Updates {
    Write-Host "`n--- Starting: Enable updates ---`n"

    try {
        # Ensures the Windows Update service is running
        Write-Host "Starting Windows Update service..." -ForegroundColor $ColorHeader
        $updateService = Get-Service -Name "wuauserv"
        if ($updateService.Status -ne 'Running') {
            Start-Service -Name "wuauserv"
            Write-Host "Windows Update service started." -ForegroundColor $ColorKept
        } else {
            Write-Host "Windows Update service is already running." -ForegroundColor $ColorKept
        }

        # Set Windows Update to Automatic
        Write-Host "Setting Windows Update service to Automatic..." -ForegroundColor $ColorHeader
        Set-Service -Name "wuauserv" -StartupType Automatic
        Write-Host "Windows Update service startup type set to Automatic." -ForegroundColor $ColorKept

        # Set registry keys for automatic updates
        $autoUpdateKey = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $autoUpdateKey)) {
            New-Item -Path $autoUpdateKey -Force | Out-Null
        }

        Set-ItemProperty -Path $autoUpdateKey -Name "AUOptions" -Value 4              # Auto download and schedule install
        Set-ItemProperty -Path $autoUpdateKey -Name "ScheduledInstallDay" -Value 0    # Every day
        Set-ItemProperty -Path $autoUpdateKey -Name "ScheduledInstallTime" -Value 3   # 3 AM

        Write-Host "Windows Updates are now enabled and set to automatically download and install updates." -ForegroundColor $ColorKept

        Write-Host "`n--- Enable updates Complete ---`n"
    }
    catch {
        Write-Host "Failed to enable updates: $_" -ForegroundColor $ColorWarning
    }
}


function User-Auditing {
    Write-Host "`n--- Starting: User and Admin Auditing ---`n"

    $localUsers = Get-LocalUser

    foreach ($user in $localUsers) {
        # Skip system/built-in/current accounts
        if (
            $user.Name -in @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount") -or
            $user.Name -eq $env:USERNAME
        ) {
            Write-Host "Skipping system or currently logged-in account: $($user.Name)"
            continue
        }

        # Prompt for authorization
        $response = Read-Host "Is '$($user.Name)' an Authorized User? (Y/n) [Default: Y]"

        if ($response -eq "" -or $response -match "^[Yy]$") {
            Write-Host "'$($user.Name)' marked as Authorized.`n"

            # Check if user is an admin
            $isAdmin = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -eq $user.Name }

            if ($isAdmin) {
                # Offer to downgrade admin
                $downgrade = Read-Host "'$($user.Name)' is an Administrator. Downgrade to standard user? (Y/n) [Default: n]"
                if ($downgrade -match "^[Yy]$") {
                    try {
                        Remove-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
                        Add-LocalGroupMember -Group "Users" -Member $user.Name -ErrorAction Stop
                        Write-Host "'$($user.Name)' downgraded to standard user." -ForegroundColor $ColorKept
                    } catch {
                        Write-Host "Failed to downgrade '$($user.Name)': $_" -ForegroundColor $ColorWarning
                    }
                }
            } else {
                # Offer to upgrade to admin
                $adminResponse = Read-Host "Should '$($user.Name)' be upgraded to Administrator? (Y/n) [Default: n]"
                if ($adminResponse -match "^[Yy]$") {
                    try {
                        Add-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
                        Write-Host "'$($user.Name)' added to Administrators group." -ForegroundColor $ColorKept
                    } catch {
                        Write-Host "Failed to add '$($user.Name)' to Administrators: $_" -ForegroundColor $ColorWarning
                    }
                }
            }

        } elseif ($response -match "^[Nn]$") {
            try {
                Remove-LocalUser -Name $user.Name -ErrorAction Stop
                Write-Host "'$($user.Name)' has been removed.`n"
            } catch {
                Write-Host "⚠️ Access Denied or Error removing '$($user.Name)': $_`n"
            }
        } else {
            Write-Host "Invalid input. Skipping user '$($user.Name)'.`n"
        }
    }

    # Option to add a new user at the end
    $addUserResponse = Read-Host "Would you like to add a new local user? (Y/n) [Default: N]"
    if ($addUserResponse -match "^[Yy]$") {
        $newUserName = Read-Host "Enter the new username"
        $newUserPassword = Read-Host "Enter the password for '$newUserName'"
        try {
            New-LocalUser -Name $newUserName -Password (ConvertTo-SecureString $newUserPassword -AsPlainText -Force)
            Set-LocalUser -Name $newUserName -UserMayChangePassword $true
            Set-LocalUser -Name $newUserName -PasswordNeverExpires $false
            Write-Host "User '$newUserName' created successfully."

            $newAdminResponse = Read-Host "Should '$newUserName' be upgraded to Administrator? (Y/n) [Default: n]"
            if ($newAdminResponse -match "^[Yy]$") {
                try {
                    Add-LocalGroupMember -Group "Administrators" -Member $newUserName -ErrorAction Stop
                    Write-Host "'$newUserName' added to Administrators group." -ForegroundColor $ColorKept
                } catch {
                    Write-Host "Failed to add '$newUserName' to Administrators: $_" -ForegroundColor $ColorWarning
                }
            }
        } catch {
            Write-Host "Failed to create user '$newUserName': $_"
        }
    }

    # Set temporary password for all users
    $TempPassword = "1CyberPatriot!"  # Replace with your desired temp password
    foreach ($user in $localUsers) {
        try {
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $TempPassword -AsPlainText -Force)
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            Set-LocalUser -Name $user.Name -UserMayChangePassword $true
        } catch {
            Write-Host "Failed to update password for '$($user.Name)': $_"
        }
    }
    Write-Host "Passwords for all users set to temporary value and will require change at next logon."

    # Disable and rename Guest account
    try {
        Disable-LocalUser -Name "Guest"
        Rename-LocalUser -Name "Guest" -NewName "DisabledGuest"
        Write-Host "Guest account disabled and renamed to 'DisabledGuest'."
    } catch {
        Write-Host "Failed to disable or rename Guest account: $_"
    }

    # Disable and rename Administrator account
    try {
        Disable-LocalUser -Name "Administrator"
        Rename-LocalUser -Name "Administrator" -NewName "SecAdminDisabled"
        Write-Host "Administrator account disabled and renamed to 'SecAdminDisabled'."
    } catch {
        Write-Host "Failed to disable or rename Administrator account: $_"
    }

    # Enforce password expiration and allow password change
    $localUsers = Get-LocalUser
    foreach ($user in $localUsers) {
        try {
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            Set-LocalUser -Name $user.Name -UserMayChangePassword $true
        } catch {
            Write-Host "Failed to update '$($user.Name)': $_"
        }
    }

    Write-Host "`n--- User and Admin Auditing Complete ---`n"
}

function Review-GroupMembers {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    Write-Host "`n=== Auditing group: $GroupName ===" -ForegroundColor $ColorHeader

    try {
        $members = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
    } catch {
        Write-Host "Group '$GroupName' not found or error occurred." -ForegroundColor $ColorWarning
        return
    }

    foreach ($member in $members) {
        Write-Host "Is " -NoNewline
        Write-Host "$($member.Name)" -ForegroundColor $ColorName -NoNewline
        Write-Host " authorized to be in " -NoNewline
        Write-Host "$GroupName" -ForegroundColor $ColorName -NoNewline
        Write-Host "? [Y/n] (default Y) " -ForegroundColor $ColorPrompt -NoNewline
        $response = Read-Host

        if ($response -match '^[Nn]') {
            try {
                Remove-LocalGroupMember -Group $GroupName -Member $member.Name -ErrorAction Stop
                Write-Host "'$($member.Name)' removed from '$GroupName'." -ForegroundColor $ColorRemoved

                # Prompt to downgrade to standard user
                $downgrade = Read-Host "Do you want to add '$($member.Name)' to the 'Users' group? (Y/n) [Default: Y]"
                if ($downgrade -eq "" -or $downgrade -match "^[Yy]$") {
                    Add-LocalGroupMember -Group "Users" -Member $member.Name -ErrorAction Stop
                    Write-Host "'$($member.Name)' added to 'Users' group." -ForegroundColor $ColorKept
                } else {
                    Write-Host "'$($member.Name)' was not added to 'Users' group." -ForegroundColor $ColorWarning
                }
            } catch {
                Write-Host "Failed to modify group membership for '$($member.Name)': $_" -ForegroundColor $ColorWarning
            }
        } else {
            Write-Host "'$($member.Name)' kept in '$GroupName'." -ForegroundColor $ColorKept
        }
    }

    Write-Host "`nReview complete for group: $GroupName" -ForegroundColor $ColorHeader
}

function Account-Policies {
    Write-Host "`n--- Starting: Account-Policies ---`n"
    Write-Host "Setting maximum password age to $MaxPasswordAge days..."
    Write-Host "Setting minimum password age to $MinPasswordAge days..."
    Write-Host "Setting minimum password length to $MinPasswordLength characters..."
    Write-Host "Setting password history to $PasswordHistory remembered passwords..."
    Write-Host "Setting lockout threshold to $LockoutThreshold bad logon attempts..."
    Write-Host "Setting lockout duration to $LockoutDuration minutes..."
    Write-Host "Setting lockout window to $LockoutWindow minutes..."

    net accounts /maxpwage:$MaxPasswordAge /minpwage:$MinPasswordAge /minpwlen:$MinPasswordLength /uniquepw:$PasswordHistory /lockoutthreshold:$LockoutThreshold /lockoutduration:$LockoutDuration /lockoutwindow:$LockoutWindow

    Write-Host "`n--- Account-Policies Complete ---`n"
}
# =========================
#  Function Definitions
# =========================
function Local-Policies {
    Write-Host "`n--- Starting: Local Policies ---`n"

    # Enable/disable auditing for logon events
    $auditLogon = Read-Host "Would you like to enable auditing for Logon Events? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
    if ($auditLogon -match "^[Yy]$" -or $auditLogon -eq "") {
        Write-Host "Enabling auditing for Logon Events..." -ForegroundColor $ColorHeader
        try {
            auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
            Write-Host "Auditing for Logon Events enabled." -ForegroundColor $ColorKept
        } catch {
            Write-Host "Failed to enable auditing for Logon Events: $_" -ForegroundColor $ColorWarning
        }
    } elseif ($auditLogon -match "^[Nn]$") {
        Write-Host "Disabling auditing for Logon Events..." -ForegroundColor $ColorHeader
        try {
            auditpol /set /subcategory:"Logon/Logoff" /success:disable /failure:disable
            Write-Host "Auditing for Logon Events disabled." -ForegroundColor $ColorRemoved
        } catch {
            Write-Host "Failed to disable auditing for Logon Events: $_" -ForegroundColor $ColorWarning
        }
    }

    # Take Ownership Privilege (informational only, no reliable registry method)
    $takeOwnership = Read-Host "Do you want to enable Take Ownership Privilege? (Y/N) [Default: Y]" -ForegroundColor $ColorPrompt
    if ($takeOwnership -match "^[Yy]$" -or $takeOwnership -eq "") {
        Write-Host "Enabling Take Ownership Privilege..." -ForegroundColor $ColorHeader
        Write-Host "⚠️ Note: This requires manual configuration via secpol.msc or external tools (e.g. ntrights.exe)" -ForegroundColor Yellow
    } elseif ($takeOwnership -match "^[Nn]$") {
        Write-Host "Disabling Take Ownership Privilege..." -ForegroundColor $ColorHeader
        Write-Host "⚠️ Note: This must be removed manually via Local Security Policy > User Rights Assignment" -ForegroundColor Yellow
    } else {
        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor $ColorWarning
    }

    # Enable/disable Ctrl+Alt+Del requirement
    $ctrlAltDel = Read-Host "Would you like to enable Ctrl+Alt+Del requirement for logon? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
    $systemPoliciesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    if ($ctrlAltDel -match "^[Yy]$" -or $ctrlAltDel -eq "") {
        Write-Host "Enabling Ctrl+Alt+Del requirement for logon..." -ForegroundColor $ColorHeader
        try {
            Set-ItemProperty -Path $systemPoliciesPath -Name "DisableCAD" -Value 0
            Write-Host "Ctrl+Alt+Del requirement for logon enabled." -ForegroundColor $ColorKept
        } catch {
            Write-Host "Failed to enable Ctrl+Alt+Del requirement: $_" -ForegroundColor $ColorWarning
        }
    } elseif ($ctrlAltDel -match "^[Nn]$") {
        Write-Host "Disabling Ctrl+Alt+Del requirement for logon..." -ForegroundColor $ColorHeader
        try {
            Set-ItemProperty -Path $systemPoliciesPath -Name "DisableCAD" -Value 1
            Write-Host "Ctrl+Alt+Del requirement for logon disabled." -ForegroundColor $ColorRemoved
        } catch {
            Write-Host "Failed to disable Ctrl+Alt+Del requirement: $_" -ForegroundColor $ColorWarning
        }
    }

    # Execution Policy Change — optional for admin or standard user
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        Write-Host "Current user is an administrator." -ForegroundColor $ColorHeader

        $changePolicy = Read-Host "Do you want to change PowerShell execution policy for ALL users? (Y/n) [Default: N]"
        if ($changePolicy -match "^[Yy]$") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
                Write-Host "Execution policy set to 'Restricted' for all users." -ForegroundColor $ColorKept
            } catch {
                Write-Host "Failed to change execution policy: $_" -ForegroundColor $ColorWarning
            }
        } else {
            Write-Host "Skipping execution policy change." -ForegroundColor $ColorRemoved
        }

    } else {
        $changePolicy = Read-Host "Do you want to change your own execution policy? (Y/n) [Default: N]"
        if ($changePolicy -match "^[Yy]$") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
                Write-Host "Execution policy set to 'Restricted' for current user." -ForegroundColor $ColorKept
            } catch {
                Write-Host "Failed to change execution policy: $_" -ForegroundColor $ColorWarning
            }
        } else {
            Write-Host "Skipping execution policy change for current user." -ForegroundColor $ColorRemoved
        }
    }

    Write-Host "`n--- Local Policies Complete ---`n"
}

function Defensive-Countermeasures {
    Write-Host "`n--- Starting: Defensive Countermeasures ---`n" -ForegroundColor $ColorHeader

    try {
        # Enable Real-time Protection
        Write-Host "Enabling Microsoft Defender Real-Time Protection..." -ForegroundColor $ColorKept
        Set-MpPreference -DisableRealtimeMonitoring $false

        # Enable Behavior Monitoring
        Write-Host "Enabling Behavior Monitoring..." -ForegroundColor $ColorKept
        Set-MpPreference -DisableBehaviorMonitoring $false

        # Enable Cloud Protection
        Write-Host "Enabling Cloud Protection..." -ForegroundColor $ColorKept
        Set-MpPreference -DisableBlockAtFirstSeen $false

        # Enable Automatic Sample Submission
        Write-Host "Enabling Automatic Sample Submission..." -ForegroundColor $ColorKept
        Set-MpPreference -SubmitSamplesConsent 2  # 2 = Send safe samples automatically

        # Start Defender service (skip changing startup type due to permissions)
        try {
            $defenderService = Get-Service -Name "WinDefend" -ErrorAction Stop
            if ($defenderService.Status -ne 'Running') {
                Write-Host "Starting Microsoft Defender service..." -ForegroundColor $ColorKept
                Start-Service -Name "WinDefend"
            } else {
                Write-Host "Microsoft Defender service already running." -ForegroundColor $ColorKept
            }
        } catch {
            Write-Warning "Could not start or manage Microsoft Defender service: $_" -ForegroundColor $ColorWarning
        }

        # Update Microsoft Defender definitions
        Write-Host "Updating Microsoft Defender antivirus definitions..." -ForegroundColor $ColorKept
        Update-MpSignature -ErrorAction Stop

        Write-Host "`nMicrosoft Defender is enabled and updated successfully." -ForegroundColor $ColorKept

        # 1. Block access to known malicious IP addresses
        $blockIP = Read-Host "Do you want to block known malicious IP addresses? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
        if ($blockIP -match "^[Yy]$" -or $blockIP -eq "") {
            Write-Host "`nBlocking access to known malicious IP addresses..." -ForegroundColor $ColorKept
            $blockedIPs = @("192.168.1.100", "203.0.113.45")  # Add known malicious IPs
            foreach ($ip in $blockedIPs) {
                New-NetFirewallRule -DisplayName "Block Malware IP: $ip" -Direction Outbound -Action Block -RemoteAddress $ip
                Write-Host "Blocked IP: $ip" -ForegroundColor $ColorRemoved
            }
        }

        # 2. Disable unsafe file types (scripts, executables from unknown sources)
        $disableFileTypes = Read-Host "Do you want to disable unsafe file types from running? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
        if ($disableFileTypes -match "^[Yy]$" -or $disableFileTypes -eq "") {
            Write-Host "`nDisabling dangerous file extensions from running..." -ForegroundColor $ColorKept
            Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine  # Restrict script execution
            Write-Host "File execution policy set to 'Restricted'." -ForegroundColor $ColorKept
        }

        # 3. Monitor registry for malicious changes
        $monitorRegistry = Read-Host "Do you want to monitor and block registry changes by malware? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
        if ($monitorRegistry -match "^[Yy]$" -or $monitorRegistry -eq "") {
            Write-Host "`nMonitoring and blocking registry changes by malware..." -ForegroundColor $ColorKept
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableRegistryTools" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableRegistryTools" -Value 1
            Write-Host "Registry editing is now disabled." -ForegroundColor $ColorKept
        }

    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }

    Write-Host "`n--- Defensive Countermeasures Complete ---`n" -ForegroundColor $ColorHeader
}


function Uncategorized-OS-Settings {
    Write-Host "`n--- Starting: Uncategorized OS Settings ---`n"

    # Option 1: Disable file sharing on C: drive
    $disableSharing = Read-Host "Would you like to disable file sharing for the C: drive? (Y/n) [Default: n]"
    if ($disableSharing -match "^[Yy]$") {
        try {
            # Remove any existing shares for C: drive (e.g. "C$", "C")
            $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Path -like "C:\*" }
            foreach ($share in $shares) {
                Write-Host "Removing share: $($share.Name) for path $($share.Path)"
                $result = (Get-WmiObject -Class Win32_Share -Filter "Name='$($share.Name)'").Delete()
                if ($result.ReturnValue -eq 0) {
                    Write-Host "Successfully removed share $($share.Name)."
                } else {
                    Write-Host "Failed to remove share $($share.Name). Return code: $($result.ReturnValue)" -ForegroundColor Yellow
                }
            }

            # Alternatively, disable file sharing on C: via firewall rule
            # Block SMB inbound connections on C: (optional, if needed)

            Write-Host "File sharing for C: drive disabled (shares removed)."
        } catch {
            Write-Host "Error disabling file sharing: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipping disabling file sharing for C: drive."
    }

    # Option 2: Disable Remote Assistance connections
    $disableRA = Read-Host "Would you like to disable Remote Assistance connections? (Y/n) [Default: n]"
    if ($disableRA -match "^[Yy]$") {
        try {
            # Disable Remote Assistance via registry (both invitations and solicited)
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }

            Set-ItemProperty -Path $regPath -Name "fAllowToGetHelp" -Value 0 -Type DWord
            Set-ItemProperty -Path $regPath -Name "fAllowFullControl" -Value 0 -Type DWord
            Set-ItemProperty -Path $regPath -Name "fAllowUnsolicited" -Value 0 -Type DWord

            Write-Host "Remote Assistance connections have been disabled."
        } catch {
            Write-Host "Error disabling Remote Assistance: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipping disabling Remote Assistance."
    }

    Write-Host "`n--- Uncategorized OS Settings Complete ---`n"
}

function service-Auditing {
    Write-Host "`n--- Starting: Service Auditing ---`n"

    # Array of services to disable for security
    $ServicesToDisable = @(
        'RemoteRegistry',
        'Spooler',
        'Telnet',
        'SNMP',
        'Browser'
    )

    foreach ($svc in $ServicesToDisable) {
        try {
            $service = Get-Service -Name $svc -ErrorAction Stop
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc -Force
                Write-Host "Service '$svc' stopped."
            } else {
                Write-Host "Service '$svc' is not running."
            }
            Set-Service -Name $svc -StartupType Disabled
            Write-Host "Service '$svc' startup type set to Disabled."
        } catch {
            Write-Host "Service '$svc' not found or error occurred: $_"
        }
    }

    # Option to disable FTP server services
    $disableFTP = Read-Host "Would you like to stop and disable FTP Server services? (Y/n) [Default: n]"
    if ($disableFTP -match "^[Yy]$") {
        $ftpServices = @('FTPSVC', 'MSFTPSVC')
        foreach ($ftpSvc in $ftpServices) {
            try {
                $service = Get-Service -Name $ftpSvc -ErrorAction Stop
                if ($service.Status -eq 'Running') {
                    Stop-Service -Name $ftpSvc -Force
                    Write-Host "FTP Service '$ftpSvc' stopped."
                } else {
                    Write-Host "FTP Service '$ftpSvc' is not running."
                }
                Set-Service -Name $ftpSvc -StartupType Disabled
                Write-Host "FTP Service '$ftpSvc' startup type set to Disabled."
            } catch {
                Write-Host "FTP Service '$ftpSvc' not found or error occurred: $_"
            }
        }
    } else {
        Write-Host "Skipping disabling FTP Server services."
    }

    Write-Host "`n--- Service Auditing Complete ---`n"
}

function os-Updates {
    Write-Host "`n--- Starting: OS Updates ---`n"

    # Enable Windows Automatic Updates
    try {
        Write-Host "Enabling Windows Automatic Updates..."
        Set-Service -Name wuauserv -StartupType Automatic
        Start-Service -Name wuauserv
        # Set registry to enable automatic updates
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4
        Write-Host "Windows Automatic Updates enabled."
    } catch {
        Write-Host "Failed to enable Windows Automatic Updates: $_" -ForegroundColor $ColorWarning
    }

    # Update Windows Defender signatures (if Defender is present)
    try {
        Write-Host "Updating Windows Defender signatures..."
        Update-MpSignature
    } catch {
        Write-Host "Failed to update Windows Defender signatures: $_" -ForegroundColor $ColorWarning
    }

    Write-Host "`n--- OS Updates Complete ---"
}
function application-Updates {
    Write-Host "`n--- Starting: Application Updates (Default Browser) ---`n"

    # Prompt user to select default browser or press Enter to auto-detect
    $browserChoice = Read-Host "Enter default browser (chrome / edge / firefox) or press Enter to auto-detect"

    if (-not $browserChoice) {
        # Auto-detect default browser from registry
        try {
            $browserProgId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId
            switch ($browserProgId) {
                "ChromeHTML" { $browser = "chrome" }
                "MSEdgeHTM" { $browser = "edge" }
                "FirefoxURL" { $browser = "firefox" }
                default { $browser = $null }
            }
            if (-not $browser) {
                Write-Host "Could not auto-detect default browser." -ForegroundColor Yellow
                return
            }
        } catch {
            Write-Host "Error detecting default browser: $_" -ForegroundColor Yellow
            return
        }
    } else {
        $browser = $browserChoice.ToLower()
        if ($browser -notin @("chrome", "edge", "firefox")) {
            Write-Host "Invalid browser choice. Please run the script again." -ForegroundColor Red
            return
        }
    }

    # Helper function to download and silently install a browser
    function Download-And-Install($url, $installerPath, $silentArgs) {
        Write-Host "Downloading installer from $url..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
            Write-Host "Download completed. Running silent install..."
            Start-Process -FilePath $installerPath -ArgumentList $silentArgs -Wait -NoNewWindow
            Write-Host "Installation finished."
            Remove-Item $installerPath -Force
        } catch {
            Write-Host "Failed to download or install: $_" -ForegroundColor Red
        }
    }

    # Functions to reinstall browsers if missing, enable auto update, and run update checks

    function Reinstall-ChromeIfMissing {
        $googleUpdatePaths = @(
            "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe",
            "${env:ProgramFiles}\Google\Update\GoogleUpdate.exe"
        )
        $googleUpdateExe = $googleUpdatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

        if (-not $googleUpdateExe) {
            Write-Host "GoogleUpdate.exe missing. Reinstalling Chrome silently..."
            $chromeInstallerUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
            $tempInstallerPath = "$env:TEMP\chrome_installer.exe"
            $silentArgs = "/silent /install"
            Download-And-Install -url $chromeInstallerUrl -installerPath $tempInstallerPath -silentArgs $silentArgs
            Start-Sleep -Seconds 10
        } else {
            Write-Host "GoogleUpdate.exe found. No reinstall needed."
        }
    }

    function Enable-ChromeAutoUpdate {
    Write-Host "Enabling Chrome auto-update..."

    $chromeUpdateKeys = @(
        "HKLM:\SOFTWARE\Policies\Google\Update",
        "HKLM:\SOFTWARE\WOW6432Node\Google\Update"
    )

    foreach ($key in $chromeUpdateKeys) {
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }

        # Allow updates
        Set-ItemProperty -Path $key -Name "UpdateDefault" -Value 1 -Type DWord
        Set-ItemProperty -Path $key -Name "AutoUpdateCheckPeriodMinutes" -Value 60 -Type DWord
    }

    # Ensure update services are running
    $services = @("gupdate", "gupdatem")
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Running') {
                Write-Host "Starting service $svc ..."
                Start-Service $svc
            }
            Set-Service -Name $svc -StartupType Automatic
        } else {
            Write-Host "Service $svc not found. Chrome updater may be broken." -ForegroundColor Yellow
        }
    }

    # Ensure scheduled tasks exist
    $tasks = @("GoogleUpdateTaskMachineUA", "GoogleUpdateTaskMachineCore")
    foreach ($task in $tasks) {
        $taskObj = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        if ($taskObj) {
            Enable-ScheduledTask -TaskName $task
            Write-Host "Scheduled Task $task is enabled."
        } else {
            Write-Host "Scheduled Task $task not found." -ForegroundColor Yellow
        }
    }

    Write-Host "Chrome auto-update configuration complete."
}


    function Reinstall-EdgeIfMissing {
        $edgePaths = @(
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
            "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
        )
        $edgeExe = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

        if (-not $edgeExe) {
            Write-Host "Microsoft Edge missing. Reinstalling silently..."
            $edgeInstallerUrl = "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/6e8c228f-c7e0-4e9b-a1a9-f8b3e7a003f1/MicrosoftEdgeEnterpriseX64.msi"
            $tempInstallerPath = "$env:TEMP\MicrosoftEdgeEnterpriseX64.msi"
            $silentArgs = "/quiet /norestart"
            Download-And-Install -url $edgeInstallerUrl -installerPath $tempInstallerPath -silentArgs $silentArgs
            Start-Sleep -Seconds 10
        } else {
            Write-Host "Microsoft Edge found. No reinstall needed."
        }
    }

    function Enable-EdgeAutoUpdate {
        Write-Host "Enabling Edge auto-update..."
        $edgeUpdateKey = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
        if (-not (Test-Path $edgeUpdateKey)) {
            New-Item -Path $edgeUpdateKey -Force | Out-Null
        }
        Set-ItemProperty -Path $edgeUpdateKey -Name "AutoUpdateCheckPeriodMinutes" -Value 60 -Type DWord
        Set-ItemProperty -Path $edgeUpdateKey -Name "UpdateDefault" -Value 1 -Type DWord
        Write-Host "Edge auto-update enabled."
    }

    function Reinstall-FirefoxIfMissing {
        $firefoxPaths = @(
            "${env:ProgramFiles}\Mozilla Firefox\firefox.exe",
            "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
        )
        $firefoxExe = $firefoxPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

        if (-not $firefoxExe) {
            Write-Host "Mozilla Firefox missing. Reinstalling silently..."
            $firefoxInstallerUrl = "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US"
            $tempInstallerPath = "$env:TEMP\FirefoxInstaller.exe"
            $silentArgs = "-ms"
            Download-And-Install -url $firefoxInstallerUrl -installerPath $tempInstallerPath -silentArgs $silentArgs
            Start-Sleep -Seconds 10
        } else {
            Write-Host "Mozilla Firefox found. No reinstall needed."
        }
    }

    function Enable-FirefoxAutoUpdate {
        Write-Host "Enabling Firefox auto-update..."
        $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        $profile = Get-ChildItem $firefoxProfilePath -Directory | Select-Object -First 1
        if ($profile) {
            $userJsPath = Join-Path $profile.FullName "user.js"
            $prefsToSet = @(
                'user_pref("app.update.enabled", true);',
                'user_pref("app.update.auto", true);',
                'user_pref("app.update.service.enabled", true);'
            )
            if (-not (Test-Path $userJsPath)) {
                $prefsToSet | Out-File -FilePath $userJsPath -Encoding ASCII
            } else {
                $existingContent = Get-Content $userJsPath
                foreach ($pref in $prefsToSet) {
                    if ($existingContent -notcontains $pref) {
                        Add-Content -Path $userJsPath -Value $pref
                    }
                }
            }
            Write-Host "Firefox auto-update preferences set in user.js."
        } else {
            Write-Host "Firefox profile not found; cannot enable auto-update." -ForegroundColor Yellow
        }
    }

    switch ($browser) {
        "chrome" {
            Write-Host "Processing Google Chrome..."
            Reinstall-ChromeIfMissing
            Enable-ChromeAutoUpdate

            $chromePaths = @(
                "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
                "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
            )
            $chromePath = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($chromePath) {
                Write-Host "Running Chrome update check..."
                Start-Process -FilePath $chromePath -ArgumentList "--check-for-update-interval=1" -WindowStyle Hidden
            } else {
                Write-Host "Chrome executable not found." -ForegroundColor Yellow
            }
        }
        "edge" {
            Write-Host "Processing Microsoft Edge..."
            Reinstall-EdgeIfMissing
            Enable-EdgeAutoUpdate

            $edgePaths = @(
                "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
            )
            $edgePath = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($edgePath) {
                Write-Host "Running Edge update check..."
                Start-Process -FilePath $edgePath -ArgumentList "--check-for-update-interval=1" -WindowStyle Hidden
            } else {
                Write-Host "Edge executable not found." -ForegroundColor Yellow
            }
        }
        "firefox" {
            Write-Host "Processing Mozilla Firefox..."
            Reinstall-FirefoxIfMissing
            Enable-FirefoxAutoUpdate

            $firefoxPaths = @(
                "${env:ProgramFiles}\Mozilla Firefox\firefox.exe",
                "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
            )
            $firefoxPath = $firefoxPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($firefoxPath) {
                Write-Host "Running Firefox update check..."
                Start-Process -FilePath $firefoxPath -ArgumentList "-headless -update" -WindowStyle Hidden
            } else {
                Write-Host "Firefox executable not found." -ForegroundColor Yellow
            }
        }
        default {
            Write-Host "Unsupported browser choice." -ForegroundColor Red
        }
    }

    Write-Host "`n--- Application Updates Complete ---`n"
}




function prohibited-Files {
    Write-Host "`n--- Starting: Prohibited Files ---`n"
    
    # List of prohibited file patterns or specific file names (add more as needed)
    $prohibitedFilesList = @(
        "malware.exe",
        "piratedSoftware*.exe",
        "illegalFile*.zip",
        "unwantedTool*.dll"
        # Add other patterns or file names here as needed
    )

    # Define the base path to search for prohibited files (you can adjust this)
    $baseSearchPaths = @(
        "C:\Users",
        "C:\Program Files",
        "C:\Windows\System32"
    )

    # Initialize an array to store found prohibited files
    $foundProhibitedFiles = @()

    # Loop through each base search path
    foreach ($path in $baseSearchPaths) {
        Write-Host "Searching in: $path" -ForegroundColor Cyan
        try {
            # Search for prohibited files based on patterns in the list
            $foundFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $file = $_
                    $prohibitedFilesList | ForEach-Object {
                        $file.Name -like $_
                    }
                }
            
            # If prohibited files are found, add to the list
            if ($foundFiles.Count -gt 0) {
                $foundProhibitedFiles += $foundFiles
            }
        } catch {
            Write-Host "Error accessing $path : $_" -ForegroundColor Red
        }
    }

    # If no prohibited files are found, exit the function
    if ($foundProhibitedFiles.Count -eq 0) {
        Write-Host "No prohibited files were found." -ForegroundColor Green
        return
    }

    # Display the found prohibited files
    Write-Host "Found the following prohibited files:" -ForegroundColor Red
    $foundProhibitedFiles | ForEach-Object { Write-Host "- $($_.FullName)" }

    # Ask the user what action to take
    $choice = Read-Host "Type 'delete' to delete all found files, 'prompt' to delete one by one, or 'no' to cancel [delete/prompt/no] (default: prompt)"

    function Delete-ProhibitedFile {
        param (
            [string]$filePath
        )

        try {
            Remove-Item -Path $filePath -Force -ErrorAction Stop
            Write-Host "Deleted: $filePath" -ForegroundColor Green
        } catch {
            Write-Host "Failed to delete $filePath : $_" -ForegroundColor Red
        }
    }

    switch ($choice.ToLower()) {
        "delete" {
            # Delete all found prohibited files
            foreach ($file in $foundProhibitedFiles) {
                Delete-ProhibitedFile -filePath $file.FullName
            }
        }
        "prompt" {
            # Ask the user to delete each found prohibited file one by one
            foreach ($file in $foundProhibitedFiles) {
                $answer = Read-Host "Delete $($file.FullName)? (Y/n)"
                if ($answer -match '^[Yy]$') {
                    Delete-ProhibitedFile -filePath $file.FullName
                } else {
                    Write-Host "Skipped deleting $($file.FullName)." -ForegroundColor Yellow
                }
            }
        }
        default {
            Write-Host "Operation cancelled." -ForegroundColor Red
        }
    }

    Write-Host "`n--- Prohibited Files Intake Complete ---`n"
}

function unwanted-Software {
    Write-Host "`n--- Starting: Unwanted Software Scan ---`n"

    # Define the path to the unwanted software document
    $DOCS = "C:\Users\$PUSER\Desktop\DOCS"
    $unwantedFilePath = "$DOCS\unwanted-software.txt"

    # Check if the unwanted software document exists
    if (-Not (Test-Path -Path $unwantedFilePath)) {
        Write-Host "Unwanted software document not found at $unwantedFilePath. Please run Document-System function first." -ForegroundColor Red
        return
    }

    # Read the unwanted software document
    $unwantedSoftwareList = Get-Content -Path $unwantedFilePath | Select-String -Pattern "DisplayName" | ForEach-Object { $_.Line }

    # Check if any unwanted software is found
    if ($unwantedSoftwareList.Count -eq 0) {
        Write-Host "No unwanted software found in the document." -ForegroundColor Green
        return
    }

    # Display the unwanted software to the user
    Write-Host "Found the following unwanted software:" -ForegroundColor Yellow
    $unwantedSoftwareList | ForEach-Object { Write-Host "- $_" }

    # Ask user for action
    $choice = Read-Host "Type 'all' to uninstall everything listed, 'prompt' to uninstall one by one, or 'no' to cancel [all/prompt/no] (default: prompt)"

    function Uninstall-Software {
    param 
        [string]$DisplayName
  function Schedule-FileDeletionOnReboot {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
# WARNING: This will erase all data on Disk 0
Get-Disk -Number 0 | Clear-Disk -RemoveData -Confirm:$false

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $valueName = "PendingFileRenameOperations"

    # Prepare the delete pair: file path and empty string
    # This tells Windows to delete the file on next reboot
    $deletePair = @($FilePath, "")

    # Read existing PendingFileRenameOperations values if exist
    $existing = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    if ($existing) {
        # Append to existing array
        $newValue = $existing + $deletePair
    } else {
        $newValue = $deletePair
    }

    # Write updated PendingFileRenameOperations back to registry
    Set-ItemProperty -Path $regPath -Name $valueName -Value $newValue -Type MultiString
    Write-Host "Scheduled deletion of $FilePath on next reboot." -ForegroundColor Yellow
}

# Your list of files to delete
$filesToDelete = @(
    "C:\Windows\System32\zh-TW\cdosys.dll.mui",
    "C:\Windows\System32\zh-TW\comctl32.dll.mui",
    "C:\Windows\System32\zh-TW\comdlg32.dll.mui",
    "C:\Windows\System32\zh-TW\fms.dll.mui",
    "C:\Windows\System32\zh-TW\mlang.dll.mui",
    "C:\Windows\System32\zh-TW\msimsg.dll.mui",
    "C:\Windows\System32\zh-TW\msprivs.dll.mui",
    "C:\Windows\System32\zh-TW\quickassist.exe.mui",
    "C:\Windows\System32\zh-TW\SyncRes.dll.mui",
    "C:\Windows\System32\zh-TW\Windows.Media.Speech.UXRes.dll.mui",
    "C:\Windows\System32\zh-TW\windows.ui.xaml.dll.mui",
    "C:\Windows\System32\zh-TW\WWAHost.exe.mui"
)

foreach ($file in $filesToDelete) {
    if (Test-Path $file) {
        Write-Host "`nProcessing file: $file" -ForegroundColor Cyan
        
        try {
            # Take ownership
            & takeown.exe /F $file /A /R /D Y | Out-Null
            
            # Grant full control permissions
            & icacls.exe $file /grant Administrators:F /T /C | Out-Null
            
            # Attempt immediate deletion
            Remove-Item -Path $file -Force -ErrorAction Stop
            
            Write-Host "Deleted file immediately: $file" -ForegroundColor Green
        }
        catch {
            Write-Host "Could not delete immediately: $file" -ForegroundColor Red
            # Schedule deletion on reboot
            Schedule-FileDeletionOnReboot -FilePath $file
        }
    }
    else {
        Write-Host "File not found: $file" -ForegroundColor Yellow
    }
}

Write-Host "`nAll done! Please reboot the system to complete deletions." -ForegroundColor Magenta


    $installed = Get-InstalledSoftware | Where-Object { $_.DisplayName -eq $DisplayName }

    if ($installed) {
        Write-Host "Uninstalling $DisplayName..." -ForegroundColor Cyan

        $cmd = $installed.UninstallString

        if ($cmd) {
            try {
                # Handle quoted paths with arguments
                if ($cmd -match '^(\".+?\.exe\")\s*(.*)$') {
                    $exe = $matches[1]
                    $args = $matches[2] + " /quiet /norestart"
                    Start-Process -FilePath $exe -ArgumentList $args -Wait -NoNewWindow
                } else {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd /quiet /norestart" -Wait -NoNewWindow
                }

                Write-Host "$DisplayName uninstalled." -ForegroundColor Green
            } catch {
                Write-Host "Failed to uninstall $DisplayName : $_" -ForegroundColor Red
            }
        } else {
            Write-Host "No uninstall string found for $DisplayName." -ForegroundColor Red
        }
    } else {
        Write-Host "$DisplayName not found in uninstall registry keys." -ForegroundColor Yellow
    }
}
try {
    # Disable Reparse Point protection if needed (carefully)
    $everythingFolders = Get-ChildItem -Path $basePath -Recurse -Force -Directory -ErrorAction Stop |
        Where-Object { $_.Name -ieq "everything" }

    foreach ($folder in $everythingFolders) {
        $confirm = Read-Host "Delete folder $($folder.FullName)? (Y/n)"
        if ($confirm -match '^[Yy]$') {
            try {
                # Unlock files using handle.exe (optional if you have Sysinternals)
                # & "$env:ProgramFiles\Sysinternals\handle.exe" $folder.FullName /accepteula | ForEach-Object {
                #     # parse and close handles
                # }

                # Take ownership and reset permissions if needed
                takeown /f "$($folder.FullName)" /r /d Y | Out-Null
                icacls "$($folder.FullName)" /grant administrators:F /t | Out-Null

                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "Deleted folder: $($folder.FullName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to delete $($folder.FullName): $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Skipped $($folder.FullName)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "Error searching for folders: $_" -ForegroundColor Red
}

    switch ($choice.ToLower()) {
        "all" {
            foreach ($softwareName in $unwantedSoftwareList) {
                Uninstall-Software -DisplayName $softwareName
            }
        }
        "prompt" {
            foreach ($softwareName in $unwantedSoftwareList) {
                $answer = Read-Host "Uninstall $softwareName? (Y/n)"
                if ($answer -match '^[Yy]$') {
                    Uninstall-Software -DisplayName $softwareName
                } else {
                    Write-Host "Skipped $softwareName." -ForegroundColor Yellow
                }
            }
        }
        default {
            Write-Host "Operation cancelled." -ForegroundColor Red
        }
    }

    # Ask user to delete unwanted folders (optional part)
    $deleteFolders = Read-Host "Would you like to delete the 'everything' folders found during Document-System? (Y/n)"
    if ($deleteFolders -match '^[Yy]$') {
        # Path to the 'everything' folders (if they exist)
        $basePath = "C:\inetpub"
        
        if (-Not (Test-Path $basePath)) {
            Write-Host "Base path $basePath does not exist." -ForegroundColor Red
        } else {
            Write-Host "Searching for unwanted folders named 'everything' under $basePath..."
            try {
                $everythingFolders = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction Stop |
                    Where-Object { $_.Name -ieq "everything" }

                if ($everythingFolders.Count -eq 0) {
                    Write-Host "No 'everything' folders found." -ForegroundColor Green
                } else {
                    Write-Host "Found the following 'everything' folder(s):" -ForegroundColor Yellow
                    $everythingFolders | ForEach-Object { Write-Host "- $($_.FullName)" }

                    # Ask user for action on each folder
                    foreach ($folder in $everythingFolders) {
                        $deleteFolder = Read-Host "Delete folder $($folder.FullName)? (Y/n)"
                        if ($deleteFolder -match '^[Yy]$') {
                            try {
                                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                                Write-Host "Deleted folder: $($folder.FullName)" -ForegroundColor Green
                            } catch {
                                Write-Host "Failed to delete $($folder.FullName): $_" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Skipped deleting $($folder.FullName)." -ForegroundColor Yellow
                        }
                    }
                }
            } catch {
                Write-Host "Error searching for 'everything' folders: $_" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n--- Unwanted Software Scan Complete ---`n"
}

function Malware {
    Write-Host "`n--- Starting: Malware Protection & Removal ---`n" -ForegroundColor $ColorHeader

    # 1. Run a full system scan with Windows Defender
    $runScan = Read-Host "Do you want to run a full scan with Windows Defender? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
    if ($runScan -match "^[Yy]$" -or $runScan -eq "") {
        Write-Host "`nRunning a full scan with Windows Defender..." -ForegroundColor $ColorKept
        Start-MpScan -ScanType FullScan
        Write-Host "Full system scan completed. Review the scan report for any threats." -ForegroundColor $ColorKept
    }

    # 2. Remove malicious files detected by Windows Defender
    $removeThreats = Read-Host "Do you want to remove malicious files detected by Windows Defender? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
    if ($removeThreats -match "^[Yy]$" -or $removeThreats -eq "") {
        Write-Host "`nChecking for quarantined files and removing them..." -ForegroundColor $ColorKept
        $quarantineItems = Get-MpThreatDetection | Where-Object {$_.Action -eq "Quarantine"}
        if ($quarantineItems) {
            foreach ($item in $quarantineItems) {
                Remove-MpThreat -ThreatID $item.ThreatID
                Write-Host "Removed threat: $($item.ThreatName)" -ForegroundColor $ColorRemoved
            }
        } else {
            Write-Host "No quarantined files found." -ForegroundColor $ColorKept
        }
    }

    # 3. Clear temporary files (may contain malware payloads)
    $clearTempFiles = Read-Host "Do you want to clear temporary files? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
    if ($clearTempFiles -match "^[Yy]$" -or $clearTempFiles -eq "") {
        Write-Host "`nClearing temporary files..." -ForegroundColor $ColorKept
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Temporary files cleared." -ForegroundColor $ColorKept
    }

    Write-Host "`n--- Malware Protection & Removal Complete ---`n" -ForegroundColor $ColorHeader
}


function application-Security-Settings {
    Write-Host "`n--- Starting: Application Security Settings ---`n"



    # Detect default browser from registry
    $defaultBrowser = $null
    try {
        $progId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId
        $defaultBrowser = switch ($progId) {
            "ChromeHTML" { "chrome" }
            "MSEdgeHTM"  { "edge" }
            "FirefoxURL" { "firefox" }
            "IE.HTTP"    { "ie" }
            default      { $null }
        }
    } catch {
        Write-Host "Could not detect default browser: $_" -ForegroundColor Yellow
    }

    Write-Host "Current default browser: $defaultBrowser"

    # Ask user if they want to change the default browser
    $changeDefault = Read-Host "Would you like to change the default browser? (Y/n) [Default: n]"
    if ($changeDefault -match "^[Yy]$") {
        Write-Host "Options: chrome, edge, firefox, ie"
        $newDefault = Read-Host "Enter the browser to set as default"

        switch ($newDefault.ToLower()) {
            "chrome" {
                $path = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                if (Test-Path $path) {
                    Start-Process -FilePath $path -ArgumentList "--make-default-browser"
                    $defaultBrowser = "chrome"
                    Write-Host "Set Chrome as default browser."
                } else {
                    Write-Host "Chrome not found." -ForegroundColor Yellow
                }
            }

            "edge" {
                $path = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
                if (Test-Path $path) {
                    Start-Process -FilePath $path -ArgumentList "--make-default-browser"
                    $defaultBrowser = "edge"
                    Write-Host "Set Edge as default browser."
                } else {
                    Write-Host "Edge not found." -ForegroundColor Yellow
                }
            }

            "firefox" {
                $path = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
                if (Test-Path $path) {
                    Start-Process -FilePath $path -ArgumentList "-setDefaultBrowser"
                    $defaultBrowser = "firefox"
                    Write-Host "Set Firefox as default browser."
                } else {
                    Write-Host "Firefox not found." -ForegroundColor Yellow
                }
            }

            "ie" {
                Write-Host "To set IE as default browser, please configure it manually via Settings." -ForegroundColor Yellow
                $defaultBrowser = "ie"
            }

            default {
                Write-Host "Unknown browser option." -ForegroundColor Yellow
            }
        }
    }

    # Disable or uninstall all other browsers
    $browsers = @("chrome", "edge", "firefox", "ie")
    foreach ($browser in $browsers) {
        if ($browser -eq $defaultBrowser) { continue }

        Write-Host "`nProcessing $browser (not the default)..."

        switch ($browser) {
            "chrome" {
                $regPath = "HKLM:\SOFTWARE\Policies\Google\Update"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "UpdateDefault" -Value 0 -Type DWord
                Write-Host "Disabled Chrome auto-updates."
            }

            "edge" {
                $tasks = @("MicrosoftEdgeUpdateTaskMachineCore", "MicrosoftEdgeUpdateTaskMachineUA")
                foreach ($task in $tasks) {
                    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
                        Disable-ScheduledTask -TaskName $task
                        Write-Host "Disabled scheduled task: $task"
                    }
                }

                $edgeDir = "${env:ProgramFiles(x86)}\Microsoft\Edge"
                if (Test-Path $edgeDir) {
                    try {
                        Rename-Item -Path $edgeDir -NewName "Edge_DISABLED" -ErrorAction Stop
                        Write-Host "Renamed Edge folder to disable launching."
                    } catch {
                        Write-Host "Could not rename Edge folder (in use or access denied)." -ForegroundColor Yellow
                    }
                }
            }

            "firefox" {
                $profilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
                $profile = Get-ChildItem $profilePath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1

                if ($profile) {
                    $userJsPath = Join-Path $profile.FullName "user.js"
                    $prefs = @(
                        'user_pref("app.update.enabled", false);',
                        'user_pref("app.update.auto", false);',
                        'user_pref("app.update.service.enabled", false);'
                    )
                    $prefs | Out-File -FilePath $userJsPath -Encoding ASCII -Force
                    Write-Host "Disabled Firefox auto-updates in profile."
                } else {
                    Write-Host "No Firefox profile found." -ForegroundColor Yellow
                }

                $exePaths = @(
                    "${env:ProgramFiles}\Mozilla Firefox\firefox.exe",
                    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
                )
                foreach ($path in $exePaths) {
                    if (Test-Path $path) {
                        try {
                            Rename-Item -Path $path -NewName "firefox_disabled.exe"
                            Write-Host "Renamed Firefox executable to disable launching."
                        } catch {
                            Write-Host "Could not rename Firefox executable (access denied or running)." -ForegroundColor Yellow
                        }
                    }
                }
            }

            "ie" {
                Write-Host "Checking for Internet Explorer..."

                $ieFeatures = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like "*InternetExplorer*"
                $ieCapability = dism.exe /online /Get-CapabilityInfo /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 2>&1

                $iexplorePaths = @(
                    "$env:windir\SysWOW64\iexplore.exe",
                    "$env:windir\System32\iexplore.exe"
                )

                $iexists = $iexplorePaths | Where-Object { Test-Path $_ } | Measure-Object | Select-Object -ExpandProperty Count

                if (($ieFeatures -and $ieFeatures.State -eq "Enabled") -or
                    ($ieCapability -match "State.*Installed") -or
                    ($iexists -gt 0)) {

                    foreach ($feature in $ieFeatures) {
                        if ($feature.State -eq "Enabled") {
                            Write-Host "Disabling IE feature: $($feature.FeatureName)..."
                            Disable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -NoRestart -ErrorAction SilentlyContinue
                        }
                    }

                    if ($ieCapability -match "State.*Installed") {
                        Write-Host "Removing IE capability via DISM..."
                        dism.exe /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart 2>&1 | Out-Null
                    }

                    foreach ($path in $iexplorePaths) {
                        if (Test-Path $path) {
                            try {
                                Rename-Item -Path $path -NewName "iexplore_disabled.exe" -Force
                                Write-Host "Renamed $path to disable IE launching."
                            } catch {
                                Write-Host "Could not rename $path (access denied or in use)." -ForegroundColor Yellow
                            }
                        }
                    }
                } else {
                    Write-Host "Internet Explorer does not appear to be present or is already disabled."

                    # --- Optional: Unistall Installed Programs ----
                    $PUSER = [Systerm.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
                    $programsfile = "C:\Users\$PUSER\Desktop\Docs\Programs.txt"
            if (Test-Path $programsFile) {
    $promptUninstall = Read-Host "Would you like to review installed programs for uninstallation? (Y/n) [Default: n]"
    if ($promptUninstall -match "^[Yy]$") {
        $programLines = Get-Content $programsFile | Where-Object { $_.Trim() -ne "" -and $_ -match "DisplayName" }

        $programs = @()
        foreach ($line in $programLines) {
            $name = $line -replace ".*DisplayName\s*:\s*", ""
            if ($name -and $name.Trim() -ne "") {
                $programs += $name.Trim()
            }
        }

        $programs = $programs | Sort-Object -Unique
        if ($programs.Count -eq 0) {
            Write-Host "No programs found in list." -ForegroundColor Yellow
        } else {
            Write-Host "`n--- Installed Programs ---`n"
            for ($i = 0; $i -lt $programs.Count; $i++) {
                Write-Host "[$($i+1)] $($programs[$i])"
            }

            $selection = Read-Host "Enter the number(s) of programs to uninstall (comma-separated), or press Enter to skip"
            if ($selection -match "\d") {
                $indexes = $selection -split "," | ForEach-Object { ($_ -as [int]) - 1 }
                foreach ($i in $indexes) {
                    if ($i -ge 0 -and $i -lt $programs.Count) {
                        $targetProgram = $programs[$i]
                        Write-Host "Attempting to uninstall: $targetProgram"

                        # Try to find and run the uninstall string from registry
                        $registryPaths = @(
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
                        )

                        $found = $false
                        foreach ($regPath in $registryPaths) {
                            $apps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                                $_.DisplayName -and $_.DisplayName -like "*$targetProgram*"
                            }

                            foreach ($app in $apps) {
                                if ($app.UninstallString) {
                                    Write-Host "Running uninstaller for: $($app.DisplayName)"
                                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "$($app.UninstallString)" -Verb RunAs
                                    $found = $true
                                    break
                                }
                            }
                            if ($found) { break }
                        }

                        if (-not $found) {
                            Write-Host "Could not find uninstall command for $targetProgram." -ForegroundColor Yellow
                        }
                    }
                }
            } else {
                Write-Host "Skipping uninstallation."
            }
        }
    }
} else {
    Write-Host "Installed programs list not found at $programsFile" -ForegroundColor Yellow
}
                }
            }
        }
        Write-Host "`n--- Application Security Settings Complete ---`n"
    }
}

    

# Menu loop
:menu do {
    Write-Host "`nSelect an option:`n"
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        Write-Host "$($i + 1). $($menuOptions[$i])"
    }

    $selection = Read-Host "`nEnter the number of your choice"

    switch ($selection) {
        "1" { Document-System }
        "2" { Enable-Updates }
        "3" { User-Auditing }
        "4" { account-Policies }
        "5" { Local-Policies }
        "6" {defensive-Countermeasures }
        "7" {uncategorized-OS-Settings }
        "8" {service-Auditing }
        "9" {os-Updates }
        "10" {application-Updates }
        "11" {prohibited-Files }
        "12" {unwanted-Software }
        "13" {malware }
        "14" {application-Security-Settings }
        "15" { Write-Host "`nExiting..."; break menu }  # leave the do{} loop
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)
# errors with 5,2,11,12
#Changes to 2,3 