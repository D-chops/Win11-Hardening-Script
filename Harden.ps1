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


function Local-Policies {
    Write-Host "`n--- Starting: Local Policies ---`n"

    # Helper function to remove 'Take Ownership' privilege
    function Remove-TakeOwnershipPrivilege {
        Write-Host "Removing 'Take Ownership' privilege from all users..."
        $exportInf = "$env:TEMP\export.inf"
        $modifiedInf = "$env:TEMP\modified.inf"
        $seceditLog = "$env:TEMP\secedit.log"

        try {
            # Export current security policy
            secedit /export /cfg $exportInf /quiet

            # Read the exported INF content
            $content = Get-Content $exportInf

            # Clear the SeTakeOwnershipPrivilege line
            $newContent = $content -replace 'SeTakeOwnershipPrivilege\s*=\s*.*', 'SeTakeOwnershipPrivilege ='

            # Save the modified INF file with Unicode encoding
            $newContent | Set-Content -Path $modifiedInf -Encoding Unicode

            # Apply the modified security policy
            secedit /configure /db secedit.sdb /cfg $modifiedInf /quiet /log $seceditLog

            # Cleanup temporary files
            Remove-Item $exportInf, $modifiedInf -Force -ErrorAction SilentlyContinue

            Write-Host "'Take Ownership' privilege successfully removed from all users."
            Write-Host "Note: A reboot or user logoff/logon may be required for the changes to take effect."
        }
        catch {
            Write-Host "Error removing 'Take Ownership' privilege: $_" -ForegroundColor Red
        }
    }

    # Auditing for Logon Events
    $auditLogon = Read-Host "Enable auditing for Logon Events? (Y/n) [Default: Y]"
    if ($auditLogon -match "^[Yy]$" -or $auditLogon -eq "") {
        Write-Host "Enabling auditing for Logon and Logoff events..."
        try {
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable
            auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
            Write-Host "Auditing for Logon events enabled."
        } catch {
            Write-Host "Failed to enable auditing for Logon events: $_" -ForegroundColor Yellow
        }
    }
    elseif ($auditLogon -match "^[Nn]$") {
        Write-Host "Disabling auditing for Logon and Logoff events..."
        try {
            auditpol /set /subcategory:"Logon" /success:disable /failure:disable
            auditpol /set /subcategory:"Logoff" /success:disable /failure:disable
            Write-Host "Auditing for Logon events disabled."
        } catch {
            Write-Host "Failed to disable auditing for Logon events: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipping auditing changes for Logon events."
    }

    # Remove 'Take Ownership' privilege
    $removeOwnership = Read-Host "Remove the 'Take Ownership' privilege from all users? (Y/n) [Default: Y]"
    if ($removeOwnership -match "^[Yy]$" -or $removeOwnership -eq "") {
        Remove-TakeOwnershipPrivilege
    } else {
        Write-Host "Skipped removal of 'Take Ownership' privilege."
    }

    # Enable/Disable Ctrl+Alt+Del requirement for logon
    $ctrlAltDel = Read-Host "Enable Ctrl+Alt+Del requirement for logon? (Y/n) [Default: Y]"
    $systemPoliciesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $systemPoliciesPath)) {
        New-Item -Path $systemPoliciesPath -Force | Out-Null
    }

    if ($ctrlAltDel -match "^[Yy]$" -or $ctrlAltDel -eq "") {
        Write-Host "Enabling Ctrl+Alt+Del requirement for logon..."
        try {
            Set-ItemProperty -Path $systemPoliciesPath -Name "DisableCAD" -Value 0
            Write-Host "Ctrl+Alt+Del requirement enabled."
        } catch {
            Write-Host "Failed to enable Ctrl+Alt+Del requirement: $_" -ForegroundColor Yellow
        }
    }
    elseif ($ctrlAltDel -match "^[Nn]$") {
        Write-Host "Disabling Ctrl+Alt+Del requirement for logon..."
        try {
            Set-ItemProperty -Path $systemPoliciesPath -Name "DisableCAD" -Value 1
            Write-Host "Ctrl+Alt+Del requirement disabled."
        } catch {
            Write-Host "Failed to disable Ctrl+Alt+Del requirement: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipping Ctrl+Alt+Del requirement changes."
    }

    # PowerShell Execution Policy Handling
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        Write-Host "Current user is an administrator."
        $changePolicy = Read-Host "Change PowerShell execution policy for ALL users? (Y/n) [Default: N]"
        if ($changePolicy -match "^[Yy]$") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
                $effectivePolicy = Get-ExecutionPolicy -Scope LocalMachine
                $currentPolicy = Get-ExecutionPolicy
                if ($effectivePolicy -ne $currentPolicy) {
                    Write-Host "Execution policy set but overridden by another scope."
                    Write-Host "Effective policy: $currentPolicy"
                    Write-Host "Run 'Get-ExecutionPolicy -List' to check policy precedence."
                } else {
                    Write-Host "Execution policy set to 'Restricted' for all users."
                }
            } catch {
                Write-Host "Failed to change execution policy: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipping execution policy change for all users."
        }
    } else {
        $changePolicy = Read-Host "Change your own PowerShell execution policy? (Y/n) [Default: N]"
        if ($changePolicy -match "^[Yy]$") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
                Write-Host "Execution policy set to 'Restricted' for current user."
            } catch {
                Write-Host "Failed to change execution policy: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipping execution policy change for current user."
        }
    }

    Write-Host "`n--- Local Policies Complete ---`n"
}

function User-Auditing {

    # --- Internal function: Prompt user with Yes/No, default No ---
    function Prompt-YesNoDefaultNo {
        param (
            [string]$Message
        )
        $choice = Read-Host "$Message [y/N]"
        return ($choice -match '^(?i)y(es)?$')
    }

    Write-Host "`n=========== LOCAL USER AUDITING ===========`n"

    # Define excluded (built-in) users
    $excludedUsers = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')

    # 1. Audit Local Users
    Write-Host "`n--- Local Users ---`n"
    $localUsers = Get-LocalUser | Where-Object { $_.Name -notin $excludedUsers }

    foreach ($user in $localUsers) {
        Write-Host "User: $($user.Name)"
        if (Prompt-YesNoDefaultNo "Do you want to remove user '$($user.Name)'?") {
            try {
                Remove-LocalUser -Name $user.Name
                Write-Host "Removed user: $($user.Name)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove user: $($user.Name). Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Skipped user: $($user.Name)"
        }
    }

    # 2. Audit Administrators Group Members
    Write-Host "`n--- Administrators Group Members ---`n"
    $adminGroup = 'Administrators'
    $adminMembers = Get-LocalGroupMember -Group $adminGroup

    foreach ($member in $adminMembers) {
        if ($member.ObjectClass -eq 'User') {
            Write-Host "Admin User: $($member.Name)"
            if (Prompt-YesNoDefaultNo "Do you want to remove '$($member.Name)' from Administrators group?") {
                try {
                    Remove-LocalGroupMember -Group $adminGroup -Member $member.Name
                    Write-Host "Removed $($member.Name) from Administrators group" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove $($member.Name). Error: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "Skipped: $($member.Name)"
            }
        }
    }

    # 3. Optionally Add a New Local User
    Write-Host "`n--- Add a New Local User ---`n"
    if (Prompt-YesNoDefaultNo "Would you like to add a new local user?") {
        $newUser = Read-Host "Enter new username"
        $password = Read-Host "Enter password for $newUser" -AsSecureString

        try {
            New-LocalUser -Name $newUser -Password $password -FullName $newUser -Description "Created via user auditing script"
            Write-Host "User '$newUser' created successfully." -ForegroundColor Green

            if (Prompt-YesNoDefaultNo "Add '$newUser' to Administrators group?") {
                Add-LocalGroupMember -Group "Administrators" -Member $newUser
                Write-Host "Added '$newUser' to Administrators group." -ForegroundColor Green
            }
        } catch {
            Write-Host "Failed to create user. Error: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "No user was added."
    }

    Write-Host "`n=========== AUDIT COMPLETE ===========`n"
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

    # Helper function to remove 'Take Ownership' privilege
    function Remove-TakeOwnershipPrivilege {
        Write-Host "Removing 'Take Ownership' privilege from all users..."
        $exportInf = "$env:TEMP\export.inf"
        $modifiedInf = "$env:TEMP\modified.inf"
        $seceditLog = "$env:TEMP\secedit.log"

        try {
            # Export current security policy
            secedit /export /cfg $exportInf /quiet

            # Read the exported INF content
            $content = Get-Content $exportInf

            # Clear the SeTakeOwnershipPrivilege line
            $newContent = $content -replace 'SeTakeOwnershipPrivilege\s*=\s*.*', 'SeTakeOwnershipPrivilege ='

            # Save the modified INF file with Unicode encoding
            $newContent | Set-Content -Path $modifiedInf -Encoding Unicode

            # Apply the modified security policy
            secedit /configure /db secedit.sdb /cfg $modifiedInf /quiet /log $seceditLog

            # Cleanup temporary files
            Remove-Item $exportInf, $modifiedInf -Force -ErrorAction SilentlyContinue

            Write-Host "'Take Ownership' privilege successfully removed from all users."
            Write-Host "Note: A reboot or user logoff/logon may be required for the changes to take effect."
        }
        catch {
            Write-Host "Error removing 'Take Ownership' privilege: $_" -ForegroundColor Red
        }
    }

    # Auditing for Logon Events
    $auditLogon = Read-Host "Enable auditing for Logon Events? (Y/n) [Default: Y]"
    if ($auditLogon -match "^[Yy]$" -or $auditLogon -eq "") {
        Write-Host "Enabling auditing for Logon and Logoff events..."
        try {
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable
            auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
            Write-Host "Auditing for Logon events enabled."
        } catch {
            Write-Host "Failed to enable auditing for Logon events: $_" -ForegroundColor Yellow
        }
    }
    elseif ($auditLogon -match "^[Nn]$") {
        Write-Host "Disabling auditing for Logon and Logoff events..."
        try {
            auditpol /set /subcategory:"Logon" /success:disable /failure:disable
            auditpol /set /subcategory:"Logoff" /success:disable /failure:disable
            Write-Host "Auditing for Logon events disabled."
        } catch {
            Write-Host "Failed to disable auditing for Logon events: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipping auditing changes for Logon events."
    }

    # Remove 'Take Ownership' privilege
    $removeOwnership = Read-Host "Remove the 'Take Ownership' privilege from all users? (Y/n) [Default: Y]"
    if ($removeOwnership -match "^[Yy]$" -or $removeOwnership -eq "") {
        Remove-TakeOwnershipPrivilege
    } else {
        Write-Host "Skipped removal of 'Take Ownership' privilege."
    }

    # Enable/Disable Ctrl+Alt+Del requirement for logon
    $ctrlAltDel = Read-Host "Enable Ctrl+Alt+Del requirement for logon? (Y/n) [Default: Y]"
    $systemPoliciesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $systemPoliciesPath)) {
        New-Item -Path $systemPoliciesPath -Force | Out-Null
    }

    if ($ctrlAltDel -match "^[Yy]$" -or $ctrlAltDel -eq "") {
        Write-Host "Enabling Ctrl+Alt+Del requirement for logon..."
        try {
            Set-ItemProperty -Path $systemPoliciesPath -Name "DisableCAD" -Value 0
            Write-Host "Ctrl+Alt+Del requirement enabled."
        } catch {
            Write-Host "Failed to enable Ctrl+Alt+Del requirement: $_" -ForegroundColor Yellow
        }
    }
    elseif ($ctrlAltDel -match "^[Nn]$") {
        Write-Host "Disabling Ctrl+Alt+Del requirement for logon..."
        try {
            Set-ItemProperty -Path $systemPoliciesPath -Name "DisableCAD" -Value 1
            Write-Host "Ctrl+Alt+Del requirement disabled."
        } catch {
            Write-Host "Failed to disable Ctrl+Alt+Del requirement: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipping Ctrl+Alt+Del requirement changes."
    }

    # PowerShell Execution Policy Handling
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        Write-Host "Current user is an administrator."
        $changePolicy = Read-Host "Change PowerShell execution policy for ALL users? (Y/n) [Default: N]"
        if ($changePolicy -match "^[Yy]$") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
                $effectivePolicy = Get-ExecutionPolicy -Scope LocalMachine
                $currentPolicy = Get-ExecutionPolicy
                if ($effectivePolicy -ne $currentPolicy) {
                    Write-Host "Execution policy set but overridden by another scope."
                    Write-Host "Effective policy: $currentPolicy"
                    Write-Host "Run 'Get-ExecutionPolicy -List' to check policy precedence."
                } else {
                    Write-Host "Execution policy set to 'Restricted' for all users."
                }
            } catch {
                Write-Host "Failed to change execution policy: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipping execution policy change for all users."
        }
    } else {
        $changePolicy = Read-Host "Change your own PowerShell execution policy? (Y/n) [Default: N]"
        if ($changePolicy -match "^[Yy]$") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
                Write-Host "Execution policy set to 'Restricted' for current user."
            } catch {
                Write-Host "Failed to change execution policy: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipping execution policy change for current user."
        }
    }

    Write-Host "`n--- Local Policies Complete ---`n"
}



function Defensive-Countermeasures {
    Write-Host "`n--- Starting: Defensive Countermeasures ---`n" -ForegroundColor $ColorHeader

    try {
        # Function to enable Real-Time Protection including policy fix
        function Enable-DefenderRealTimeProtection {
            $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
            $policyName = "DisableRealtimeMonitoring"

            if (Test-Path $policyPath) {
                $policyValue = Get-ItemProperty -Path $policyPath -Name $policyName -ErrorAction SilentlyContinue

                if ($null -ne $policyValue) {
                    if ($policyValue.$policyName -eq 1) {
                        Write-Host "Group Policy disables Real-Time Protection. Attempting to enable..."
                        try {
                            Set-ItemProperty -Path $policyPath -Name $policyName -Value 0 -ErrorAction Stop
                            Write-Host "Registry updated to allow Real-Time Protection. A reboot or gpupdate may be required."
                        } catch {
                            Write-Host "Failed to update Group Policy registry key: $_"
                            return $false
                        }
                    } else {
                        Write-Host "Group Policy allows Real-Time Protection."
                    }
                } else {
                    Write-Host "No Group Policy disabling Real-Time Protection found."
                }
            } else {
                Write-Host "No Group Policy for Real-Time Protection found."
            }

            # Attempt to enable Real-Time Protection
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                Start-Sleep -Seconds 2
                $rtpStatus = (Get-MpComputerStatus).RealTimeProtectionEnabled
                if ($rtpStatus) {
                    Write-Host "Real-Time Protection successfully enabled."
                    return $true
                } else {
                    Write-Host "Real-Time Protection did NOT enable. Tamper Protection or remaining policies may be blocking it."
                    return $false
                }
            } catch {
                Write-Host "Failed to enable Real-Time Protection: $_"
                return $false
            }
        }

        # Enable Real-Time Protection with policy fix
        Write-Host "Enabling Microsoft Defender Real-Time Protection..." -ForegroundColor $ColorHeader
        Enable-DefenderRealTimeProtection | Out-Null

        # Enable Behavior Monitoring
        Write-Host "Enabling Behavior Monitoring..." -ForegroundColor $ColorHeader
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Write-Host "Behavior Monitoring enabled." -ForegroundColor $ColorKept

        # Enable Cloud Protection
        Write-Host "Enabling Cloud Protection..." -ForegroundColor $ColorHeader
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
        Write-Host "Cloud Protection enabled." -ForegroundColor $ColorKept

        # Enable Automatic Sample Submission
        Write-Host "Enabling Automatic Sample Submission..." -ForegroundColor $ColorHeader
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
        Write-Host "Sample submission enabled." -ForegroundColor $ColorKept

        # Ensure Defender Service is running
        Write-Host "Checking Microsoft Defender service..." -ForegroundColor $ColorHeader
        try {
            $defenderService = Get-Service -Name "WinDefend" -ErrorAction Stop
            if ($defenderService.Status -ne 'Running') {
                Start-Service -Name "WinDefend"
                Write-Host "Microsoft Defender service started." -ForegroundColor $ColorKept
            } else {
                Write-Host "Microsoft Defender service is already running." -ForegroundColor $ColorKept
            }
        } catch {
            Write-Host "Could not start Microsoft Defender service: $_" -ForegroundColor $ColorWarning
        }

        # Update Defender Definitions
        Write-Host "Updating Microsoft Defender definitions..." -ForegroundColor $ColorHeader
        try {
            Update-MpSignature -ErrorAction Stop
            Write-Host "Definitions updated." -ForegroundColor $ColorKept
        } catch {
            Write-Host "Failed to update Defender definitions: $_" -ForegroundColor $ColorWarning
        }

        # Option 1: Block Known Malicious IPs
        $blockIP = Read-Host "Do you want to block known malicious IP addresses? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
        if ($blockIP -match "^[Yy]$" -or $blockIP -eq "") {
            Write-Host "Blocking access to known malicious IP addresses..." -ForegroundColor $ColorHeader
            $blockedIPs = @("192.168.1.100", "203.0.113.45")  # Add known malicious IPs
            foreach ($ip in $blockedIPs) {
                New-NetFirewallRule -DisplayName "Block Malware IP: $ip" -Direction Outbound -Action Block -RemoteAddress $ip -ErrorAction SilentlyContinue
                Write-Host "Blocked IP: $ip" -ForegroundColor $ColorRemoved
            }
        }

        # Option 2: Disable Unsafe File Types (Script Execution)
        $disableFileTypes = Read-Host "Do you want to disable unsafe file types from running? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
        if ($disableFileTypes -match "^[Yy]$" -or $disableFileTypes -eq "") {
            Write-Host "Setting execution policy to 'Restricted'..." -ForegroundColor $ColorHeader
            try {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
                Write-Host "Execution policy set to 'Restricted'." -ForegroundColor $ColorKept
            } catch {
                Write-Host "Failed to set execution policy: $_" -ForegroundColor $ColorWarning
            }
        }

        # Option 3: Monitor & Block Registry Changes
        $monitorRegistry = Read-Host "Do you want to block registry changes by malware? (Y/n) [Default: Y]" -ForegroundColor $ColorPrompt
        if ($monitorRegistry -match "^[Yy]$" -or $monitorRegistry -eq "") {
            Write-Host "Blocking registry tools for malware defense..." -ForegroundColor $ColorHeader
            try {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null
                Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableRegistryTools" -Value 1
                Write-Host "Registry editing disabled." -ForegroundColor $ColorKept
            } catch {
                Write-Host "Failed to disable registry tools: $_" -ForegroundColor $ColorWarning
            }
        }

    } catch {
        Write-Host "An unexpected error occurred: $_" -ForegroundColor Red
    }

    Write-Host "`n--- Defensive Countermeasures Complete ---`n" -ForegroundColor $ColorHeader
}

function Uncategorized-OS-Settings {
    Write-Host "`n--- Starting: Uncategorized OS Settings ---`n"

    # Option 1: Disable file sharing on C: drive
    $disableSharing = Read-Host "Would you like to disable file sharing for the C: drive? (Y/n) [Default: n]"
    if ($disableSharing -match "^[Yy]$") {
        try {
            # Remove existing shares for C: drive (e.g. "C$", "C")
            $shares = Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Path -like "C:\*" }
            foreach ($share in $shares) {
                Write-Host "Removing share: $($share.Name) for path $($share.Path)"
                $result = (Get-CimInstance -ClassName Win32_Share -Filter "Name='$($share.Name)'").Delete()
                if ($result.ReturnValue -eq 0) {
                    Write-Host "Successfully removed share $($share.Name)." -ForegroundColor Green
                } else {
                    Write-Host "Failed to remove share $($share.Name). Return code: $($result.ReturnValue)" -ForegroundColor Yellow
                }
            }

            Write-Host "File sharing for C: drive disabled (shares removed)." -ForegroundColor Green
        } catch {
            Write-Host "Error disabling file sharing: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipping disabling file sharing for C: drive." -ForegroundColor Cyan
    }

    # Option 2: Disable Remote Assistance connections
    $disableRA = Read-Host "Would you like to disable Remote Assistance connections? (Y/n) [Default: n]"
    if ($disableRA -match "^[Yy]$") {
        try {
            # Disable Remote Assistance via registry
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }

            Set-ItemProperty -Path $regPath -Name "fAllowToGetHelp" -Value 0 -Type DWord
            Set-ItemProperty -Path $regPath -Name "fAllowFullControl" -Value 0 -Type DWord
            Set-ItemProperty -Path $regPath -Name "fAllowUnsolicited" -Value 0 -Type DWord

            Write-Host "Remote Assistance connections have been disabled." -ForegroundColor Green
        } catch {
            Write-Host "Error disabling Remote Assistance: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipping disabling Remote Assistance." -ForegroundColor Cyan
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




function Prohibited-Files {
    param (
        [string]$SearchPath = "C:\",   # Default search root
        [string]$FileName = "users.txt"
    )

    Write-Host "`n--- Starting: Remove Prohibited Files ---`n"

    try {
        # Find all instances of the prohibited file
        $files = Get-ChildItem -Path $SearchPath -Filter $FileName -Recurse -ErrorAction SilentlyContinue

        if ($files.Count -eq 0) {
            Write-Host "No prohibited files named '$FileName' found in $SearchPath." -ForegroundColor Green
        } else {
            foreach ($file in $files) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    Write-Host "Removed prohibited file: $($file.FullName)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove file: $($file.FullName). Error: $_" -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "An error occurred while searching/removing files: $_" -ForegroundColor Red
    }

    Write-Host "`n--- Remove Prohibited Files Complete ---`n"
}

function Unwanted-Software {
    Write-Host "`n--- Starting: Unwanted Software Removal ---`n"

    # List of unwanted executable filenames (you can add more patterns here)
    $unwantedFiles = @(
        "Everything.exe",
        "Angry IP Scanner.exe",
        "AngryIPScanner.exe",
        "AngryIPScannerPortable.exe"
    )

    # Define drives to scan (C: and any others)
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 } | Select-Object -ExpandProperty Root

    foreach ($drive in $drives) {
        Write-Host "Scanning drive $drive for unwanted files..."

        foreach ($filePattern in $unwantedFiles) {
            try {
                $foundFiles = Get-ChildItem -Path $drive -Filter $filePattern -Recurse -ErrorAction SilentlyContinue -Force

                foreach ($file in $foundFiles) {
                    Write-Host "Found unwanted file: $($file.FullName)"
                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        Write-Host "Removed file: $($file.FullName)" -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to remove $($file.FullName): $_" -ForegroundColor Red
                    }
                }
                if (-not $foundFiles) {
                    Write-Host "No files found matching pattern '$filePattern' on drive $drive."
                }
            } catch {
                Write-Host "Error searching for files '$filePattern' on drive $drive : $_" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n--- Unwanted Software File Removal Complete ---`n"
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
#3 needs to downgrade scream
