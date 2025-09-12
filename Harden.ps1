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

# Define menu options
$menuOptions = @(
    "document the system",
    "enable updates",
    "user auditing",
    "Admin Auditing",
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
# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"

# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"

# Display the Windows version
Write-Host "Windows Version:"
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
Write-Host "Script Run Time: $(Get-Date)"

function Document-System {
    Write-Host "`n--- Starting: Document the system ---`n"
$PUSER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
$folderPath = "C:\Users\$PUSER\Desktop\DOCS"

if (-not (Test-Path -Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory | Out-Null
    Write-Host "Created folder: $folderPath"
} else {
    Write-Host "Folder already exists: $folderPath"
}
$PUSER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
$DOCS = "C:\Users\$PUSER\Desktop\DOCS"
Get-LocalUser | Out-File -FilePath "$DOCS\LocalUsers.txt"
# Save list of administrators
Get-LocalGroupMember -Group 'Administrators' | Out-File -FilePath "$DOCS\administrators.txt"

# Save list of installed programs
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Out-File -FilePath "$DOCS\programs.txt"

# Save list of running services
Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File -FilePath "$DOCS\services.txt"

# Save list of installed Windows optional features (Windows 10/11)
Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Out-File -FilePath "$DOCS\features.txt"

# Export security configuration
secedit /export /cfg "$DOCS\secedit-export.inf"

# Save Windows Defender preferences
Get-MpPreference | Out-File -FilePath "$DOCS\defender.txt"

# Save list of scheduled tasks
Get-ScheduledTask | Out-File -FilePath "$DOCS\scheduled-tasks.txt"
}
function Enable-Updates {
    Write-Host "`n--- Starting: Enable updates ---`n"
}
function Review-GroupMembers {
    param (
        [Parameter(Mandatory=$true)]
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
            } catch {
                Write-Host "Failed to remove '$($member.Name)': $_" -ForegroundColor $ColorWarning
            }
        } else {
            Write-Host "'$($member.Name)' kept in '$GroupName'." -ForegroundColor $ColorKept
        }
    }
    Write-Host "`nReview complete for group: $GroupName" -ForegroundColor $ColorHeader
}
function User-Auditing {
    Write-Host "`n--- Starting: User Auditing ---`n"

    # Loop through every local user account and prompt for authorization
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
            New-LocalUser -Name $newUserName -Password (ConvertTo-SecureString $newUserPassword -AsPlainText -Force) -UserMayChangePassword $true -PasswordNeverExpires $false
            Write-Host "User '$newUserName' created successfully."
        } catch {
            Write-Host "Failed to create user '$newUserName': $_"
        }
    }

    foreach ($user in $localUsers) {
        try {
            # Set password to $TempPassword
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $TempPassword -AsPlainText -Force)
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            Set-LocalUser -Name $user.Name -UserMayChangePassword $true
        } catch {
            Write-Host "Failed to update password for '$($user.Name)': $_"
        }
    }

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

    $localUsers = Get-LocalUser
    foreach ($user in $localUsers) {
        try {
        New-LocalUser -Name $newUserName -Password (ConvertTo-SecureString $newUserPassword -AsPlainText -Force)
        # Set properties after creation
        Set-LocalUser -Name $newUserName -UserMayChangePassword $true
        Set-LocalUser -Name $newUserName -PasswordNeverExpires $false
        Write-Host "User '$newUserName' created successfully."
    } catch {
        Write-Host "Failed to create user '$newUserName': $_"
    }
    }
    Write-Host "All users set: Password expires, User may change password."
    Write-Host "Passwords for all users set to temporary value and will require change at next logon."
    Write-Host "`n--- User Auditing Complete --"
}

function Admin-Auditing {
    Write-Host "`n--- Starting: Admin Auditing ---`n"
    Review-GroupMembers -GroupName 'Administrators'
    Review-GroupMembers -GroupName 'Backup Operators'
    Review-GroupMembers -GroupName 'Remote Management Users'
    Review-GroupMembers -GroupName 'Event Log Readers'

    # Loop through all users with Administrator permissions
$adminGroup = Get-LocalGroupMember -Group 'Administrators'
foreach ($admin in $adminGroup) {
    $default = 'Y'
    $prompt = "Is '$($admin.Name)' an Authorized Administrator? [Y/n]: "
    $answer = Read-Host -Prompt $prompt
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $default }
    if ($answer -match '^[Nn]$') {
        Write-Host "Removing '$($admin.Name)' from Administrators group"
        Remove-LocalGroupMember -Group 'Administrators' -Member $admin.Name
    }
}
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
function local-Policies {
     Write-Host "`n--- Exporting and Hardening User Rights Assignments ---`n"
    
        # Paths
        $secpolInf = ".\secpol.inf"
        $backupInf = ".\secpol-backup.inf"
        $localSdb  = "C:\Windows\Security\local.sdb"
    
        # Backup current local security database
        Copy-Item -Path $localSdb -Destination $backupInf -ErrorAction SilentlyContinue
        Write-Host "Backup of local security database saved to $backupInf"
    
        # Export current security policy to INF
        secedit /export /cfg $secpolInf
    
        # Harden user rights assignments
        $content = Get-Content $secpolInf
    
        $content = $content `
            -replace '^.*SeTakeOwnershipPrivilege.*$',         'SeTakeOwnershipPrivilege = *S-1-5-32-544' `
            -replace '^.*SeTrustedCredManAccessPrivilege.*$',  'SeTrustedCredManAccessPrivilege = *S-1-5-32-544' `
            -replace '^.*SeDenyNetworkLogonRight.*$',          'SeDenyNetworkLogonRight = *S-1-1-0,*S-1-5-32-546' `
            -replace '^.*SeCreateTokenPrivilege.*$',           'SeCreateTokenPrivilege = *S-1-5-32-544' `
            -replace '^.*SeCreateGlobalPrivilege.*$',          'SeCreateGlobalPrivilege = *S-1-5-32-544' `
            -replace '^.*SeRemoteShutdownPrivilege.*$',        'SeRemoteShutdownPrivilege = *S-1-5-32-544' `
            -replace '^.*SeLoadDriverPrivilege.*$',            'SeLoadDriverPrivilege = *S-1-5-32-544' `
            -replace '^.*SeSecurityPrivilege.*$',              'SeSecurityPrivilege = *S-1-5-32-544'
    
        Set-Content -Path $secpolInf -Value $content
        Write-Host "User rights assignments updated in $secpolInf"
    
        # Import the modified policy and overwrite the database
        echo y | secedit /configure /db $localSdb /cfg $secpolInf /overwrite
    
        Write-Host "`n--- User Rights Hardening Complete ---`n"
    
        # Optional: Verify changes
        secedit /export /cfg ".\verify.inf"
        Write-Host "Verification lines:"
        Select-String -Path ".\verify.inf" -Pattern '^SeTakeOwnershipPrivilege|^SeTrustedCredManAccessPrivilege|^SeDenyNetworkLogonRight|^SeCreateTokenPrivilege|^SeCreateGlobalPrivilege|^SeRemoteShutdownPrivilege|^SeLoadDriverPrivilege|^SeSecurityPrivilege'
      }
        function defensive-Countermeasures {
    Write-Host "`n--- Starting: Defensive Countermeasures ---`n"
}
function uncategorized-OS-Settings {
    Write-Host "`n--- Starting: Uncategorized OS Settings ---`n"
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
    }
function os-Updates {
    Write-Host "`n--- Starting: OS Updates ---`n"

    # Check for Windows updates using PowerShell Update module (if available)
    try {
        # Install PSWindowsUpdate module if not present
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "Installing PSWindowsUpdate module..."
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        }

        Import-Module PSWindowsUpdate

        # List available updates
        Write-Host "Checking for available Windows updates..."
        Get-WindowsUpdate

        # Install all available updates
        Write-Host "Installing all available Windows updates..."
        Install-WindowsUpdate -AcceptAll -AutoReboot

    } catch {
        Write-Host "Failed to run Windows updates: $_" -ForegroundColor $ColorWarning
    }

    # Update Windows Defender signatures (if Defender is present)
    try {
        Write-Host "Updating Windows Defender signatures..."
        Update-MpSignature
    } catch {
        Write-Host "Failed to update Windows Defender signatures: $_" -ForegroundColor $ColorWarning
    }
}

    Write-Host "`n--- OS Updates Complete ---"
function application-Updates {
    Write-Host "`n--- Starting: Application Updates (Default Browser) ---`n"

    # Detect default browser from registry
    try {
        $browserProgId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId
        switch ($browserProgId) {
            "ChromeHTML" {
                Write-Host "Detected default browser: Google Chrome"
                $chromePath = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                if (Test-Path $chromePath) {
                    Write-Host "Running Chrome update..."
                    Start-Process -FilePath $chromePath -ArgumentList "--check-for-update-interval=1" -WindowStyle Hidden
                } else {
                    Write-Host "Chrome executable not found." -ForegroundColor $ColorWarning
                }
            }
            "MSEdgeHTM" {
                Write-Host "Detected default browser: Microsoft Edge"
                $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
                if (Test-Path $edgePath) {
                    Write-Host "Running Edge update..."
                    Start-Process -FilePath $edgePath -ArgumentList "--check-for-update-interval=1" -WindowStyle Hidden
                } else {
                    Write-Host "Edge executable not found." -ForegroundColor $ColorWarning
                }
            }
            "FirefoxURL" {
                Write-Host "Detected default browser: Mozilla Firefox"
                $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
                if (Test-Path $firefoxPath) {
                    Write-Host "Running Firefox update..."
                    Start-Process -FilePath $firefoxPath -ArgumentList "-headless -update" -WindowStyle Hidden
                } else {
                    Write-Host "Firefox executable not found." -ForegroundColor $ColorWarning
                }
            }
            default {
                Write-Host "Default browser not recognized or not supported for auto-update." -ForegroundColor $ColorWarning
            }
        }
    } catch {
        Write-Host "Could not detect default browser or run update: $_" -ForegroundColor $ColorWarning
    }
}

    Write-Host "`n--- Application Updates Complete ---`n"
function prohibited-Files {
    Write-Host "`n--- Starting: Prohibited Files ---`n"
}
function unwanted-Software {
    Write-Host "`n--- Starting: Unwanted Software ---`n"
}
function malware {
    Write-Host "`n--- Starting: Malware ---`n"
}
function application-Security-Settings {
    Write-Host "`n--- Starting: Application Security Settings ---`n"

    # Detect default browser from registry
    try {
        $browserProgId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId
        switch ($browserProgId) {
            "ChromeHTML"   { $defaultBrowser = "chrome" }
            "MSEdgeHTM"    { $defaultBrowser = "edge" }
            "FirefoxURL"   { $defaultBrowser = "firefox" }
            default        { $defaultBrowser = $null }
        }
    } catch {
        Write-Host "Could not detect default browser: $_" -ForegroundColor $ColorWarning
        $defaultBrowser = $null
    }

    Write-Host "Current default browser: $defaultBrowser"

    # Option to change default browser before uninstall
    $changeDefault = Read-Host "Would you like to change the default browser? (Y/n) [Default: n]"
    if ($changeDefault -match "^[Yy]$") {
        Write-Host "Options: chrome, edge, firefox"
        $newDefault = Read-Host "Enter the browser to set as default"
        switch ($newDefault.ToLower()) {
            "chrome" {
                $chromePath = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                if (Test-Path $chromePath) {
                    Start-Process -FilePath $chromePath -ArgumentList "--make-default-browser"
                    $defaultBrowser = "chrome"
                    Write-Host "Set Chrome as default browser."
                } else {
                    Write-Host "Chrome not found." -ForegroundColor $ColorWarning
                }
            }
            "edge" {
                $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
                if (Test-Path $edgePath) {
                    Start-Process -FilePath $edgePath -ArgumentList "--make-default-browser"
                    $defaultBrowser = "edge"
                    Write-Host "Set Edge as default browser."
                } else {
                    Write-Host "Edge not found." -ForegroundColor $ColorWarning
                }
            }
            "firefox" {
                $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
                if (Test-Path $firefoxPath) {
                    Start-Process -FilePath $firefoxPath -ArgumentList "-setDefaultBrowser"
                    $defaultBrowser = "firefox"
                    Write-Host "Set Firefox as default browser."
                } else {
                    Write-Host "Firefox not found." -ForegroundColor $ColorWarning
                }
            }
            default {
                Write-Host "Unknown browser option." -ForegroundColor $ColorWarning
            }
        }
    }

    # Uninstall all browsers except the default
    $browsers = @{
        "chrome"  = "Google Chrome"
        "edge"    = "Microsoft Edge"
        "firefox" = "Mozilla Firefox"
    }

    foreach ($browser in $browsers.Keys) {
        if ($browser -ne $defaultBrowser) {
            Write-Host "Attempting to uninstall $($browsers[$browser])..."
            switch ($browser) {
                "chrome" {
                    $chromeUninstall = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                    if (Test-Path $chromeUninstall) {
                        Start-Process -FilePath $chromeUninstall -ArgumentList "--uninstall --force-uninstall" -Wait
                        Write-Host "Google Chrome uninstall command executed."
                    } else {
                        Write-Host "Google Chrome not found." -ForegroundColor $ColorWarning
                    }
                }
                "edge" {
                    $edgeUninstall = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\Installer\setup.exe"
                    if (Test-Path $edgeUninstall) {
                        Start-Process -FilePath $edgeUninstall -ArgumentList "--uninstall --system-level --force-uninstall" -Wait
                        Write-Host "Microsoft Edge uninstall command executed."
                    } else {
                        Write-Host "Microsoft Edge uninstaller not found." -ForegroundColor $ColorWarning
                    }
                }
                "firefox" {
                    $firefoxUninstall = "${env:ProgramFiles}\Mozilla Firefox\uninstall\helper.exe"
                    if (Test-Path $firefoxUninstall) {
                        Start-Process -FilePath $firefoxUninstall -ArgumentList "/S" -Wait
                        Write-Host "Mozilla Firefox uninstall command executed."
                    } else {
                        Write-Host "Mozilla Firefox uninstaller not found." -ForegroundColor $ColorWarning
                    }
                }
            }
        }
    }
}

    Write-Host "`n--- Application Security Settings Complete ---`n"

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
        "4" { Admin-Auditing }
        "5" {account-Policies }
        "6" {local-Policies }
        "7" {defensive-Countermeasures }
        "8" {uncategorized-OS-Settings }
        "9" {service-Auditing }
        "10" {os-Updates }
        "11" {application-Updates }
        "12" {prohibited-Files }
        "13" {unwanted-Software }
        "14" {malware }
        "15" {application-Security-Settings }
        "16" { Write-Host "`nExiting..."; break menu }  # leave the do{} loop
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)
