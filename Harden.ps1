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
            # Ask if user should be upgraded to admin
            $adminResponse = Read-Host "Should '$($user.Name)' be upgraded to Administrator? (Y/n) [Default: n]"
            if ($adminResponse -match "^[Yy]$") {
                try {
                    Add-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
                    Write-Host "'$($user.Name)' added to Administrators group." -ForegroundColor $ColorKept
                } catch {
                    Write-Host "Failed to add '$($user.Name)' to Administrators: $_" -ForegroundColor $ColorWarning
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

    # Set password for all users to $TempPassword and require change at next logon
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

    # Enforce password expiration and allow password change for all users
    $localUsers = Get-LocalUser
    foreach ($user in $localUsers) {
        try {
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            Set-LocalUser -Name $user.Name -UserMayChangePassword $true
        } catch {
            Write-Host "Failed to update '$($user.Name)': $_"
        }
    }
    Write-Host "All users set: Password expires, user may change password."
    Write-Host "`n--- User and Admin Auditing Complete ---`n"
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

    try {
        # Enable Real-time Protection
        Write-Host "Enabling Microsoft Defender Real-Time Protection..."
        Set-MpPreference -DisableRealtimeMonitoring $false

        # Enable Behavior Monitoring
        Write-Host "Enabling Behavior Monitoring..."
        Set-MpPreference -DisableBehaviorMonitoring $false

        # Enable Cloud Protection
        Write-Host "Enabling Cloud Protection..."
        Set-MpPreference -DisableBlockAtFirstSeen $false

        # Enable Automatic Sample Submission
        Write-Host "Enabling Automatic Sample Submission..."
        Set-MpPreference -SubmitSamplesConsent 2  # 2 = Send safe samples automatically

        # Start Defender service (skip changing startup type due to permissions)
        try {
            $defenderService = Get-Service -Name "WinDefend" -ErrorAction Stop
            if ($defenderService.Status -ne 'Running') {
                Write-Host "Starting Microsoft Defender service..."
                Start-Service -Name "WinDefend"
            } else {
                Write-Host "Microsoft Defender service already running."
            }
        } catch {
            Write-Warning "Could not start or manage Microsoft Defender service: $_"
        }

        # Update Microsoft Defender definitions
        Write-Host "Updating Microsoft Defender antivirus definitions..."
        Update-MpSignature -ErrorAction Stop

        Write-Host "`nMicrosoft Defender is enabled and updated successfully."

    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }

    Write-Host "`n--- Defensive Countermeasures Complete ---`n"
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
        $progId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId
        switch ($progId) {
            "ChromeHTML" { $defaultBrowser = "chrome" }
            "MSEdgeHTM" { $defaultBrowser = "edge" }
            "FirefoxURL" { $defaultBrowser = "firefox" }
            "IE.HTTP" { $defaultBrowser = "ie" }
            default { $defaultBrowser = $null }
        }
    } catch {
        Write-Host "Could not detect default browser: $_" -ForegroundColor Yellow
        $defaultBrowser = $null
    }

    Write-Host "Current default browser: $defaultBrowser"

    # Option to change default browser before disabling others
    $changeDefault = Read-Host "Would you like to change the default browser? (Y/n) [Default: n]"
    if ($changeDefault -match "^[Yy]$") {
        Write-Host "Options: chrome, edge, firefox, ie"
        $newDefault = Read-Host "Enter the browser to set as default"
        switch ($newDefault.ToLower()) {
            "chrome" {
                $chromePath = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                if (Test-Path $chromePath) {
                    Start-Process -FilePath $chromePath -ArgumentList "--make-default-browser"
                    $defaultBrowser = "chrome"
                    Write-Host "Set Chrome as default browser."
                } else {
                    Write-Host "Chrome not found." -ForegroundColor Yellow
                }
            }
            "edge" {
                $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
                if (Test-Path $edgePath) {
                    Start-Process -FilePath $edgePath -ArgumentList "--make-default-browser"
                    $defaultBrowser = "edge"
                    Write-Host "Set Edge as default browser."
                } else {
                    Write-Host "Edge not found." -ForegroundColor Yellow
                }
            }
            "firefox" {
                $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
                if (Test-Path $firefoxPath) {
                    Start-Process -FilePath $firefoxPath -ArgumentList "-setDefaultBrowser"
                    $defaultBrowser = "firefox"
                    Write-Host "Set Firefox as default browser."
                } else {
                    Write-Host "Firefox not found." -ForegroundColor Yellow
                }
            }
            "ie" {
                # IE does not have a simple command line for default browser, suggest manual
                Write-Host "To set IE as default browser, please configure via Settings manually." -ForegroundColor Yellow
                $defaultBrowser = "ie"
            }
            default {
                Write-Host "Unknown browser option." -ForegroundColor Yellow
            }
        }
    }

    # Disable all other browsers (instead of uninstalling)
    $browsers = @("chrome", "edge", "firefox", "ie")
    foreach ($browser in $browsers) {
        if ($browser -ne $defaultBrowser) {
            Write-Host "Disabling $browser since it's not the default..."

            switch ($browser) {
                "chrome" {
                    # Disable Chrome auto-updates via registry policy
                    $chromeRegPath = "HKLM:\SOFTWARE\Policies\Google\Update"
                    if (-not (Test-Path $chromeRegPath)) {
                        New-Item -Path $chromeRegPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $chromeRegPath -Name "UpdateDefault" -Value 0 -Type DWord
                    Write-Host "Disabled Chrome auto-updates."
                }

                "edge" {
                    # Disable Edge update tasks
                    $tasks = @(
                        "MicrosoftEdgeUpdateTaskMachineCore",
                        "MicrosoftEdgeUpdateTaskMachineUA"
                    )
                    foreach ($task in $tasks) {
                        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
                            Disable-ScheduledTask -TaskName $task
                            Write-Host "Disabled scheduled task: $task"
                        }
                    }

                    # Attempt to rename Edge folder (if allowed)
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
                    $profile = Get-ChildItem $profilePath -Directory | Select-Object -First 1
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

                    # Try renaming Firefox executable to prevent launching
                    $firefoxExePaths = @(
                        "${env:ProgramFiles}\Mozilla Firefox\firefox.exe",
                        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
                    )
                    foreach ($path in $firefoxExePaths) {
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
                    # Disable IE via Windows Feature
                    $featureName = "Internet-Explorer-Optional-amd64"
                    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
                    if ($feature -and $feature.State -eq "Enabled") {
                        Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart
                        Write-Host "Disabled Internet Explorer feature."
                    } else {
                        Write-Host "Internet Explorer feature already disabled or not found."
                    }

                    # Try renaming iexplore.exe (usually in SysWOW64 and System32)
                    $iePaths = @(
                        "$env:windir\SysWOW64\iexplore.exe",
                        "$env:windir\System32\iexplore.exe"
                    )
                    foreach ($iePath in $iePaths) {
                        if (Test-Path $iePath) {
                            try {
                                Rename-Item -Path $iePath -NewName "iexplore_disabled.exe"
                                Write-Host "Renamed iexplore.exe to disable launching."
                            } catch {
                                Write-Host "Could not rename iexplore.exe (access denied or running)." -ForegroundColor Yellow
                            }
                        }
                    }
                }
            }
        }
    }

    Write-Host "`n--- Application Security Settings Complete ---`n"
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
        "4" {account-Policies }
        "5" {local-Policies }
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
