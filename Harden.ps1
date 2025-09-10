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
function Document-System {
    Write-Host "`n--- Starting: Document the system ---`n"
}
# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"

# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"

# Display the Windows version
Write-Host "Windows Version:"
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
Write-Host "Script Run Time: $(Get-Date)"

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
        # Ensure password expires
        Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
        # Ensure user can change password
        Set-LocalUser -Name $user.Name -UserMayChangePassword $true
    } catch {
        Write-Host "Failed to update '$($user.Name)': $_"
    }
}
Write-Host "All users set: Password expires, User may change password."
Write-Host "Passwords for all users set to temporary value and will require change at next logon."
    
    Write-Host "`n--- User Auditing Complete ---`n"
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
    Write-Host "`n--- Starting: Local Policies ---`n"
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
}
function application-Updates {
    Write-Host "`n--- Starting: Application Updates ---`n"
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
