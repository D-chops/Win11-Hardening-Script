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

    Write-Host "`n--- User Auditing Complete ---`n"
}
function Admin-Auditing {
    Write-Host "`n--- Starting: Admin Auditing ---`n"

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
function account-Policies {
    Write-Host "`n--- Starting: Account-Policies ---`n"
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