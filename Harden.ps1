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
    "exit"
    )
    # Define functions for each option
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
}
function User-Auditing {
    Write-Host "`n--- Starting: User Auditing ---`n"

    # Get local user accounts
    $localUsers = Get-LocalUser

    foreach ($user in $localUsers) {
        # Skip default or built-in accounts if you want (optional)
        if ($user.Name -in @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")) {
            continue
        }

        # Prompt for confirmation
        $response = Read-Host "Is '$($user.Name)' an Authorized User? (Y/n) [Default: Y]"

        if ($response -eq "" -or $response -match "^[Yy]$") {
            Write-Host "'$($user.Name)' marked as Authorized.`n"
        } elseif ($response -match "^[Nn]$") {
            try {
                Remove-LocalUser -Name $user.Name -ErrorAction Stop
                Write-Host "'$($user.Name)' has been removed.`n"
            } catch {
                Write-Host "Error removing '$($user.Name)': $_`n"
            }
        } else {
            Write-Host "Invalid input. Skipping user '$($user.Name)'.`n"
        }
    }
if (
    $user.Name -in @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount") -or 
    $user.Name -eq $env:USERNAME
) {
    continue
}
    Write-Host "`n--- User Auditing Complete ---`n"
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
        "4" { Write-Host "`nExiting..."; break menu }  # leave the do{} loop
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)