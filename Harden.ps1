<#
.SYNOPSIS
    System Configuration and Auditing Menu
#>

# -------------------------------
# MENU OPTIONS
# -------------------------------
$menuOptions = @(
    "Document the System",
    "Enable Updates",
    "User Auditing",
    "Account Policies",
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
    "Exit"
)

# -------------------------------
# FUNCTIONS
# -------------------------------

function Show-Menu {
    Clear-Host
    Write-Host "========================================="
    Write-Host "         System Configuration Menu        "
    Write-Host "========================================="
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        Write-Host "$($i + 1). $($menuOptions[$i])"
    }
}

# ===========================================================
# MODULE FUNCTION: Document the System
# ===========================================================
function Document-System {
    Write-Host "========================================="
    Write-Host "        SYSTEM DOCUMENTATION MODULE"
    Write-Host "========================================="

    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $outputFile = ".\SystemDocumentation_$timestamp.txt"

        Write-Host "`nGenerating system documentation report..."
        Write-Host "Output file: $outputFile"

        $report = @()

        $report += "=== SYSTEM INFORMATION ==="
        $os = Get-CimInstance Win32_OperatingSystem
        $report += "Computer Name : $env:COMPUTERNAME"
        $report += "User Name     : $env:USERNAME"
        $report += "OS Version    : $($os.Caption)"
        $report += "OS Build      : $($os.BuildNumber)"
        $report += ""

        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
        $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
                Select-Object DeviceID, @{Name="Size(GB)";Expression={[math]::Round($_.Size / 1GB, 2)}},
                              @{Name="Free(GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}

        $report += "=== HARDWARE SUMMARY ==="
        $report += "CPU : $cpu"
        $report += "RAM : $ramGB GB"
        $report += ""
        $report += "Disk Information:"
        $report += ($disk | Out-String)
        $report += ""

        $ipConfig = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1" }
        $report += "=== NETWORK CONFIGURATION ==="
        $report += ($ipConfig | Select-Object InterfaceAlias, IPAddress | Out-String)
        $report += ""

        $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
        $report += "=== RECENT UPDATES (Last 5) ==="
        $report += ($updates | Out-String)
        $report += ""

        $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon
        $report += "=== LOCAL USERS ==="
        $report += ($users | Out-String)
        $report += ""

        $services = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType
        $report += "=== RUNNING SERVICES ==="
        $report += ($services | Out-String)
        $report += ""

        $report | Out-File -FilePath $outputFile -Encoding UTF8

        Write-Host "`nSystem documentation completed successfully." -ForegroundColor Green
        Write-Host "Report saved to: $outputFile"
    }
    catch {
        Write-Host "`n[!] An error occurred while documenting the system:" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
    finally {
        Write-Host "`nReturning to main menu..."
        Start-Sleep -Seconds 2
    }
}

# -------------------------------
# MAIN LOOP
# -------------------------------
do {
    Show-Menu
    $choice = Read-Host "`nEnter your choice (1-$($menuOptions.Count))"

    switch ($choice) {
        1  { Document-System }
        2  { Write-Host "Enable Updates - coming soon..." }
        3  { Write-Host "User Auditing - coming soon..." }
        4  { Write-Host "Account Policies - coming soon..." }
        5  { Write-Host "Local Policies - coming soon..." }
        6  { Write-Host "Defensive Countermeasures - coming soon..." }
        7  { Write-Host "Uncategorized OS Settings - coming soon..." }
        8  { Write-Host "Service Auditing - coming soon..." }
        9  { Write-Host "OS Updates - coming soon..." }
        10 { Write-Host "Application Updates - coming soon..." }
        11 { Write-Host "Prohibited Files - coming soon..." }
        12 { Write-Host "Unwanted Software - coming soon..." }
        13 { Write-Host "Malware - coming soon..." }
        14 { Write-Host "Application Security Settings - coming soon..." }
        15 { Write-Host "Exiting script..."; break }
        Default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red }
    }

    if ($choice -ne 15) {
        Write-Host "`nPress any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

} while ($choice -ne 15)
