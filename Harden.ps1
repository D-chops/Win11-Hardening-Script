# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"
# Display the windows version
Write-Host "Windows Version"
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
Write-Host "Script Run Time: $(Get-Date)"