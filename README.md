 Write-Host "`n--- Restricting execution of untrusted applications for non-admin users ---"
         # Apply the execution policy restriction for non-admin users
    try {
        # Set the execution policy to 'Restricted' for all users (non-admins will be affected by this)
        Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
        Write-Host "Execution Policy set to Restricted for all non-admin users."
    }
    catch {
        Write-Host "Failed to set execution policy: $_" -ForegroundColor Red
    }
    