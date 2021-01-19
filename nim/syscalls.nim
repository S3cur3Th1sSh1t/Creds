{.passC:"-masm=intel".}

type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST


proc NtAllocateVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                 
NtAllocateVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtAllocateVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtAllocateVirtualMemory_Check_10_0_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtAllocateVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtAllocateVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtAllocateVirtualMemory_SystemCall_6_1_7601
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtAllocateVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtAllocateVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtAllocateVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtAllocateVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtAllocateVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtAllocateVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtAllocateVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtAllocateVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtAllocateVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtAllocateVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtAllocateVirtualMemory_SystemCall_10_0_19042
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x0015
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x0015
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x0016
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x0017
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x0018
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_Unknown:           
	ret
NtAllocateVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtClose*(Handle: HANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                 
NtClose_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtClose_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtClose_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtClose_SystemCall_10_0_19042
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_6_1_7600:          
	mov eax, 0x000c
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:          
	mov eax, 0x000c
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:          
	mov eax, 0x000d
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:          
	mov eax, 0x000e
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19041:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19042:        
	mov eax, 0x000f
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtCreateThreadEx*(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                          
NtCreateThreadEx_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtCreateThreadEx_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtCreateThreadEx_Check_10_0_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtCreateThreadEx_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtCreateThreadEx_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtCreateThreadEx_SystemCall_6_3_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtCreateThreadEx_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtCreateThreadEx_SystemCall_6_1_7601
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtCreateThreadEx_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtCreateThreadEx_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtCreateThreadEx_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtCreateThreadEx_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtCreateThreadEx_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtCreateThreadEx_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtCreateThreadEx_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtCreateThreadEx_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtCreateThreadEx_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtCreateThreadEx_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtCreateThreadEx_SystemCall_10_0_19042
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_SystemCall_6_1_7600:          
	mov eax, 0x00a5
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_1_7601:          
	mov eax, 0x00a5
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_2_XXXX:          
	mov eax, 0x00af
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_3_XXXX:          
	mov eax, 0x00b0
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_10240:        
	mov eax, 0x00b3
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_10586:        
	mov eax, 0x00b4
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_14393:        
	mov eax, 0x00b6
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_15063:        
	mov eax, 0x00b9
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_16299:        
	mov eax, 0x00ba
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_17134:        
	mov eax, 0x00bb
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_17763:        
	mov eax, 0x00bc
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_18362:        
	mov eax, 0x00bd
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_18363:        
	mov eax, 0x00bd
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_19041:        
	mov eax, 0x00c1
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_19042:        
	mov eax, 0x00c1
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_Unknown:           
	ret
NtCreateThreadEx_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtOpenProcess*(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                       
NtOpenProcess_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtOpenProcess_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtOpenProcess_SystemCall_10_0_19042
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NtWriteVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                              
NtWriteVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NtWriteVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NtWriteVirtualMemory_Check_10_0_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NtWriteVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NtWriteVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NtWriteVirtualMemory_SystemCall_6_3_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NtWriteVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NtWriteVirtualMemory_SystemCall_6_1_7601
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NtWriteVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NtWriteVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NtWriteVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NtWriteVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NtWriteVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NtWriteVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NtWriteVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NtWriteVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NtWriteVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NtWriteVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NtWriteVirtualMemory_SystemCall_10_0_19042
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x0037
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x0037
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x0038
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x0039
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x003a
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_Unknown:           
	ret
NtWriteVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
    """
