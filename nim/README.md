# Some of my experiments with [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) templates

To not popup the Nim binaries console window compile them with the `--app:gui` parameter.

For the best size:

```
nim c -d:danger -d:strip --opt:size --passc=-flto --passl=-flto executable.nim
```

To compile the DLL:

```
nim c -d=mingw --app=lib --nomain --cpu=amd64 DLLHijack.nim
```

For unhook.nim:
```
nim cpp -d:release --passL:"-L. -lPsapi" unhook.nim
```

For reflective loading:

```
--dynamicbase,--export-all-symbols
```

For syscall_shellcode.nim:
```
git clone https://github.com/ajpc500/NimlineWhispers.git
#Modify functions.txt to include our five Native API functions:

NtCreateThreadEx
NtOpenProcess
NtAllocateVirtualMemory
NtWriteVirtualMemory
NtClose

And run:
python3 NimlineWhispers


edit syscalls.nim and add:

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
```

According to: [https://ajpc500.github.io/nim/Shellcode-Injection-using-Nim-and-Syscalls/](https://ajpc500.github.io/nim/Shellcode-Injection-using-Nim-and-Syscalls/)
