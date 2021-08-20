import winim/clr
import sugar
import strformat
import os

var buf: array[500000000, byte] = [bytex x x x]

var assembly = load(buf)
dump assembly


var cmd: seq[string]
var i = 1
while i <= paramCount():
    cmd.add(paramStr(i))
    inc(i)
echo cmd
var arr = toCLRVariant(cmd, VT_BSTR)
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
