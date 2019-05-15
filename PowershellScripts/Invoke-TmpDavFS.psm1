<#
.SYNOPSIS
 
In Memory Powershell WebDav Server
 
Author: p3nt4 (https://twitter.com/xP3nt4)
License: MIT
 
.DESCRIPTION
 
Creates a memory backed webdav server using powershell that can be mounted as a filesystem.

Note: Mounting the remote filesystem on windows implies local caching of accessed files in the C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV system directory.
 
.USAGE

Import-Module Invoke-TempDavFS.psm1

Invoke-TempDavFS

.PARAMETERS

port: Port to listen on, defaults to 8080.

sharename: Name of the share to export, defaults to Temp
 
export: Listen on any interface, instead of localhost (requires admin).

auth: Require authentication, defaults to false.

 
#>

class TmpDavFSNode{
    [String]$name;
    [Boolean]$isCollection;
    [Hashtable]$nodes;
    [Byte[]]$file;
    [String]$DateModified;
    Static [String] $propfindTemplate = '<ns0:response><ns0:href>{0}</ns0:href><ns0:propstat><ns0:prop>{2}<ns0:creationdate>{3}</ns0:creationdate><ns0:getlastmodified>{3}</ns0:getlastmodified><ns0:displayname>{1}</ns0:displayname><ns0:lockdiscovery /><ns0:supportedlock><ns0:lockentry><ns0:lockscope><ns0:exclusive /></ns0:lockscope><ns0:locktype><ns0:write /></ns0:locktype></ns0:lockentry><ns0:lockentry><ns0:lockscope><ns0:shared /></ns0:lockscope><ns0:locktype><ns0:write /></ns0:locktype></ns0:lockentry></ns0:supportedlock></ns0:prop><ns0:status>HTTP/1.1 200 OK</ns0:status></ns0:propstat></ns0:response>'
    Static [String] $proppatchTemplate = '<?xml version="1.0"?><a:multistatus xmlns:b="urn:schemas-microsoft-com:office:office" xmlns:a="DAV:"><a:response><a:href>{0}/</a:href><a:propstat><a:status>HTTP/1.1 200 OK</a:status><a:prop><b:Author/></a:prop></a:propstat></a:response></a:multistatus>';
    Static [String] $lockTemplate = '<?xml version="1.0" encoding="utf-8" ?><d:prop xmlns:d="DAV:">  <d:lockdiscovery> <d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope><d:depth>Infinity</d:depth><d:owner> <d:href>{0}</d:href></d:owner><d:timeout>Second-345600</d:timeout><d:locktoken>  <d:href>opaquelocktoken:e71d4fae-5dec-22df-fea5-00a0c93bd5eb1</d:href></d:locktoken> </d:activelock>  </d:lockdiscovery></d:prop>'
    TmpDavFSNode([String]$name){
        $this.DateModified =  Get-Date -Format r;
        $this.name=$name;
        $this.isCollection=$true;
        $this.nodes=@{};
    }
    TmpDavFSNode([String]$name, [Byte[]]$file){
        $this.DateModified =  Get-Date -Format r;
        $this.name=$name;
        $this.isCollection=$false;
        $this.file=$file;
    }

    TmpDavFSNode([String]$name, [String]$file){
        $this.DateModified =  Get-Date -Format r;
        $this.name=$name;
        $this.isCollection=$false;
        $this.file = [System.Text.Encoding]::ASCII.GetBytes($file) ;
    }

    addNode([String]$name){
        $tmpFs = [TmpDavFSNode]::new($name);
        $this.nodes[$name] = $tmpFs;
    }
    addNode([String]$name, [TmpDavFSNode] $node){
        $node.name = $name;
        $this.nodes[$name] = $node;
    }
    addNode([String]$name,[Byte[]]$file){
        $tmpFs = [TmpDavFSNode]::new($name, $file);
        $this.nodes[$name] = $tmpFs;
    }
    addNode([String]$name,[String]$file){
        $tmpFs = [TmpDavFSNode]::new($name, $file);
        $this.nodes[$name] = $tmpFs;
    }
    delNode([String]$name){
        $this.nodes.Remove($name);
    }
    print(){
        Write-Host "Printing " $this.name
        if($this.isCollection){
        Write-Host "Listing Nodes:"
            foreach ($key in $this.nodes.Keys){
                 if ($this.nodes[$key].isCollection){
                     Write-Host $key "- DIR";
                 } else{
                     Write-Host $key;
                 }
            }
        }else{
             $str =  [System.Text.Encoding]::ASCII.GetString($this.file);
             Write-Host $str;
        }
    }
    [TmpDavFSNode] getNode([String]$path){
        $path2 = $path -split("/");
        $node=$this;
        foreach($name in $path2){
            if ($name -ne ""){
                $node = $node.nodes[$name];
            }
        }
        return $node;
    }
    moveNode([String]$source, [String]$destination){
        $sourceNode=$this.getNode($source);
        $destNode=$this.getNode((Split-Path $destination).replace("\","/"));
        $destNode.addNode((Split-Path $destination -leaf), $sourceNode);
        $parentNode = $this.getNode((Split-Path $source).replace("\","/"));
        $parentNode.delNode((Split-Path $source -leaf));
    }

    [String] fullPropfind([String]$path, [int]$depth){
        $node = $this.getNode($path);
        $response='<?xml version="1.0" encoding="utf-8" ?><ns0:multistatus xmlns:ns0="DAV:">';
        $response += $node.propfind($path);
        if(($node.isCollection) -and ($depth -ne 0)){
            foreach ($key in $node.nodes.Keys){
                 $response += $node.nodes[$key].propfind($path+"/"+$node.nodes[$key].name);
            }
        }
        $response += "</ns0:multistatus>";
        return $response;
    }

    [String] propfind([String]$path){
        if ($this.isCollection){
            return [string]::Format([TmpDavFSNode]::propfindTemplate, $path+"/", $this.name, "<ns0:resourcetype><ns0:collection /></ns0:resourcetype>",$this.DateModified);
            }
         return [string]::Format([TmpDavFSNode]::propfindTemplate, $path, $this.name, "<ns0:getcontentlength>"+$this.file.Length+"</ns0:getcontentlength><ns0:getcontenttype>application/octet-stream</ns0:getcontenttype>",$this.DateModified);
    }

}


function Invoke-TmpDavFS(){
    param (

        [Int]$port = 8080,

        [String]$sharename = "Temp",

        [switch]$export,

        [Switch]$auth
    )
  try{
    $tmpFs = [TmpDavFSNode]::new("");
    $tmpFs.addNode($sharename);
    $listener = New-Object System.Net.HttpListener;
    if($export){
        $listener.Prefixes.Add('http://+:'+$port+'/');
    }else{
        $listener.Prefixes.Add('http://localhost:'+$port+'/');
    }
    if ($auth){
        $listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::Negotiate;
    
    }
    $listener.Start();
    Write-Host 'Listening on ' $port;
    $instruction = 'Mount with: net use X: \\localhost@'+$port+'\'+$sharename;
    Write-Host $instruction;
    while ($true) {
        $context = $listener.GetContext();
        $request = $context.Request;
        $response = $context.Response;
	$hostip = $request.RemoteEndPoint;
        Write-Host $request.HttpMethod $request.Url;
        if ($request.HttpMethod -eq "OPTIONS"){  
            $response.AddHeader("Allow","OPTIONS, GET, PROPFIND, PUT, MKCOL, DELETE, MOVE, PROPPATCH, LOCK, UNLOCK");
            $response.Close();
            continue;
         
        }		 
        elseif ($request.HttpMethod -eq "PROPFIND") { 
            try{
                $message = $tmpFs.fullPropfind($request.Url.LocalPath, $request.Headers["Depth"]);
                $response.AddHeader("Content-Type","application/xml");
                $response.StatusCode = 207;
                $response.StatusDescription = "Multi-Status";
                }
            catch{
                Write-Host $_
                $response.StatusCode = 404;
                $response.StatusDescription = "Not Found";
                $response.Close()
                continue;
                }
        
        }
        elseif ($request.HttpMethod -eq "MOVE") { 
            try{
                $source = $request.Url.LocalPath;
                $destination = [System.URI]::new($request.Headers["Destination"]).LocalPath;
                if ($source -ne $destination){
                     $tmpFs.moveNode($source, $destination)}
                $response.StatusCode = 201;
                $response.StatusDescription = "Created";
                }
            catch{
                Write-Host $_.Exception
                $response.StatusCode = 404;
                $response.StatusDescription = "Not Found";
                $response.Close()
                continue;
                }
        
        }
        elseif ($request.HttpMethod -eq "LOCK") { 
            $message = [string]::Format([TmpDavFSNode]::lockTemplate, $request.Url.LocalPath);
        }
        elseif ($request.HttpMethod -eq "UNLOCK") { 
            $response.StatusCode = 204;
            $response.StatusDescription = "No Content";
            $response.Close()
            continue;
        }
        elseif ($request.HttpMethod -eq "DELETE") {
            try{
                $filename = [System.Uri]::UnescapeDataString($request.Url.Segments[-1]);
                $path = [System.Uri]::UnescapeDataString(-join $request.Url.Segments[0..($request.Url.Segments.Length-2)]);
                $tmpFs.getNode($path).delNode($filename);
                $response.StatusCode = 204;
                $response.StatusDescription = "No Content";
                $response.Close();
                continue;
             }catch{
                Write-Host $_.Exception;
                $response.StatusCode = 404;
                $response.StatusDescription = "Not Found";
                $response.Close()
                continue;
             }
        }
        elseif ($request.HttpMethod -eq "HEAD") { 
            $response.StatusCode = 200;
            $response.StatusDescription = "OK";
            $response.Close();
            continue;
        }
	    elseif ($request.HttpMethod -eq "PROPPATCH") {
            $message = [string]::Format([TmpDavFSNode]::proppatchTemplate, $request.Url.LocalPath);
        }
	    elseif ($request.HttpMethod -eq "PUT") {
            try{
		$ms = New-Object System.IO.MemoryStream;
		[byte[]] $buffer = New-Object byte[] 65536;
		[int] $bytesRead | Out-Null;
		$Stream = $request.InputStream;
		do
		{
			$bytesRead = $Stream.Read($buffer, 0, $buffer.Length);
			$ms.Write($buffer, 0, $bytesRead);

		} while ( $bytesRead -ne 0)

		$filename = [System.Uri]::UnescapeDataString($request.Url.Segments[-1]);
		$path = [System.Uri]::UnescapeDataString(-join $request.Url.Segments[0..($request.Url.Segments.Length-2)]);
		[byte[]] $Content = $ms.ToArray();
		$tmpFs.getNode($path).addNode($filename, $Content);
		$response.StatusCode = 201;
		$response.StatusDescription = "Created";
		$response.Close()
                continue;
            }catch{
                Write-Host $_.Exception;
                $response.StatusCode = 404;
                $response.StatusDescription = "Not Found";
                $response.Close()
                continue;
            }
    }
        elseif ($request.HttpMethod -eq "MKCOL") {
	    try{
		$name = [System.Uri]::UnescapeDataString($request.Url.Segments[-1]);
		$path = [System.Uri]::UnescapeDataString(-join $request.Url.Segments[0..($request.Url.Segments.Length-2)]);
		$tmpFs.getNode($path).addNode($name);
		$response.StatusCode = 201;
		$response.StatusDescription = "Created";
		$response.Close()
		continue;
	    }catch{
		Write-Host $_.Exception;
		$response.StatusCode = 404;
		$response.StatusDescription = "Not Found";
		$response.Close()
		continue;
	    }
	    }
	    elseif ($request.HttpMethod -eq "GET"){ 
            try{
		$node = $tmpFs.getNode($request.Url.LocalPath);
                if (-not $node -or $node.isCollection){
                    $response.StatusCode=404;
                }else{
                    [byte[]] $buffer = $node.file;
                    $response.ContentType = 'application/octet-stream';
		    $response.ContentLength64 = $buffer.length;
		    $output = $response.OutputStream;
		    $output.Write($buffer, 0, $buffer.length);
		    $output.Close();
                    continue;
                }
           }catch{
                Write-Host $_.Exception;
                $response.StatusCode = 404;
                $response.StatusDescription = "Not Found";
                $response.Close()
                continue;
                }

		   	
	    }
        [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
        $response.ContentLength64 = $buffer.length
        $output = $response.OutputStream
        $output.Write($buffer, 0, $buffer.length)
        $output.Close()
    }

    $listener.Stop()
     }catch{
        Write-Host $_.Exception
        $listener.Stop()
        return;
    }
 }

export-modulemember -function Invoke-TmpDavFS
