function Invoke-Vulmap {
    <#
.SYNOPSIS
Local vulnerability scanner

.DESCRIPTION
Gets installed software information from the local host and asks to vulmon.com if vulnerabilities and exploits exists. 

.PARAMETER DefaultMode
Conducts a vulnerability scanning. Default mode.

.PARAMETER OnlyExploitableVulns
Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.

.PARAMETER DownloadExploit
Downloads given exploit.

.PARAMETER DownloadAllExploits
Scans the computer and downloads all available exploits.

.EXAMPLE
PS> Invoke-Vulmap

Default mode. Conducts a vulnerability scanning.

.EXAMPLE
PS> Invoke-Vulmap -OnlyExploitableVulns

Conducts a vulnerability scanning and only shows vulnerabilities that have exploits

.EXAMPLE
PS> Invoke-Vulmap -DownloadExploit EDB9386

Downloads given exploit

.EXAMPLE
PS> Invoke-Vulmap -DownloadAllExploits

Scans the computer and downloads all available exploits

.LINK
https://github.com/vulmon
https://github.com/yavuzatlas
https://vulmon.com
#>

    Param (
        [switch] $DefaultMode,
        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit = "",
        [switch] $DownloadAllExploits,
        [switch] $Help
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
    function Send-Request($ProductList) {
        $product_list = '"product_list": ' + $ProductList
        
        $json_request_data = '{'
        $json_request_data = $json_request_data + '"os": "' + (Get-CimInstance Win32_OperatingSystem).Caption + '",'
        $json_request_data = $json_request_data + $product_list 
        $json_request_data = $json_request_data + '}'

        $postParams = @{querydata = $json_request_data}
        return (Invoke-WebRequest -Uri https://vulmon.com/scannerapi_vv211 -Method POST -Body $postParams).Content
    }
    function Get-ProductList() {
        $registry_paths = ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") 
   
        $objectArray = @();
    
        foreach ($registry_path in $registry_paths) {
            $subkeys = Get-ChildItem -Path $registry_path
    
            ForEach ($key in $subkeys) {
                $DisplayName = $key.getValue('DisplayName');
    
                if (!([string]::IsNullOrEmpty($DisplayName))) {
                    $DisplayVersion = $key.GetValue('DisplayVersion');
    
                    $Object = [pscustomobject]@{ 
                        DisplayName     = $DisplayName.Trim();
                        DisplayVersion  = $DisplayVersion;
                        NameVersionPair = $DisplayName.Trim() + $DisplayVersion;
                    }
    
                    $Object.pstypenames.insert(0, 'System.Software.Inventory')
    
                    $objectArray += $Object
                }
    
            }
    
        }
    
        $objectArray | sort-object NameVersionPair -unique;  
    }   
    function Get-Exploit($ExploitID) {  
        $request1 = Invoke-WebRequest -Uri ('http://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0";
        Invoke-WebRequest -Uri ('http://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0" -OutFile ( ($request1.Headers."Content-Disposition" -split "=")[1]);
    }
    function Out-Result($product_list) {
        $product_list = $product_list.Substring(0, $product_list.Length - 1)
        $product_list = $product_list + ']'
        $response = (Send-Request -ProductList $product_list | ConvertFrom-Json)

        $vuln_found=0;
        foreach ($var2 in $response.results) {
            
            if ($OnlyExploitableVulns -Or $DownloadAllExploits) {
                $var3 = $var2 | Select-Object -Property query_string -ExpandProperty vulnerabilities | where-object {$_.exploits -ne $null} | `
                    Select-Object -Property @{N = 'Product'; E = {$_.query_string}}, @{N = 'CVE ID'; E = {$_.cveid}}, @{N = 'Risk Score'; E = {$_.cvssv2_basescore}}, @{N = 'Vulnerability Detail'; E = {$_.url}}, @{L = 'ExploitID'; E = {if ($null -ne $_.exploits) {"EDB" + ($_.exploits[0].url).Split("{=}")[2]}else { null }}}, @{L = 'Exploit Title'; E = {if ($null -ne $_.exploits) {$_.exploits[0].title}else { null }  }}

                $var3 | Format-Table -AutoSize;

                if ($DownloadAllExploits) {    
                    foreach ($var4 in $var3) {
                        $exploit_id = $var4.ExploitID
                        Get-Exploit($exploit_id);                     
                    }
                }
            }
            else {
                $var3 = $var2 | Select-Object -Property query_string -ExpandProperty vulnerabilities | `
                    Select-Object -Property @{N = 'Product'; E = {$_.query_string}}, @{N = 'CVE ID'; E = {$_.cveid}}, @{N = 'Risk Score'; E = {$_.cvssv2_basescore}}, @{N = 'Vulnerability Detail'; E = {$_.url}}, @{L = 'Exploit ID'; E = {if ($null -ne $_.exploits) {"EDB" + ($_.exploits[0].url).Split("{=}")[2]}else { null }}}, @{L = 'Exploit Title'; E = {if ($null -ne $_.exploits) {$_.exploits[0].title}else { null }  }};
                $var3 | Format-Table -AutoSize;
            }
        }

          
    }
    function Invoke-VulnerabilityScan() {
        Write-Host 'Vulnerability scan started...';
        $var1 = Get-ProductList;

        $vuln_found=1;
        $count = 0;
        foreach ($element in $var1) {
            if ($count -eq 0) { $product_list = '[' }
                   
            if ($element.DisplayName) {
                $product_list = $product_list + '{'
                $product_list = $product_list + '"product": "' + $element.DisplayName + '",'
                $product_list = $product_list + '"version": "' + $element.DisplayVersion + '"'
                $product_list = $product_list + '},'
            }
                   
            $count++
            if ($count -eq 100) {
                $count = 0
                Out-Result($product_list);           
            }
        }
        Out-Result($product_list);

        if($vuln_found -eq 0){Write-Host 'No vulnerabilities found.'}
    }

    #-----------------------------------------------------------[Execution]------------------------------------------------------------
    if (!([string]::IsNullOrEmpty($DownloadExploit))) {
        "Exploit Download...";
        Get-Exploit($DownloadExploit);
    }
    else {
        invoke-VulnerabilityScan;
    }
}
