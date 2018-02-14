<#
	    .SYNOPSIS
	       This script can be used to enumerate information about federated domains from Microsoft's APIs.

	    .DESCRIPTION
	       This script can be used to identify potential authentication points for federated domains. A "test" email address is sent to Microsoft's federation check API and the JSON response is parsed by the script. The data is then returned as a datatable.

	    .EXAMPLE
	       
	       PS C:\> Get-FederationEndpoint -domain microsoft.com | ft -AutoSize

	       Domain        Type      BrandName AuthURL                                                                                                                             
	       ------        ----      --------- -------                                                                                                                             
	       microsoft.com Federated Microsoft https://msft.sts.microsoft.com/adfs/ls/?username=test%40microsoft.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=

	       
	    .EXAMPLE
	       
	       PS C:\> Get-Content "C:\Temp\domains.txt" | ForEach-Object {Get-FederationEndpoint -domain $_}  | ft -AutoSize

	    .NOTES
	       Author: Karl Fosaaen (@kfosaaen) - 2016, NetSPI
	       	       
	    .LINK
	       https://blog.netspi.com/using-powershell-identify-federated-domains/
		   http://www.economyofmechanism.com/office365-authbypass.html
		   https://blogs.msdn.microsoft.com/besidethepoint/2012/10/17/request-adfs-security-token-with-powershell/
		   https://msdn.microsoft.com/en-us/library/jj151815.aspx
		   https://technet.microsoft.com/en-us/library/dn568015.aspx
#>

function Get-FederationEndpoint{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="Domain name to get the ADFS endpoint for.")]
        [string]$domain,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Flag for authentication command output.")]
        [switch]$cmd
    )

    # "Test" Email
    $email = "test@"+$domain

    # Microsoft URL to get the JSON response from
    $url = "https://login.microsoftonline.com/common/userrealm/?user="+$email+"&api-version=2.1&checkForMicrosoftAccount=true";

    # Create data table to house results
    $EmailTestResults = new-object system.data.datatable
    $EmailTestResults.columns.add("Domain") | Out-Null
    $EmailTestResults.columns.add("Type") | Out-Null
    $EmailTestResults.columns.add("BrandName") | Out-Null
    $EmailTestResults.columns.add("AuthURL") | Out-Null
   
    try{

        # Make the request
        $JSON = Invoke-RestMethod -Uri $url

        # Handle the Response
        $NameSpaceType = $JSON[0].NameSpaceType

        if ($NameSpaceType -eq "Managed"){
            
            #Add data to the table
            $EmailTestResults.Rows.Add($JSON[0].DomainName, "Managed", $JSON[0].FederationBrandName, "NA") | Out-Null

            if ($cmd){

                # Sample command
                Write-Host "`nDomain is managed by Microsoft, try guessing creds this way:`n`n`t`$msolcred = get-credential`n`tconnect-msolservice -credential `$msolcred"
                # Check if AzureAD module is installed
                if (Get-Module -Name MsOnline){}
                else{Write-Host "`n`t*Requires AzureAD PowerShell module to be installed and loaded - https://msdn.microsoft.com/en-us/library/jj151815.aspx"}
            }
        }
        ElseIf ($NameSpaceType -eq "Federated"){

            # Parse Stuff
            $username = $email.Split("@")[0]
            $domain = $JSON[0].DomainName
            $ADFSBaseUri = [string]$JSON[0].AuthURL.Split("/")[0]+"//"+[string]$JSON[0].AuthURL.Split("/")[2]+"/"
            $AppliesTo = $ADFSBaseUri+"adfs/services/trust/13/usernamemixed"

            
            #Add data to the table
            $EmailTestResults.Rows.Add($JSON[0].DomainName, "Federated", $JSON[0].FederationBrandName, $JSON[0].AuthURL) | Out-Null

            if ($cmd){

                # Write out the sample
                Write-Host "`nMake sure you use the correct Username and Domain parameters when you try to authenticate!`n`nAuthentication Command:`nInvoke-ADFSSecurityTokenRequest -ClientCredentialType UserName -ADFSBaseUri"$ADFSBaseUri" -AppliesTo "$AppliesTo" -UserName '"$username"' -Password 'Winter2016' -Domain '"$domain"' -OutputType Token -SAMLVersion 2 -IgnoreCertificateErrors"
                # Check if Invoke-ADFSSecurityTokenRequest is loaded
                try {Get-Command -Name Invoke-ADFSSecurityTokenRequest -ErrorAction Stop}
                catch{Write-Host `n`n'*Requires the command imported from here - https://gallery.technet.microsoft.com/scriptcenter/Invoke-ADFSSecurityTokenReq-09e9c90c'}
            }
        }
        Else{
            
            # If the domain has no federation information available from Microsoft
            $EmailTestResults.Rows.Add("NA", "NA", "NA", "NA") | Out-Null
        }
    }
    catch{
        Write-Host "`nThe Request out to Microsoft failed."
    }

    Return $EmailTestResults
}

