<# 
                                           Spect
   #              #      # # #     #       # # #
    #            #        #       # #     #
     #     #    #        #       #   #   #
      #	 #  #  #        #       #     # #   
     	#     #       # # #    #       # 
	 
 beta version
 Author : A-mIn3

#>

[Console]::ForegroundColor="White"
[Console]::BackGroundColor="Black"

[System.String]$scriptDirectoryPath  = split-path -parent $MyInvocation.MyCommand.Definition
[System.String]$secpolFilePath       = join-path $scriptDirectoryPath "secedit.log"
[System.String]$reportFilePath       = join-path $scriptDirectoryPath "report-$env:COMPUTERNAME.txt"
[System.String]$exceptionsFilePath   = join-path $scriptDirectoryPath "exceptions-$env:COMPUTERNAME.txt"

[System.String]$culture=(Get-Culture).Name

$PSVersion=$PSVersionTable.PSVersion.Major

[int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole



$systemRoles = @{
                              0         =    " Standalone Workstation    " ;
                              1         =    " Member Workstation        " ;
                              2         =    " Standalone Server         " ;
                              3         =    " Member Server             " ;
                              4         =    " Backup  Domain Controller " ;
                              5         =    " Primary Domain Controller "       
}


$permissionFlags = @{
                            0x1         =     "Read-List";
                            0x2         =     "Write-Create";
                    	    0x4         =     "Append-Create Subdirectory";                  	
                    	   0x20         =     "Execute file-Traverse directory";
                	   0x40         =     "Delete child"
                        0x10000         =     "Delete";                     
                        0x40000         =     "Write access to DACL";
                        0x80000         =     "Write Onwer"
}



$aceTypes = @{ 
                             0           =     "Allow";
                             1           =     "Deny"
 }





function initialize-audit {
    
    clear-host
     
    SecEdit.exe /export /cfg $secpolFilePath /quiet
     
    $start = get-date 
    
    sleep 1 
   
    write-host "Starting Audit at", $start
    "-------------------------------------`n"
   
    sleep 2

    Write-Host "[?] Checking for administrative privileges ..`n" -ForegroundColor black -BackgroundColor white 

    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if(!$isAdmin){
            
            Write-Warning  "[-] Some of the operations need administrative privileges.`n"
            
            Write-Warning  "[*] Please run the script using an administrative account.`n"
            
            Read-Host "Type any key to continue .."

            exit
    }
    
    write-host "[?] Checking for Default PowerShell version ..`n" -ForegroundColor black -BackgroundColor white 
   
    if($PSVersion -lt 2){
       
            Write-Warning  "[!] You have PowerShell v1.0.`n"
        
            Write-Warning  "[!] This script only supports Powershell verion 2 or above.`n"
        
            read-host "Type any key to continue .."
        
            exit  
    }
   
    write-host "       [+] ----->  PowerShell v$PSVersion`n" 
  
    write-host "[?] Detecting system role ..`n" -ForegroundColor black -BackgroundColor white 
  
    $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
     
    write-host "       [+] ----->",$systemRoles[[int]$systemRoleID],"`n" 
   
    
    get-LocalSecurityProducts
    
    get-WorldExposedLocalShares 
    
    if($systemRoleID -eq 1){
    	check-LocalMembership
    }
    
    check-UACLevel
    
    check-autoruns
    
    get-BinaryWritableServices 	   -display
    
    get-ConfigurableServices   	   -display
    
    get-UnquotedPathServices       -display
    
    check-HostedServices           -display
    
    check-DLLHijackability     
    
    check-UnattendedInstallFiles
    
    check-scheduledTasks
    
    $fin = get-date
    
    "`n[!]Done`n"
    
    "Audit completed in {0} seconds. `n" -f $(New-TimeSpan -Start $start -End $fin ).TotalSeconds
    
}

function get-LocalSecurityProducts
{
      <#    
       .SYNOPSIS		
	   Gets Windows Firewall Profile status and checks for installed third party security products.
			
       .DESCRIPTION
           This function operates by examining registry keys specific to the Windows Firewall and by using the 
        Windows Security Center to get information regarding installed security products. 
	            
       .NOTE
           The documentation in the msdn is not very clear regarding the productState property provided by
        the SecurityCenter2 namespace. For this reason, this function only uses available informations that were obtained by testing 
        different security products againt the Windows API. 
                            
       .LINK
           http://neophob.com/2010/03/wmi-query-windows-securitycenter2
     #>


      $firewallPolicySubkey="HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
               
      Write-host "`n[?] Checking if Windows Firewall is enabled ..`n"     -ForegroundColor black -BackgroundColor white 
              
      Write-host "       [?] Checking Firewall Profiles ..`n" -ForegroundColor black -BackgroundColor white 
      
      try{
      		
		if(Test-Path -Path $($firewallPolicySubkey+"\StandardProfile")){
              
            		   $enabled = $(Get-ItemProperty -Path $($firewallPolicySubkey+"\StandardProfile") -Name EnableFirewall).EnableFirewall  
              
                           if($enabled -eq 1){$standardProfile="Enabled"}else{$standardProfile="Disabled"}
              
                           "                   [*] Standard Profile  Firewall     :  {0}.`n" -f $standardProfile
                }else{
                    
                                         Write-Warning  "       [-] Could not find Standard Profile Registry Subkey.`n"
              
	        }    
                
                if(Test-Path -Path $($firewallPolicySubkey+"\PublicProfile")){
                   
                           $enabled = $(Get-ItemProperty -Path $($firewallPolicySubkey+"\PublicProfile") -Name EnableFirewall).EnableFirewall  
                           
                           if($enabled -eq 1){$publicProfile="Enabled"}else{$publicProfile="Disabled"}
                           
                           "                   [*] Public   Profile  Firewall     :  {0}.`n" -f $publicProfile
                }else{         
			   Write-Warning "       [-] Could not find Public Profile Registry Subkey.`n"
             
                }

                if(Test-Path -Path $($firewallPolicySubkey+"\DomainProfile")){
                     
                           $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\DomainProfile") -Name EnableFirewall).EnableFirewall  
              
                           if($enabled -eq 1){$domainProfile="Enabled"}else{$domainProfile="Disabled"}
              
                           "                   [*] Domain   Profile  Firewall     :  {0}.`n`n" -f $domainProfile
                }else{       
                          Write-Warning  "       [-] Could not find Private Profile Registry Subkey.`n`n"          
	        }              
               
                 
            
     
      }catch{
              $errorMessage = $_.Exception.Message
            
              $failedItem   = $_.Exception.ItemName

              "[-] Exception : "| Set-Content $exceptionsFilePath
              
              "[*] Error Message : `n",$errorMessage | Set-Content $exceptionsFilePath
              
              "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
      	      Write-Warning -Message "[-] Error : Could not check Windows Firewall registry informations .`n`n"	
      }       
            
      
      $SecurityProvider=@{         
                                "00"     =   "None";
                                "01"     =   "Firewall";
                                "02"     =   "AutoUpdate_Settings";
                                "04"     =   "AntiVirus";           
                                "08"     =   "AntiSpyware";
                                "10"     =   "Internet_Settings";
                                "20"     =   "User_Account_Control";
                                "40"     =   "Service"
      }
               
               
      $RealTimeBehavior = @{                              
                                "00"    =    "Off";
                                "01"    =    "Expired";
                                "10"    =    "ON";
                                "11"    =    "Snoozed"
      }
               
     
      $DefinitionStatus = @{
                                "00"     =     "Up-to-date";
                                "10"     =     "Out-of-date"
               
      }
               
      $role = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole

      if($role -ne 0 -and $role -ne 1){
               return
      }
      
      if(Get-WmiObject -Namespace root -class __NAMESPACE -filter "name='SecurityCenter2'"){

                 $securityCenterNS="root\SecurityCenter2"

      }else{

                 $securityCenterNS="root\SecurityCenter"
      } 
     
      
      
      # checks for third party firewall products 
 
      Write-host "`n[?] Checking for third party Firewall products .. `n" -ForegroundColor Black -BackgroundColor White
              
      
      try {  
            
             $firewalls= @(Get-WmiObject -Namespace $securityCenterNS -class FirewallProduct)
           
             if($firewalls.Count -eq 0){
           
	            "       [-] No other firewall installed.`n"
             }else{
             
                    "       [+] Found {0} third party firewall products.`n"  -f $($firewalls.Count)    
            
                    Write-host "            [?] Checking for product configuration ...`n" -ForegroundColor black -BackgroundColor white 
            
                    $firewalls| % {
                          
                          # The structure of the API is different depending on the version of the SecurityCenter Namespace
                          if($securityCenterNS.endswith("2")){
                                            
                                       [int]$productState=$_.ProductState
                          
                        	       $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                          	
                                       $provider=$hexString.substring(0,2)
                          
                                       $realTimeProtec=$hexString.substring(2,2)
                          
                                       $definition=$hexString.substring(4,2)
                                         
                                       "                     [+] Product Name          : {0}."     -f $_.displayName
                                       "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$provider]
                                       "                     [+] State                 : {0}.`n`n" -f $RealTimeBehavior[[String]$realTimeProtec]

                          }else{
                            
                                       "                     [+] Company Name           : {0}."     -f $_.CompanyName
                                       "                     [+] Product Name           : {0}."     -f $_.displayName
                                       "                     [+] State                  : {0}.`n`n" -f $_.enabled

                          }

                    }
              
              }
            
              sleep 2
  
              # checks for antivirus products

              Write-host "`n[?] Checking for installed antivirus products ..`n"-ForegroundColor Black -BackgroundColor white 

              $antivirus=@(Get-WmiObject -Namespace $securityCenterNS -class AntiVirusProduct)
              
              if($antivirus.Count -eq 0){
                
                                "       [-] No antivirus product installed.`n`n"      
              
              }else{
                                "       [+] Found {0} AntiVirus solutions.`n" -f $($antivirus.Count)
              
                                Write-host "            [?] Checking for product configuration ..`n" -ForegroundColor black -BackgroundColor white 
              
             			$antivirus|%{
                                                if($securityCenterNS.endswith("2")){
                                            
                                                	[int]$productState=$_.ProductState
                                       
                                      		         $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                                       
                                                         $provider=$hexString.substring(0,2)
                                       
                                                         $realTimeProtec=$hexString.substring(2,2)
                                       
                                                         $definition=$hexString.substring(4,2)
                                         
                                                         "                     [+] Product Name          : {0}."     -f $_.displayName
                                                         "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$provider]
                                                         "                     [+] Real Time Protection  : {0}."     -f $RealTimeBehavior[[String]$realTimeProtec]
                                                         "                     [+] Signature Definitions : {0}.`n`n" -f $DefinitionStatus[[String]$definition]
                                                                     
                                                }else{
                            
                                                         "                     [+] Company Name           : {0}."     -f $_.CompanyName
                                                         "                     [+] Product Name           : {0}."     -f $_.displayName
                                                         "                     [+] Real Time Protection   : {0}."     -f $_.onAccessScanningEnabled
                                                         "                     [+] Product up-to-date     : {0}.`n`n" -f $_.productUpToDate
                                                }

                                }
               
                
              }


              # Checks for antispyware products

	      Write-host "`n[?] Checking for installed antispyware products ..`n"-ForegroundColor Black -BackgroundColor white 
            
              $antispyware=@(Get-WmiObject -Namespace $securityCenterNS -class AntiSpywareProduct)
         
              if($antispyware.Count -eq 0){
          
                                "       [-] No antiSpyware product installed.`n`n"     
         
              }else{
                                "       [+] Found {0} antiSpyware solutions.`n" -f $($antiSpyware.Count)

                                Write-host "            [?] Checking for product configuration ..`n" -ForegroundColor black -BackgroundColor white 
          
                                $antispyware| % {
                		              
				         	       if($securityCenterNS.endswith("2")){
                                            
                                                         [int]$productState=$_.ProductState
                                         
                                                 	 $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                                         
                                                         $provider=$hexString.substring(0,2)
                                         
                                                         $realTimeProtec=$hexString.substring(2,2)
                                         
                                                         $definition=$hexString.substring(4,2)
                                         
                                         		 "                     [+] Product Name          : {0}."     -f $_.displayName
                                         		 "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$provider]
                                         		 "                     [+] Real Time Protection  : {0}."     -f $RealTimeBehavior[[String]$realTimeProtec]
                                         		 "                     [+] Signature Definitions : {0}.`n`n" -f $DefinitionStatus[[String]$definition]
                                         
                               			}else{
                            
                                         		 "                     [+] Company Name           : {0}."     -f $_.CompanyName
                                         		 "                     [+] Product Name           : {0}."     -f $_.displayName
                                         		 "                     [+] Real Time Protection   : {0}."     -f $_.onAccessScanningEnabled
                                        		 "                     [+] Product up-to-date     : {0}.`n`n" -f $_.productUpToDate
                            
                                                }

                                }

              }

     
      }catch{
              
               $errorMessage = $_.Exception.Message
            
               $failedItem   = $_.Exception.ItemName

              "[-] Exception : "| Set-Content $exceptionsFilePath
              
              "[*] Error Message : `n",$errorMessage | Set-Content $exceptionsFilePath
              
              "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath

              
            
      }

}


function get-WorldExposedLocalShares
{
      <#
       .SYNOPSIS
           Gets informations about local shares and their associated DACLs.

       .DESCRIPTION
           This function checks local file system shares and collects informations about each 
	Access Control Entry (ACE) looking for those targeting the Everyone(Tout le monde) group.
            
       .NOTE
	  This function can be modified in a way that for each share we
        return its corresponding ace objects for further processing.

        .LINK
            https://msdn.microsoft.com/en-us/library/windows/desktop/aa374862(v=vs.85).aspx

      #>

    
        $exists = $false
   
        $rules=@()

        Write-Host "`n[?] Checking for World-exposed local shares ..`n" -ForegroundColor black -BackgroundColor White 

        try{
		  
                     Get-WmiObject -class Win32_share -Filter "type=0"|%{
                  
		    	     $rules=@()
                   
                             $shareName = $_.Name
                 
                             $shareSecurityObj = Get-WmiObject -class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'"
                   
                             $securityDescriptor = $shareSecurityObj.GetSecurityDescriptor().Descriptor
 
                             ForEach($ace in $securityDescriptor.dacl){
 
                                     # Looking for Everyone group (SID="S-1-1-0") permissions 
                                     $trusteeSID = (New-Object System.Security.Principal.SecurityIdentifier($ace.trustee.SID, 0)).Value.ToString()
                            
                                     
                                     if($trusteeSID -eq "S-1-1-0" -and $aceTypes[[int]$ace.aceType] -eq "Allow"){

                                                $accessMask  = $ace.accessmask
                            
                                                $permissions =""
                            
                                                foreach($flag in $permissionFlags.Keys){

                                                       if($flag -band $accessMask){
                                          
                                                                 $permissions+=$permissionFlags[$flag]
                                          
                                                                 $permissions+="$"
                                                       }
                                                }

                                                $rule = New-Object  PSObject -Property @{
                                
                                                             "ShareName"    =  $shareName     
                           		                     "Trustee"      =  $ace.trustee.Name 
                         		                     "Permissions"  =  $permissions
                                                }

                                                $rules+=$rule

                                                $exists=$true

                                     }
             
                           }

                           if($rules.Count -gt 0){
           
                                     "[*]-----------------------------------------------------------------------------[*]"
                               
                                      $rules| fl ShareName,Trustee,Permissions
            
                           }

                    }

                    if(!$exists){
        
                         "       [-] No local World-exposed shares were found .`n`n"
                    }
      
    
    
    
        }catch{
               
               $errorMessage = $_.Exception.Message
            
               $failedItem   = $_.Exception.ItemName

               "[-] Exception : "| Set-Content $exceptionsFilePath
              
               "[*] Error Message : `n",$errorMessage | Set-Content $exceptionsFilePath
              
               "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
               "[-] Unable to inspect local shares. "
        }

}





$global:local_member = $false

function check-LocalMembership
{
     <#
       .SYNOPSIS
           Gets domain users and groups with local group membership.
                        
       .DESCRIPTION
           This function checks local groups on the machine for domain users/groups who are members in a local group.
        It uses ADSI with the WinNT and LDAP providers to access user and group objects.
                  
       .NOTE 
           The machine must be a domain member. This is needed in order to resolve 
	the identity references of domain members.
            
     #>
           
           try{ 
           
                   write-host "`n[?] Checking for domain users with local group membership ..`n" -ForegroundColor Black -BackgroundColor White 

                   $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

                   $adsigroups= $adsi.Children|? {$_.SchemaClassName -eq "group"}

                   $adsigroups|%{
	   			
                              check-GroupLocalMembership $_
                   }

                   if($global:local_member -eq $false){
                    
           	                  "       [-] Found no domain user or group with local group membership."
                   }
            
                   "`n`n"
   
          }catch{
          
                   $errorMessage = $_.Exception.Message
            
                   $failedItem   = $_.Exception.ItemName

                   "[-] Exception : "| Set-Content $exceptionsFilePath
              
                   '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
                   "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
         
          }
   
}


function check-GroupLocalMembership($group)
{
    <# 
       .SYNOPSIS                                  
            Given a specific  ADSI group object, it checks whether it is a local or domain 
        group and looks fro its members.

       .DESCRIPTION                           
            This function is used by the get-LocalMembership function for inspecting nested
        groups membership.
                         
    #>

          $groupName=$group.GetType.Invoke().InvokeMember("Name","GetProperty", $null, $group, $null)
                      
          $GroupMembers = @($group.invoke("Members")) 
	  
	  $GroupMembers|% {                
                       
		       $adspath = $_.GetType.Invoke().InvokeMember("ADsPath", "GetProperty", $null, $_, $null)
                         
		       $sidBytes = $_.GetType.Invoke().InvokeMember("ObjectSID", "GetProperty", $null, $_, $null)
           
              	       $subjectName = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)).Translate([System.Security.Principal.NTAccount])

                       if($_.GetType.Invoke().InvokeMember("class", "GetProperty", $null, $_, $null) -eq "group"){

                                   # check if we have a local group object                                  
                                    if($adspath -match "/$env:COMPUTERNAME/") {

                                                 check-LocalGroupMembership $_

                                    }else{
                                                 # It is a domain group, no further processing needed                                                                                    
                                                 Write-Host "          [+] Domain group ",$subjectName," is a member in the",$groupName,"local group.`n"

                                                 $global:local_member=$true
                                    }


                       }else{
                                     # if not a group, then it must be a user
                                    if( !($adspath -match $env:COMPUTERNAME) ){

                                                   Write-Host "          [+] Domain user  ",$subjectName,"is a member of the",$groupName,"local group.`n"
                                        
                                                   $global:local_member=$true                                             
                                     }
                      }

          }

 


}

function check-UACLevel
{
        <#
           .SYNOPSIS
              Checks current configuration of User Account Control.

           .DESCRIPTION
              This functions inspects registry informations related to UAC configuration 
           and checks whether UAC is enabled and which level of operation is used.

       #>
        
          try{
                  
                  Write-Host "`n[?] Checking for UAC configuration ..`n" -ForegroundColor Black -BackgroundColor White
         
                  $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
              
                  if([int]$UACRegValues.EnableLUA -eq 1){
             
                               "          [+] UAC is enabled.`n"
                  }else{
               
                               "          [-] UAC is disabled.`n"
               
                  }
                             
                  Write-Host "            [?]Checking for UAC level ..`n" -ForegroundColor black -BackgroundColor white 
  
                  $consentPrompt=$UACregValues.ConsentPromptBehaviorAdmin
              
                  $secureDesktop=$UACregValues.PromptOnSecureDesktop
               
                  if( $consentPrompt -eq 0 -and $secureDesktop -eq 0){
                            
                              "                          [*] UAC Level : Never Notify.`n`n"
          
	          }elseif($consentPrompt -eq 5 -and $secureDesktop -eq 0){
                          
                              "                          [*] UAC Level : Notify only when apps try to make changes (No secure desktop).`n`n"
              
                  }elseif($consentPrompt -eq 5 -and $secureDesktop -eq 1){
                          
                              "                          [*] UAC Level : Notify only when apps try to make changes (secure desktop on).`n`n"
              
                  }elseif($consentPrompt -eq 5 -and $secureDesktop -eq 2){
               
                              "                          [*] UAC Level : Always Notify with secure desktop.`n`n"
                  }

                  
         
         }catch{
         
                 $errorMessage = $_.Exception.Message
            
                 $failedItem   = $_.Exception.ItemName

                 "[-] Exception : "| Set-Content $exceptionsFilePath
              
                 '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
                 "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
         
        }


}


function check-DLLHijackability{ 

      <#
        .SYNOPSIS
            Checks DLL Search mode and inspects permissions for directories in system %PATH%
         and checks write access for Authenticated Users group on these directories.
            
        .DESCRIPTION
            This functions tries to identify if DLL Safe Search is used and inspects 
         write access to directories in the path environment variable .
         It also looks for any DLLs loaded by running processes (#TODO)
               
     #>
        
         Write-host "`n[?] Checking for DLL hijackability ..`n" -ForegroundColor Black -BackgroundColor White 

         Write-host "       [?] Checking for Safe DLL Search mode ..`n" -ForegroundColor Black -BackgroundColor White 
       
         try{
         
                $value = Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\' -Name SafeDllSearchMode -ErrorAction SilentlyContinue
                   
                if($value -and ($value.SafeDllSearchMode -eq 0)){
        
	                    "                [+] DLL Safe Search is disabled !`n"      
                }else{
                   
                            "                [+] DLL Safe Search is enabled !`n"        
                }

                Write-Host "       [?] Checking directories in PATH environment variable ..`n" -ForegroundColor black -BackgroundColor white
           
                $systemPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
           
                $systemPath.split(";")| %{
  
                                    $directory = $_
                 
                                    $writable=$false   

                         # We are inspecting write access for the Authenticated Users group
                 
                                    $sid = "S-1-5-11"
                           
                                    $dirAcl = Get-Acl $($directory.trim('"'))            		

                                    foreach($rule in $dirAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])){
                 
                                               if($rule.IdentityReference -eq $sid){
                        
                                                            $accessMask = $rule.FileSystemRights.value__

                         # Here we are checking directory write access in UNIX sense (write/delete/modify permissions)
                         # We use a combination of flags 
                                   
                                                            if($accessMask -BAND 0xd0046){
                                    
                                                                       $writable=$true
                                                            }
                                               }
                                    }
              
                                    $item = New-Object psobject -Property @{
                               
                                               "Directory"   =  $directory        
                                               "Writable"    =  $writable           
                                
                                    }

                                    $item
              
         
                }| ft Directory,Writable
              
                "`n`n"
     
        }catch{
        
              $errorMessage = $_.Exception.Message
            
              $failedItem   = $_.Exception.ItemName

              "[-] Exception : "| Set-Content $exceptionsFilePath
              
              '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
              "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
        
        
        }


}


function get-BinaryWritableServices
{
    param([switch]$display)
       
      <#
        .SYNOPSIS
           Gets services whose binaries are writable by Authenticated Users and Everyone group members.
                    
        .DESCRIPTION
           This function checks services that have writable binaries and returns an array 
         containing service objects.
                
        .RETURNS
           When invoked without the $display switch, returns a hashtable of {name : pathname}
        couples.
         
     #>
        


         [array]$writableServices=@()

         # We are inspecting write access for Authenticated Users group members (SID = "S-1-5-11") and Everyone (SID = "S-1-1-0")	
         $sids = @("S-1-5-11", "S-1-1-0")
         # Services to be ignored are those in system32 subtree
         $services = Get-WmiObject -Class Win32_Service|?{$_.pathname -ne $null -and $_.pathname -notmatch ".*system32.*"}
         
         Write-Host "`n[?] Checking for binary-writable services ..`n" -ForegroundColor Black -BackgroundColor White
         
         try{
 
         if($services){
	 	
                  $services | % {
		  
                         $service = $_

                         $pathname = $($service.pathname.subString(0, $service.pathname.toLower().IndexOf(".exe")+4)).trim('"')
                            
                         $binaryAcl = Get-Acl $pathname  -ErrorAction SilentlyContinue  
                                 
                         if($binaryAcl){    		

                                   foreach($rule in $binaryAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])){
                                        
                                         $sids | %{
                                                
                                                 $sid  = $_
                                                
                                                 if($rule.IdentityReference -eq $sid){

                                                         $accessMask = $rule.FileSystemRights.value__
                        
                                                                 if($accessMask -band 0xd0006){
                                    
                                                                         $writableServices+=$service
                                                                  }
                                                 }
                                         }
                                   } 
                                
                         }
         
	          }

         }

         if($display){

                 if($writableServices.Count -gt 0){

                          $writableServices|ft @{Expression={$_.name};Label="Name";width=12}, `
                                                      @{Expression={$_.pathname};Label="Path"}
                
                 }else{

                                 "       [-] Found no binary-writable service."
                 }

         }else{
 
                 return $writableServices

         }
        
         "`n`n"

       
        }catch{
        
              $errorMessage = $_.Exception.Message
            
              $failedItem   = $_.Exception.ItemName

              "[-] Exception : "| Set-Content $exceptionsFilePath
              
              '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
              "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
        }
      

}



function get-UnquotedPathServices
{
    param([switch]$display)
   
   <#
    .SYNOPSIS
        Looks for services with unquoted path vulnerability .

    .DESCRIPTION
        This function gets all non-system32 services with unquotted pathnames.
     If display switch is used, it displays the name, state, start mode and pathname information,            
     otherwise it returns a array of the vulnerable services.
	      
    .RETURNS
       When invoked without the $display switch, returns a hashtable of {name: pathname}
    couples.
     
   #>

     Write-Host "`n[?] Checking for unquoted path services ..`n" -ForegroundColor Black -BackgroundColor White 

     try{
      
               [array]$services = Get-WmiObject -Class Win32_Service| ? {

                                         $_.pathname.trim() -ne "" -and
                                                    
                                         $_.pathname.trim() -notmatch '^"' -and
                                                
                                         $_.pathname.subString(0, $_.pathname.IndexOf(".exe")+4) -match ".* .*"

               }


               if($display){

                         if($services.Count -gt 0){
                             
                                 $services|ft  @{Expression={$_.name};Label="Name";width=12}, `
                           
                                               @{Expression={$_.state};Label="Sate";width=12}, `
                           
                                                @{Expression={$_.StartMode};Label="Start Mode";width=12}, `
                           
                                                @{Expression={$_.pathname};Label="Path"} ;
                               
                                 ""
                         }else{

                                 "          [-] Found no service with unquoted pathname."
                         }

                         "`n`n"
       
               }else{
              
                         return $services
       
               }


      }catch{
           
              $errorMessage = $_.Exception.Message
            
              $failedItem   = $_.Exception.ItemName

              "[-] Exception : "| Set-Content $exceptionsFilePath
              
              '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
              "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
               
      
      }


}



function get-ConfigurableServices{

      param([Switch]$display)

      <#
           .SYNOPSYS
                Gets all services that the current user can configure

           .DESCRIPTION
                This function tries to enumerate services for which configuration
             properties can be modified by the Authenticated Users group members.
             It uses the sc utility with the sdshow command to inspect the security 
             descriptor of the service object.
                             

           .RETURNS
                When invoked without the $display switch, returns a hashtable of {name: pathname}
             couples.

      #>

            
       $configurable=@{} 
            
       Write-Host "`n[?] Checking for configurable services ..`n" -ForegroundColor Black -BackgroundColor White 
     
       try{       
           
                  Get-WmiObject -Class Win32_Service| ? { $_.pathname -notmatch ".*system32.*"}| % {

                             # get the security descriptor of the service in SDDL format
                  
                             $sddl = [String]$(sc.exe sdshow $($_.Name))
                  
                             if($sddl -match "S:"){
                       
                                      $dacl = $sddl.substring(0,$sddl.IndexOf("S:"))
                  
                             }else{
                       
                                      $dacl = $sddl          
                  
                             }
                
			     # We are interested in permissions related to Authenticated Users and Everyone group which are assigned
                             # well known aliases ("AU", "WD" respectively) in the security descriptor sddl string.
        
                             $permissions = [regex]::match($dacl, '\(A;;[A-Z]+;;;(AU|WD)\)')
		
                             if($permissions){
                  
                                      if($permissions.value.split(';')[2] -match "CR|RP|WP|DT|DC|SD|WD|WO"){

                                                 $configurable[$_.Name] = $($_.pathname.substring(0, $_.pathname.toLower().indexOf(".exe")+4)).trim('"')
 
                                      }
                             }
            
                  }

                  if($display){
                  
                            if($configurable.Count -gt 0){

                                    $configurable.GetEnumerator() | ft  @{Expression={$_.name};Label="Name"}, `
                                                                        @{Expression={$_.value};Label="Path"} ;

                            }else{
                                   
                                    "       [-] Found no configurable services."

                            }

                            "`n`n"
            
                  }else{

                            return $configurable

                  }

       
       }catch{
       
                 
                  $errorMessage = $_.Exception.Message
            
                  $failedItem   = $_.Exception.ItemName

                  "[-] Exception : "| Set-Content $exceptionsFilePath
              
                  '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
                  "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
       
       }
 

}
       

function check-HostedServices {
  
      param([Switch]$display)
      <#
          .SYNOPSIS
               Checks hosted services running DLLs not located in the system32 subtree.

          .DESCRIPTION
               This functions tries to identify whether there are any configured hosted 
           services based on DLLs not in system32.
                
          .RETURNS
               When invoked without the $display switch, returns 
           PSobject array containing the service name, service groupname 
           and the service DLL path. 
        
     #>
       
       
     $exits=$false
       
     $svcs=@()
     
     try{   
       
            $services = Get-WmiObject -Class Win32_service | ?{ $_.pathname -match "svchost\.exe" -and $(Test-Path $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$_.Name+"\Parameters")) -eq $true}
        
            Write-Host "`n[?] Checking hosted services (svchost.exe) ..`n" -ForegroundColor Black -BackgroundColor White 
       
            if($services){
        
                    foreach($service in $services){
                
                            $serviceName  = $service.Name 
              
                            $serviceGroup = $service.pathname.split(" ")[2]
                   
                            $serviceDLLPath=$(Get-ItemProperty $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name+"\Parameters") -Name ServiceDLL).ServiceDLL
                        
                            if($serviceDLLPath -ne $null -and $serviceDLLPath -notmatch ".*system32.*"){ 
                              
                                       $svcs+= New-Object psobject -Property @{
                            
                                                      serviceName    = $serviceName
                                                      serviceGroup   = $serviceGroup
                                                      serviceDLLPath = $serviceDLLPath
                        
                                       }
                       
                                       $exits=$true
                       
                            }
               
                    }

            if($display){   
                         
                    $svcs|ft *
                         
                    "`n`n"
            }else{
                    return $svcs
                
            }
                
        }
        
        if(! $exits){
        
                   "          [-] Found no user hosted services.`n"
                   
        }

   
   
   
   }catch{
             
          $errorMessage = $_.Exception.Message
            
          $failedItem   = $_.Exception.ItemName

          "[-] Exception : "| Set-Content $exceptionsFilePath
              
          '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
          "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
               
   }

  
}

function check-autoruns {

       <#
         .SYNOPSIS
              Looks for autoruns specified in different places in the registry.
                         
         .DESCRIPTION
              This function inspects common registry keys used for autoruns.
          It examines the properties of these keys and report any found executables along with their pathnames.
                  
       #>

    
         $RegistryKeys = @( 
                            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
                            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                            "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
                            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                            "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
                            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"   # DLLs specified in this entry can hijack any process that uses user32.dll 
                            
                             # not sure if it is all we need to check!
                     )


         
         $exits=$false

         Write-Host "`n[?] Checking registry keys for autoruns ..`n" -ForegroundColor Black -BackgroundColor White 

         try{
         
                $RegistryKeys | %{

                             $key = $_

                             if(Test-Path -Path $key){

                                          $executables = @{}

                                          [array]$properties = get-item $key | Select-Object -ExpandProperty Property

                                          if($properties.Count -gt 0){

                                                        "          [*] $key : "

                                                        foreach($exe in $properties) {

                                                                  $executables[$exe]=$($($(Get-ItemProperty $key).$exe)).replace('"','')

                                                        }

                                                        $executables | ft  @{Expression={$_.Name};Label="Executable"}, `
                                                                       @{Expression={$_.Value};Label="Path"}

                                                        $exits=$true
                                          }
                             }
                }



                if($exits -eq $false){

                          "          [-] Found no autoruns ."
                }

                "`n`n"
      
      }catch{
              
               $errorMessage = $_.Exception.Message
            
               $failedItem   = $_.Exception.ItemName

               "[-] Exception : "| Set-Content $exceptionsFilePath
              
               '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
               "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
      
      
      }

 
 }
 
 
 
 
 function check-UnattendedInstallFiles{

      <#  
	     .SYNOPSIS
              Checks for remaining files used by unattended installs .

         .DESCRIPTION
              This functions checks for remaining files used during Windows deployment
	      by searching for specific files .
  
      #>

        $found = $false

        $targetFiles = @(
                            "C:\unattended.xml",
                            "C:\Windows\Panther\unattend.xml",
                            "C:\Windows\Panther\Unattend\Unattend.xml",
                            "C:\Windows\System32\sysprep.inf",
                            "C:\Windows\System32\sysprep\sysprep.xml"

        )

        Write-Host "[?] Checking for unattended install leftovers ..`n" -ForegroundColor Black -BackgroundColor White 

        try{
       
                 $targetFiles | ? {$(Test-Path $_) -eq $true} | %{
	           
		                         $found=$true; "          [+] Found : $_"
            
                 }

        
        
	             if(!$found){

                            "             [-] No unattended install files were found.`n"
                 }
      
                 "`n"

        }catch{
                    
                 $errorMessage = $_.Exception.Message
            
                 $failedItem   = $_.Exception.ItemName
  
                 "[-] Exception : "| Set-Content $exceptionsFilePath
              
                 '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
                 "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath
              
        
       }


}



function check-scheduledTasks {

       <#
	     .SYNOPSIS
             Checks for scheduled tasks whose binaries are not in *.system32.*
   
         .DESCRIPTION
             This function looks for scheduled tasks invoking non-system executables.

         .NOTE
             This functions uses the schtasks.exe utility to get informations about
          scheduled task and then tries to parse the results. Here I choose to parse XML output from the command.
          Another approach would be using the ScheduledTask Powershell module that was introduced starting from version 3.0 .

       #>

        
         $found=$false

         Write-Host "[?] Checking scheduled tasks.." -ForegroundColor Black -BackgroundColor white
         
         try{
                 [xml]$tasksXMLobj = $(schtasks.exe /query /xml ONE)

                 $tasksXMLobj.Tasks.Task | %{

                          $taskCommandPath = [System.Environment]::ExpandEnvironmentVariables($_.actions.exec.command).trim()

                          if($taskCommandPath -ne $null -and $taskCommandPath -notmatch ".*system32.*"){

                                   $sid = New-Object System.Security.Principal.SecurityIdentifier($_.Principals.Principal.UserID)

                                   $taskSecurityContext = $sid.Translate([System.Security.Principal.NTAccount])

                                   $task = New-Object psobject -Property @{

                                             TaskCommand = $taskCommandPath

                                             SecurityContext  = $taskSecurityContext

                                   }

                                   $found=$true

                                   $task
                          }

                 
                 }| fl taskCommand,SecurityContext

                if($found -eq $false){

                          "         [-] No suspicious scheduled tasks were found.`n`n"
                }

         
         }catch{            
                
                $errorMessage = $_.Exception.Message
            
                $failedItem   = $_.Exception.ItemName
           
                "[-] Exception : "| Set-Content $exceptionsFilePath
              
                '[*] Error Message : `n',$errorMessage | Set-Content $exceptionsFilePath
              
                "[*] Failed Item   : `n",$failedItem   | Set-Content $exceptionsFilePath    
         
        }

}



 initialize-audit

