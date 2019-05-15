function Invoke-SMBNegotiate
{
<#
.SYNOPSIS

    Enumerates whether SMB signing is enabled on host.
    
    Author: Kevin Robertson (@kevin_robertson) with modifications by Lee Christensen (@tifkin_)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION
    
    Enumerates whether SMB signing is enabled on host. It does this by implementing the SMB
    protocol and determing whether the remote server requires SMB signing.
    
    Basically all this was developed by Kevin Robertson's Inveigh project
    (https://github.com/Kevin-Robertson/Inveigh). The code was slightly modified for ease of
    use.

.PARAMETER ComputerName

    The target computer

.EXAMPLE
    
    Invoke-SMBNegotiate -ComputerName localhost

.EXAMPLE

    'JOHN-PC',"BOB-PC','localhost' | Invoke-SMBNegotiate -ErrorAction SilentlyContinue

#>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [string]
        $ComputerName
    )

    Begin {

    function ConvertFrom-PacketOrderedDictionary
    {
        param($OrderedDictionary)

        ForEach($field in $OrderedDictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }
    
    function Get-ProcessIDArray
    {
        $process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
        $process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
        [Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        return $process_ID
    }
    
    #region NetBIOS
    function New-PacketNetBIOSSessionService
    {
        param([Int]$HeaderLength,[Int]$DataLength)
    
        [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]
    
        $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
        $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
        $NetBIOSSessionService.Add("Length",$length)
    
        return $NetBIOSSessionService
    }
    #endregion

    #region SMB1
    function New-PacketSMBHeader
    {
        param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)
    
        $ProcessID = $ProcessID[0,1]
    
        $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
        $SMBHeader.Add("Command",$Command)
        $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
        $SMBHeader.Add("Reserved",[Byte[]](0x00))
        $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
        $SMBHeader.Add("Flags",$Flags)
        $SMBHeader.Add("Flags2",$Flags2)
        $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
        $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
        $SMBHeader.Add("TreeID",$TreeID)
        $SMBHeader.Add("ProcessID",$ProcessID)
        $SMBHeader.Add("UserID",$UserID)
        $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))
    
        return $SMBHeader
    }


    function New-PacketSMBNegotiateProtocolRequest
    {
        param([String]$Version)
    
        if($Version -eq 'SMB1')
        {
            [Byte[]]$byte_count = 0x0c,0x00
        }
        else
        {
            [Byte[]]$byte_count = 0x22,0x00  
        }
    
        $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
        $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
    
        if($version -ne 'SMB1')
        {
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }
    
        return $SMBNegotiateProtocolRequest
    }
    #endregion

    #region SMB2
    function New-PacketSMB2Header
    {
        param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)
    
        if($Signing)
        {
            $flags = 0x08,0x00,0x00,0x00      
        }
        else
        {
            $flags = 0x00,0x00,0x00,0x00
        }
    
        [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)
    
        if($message_ID.Length -eq 4)
        {
            $message_ID += 0x00,0x00,0x00,0x00
        }
    
        $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
        $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
        $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
        $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
        $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2Header.Add("Command",$Command)
        $SMB2Header.Add("CreditRequest",$CreditRequest)
        $SMB2Header.Add("Flags",$flags)
        $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2Header.Add("MessageID",$message_ID)
        $SMB2Header.Add("ProcessID",$ProcessID)
        $SMB2Header.Add("TreeID",$TreeID)
        $SMB2Header.Add("SessionID",$SessionID)
        $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    
        return $SMB2Header
    }
    
    function New-PacketSMB2NegotiateProtocolRequest
    {
        $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
        $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
        $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
        $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
        $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))
    
        return $SMB2NegotiateProtocolRequest
    }
    
    function New-PacketSMB2SessionSetupRequest
    {
        param([Byte[]]$SecurityBlob)
    
        [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]
    
        $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
        $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
        $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
        $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
        $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
        $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)
    
        return $SMB2SessionSetupRequest 
    }
    
    function New-PacketSMB2TreeConnectRequest
    {
        param([Byte[]]$Buffer)
    
        [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]
    
        $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
        $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
        $SMB2TreeConnectRequest.Add("PathLength",$path_length)
        $SMB2TreeConnectRequest.Add("Buffer",$Buffer)
    
        return $SMB2TreeConnectRequest
    }
    
    function New-PacketSMB2CreateRequestFile
    {
        param([Byte[]]$NamedPipe)
    
        $name_length = ([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]
    
        $SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
        $SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
        $SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
        $SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
        $SMB2CreateRequestFile.Add("NameLength",$name_length)
        $SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("Buffer",$NamedPipe)
    
        return $SMB2CreateRequestFile
    }
    
    function New-PacketSMB2ReadRequest
    {
        param ([Byte[]]$FileID)
    
        $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
        $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
        $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
        $SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
        $SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("FileID",$FileID)
        $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
        $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
        $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))
    
        return $SMB2ReadRequest
    }
    
    function New-PacketSMB2WriteRequest
    {
        param([Byte[]]$FileID,[Int]$RPCLength)
    
        [Byte[]]$write_length = [System.BitConverter]::GetBytes($RPCLength)
    
        $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
        $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
        $SMB2WriteRequest.Add("Length",$write_length)
        $SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2WriteRequest.Add("FileID",$FileID)
        $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
        $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
        $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    
        return $SMB2WriteRequest
    }
    
    function New-PacketSMB2CloseRequest
    {
        param ([Byte[]]$FileID)
    
        $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
        $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
        $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CloseRequest.Add("FileID",$FileID)
    
        return $SMB2CloseRequest
    }
    
    function New-PacketSMB2TreeDisconnectRequest
    {
        $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    
        return $SMB2TreeDisconnectRequest
    }
    
    function New-PacketSMB2SessionLogoffRequest
    {
        $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))
    
        return $SMB2SessionLogoffRequest
    }

    function New-PacketSMB2QueryInfoRequest
    {
        param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$OutputBufferLength,[Byte[]]$InputBufferOffset,[Byte[]]$FileID,[Int]$Buffer)

        [Byte[]]$buffer_bytes = ,0x00 * $Buffer

        $SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2QueryInfoRequest.Add("StructureSize",[Byte[]](0x29,0x00))
        $SMB2QueryInfoRequest.Add("InfoType",$InfoType)
        $SMB2QueryInfoRequest.Add("FileInfoClass",$FileInfoClass)
        $SMB2QueryInfoRequest.Add("OutputBufferLength",$OutputBufferLength)
        $SMB2QueryInfoRequest.Add("InputBufferOffset",$InputBufferOffset)
        $SMB2QueryInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2QueryInfoRequest.Add("InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2QueryInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2QueryInfoRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2QueryInfoRequest.Add("FileID",$FileID)

        if($Buffer -gt 0)
        {
            $SMB2QueryInfoRequest.Add("Buffer",$buffer_bytes)
        }

        return $SMB2QueryInfoRequest
    }

    function New-PacketSMB2IoctlRequest
    {
        param([Byte[]]$Function,[Byte[]]$FileName,[Int]$Length,[Int]$OutSize)

        [Byte[]]$indata_length = [System.BitConverter]::GetBytes($Length + 24)
        [Byte[]]$out_size = [System.BitConverter]::GetBytes($OutSize)

        $SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
        $SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2IoctlRequest.Add("Function",$Function)
        $SMB2IoctlRequest.Add("GUIDHandle",$FileName)
        $SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("InData_Length",$indata_length)
        $SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("MaxIoctlOutSize",$out_size)
        $SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))

        if($out_size -eq 40)
        {
            $SMB2IoctlRequest.Add("InData_Capabilities",[Byte[]](0x7f,0x00,0x00,0x00))
            $SMB2IoctlRequest.Add("InData_ClientGUID",[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
            $SMB2IoctlRequest.Add("InData_SecurityMode",[Byte[]](0x01))
            $SMB2IoctlRequest.Add("InData_Unknown",[Byte[]](0x00))
            $SMB2IoctlRequest.Add("InData_DialectCount",[Byte[]](0x02,0x00))
            $SMB2IoctlRequest.Add("InData_Dialect",[Byte[]](0x02,0x02))
            $SMB2IoctlRequest.Add("InData_Dialect2",[Byte[]](0x10,0x02))
        }

        return $SMB2IoctlRequest
    }
    #endregion

    #region NTLM - Currently not used

    function New-PacketNTLMSSPNegotiate
    {
        param([Byte[]]$NegotiateFlags,[Byte[]]$Version)
    
        [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
        [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
        [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
        [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
        [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2
    
        $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
        $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
        $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
        $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
        $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
        $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
        $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
        $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
        $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
        $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
        $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
        $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
        $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
        $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
        $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
        $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
        $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
        $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    
        if($Version)
        {
            $NTLMSSPNegotiate.Add("Version",$Version)
        }
    
        return $NTLMSSPNegotiate
    }
    
    function New-PacketNTLMSSPAuth
    {
        param([Byte[]]$NTLMResponse)
    
        [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
        [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
        [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
        [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]
    
        $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
        $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
        $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
        $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
        $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
        $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
        $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
        $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
        $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
        $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)
    
        return $NTLMSSPAuth
    }
    #endregion

    }

    Process {
        try {
            $client = New-Object System.Net.Sockets.TCPClient
            $client.Client.ReceiveTimeout = 60000
            $null = $client.Connect($ComputerName,"445")
        } catch {
            Write-Error "Could not connect to $ComputerName"
            return
        }

        $ProcessId = Get-ProcessIDArray
        try
        {
            $client_stream = $client.GetStream()
            $stage = 'NegotiateSMB'
            $client_receive = New-Object System.Byte[] 1024
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            Write-Error ("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim()) stage $stage")
            $stage = 'Exit'
        }

        while($stage -ne 'Exit')
        {
            try
            {
                
                switch ($stage)
                {

                    'NegotiateSMB'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $ProcessID 0x00,0x00       
                        $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                        {
                            $SMB2 = $false
                            #Write-Error ("[!] [$(Get-Date -format s)] Negotiated SMB1 not supported") > $null
                            #Write-Warning ("[*] [$(Get-Date -format s)] Trying anonther target") > $null
                            $client.Close()
                            $stage = 'Exit'
                        }
                        else
                        {
                            $SMB2 = $true
                            $stage = 'NegotiateSMB2'
                        }

                        if($ComputerName -and [System.BitConverter]::ToString($client_receive[70]) -eq '03')
                        {        
                            #Write-Warning ("[!] [$(Get-Date -format s)] Signing is required on $ComputerName")
                            #Write-Warning ("[*] [$(Get-Date -format s)] Trying another target")
                            $signing = $true
                            $client.Close()
                            $stage = 'Exit'
                        }
                        else
                        {
                            $signing = $false    
                        }

                    }
                        
                    'NegotiateSMB2'
                    { 
                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $message_ID = 1
                        $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $ProcessID $tree_ID $session_ID  
                        $packet_SMB2_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                        #Write-Warning ("[!] [$(Get-Date -format s)] Grabbing challenge for relay from $ComputerName")
                    }
                    
                }

            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                Write-Error ("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim()) stage $stage")
                $stage = 'Exit'
            }
            
        }
    
        if($Client -ne $null) {
            $client.Close()
        }

        New-Object PSObject -Property @{
            ComputerName = $ComputerName
            SMBv2 = $SMB2
            SmbSigning = $signing
        }
    }
}
