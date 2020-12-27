function CSharpToNimByteArray
{

Param
    (
        [string]
        $inputfile,
	    [switch]
        $folder
)

    if ($folder)
    {
        $Files = Get-Childitem -Path $inputfile -File
        $fullname = $Files.FullName
        foreach($file in $fullname)
        {
            Write-Host "Converting $file"
            $outfile = $File + "NimByteArray.txt"
    
            [byte[]] $hex = get-content -encoding byte -path $File
            $hexString = ($hex|ForEach-Object ToString X2) -join ',0x'
            $Results = $hexString.Insert(0,"var buf: array[" + $hex.Length + ", byte] = [byte 0x")
            $Results = $Results + "]"         
            $Results | out-file $outfile
         
        }
        Write-Host -ForegroundColor yellow "Results Written to the same folder"
    }
    else
    {
        Write-Host "Converting $inputfile"
        $outfile = $inputfile + "NimByteArray.txt"
        
        [byte[]] $hex = get-content -encoding byte -path $inputfile
        $hexString = ($hex|ForEach-Object ToString X2) -join ',0x'
        $Results = $hexString.Insert(0,"var buf: array[" + $hex.Length + ", byte] = [byte 0x")
        $Results = $Results + "]"         
        $Results | out-file $outfile
        Write-Host "Result Written to $outfile"
    }
} 
