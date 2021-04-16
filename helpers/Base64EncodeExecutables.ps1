function base64encodeExecutables
{
param (
   [string]$directory  = $(throw "-directory is required.")
)
function base64
{

param (
   [string]$inputFile  = $(throw "-inputFile is required."),
   [string]$outputFile = $(throw "-outputFile is required.")
)

Write-Host ""
Write-Host "Reading input file: " -NoNewline 
Write-Host $inputFile 
Write-Host ""
$content = [io.file]::ReadAllBytes("$inputFile")
if( $content -eq $null ) {
	Write-Host "No data found. May be read error or file protected."
	exit -2
}

$script = [System.Convert]::ToBase64String($content)

Write-Host "Writing Base64 string to: " -NoNewline 
Write-Host $outputFile 
Write-Host ""
$script | out-file $outputFile

}

Get-ChildItem "$directory" -Filter *.exe | 
Foreach-Object {
    $out = $_.FullName + ".txt"
    base64 -inputfile $_.FullName -outputFile $out

}
}
