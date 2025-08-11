# Define the root directory to search
$rootPath = "C:\Windows\System32\DriverStore\FileRepository\"
# Define the regular expression pattern to match USB VID:PID
$pattern = "USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}"
# Use a HashSet-like approach to ensure uniqueness
$uniqueVIDPIDs = @{}
# Define common executable extensions
$executableExtensions = @('.exe', '.bat', '.cmd', '.msi')

Write-Host "Step 1: Finding directories with executables..."
# First, find all directories that contain executables
$dirsWithExecutables = @{}
Get-ChildItem -Path $rootPath -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        !$_.PSIsContainer -and 
        $executableExtensions -contains $_.Extension.ToLower() 
    } | 
    ForEach-Object {
        $dirsWithExecutables[$_.DirectoryName] = $true
    }

Write-Host "Found $($dirsWithExecutables.Keys.Count) directories containing executables"
Write-Host "Step 2: Processing INF files in those directories..."

Get-ChildItem -Path $rootPath -Filter *.inf -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.DirectoryName -and $dirsWithExecutables.ContainsKey($_.DirectoryName) } |
    ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                $vidpid = $match.Value -replace "USB\\VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", '$1:$2'
                $uniqueVIDPIDs[$vidpid.ToUpper()] = $true
            }
        } catch {
            Write-Verbose "Error reading file: $($_.FullName)"
        }
    }

# Output the unique matches in VID:PID format
$uniqueVIDPIDs.Keys | Sort-Object | Out-File -FilePath "vid_pid.txt" -Encoding UTF8
Write-Host "Found $($uniqueVIDPIDs.Keys.Count) unique VID:PID pairs from INF files with executables"
