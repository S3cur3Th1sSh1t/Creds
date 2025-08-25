# Search for weak ACEs inside DriverStore INF files
$DriverStore = "C:\Windows\System32\DriverStore"

# More flexible patterns - looking for SDDL components without rigid structure
$WeakSddlPatterns = @(
    'A;[^;]*;GA;[^;]*;BU',  # Generic All for Built-in Users (flexible)
    'A;[^;]*;GW;[^;]*;BU',  # Generic Write for Built-in Users
    'A;[^;]*;GX;[^;]*;BU',  # Execute rights for Users
    'A;[^;]*;GA;[^;]*;WD',  # Generic All for Everyone
    'A;[^;]*;GW;[^;]*;WD',  # Generic Write for Everyone
    'A;[^;]*;GA;[^;]*;AU',  # Generic All for Authenticated Users
    'A;[^;]*;GW;[^;]*;AU',  # Generic Write for Authenticated Users
    'GA.*BU',               # Generic All + Built-in Users (loose match)
    'GW.*BU',               # Generic Write + Built-in Users
    'GA.*WD',               # Generic All + Everyone
    'GW.*WD'                # Generic Write + Everyone
)

# Also look for suspicious registry security entries
$SuspiciousRegistryPatterns = @(
    'HKR.*Security.*".*GA.*"',  # HKR entries with Generic All
    'HKR.*Security.*".*GW.*"',  # HKR entries with Generic Write
    'AddReg.*Security.*GA',     # AddReg with Generic All
    'AddReg.*Security.*GW'      # AddReg with Generic Write
)

Write-Host "Scanning INF files for weak registry ACEs..." -ForegroundColor Cyan
Write-Host "Driver Store Path: $DriverStore" -ForegroundColor Gray

$FoundFiles = 0
$TotalFiles = 0

Get-ChildItem -Path $DriverStore -Recurse -Filter *.inf -ErrorAction SilentlyContinue | ForEach-Object {
    $TotalFiles++
    $File = $_.FullName
    $Content = Get-Content -Path $File -Raw -ErrorAction SilentlyContinue
    
    if (-not $Content) {
        return
    }
    
    $WeakFound = $false
    
    # Check SDDL patterns
    foreach ($Pattern in $WeakSddlPatterns) {
        if ($Content -match $Pattern) {
            if (-not $WeakFound) {
                Write-Host "[!] Potentially weak ACE found in:" -ForegroundColor Red
                Write-Host "    $File" -ForegroundColor Yellow
                $FoundFiles++
                $WeakFound = $true
            }
            Write-Host "    SDDL Pattern match: $Pattern" -ForegroundColor Magenta
            
            # Show context around the match
            $matches = [regex]::Matches($Content, $Pattern)
            foreach ($match in $matches) {
                $start = [Math]::Max(0, $match.Index - 50)
                $length = [Math]::Min(100, $Content.Length - $start)
                $context = $Content.Substring($start, $length).Replace("`n", " ").Replace("`r", "")
                Write-Host "    Context: ...$context..." -ForegroundColor DarkGray
            }
        }
    }
    
    # Check registry-specific patterns
    foreach ($Pattern in $SuspiciousRegistryPatterns) {
        if ($Content -match $Pattern) {
            if (-not $WeakFound) {
                Write-Host "[!] Suspicious registry security found in:" -ForegroundColor Red
                Write-Host "    $File" -ForegroundColor Yellow
                $FoundFiles++
                $WeakFound = $true
            }
            Write-Host "    Registry Pattern match: $Pattern" -ForegroundColor Magenta
        }
    }
    
    # Also look for any SDDL-like strings (D: descriptor format)
    if ($Content -match 'D:\([^)]*A;[^;]*;G[AW];[^;]*;[BUWDA][UWD]') {
        if (-not $WeakFound) {
            Write-Host "[!] SDDL descriptor found in:" -ForegroundColor Red
            Write-Host "    $File" -ForegroundColor Yellow
            $FoundFiles++
            $WeakFound = $true
        }
        Write-Host "    SDDL descriptor detected" -ForegroundColor Magenta
    }
}

Write-Host "`nScan complete!" -ForegroundColor Green
Write-Host "Files scanned: $TotalFiles" -ForegroundColor Gray
Write-Host "Files with potential issues: $FoundFiles" -ForegroundColor Gray

if ($FoundFiles -eq 0) {
    Write-Host "`nNo obvious weak ACEs found in INF files." -ForegroundColor Green
    Write-Host "This could mean:" -ForegroundColor Yellow
    Write-Host "- Security descriptors are properly configured" -ForegroundColor Yellow
    Write-Host "- Security info is in binary format or external files" -ForegroundColor Yellow
    Write-Host "- Different SDDL format is used" -ForegroundColor Yellow
}
