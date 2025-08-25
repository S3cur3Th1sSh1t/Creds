
$DriverStore = "C:\temp\"
$WeakSddlPatterns = @(
    'A;;GA;;BU',  # Generic All for Built-in Users
    'A;;GW;;BU',  # Generic Write for Built-in Users
    'A;;GX;;BU',  # Execute rights for Users (can be risky in registry context)
    'A;;GA;;WD',  # Generic All for Everyone
    'A;;GW;;WD',  # Generic Write for Everyone
    'A;;GA;;AU',  # Generic All for Authenticated Users
    'A;;GW;;AU'   # Generic Write for Authenticated Users
)

Write-Host "Scanning INF files for weak registry ACEs..." -ForegroundColor Cyan

Get-ChildItem -Path $DriverStore -Recurse -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object {
    $File = $_.FullName
    $Content = Get-Content -Path $File -ErrorAction SilentlyContinue
    
    foreach ($Pattern in $WeakSddlPatterns) {
        if ($Content -match [regex]::Escape($Pattern)) {
            Write-Host "[!] Weak ACE found in:" $File -ForegroundColor Red
            Write-Host "    Matching pattern: $Pattern" -ForegroundColor Yellow
            break
        }
    }
}
