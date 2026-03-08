[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$targets = @('Cargo.toml', 'Cargo.lock') + (Get-ChildItem src -Recurse -File | ForEach-Object { $_.FullName })
$patterns = @(
    'sing-box_mod',
    'sing-box',
    'sing_box',
    'singbox',
    'std::process',
    'tokio::process',
    'Command::new'
)

foreach ($pattern in $patterns) {
    $matches = Select-String -Path $targets -Pattern $pattern
    if ($matches) {
        Write-Error "Forbidden external-core pattern found: $pattern"
        $matches | ForEach-Object {
            Write-Host ("{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line.Trim())
        }
        exit 1
    }
}

Write-Host 'Pure-Rust protocol check passed.'
