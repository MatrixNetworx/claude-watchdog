# Windows PowerShell 5.1+ or PowerShell 7; token analytics only.
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'usage-windows.py'
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $scriptPath @args
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $scriptPath @args
} else {
    throw 'Install Python 3.9+ and ensure py or python is on PATH.'
}
