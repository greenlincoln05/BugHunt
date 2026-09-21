param(
    [int]$IntervalSeconds = 900,
    [int]$MaxPages = 3
)

$ErrorActionPreference = 'Stop'
if ($IntervalSeconds -lt 60 -or $IntervalSeconds -gt 86400) { throw 'IntervalSeconds must be 60-86400.' }
if ($MaxPages -lt 1 -or $MaxPages -gt 20) { throw 'MaxPages must be 1-20.' }
$bughuntRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$bughuntRuntime = (Get-Command python -ErrorAction Stop).Source
$bughuntLogDir = Join-Path $bughuntRoot '.bughunt'
New-Item -ItemType Directory -Path $bughuntLogDir -Force | Out-Null
$bughuntPriorIdentifier = $env:HACKERONE_USERNAME
$bughuntPriorToken = $env:HACKERONE_API_TOKEN
$bughuntTokenPointer = [IntPtr]::Zero
try {
    if (-not $env:HACKERONE_USERNAME) {
        $env:HACKERONE_USERNAME = Read-Host 'HackerOne API token identifier (from API settings)'
    }
    if (-not $env:HACKERONE_API_TOKEN) {
        $bughuntSecret = Read-Host 'HackerOne API token (hidden)' -AsSecureString
        $bughuntTokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($bughuntSecret)
        $env:HACKERONE_API_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bughuntTokenPointer)
    }
    if (-not $env:HACKERONE_USERNAME -or -not $env:HACKERONE_API_TOKEN) { throw 'Both credential values are required.' }
    # Credentials are inherited through the child environment, never command arguments.
    $bughuntArguments = @('-u', 'run_bughunt.py', 'worker', 'run', '--interval-seconds', "$IntervalSeconds", '--max-pages', "$MaxPages")
    $bughuntProcess = Start-Process -FilePath $bughuntRuntime -WorkingDirectory $bughuntRoot -ArgumentList $bughuntArguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $bughuntLogDir 'worker.stdout.log') -RedirectStandardError (Join-Path $bughuntLogDir 'worker.stderr.log')
    Write-Output "Worker started with PID $($bughuntProcess.Id). Check: python run_bughunt.py worker status"
    Write-Output 'Stop: python run_bughunt.py worker stop'
    Write-Output 'Discovery prepares program candidates; it does not test targets or submit reports.'
} finally {
    if ($bughuntTokenPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bughuntTokenPointer) }
    if ($bughuntSecret) { $bughuntSecret.Dispose() }
    $env:HACKERONE_USERNAME = $bughuntPriorIdentifier
    $env:HACKERONE_API_TOKEN = $bughuntPriorToken
}
