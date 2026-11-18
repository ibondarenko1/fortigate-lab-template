[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_.][a-zA-Z0-9_.@-]+$')][string]$SshHost,
    [Parameter(Mandatory)][ValidateRange(1024,65535)][int]$LocalPort,
    [Parameter(Mandatory)][ValidateRange(1024,65535)][int]$RemotePort,
    [string]$IdentityFile,
    [switch]$ExistingLabBridge,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$forward = "127.0.0.1:${LocalPort}:127.0.0.1:$RemotePort"
$url = if ($ExistingLabBridge) { "http://127.0.0.1:$LocalPort/_lab/open" } else { "https://127.0.0.1:$LocalPort/" }
$listener = Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue
if ($listener) {
    $candidate = $listener | Where-Object LocalAddress -eq '127.0.0.1' | Select-Object -First 1
    $process = if ($candidate) { Get-CimInstance Win32_Process -Filter "ProcessId=$($candidate.OwningProcess)" }
    $expectedTarget = '\s' + [regex]::Escape($SshHost) + '\s*$'
    if (-not $process -or $process.Name -ne 'ssh.exe' -or
        $process.CommandLine -notmatch [regex]::Escape($forward) -or $process.CommandLine -notmatch $expectedTarget) {
        throw "Local port $LocalPort is already occupied by a different listener."
    }
} else {
    $sshArgs = @(
        '-N', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=8',
        '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3',
        '-L', $forward
    )
    if ($IdentityFile) {
        $key = (Resolve-Path -LiteralPath $IdentityFile).ProviderPath
        if ($key.Contains('"')) { throw 'Invalid identity file path' }
        $sshArgs += @('-o', 'IdentitiesOnly=yes', '-i', ('"' + $key + '"'))
    }
    $sshArgs += $SshHost
    $process = Start-Process "$env:WINDIR/System32/OpenSSH/ssh.exe" -ArgumentList $sshArgs -WindowStyle Hidden -PassThru
    $ready = $false
    try {
        for ($attempt = 0; $attempt -lt 16; $attempt++) {
            if ($process.HasExited) { break }
            $ready = $null -ne (Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $LocalPort -State Listen -OwningProcess $process.Id -ErrorAction SilentlyContinue)
            if ($ready) { break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) { throw "SSH did not open the loopback tunnel on $LocalPort." }
    } finally {
        if (-not $ready -and -not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

if (-not $NoBrowser) { Start-Process $url }
Write-Output $url
