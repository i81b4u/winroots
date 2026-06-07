#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # curl publishes a PEM bundle generated from Mozilla's CA certificate store.
    [string]$SourceUrl = 'https://curl.se/ca/cacert.pem',

    # The current Windows AuthRoot store is exported before anything is changed.
    [string]$BackupPath = (Join-Path -Path (Get-Location) -ChildPath ('thirdpartyrootsbackup-{0}.p7b' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    # The downloaded PEM file is temporary and is removed when the script exits.
    [string]$DownloadPath = (Join-Path -Path $env:TEMP -ChildPath ('mozilla-cacert-{0}.pem' -f ([guid]::NewGuid().ToString('N')))),

    # When set, the existing AuthRoot store is cleared before importing Mozilla roots.
    [switch]$Replace
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    # Writing to LocalMachine certificate stores requires an elevated session.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CertificatesFromPem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Windows PowerShell 5.1 cannot import a multi-certificate PEM bundle directly
    # into AuthRoot, so split the bundle and construct X509Certificate2 objects.
    $pem = Get-Content -LiteralPath $Path -Raw
    $pattern = '-----BEGIN CERTIFICATE-----\s*(?<Body>[A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----'
    $matches = [regex]::Matches($pem, $pattern)

    foreach ($match in $matches) {
        $body = $match.Groups['Body'].Value -replace '\s', ''
        $bytes = [Convert]::FromBase64String($body)
        New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    }
}

if (-not (Test-IsAdministrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

if (-not ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls12')) {
    throw 'TLS 1.2 is not available in this PowerShell/.NET runtime.'
}

# Make sure older Windows PowerShell/.NET defaults can still connect to curl.se.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Verbose "Downloading Mozilla-derived CA bundle from $SourceUrl"
Invoke-WebRequest -Uri $SourceUrl -OutFile $DownloadPath -UseBasicParsing

$mozillaRoots = @(Get-CertificatesFromPem -Path $DownloadPath)
if ($mozillaRoots.Count -eq 0) {
    throw "No certificates found in downloaded bundle: $DownloadPath"
}

$store = New-Object Security.Cryptography.X509Certificates.X509Store('AuthRoot', 'LocalMachine')
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

try {
    # Take a PKCS#7 backup first so the previous store can be restored manually.
    $existingRoots = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    $existingRoots.AddRange($store.Certificates)

    if ($existingRoots.Count -gt 0) {
        $backupDirectory = Split-Path -Parent $BackupPath
        if ($backupDirectory -and -not (Test-Path -LiteralPath $backupDirectory)) {
            New-Item -Path $backupDirectory -ItemType Directory -Force | Out-Null
        }

        $backupBytes = $existingRoots.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7)
        [IO.File]::WriteAllBytes($BackupPath, $backupBytes)
        Write-Host "Backed up $($existingRoots.Count) existing AuthRoot certificate(s) to $BackupPath"
    }
    else {
        Write-Host 'AuthRoot store is empty; no backup file was written.'
    }

    if ($Replace) {
        # Copy the collection to an array before removing items from the store.
        Write-Verbose 'Removing existing AuthRoot certificates'
        foreach ($certificate in @($store.Certificates)) {
            if ($PSCmdlet.ShouldProcess($certificate.Subject, 'Remove certificate from LocalMachine\AuthRoot')) {
                $store.Remove($certificate)
            }
        }
    }

    $imported = 0
    $skipped = 0

    foreach ($certificate in $mozillaRoots) {
        # Import only certificates that are not already present by thumbprint.
        $alreadyPresent = $false
        foreach ($existing in $store.Certificates) {
            if ($existing.Thumbprint -eq $certificate.Thumbprint) {
                $alreadyPresent = $true
                break
            }
        }

        if ($alreadyPresent) {
            $skipped++
            continue
        }

        if ($PSCmdlet.ShouldProcess($certificate.Subject, 'Import certificate into LocalMachine\AuthRoot')) {
            $store.Add($certificate)
            $imported++
        }
    }
}
finally {
    $store.Close()

    # Do not leave the downloaded CA bundle behind unless cleanup fails.
    if (Test-Path -LiteralPath $DownloadPath) {
        Remove-Item -LiteralPath $DownloadPath -Force
    }
}

Write-Host "Downloaded $($mozillaRoots.Count) Mozilla root certificate(s)."
Write-Host "Imported $imported certificate(s); skipped $skipped already-present certificate(s)."
