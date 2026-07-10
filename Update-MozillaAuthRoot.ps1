#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # curl publishes a PEM bundle generated from Mozilla's CA certificate store.
    [ValidatePattern('^https://')]
    [string]$SourceUrl = 'https://curl.se/ca/cacert.pem',

    # SHA-256 expected for the exact downloaded PEM. Obtain it independently.
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSha256,

    # Reject suspiciously incomplete bundles. curl's bundle has well over 100 roots.
    [ValidateRange(1, 1000)]
    [int]$MinimumCertificateCount = 100,

    # The current Windows AuthRoot store is exported before anything is changed.
    [string]$BackupPath = (Join-Path -Path (Get-Location) -ChildPath ('thirdpartyrootsbackup-{0}.p7b' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    # The downloaded PEM file is temporary and is removed when the script exits.
    [string]$DownloadPath = (Join-Path -Path $env:TEMP -ChildPath ('mozilla-cacert-{0}.pem' -f ([guid]::NewGuid().ToString('N')))),

    # Remove certificates that are not in the Mozilla-derived bundle after all additions succeed.
    [switch]$Replace
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CertificatesFromPem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Windows PowerShell 5.1 cannot import a multi-certificate PEM bundle directly.
    $pem = Get-Content -LiteralPath $Path -Raw
    $pattern = '-----BEGIN CERTIFICATE-----\s*(?<Body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----'
    $matches = [regex]::Matches($pem, $pattern)
    $beginCount = [regex]::Matches($pem, '-----BEGIN CERTIFICATE-----').Count
    $endCount = [regex]::Matches($pem, '-----END CERTIFICATE-----').Count

    if ($matches.Count -eq 0 -or $matches.Count -ne $beginCount -or $matches.Count -ne $endCount) {
        throw 'The downloaded PEM bundle contains no certificates or has malformed certificate delimiters.'
    }

    $certificates = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    $thumbprints = @{}
    foreach ($match in $matches) {
        $bytes = [Convert]::FromBase64String(($match.Groups['Body'].Value -replace '\s', ''))
        $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)

        $basicConstraints = $certificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | Select-Object -First 1
        if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority) {
            throw "Downloaded bundle contains a certificate that is not a CA: $($certificate.Subject)"
        }

        $keyUsage = $certificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] } | Select-Object -First 1
        if ($keyUsage -and -not (($keyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -ne 0)) {
            throw "Downloaded bundle contains a CA without key-cert-sign usage: $($certificate.Subject)"
        }

        if ($certificate.HasPrivateKey) {
            throw "Downloaded bundle contains a certificate with a private key: $($certificate.Subject)"
        }

        if ($thumbprints.ContainsKey($certificate.Thumbprint)) {
            throw "Downloaded bundle contains the same certificate more than once: $($certificate.Thumbprint)"
        }

        $thumbprints[$certificate.Thumbprint] = $true
        [void]$certificates.Add($certificate)
    }

    # Keep the collection intact rather than writing each certificate to the pipeline.
    return ,$certificates
}

function Get-ThumbprintMap {
    param([Security.Cryptography.X509Certificates.X509Certificate2Collection]$Certificates)

    $map = @{}
    foreach ($certificate in $Certificates) {
        $map[$certificate.Thumbprint] = $certificate
    }
    return $map
}

if (-not (Test-IsAdministrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

if (-not ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls12')) {
    throw 'TLS 1.2 is not available in this PowerShell/.NET runtime.'
}

if (-not $ExpectedSha256 -and -not $WhatIfPreference) {
    throw 'Pass -ExpectedSha256 with a trusted SHA-256 value for the exact PEM bundle. Use -WhatIf to inspect changes without modifying the store.'
}

# Make sure older Windows PowerShell/.NET defaults can still connect to curl.se.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$store = $null
try {
    Write-Verbose "Downloading Mozilla-derived CA bundle from $SourceUrl"
    Invoke-WebRequest -Uri $SourceUrl -OutFile $DownloadPath -UseBasicParsing

    # A PEM parser only proves the file is well-formed; bind it to an independently
    # obtained digest before it can supply new machine trust anchors.
    $actualSha256 = (Get-FileHash -LiteralPath $DownloadPath -Algorithm SHA256).Hash
    if ($ExpectedSha256 -and $actualSha256 -ne $ExpectedSha256.ToUpperInvariant()) {
        throw "Downloaded bundle SHA-256 does not match -ExpectedSha256. Expected $($ExpectedSha256.ToUpperInvariant()), got $actualSha256."
    }
    Write-Verbose "Verified downloaded bundle SHA-256: $actualSha256"

    $mozillaRoots = Get-CertificatesFromPem -Path $DownloadPath
    if ($mozillaRoots.Count -lt $MinimumCertificateCount) {
        throw "Downloaded bundle contains $($mozillaRoots.Count) certificate(s), below -MinimumCertificateCount ($MinimumCertificateCount)."
    }

    $store = New-Object Security.Cryptography.X509Certificates.X509Store('AuthRoot', 'LocalMachine')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    $existingRoots = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    $existingRoots.AddRange($store.Certificates)
    $mozillaByThumbprint = Get-ThumbprintMap -Certificates $mozillaRoots
    $existingByThumbprint = Get-ThumbprintMap -Certificates $existingRoots
    $rootsToAdd = @($mozillaRoots | Where-Object { -not $existingByThumbprint.ContainsKey($_.Thumbprint) })
    $rootsToRemove = @()
    if ($Replace) {
        # Work from the desired set, rather than clearing AuthRoot. This lets all
        # additions succeed and be verified before any existing root is removed.
        $rootsToRemove = @($existingRoots | Where-Object { -not $mozillaByThumbprint.ContainsKey($_.Thumbprint) })
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess('LocalMachine\AuthRoot', "Back up $($existingRoots.Count) certificate(s) to $BackupPath; import $($rootsToAdd.Count); remove $($rootsToRemove.Count)")
        Write-Host "What if: bundle contains $($mozillaRoots.Count) Mozilla root certificate(s); would import $($rootsToAdd.Count) and remove $($rootsToRemove.Count)."
        return
    }

    $hasChanges = $rootsToAdd.Count -gt 0 -or $rootsToRemove.Count -gt 0
    if ($hasChanges -and -not $PSCmdlet.ShouldProcess('LocalMachine\AuthRoot', "Back up $($existingRoots.Count) certificate(s) to $BackupPath; import $($rootsToAdd.Count); remove $($rootsToRemove.Count)")) {
        Write-Host 'No changes were made.'
        return
    }

    if ($hasChanges) {
        # Persist recovery material before the first store mutation.
        $backupDirectory = Split-Path -Parent $BackupPath
        if ($backupDirectory -and -not (Test-Path -LiteralPath $backupDirectory)) {
            New-Item -Path $backupDirectory -ItemType Directory -Force | Out-Null
        }
        $backupBytes = $existingRoots.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7)
        [IO.File]::WriteAllBytes($BackupPath, $backupBytes)
        Write-Host "Backed up $($existingRoots.Count) existing AuthRoot certificate(s) to $BackupPath"
    }

    $imported = 0
    foreach ($certificate in $rootsToAdd) {
        $store.Add($certificate)
        $imported++
    }

    # Never remove a root until every desired root is in the store.
    $currentByThumbprint = Get-ThumbprintMap -Certificates $store.Certificates
    $missingRoots = @($mozillaRoots | Where-Object { -not $currentByThumbprint.ContainsKey($_.Thumbprint) })
    if ($missingRoots.Count -gt 0) {
        throw "Refusing to remove existing roots because $($missingRoots.Count) Mozilla root certificate(s) are missing after import."
    }

    $removed = 0
    foreach ($certificate in $rootsToRemove) {
        $store.Remove($certificate)
        $removed++
    }

    Write-Host "Verified $($mozillaRoots.Count) Mozilla root certificate(s)."
    Write-Host "Imported $imported certificate(s); removed $removed certificate(s); retained $($mozillaRoots.Count - $imported) already-present Mozilla certificate(s)."
}
finally {
    if ($store) {
        $store.Close()
    }

    if (Test-Path -LiteralPath $DownloadPath) {
        # Cleanup is intentional even for -WhatIf: the download itself is temporary.
        Remove-Item -LiteralPath $DownloadPath -Force -WhatIf:$false
    }
}
