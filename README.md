# winroots

`Update-MozillaAuthRoot.ps1` manages Windows' **Third-party Root Certification Authorities** store (`Cert:\LocalMachine\AuthRoot`) from curl's PEM conversion of Mozilla's CA store. This is a security-sensitive operation: certificates in this store can establish trust for TLS, code signing, Wi-Fi/VPN, proxy inspection, and internal services.

The curl bundle is a conversion of Mozilla's store, not Mozilla's original trust database. In particular, it does not retain browser-specific constraints such as name constraints. See curl's [CA Extract documentation](https://curl.se/docs/caextract.html).

## Before you run it

- Run it only from an elevated Windows PowerShell session.
- For higher assurance, obtain the SHA-256 for the exact `cacert.pem` revision from a trusted, independent channel and pass it as `-ExpectedSha256`. A checksum fetched from the same HTTPS source is mainly an accidental-corruption check, not an independent trust boundary.
- Start with `-WhatIf`; it downloads and validates the bundle, then removes its temporary file without creating a backup or changing the certificate store.
- Prefer the default additive mode. `-Replace` removes every AuthRoot certificate not in the bundle, including roots installed by your organisation or management tooling.
- Keep the generated backup somewhere durable. Test the recovery procedure in a non-production environment before depending on it.

## Usage

First inspect the proposed change. The current curl CA Extract page publishes the current bundle's SHA-256.

```powershell
.\Update-MozillaAuthRoot.ps1 -WhatIf
```

Import missing Mozilla roots while retaining existing AuthRoot certificates. This downloads the bundle over HTTPS and performs structural validation:

```powershell
.\Update-MozillaAuthRoot.ps1
```

For higher assurance, pin an independently obtained digest:

```powershell
.\Update-MozillaAuthRoot.ps1 -ExpectedSha256 '<trusted-64-character-SHA-256>'
```

To use a file you downloaded and reviewed yourself—for example, `cacert.pem` beside the script—pass `-BundlePath`. The script does not download or delete that file:

```powershell
.\Update-MozillaAuthRoot.ps1 -BundlePath .\cacert.pem -ExpectedSha256 '<trusted-64-character-SHA-256>'
```

Only when you explicitly intend to make AuthRoot match the bundle, replace certificates not in it:

```powershell
.\Update-MozillaAuthRoot.ps1 -BundlePath .\cacert.pem -Replace -Confirm
```

The script downloads the PEM over HTTPS (or uses `-BundlePath`), optionally verifies its SHA-256, rejects malformed/non-CA/duplicate entries and unexpectedly small bundles, creates a PKCS#7 backup before a real change, imports all missing Mozilla roots, verifies they are present, and only then removes non-Mozilla roots. Therefore an import failure retains the existing roots rather than clearing the store first.

`-ExpectedSha256` is optional; when it is omitted, the script warns before proceeding. `-WhatIf` is intentionally a dry run. Real changes have a high-impact, single confirmation prompt; use `-Confirm:$false` only in an appropriately controlled automation context. The backup defaults to `thirdpartyrootsbackup-<timestamp>.p7b` in the current directory.

## Compatibility and test coverage

The script requires administrator rights and is compatible with Windows PowerShell 5.1 and PowerShell 7. It was tested on Windows with Windows PowerShell `5.1.26100.8737` and PowerShell `7.6.3`.

The test runs covered PEM parsing, `-WhatIf` cleanup and non-mutation, SHA-256 and minimum-count rejection, additive import, `-Replace`, PKCS#7 backup recovery, and HTTPS validation after replacement.

## Recovery

The backup is a PKCS#7 certificate collection. To **add** its certificates back without removing currently installed certificates, use .NET's certificate-store API. This is reliable in both interactive and non-interactive sessions:

```powershell
$certificates = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
$certificates.Import('.\thirdpartyrootsbackup-<timestamp>.p7b')
$store = New-Object Security.Cryptography.X509Certificates.X509Store('AuthRoot', 'LocalMachine')
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    $store.AddRange($certificates)
}
finally {
    $store.Close()
}
```

To restore the backed-up store *exactly*, first export anything you need from the current AuthRoot store, then remove its contents and import the backup. This is destructive; use it only for recovery and test it before production use.

```powershell
Get-ChildItem Cert:\LocalMachine\AuthRoot | Remove-Item
$certificates = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
$certificates.Import('.\thirdpartyrootsbackup-<timestamp>.p7b')
$store = New-Object Security.Cryptography.X509Certificates.X509Store('AuthRoot', 'LocalMachine')
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    $store.AddRange($certificates)
}
finally {
    $store.Close()
}
```

## Validation checklist

Before production use, test on a representative non-production machine:

- Run `-WhatIf` and confirm the planned add/remove counts are expected.
- Run the default additive mode and confirm the backup can be imported into a test store.
- If `-Replace` is required, verify that organisation-specific roots are intentionally absent from the bundle and that internal TLS, VPN, Wi-Fi, proxy, and code-signing workflows still work.
- Simulate a bad SHA-256 or incomplete download and confirm that the script stops before backing up or changing AuthRoot.

## Parameters

- `-SourceUrl` overrides the HTTPS bundle URL. It is ignored when `-BundlePath` is used.
- `-ExpectedSha256` is an optional trusted, 64-character SHA-256 of the PEM. It is recommended when the digest comes from an independent trusted channel.
- `-BundlePath` uses an existing local PEM file instead of downloading one. The script never deletes this file.
- `-MinimumCertificateCount` defaults to 100 and rejects suspiciously incomplete bundles.
- `-BackupPath` chooses the PKCS#7 backup location.
- `-DownloadPath` chooses the temporary PEM location; it is removed on every exit path where possible.
- `-Replace` removes AuthRoot certificates absent from the validated bundle, after all needed imports succeed.
- `-Verbose` shows download and hash details.
- `-WhatIf` validates and displays the planned backup/import/removal actions without retaining files or changing the certificate store.
