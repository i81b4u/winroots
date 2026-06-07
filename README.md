# winroots

Use at your own risk. While this procedure works for me, I can and will not guarantee it will work for you too.

## What it does

`Update-MozillaAuthRoot.ps1` downloads the current Mozilla-derived CA bundle from curl, backs up the existing Windows Third-party Root Certification Authorities store, and imports the certificates into `Cert:\LocalMachine\AuthRoot`.

The script is intended to run without user interaction from an elevated PowerShell session.

## Usage

Run this from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Update-MozillaAuthRoot.ps1 -Replace
```

`-Replace` removes all existing certificates from `LocalMachine\AuthRoot` before importing the Mozilla roots. Without `-Replace`, the script keeps existing certificates and imports only missing certificates from the downloaded bundle.

The backup file is written to the current directory as `thirdpartyrootsbackup-<timestamp>.p7b` unless `-BackupPath` is specified.

Optional parameters:

- `-SourceUrl` overrides the default bundle URL, `https://curl.se/ca/cacert.pem`.
- `-BackupPath` chooses where the PKCS#7 backup of the existing store is written.
- `-DownloadPath` chooses where the temporary PEM bundle is downloaded.
- `-Verbose` shows the download and removal steps.
- `-WhatIf` shows which remove/import operations would be attempted.

## Notes

curl's converted PEM bundle contains the CA certificates from Mozilla's store, but not browser-specific constraints such as name constraints.

The script requires Windows PowerShell 5.1 or later and administrator rights because it writes to the LocalMachine certificate store.
