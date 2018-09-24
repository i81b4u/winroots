# winroots

To replace all Microsoft third party trusted root certificates with certificates that are in Mozilla's trust store (https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt) you can follow the following procedure:

1. On a Linux box, md and cd into a directory where files will be downloaded/created;
2. Execute (the commands in) gencabundle (wget, perl and openssl needed);
3. Transfer ca-bundle.p7b to the Windows box;
4. Start a powershell with administrator rights;
5. Execute (the commands in) newrootswin;
6. Done.
