# winroots

## Use at your own risk. While this procedure works for me, I can and will not guarantee it will work for you too!

To replace all Microsoft Third-party Root Certification Authorities with certificates that are in Mozilla's trust store (https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt) you can follow the following procedure:

1. On a Linux box, md and cd into a directory where files will be downloaded/created;
2. Execute (the commands in) gencabundle (wget, perl and openssl needed);
3. Transfer ca-bundle.p7b to the Windows box;
4. Start a powershell with administrator rights;
5. Execute (the commands in) newrootswin;
6. Done.
