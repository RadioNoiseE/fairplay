This is a rewrite of the tool [`dumpdecrypted`](https://github.com/stefanesser/dumpdecrypted) by Stefan Esser,
later forked by Conrad Kramer adding framework support, supporting
Dopamine semi-untethered jailbreak.

Recent (?) iOS hardening prevents non-system processes from spawning
containerized apps (only launchd is allowed to do so). Entitlement
workarounds that try to make an app a platform binary break framework
loading (dyld rejects non-platform frameworks with "mapping process is
a platform binary, but mapped file is not"). Thus I adapted this tool
to run as a MobileSubstrate/ElleKit injected dynamic library.

To compile, adjust the makefile so the SDK version matches your target
device. After obtaining the resulting `fairplay.dylib`, transfer it to
your jailbroken device, and install it with `fairplay.plist`.

Due to sandbox restrictions, files are written to `tmp/` in the app
container root. Dumped images have a `.d` suffix and log is written to
`fairplay.log`.

> [!IMPORTANT]
> This tool is only meant for security research purposes, not
> for application crackers.
