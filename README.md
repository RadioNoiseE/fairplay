This is a rewritten of the tool [`dumpdecrypted`](https://github.com/stefanesser/dumpdecrypted) by Stefan Esser,
later forked by Conrad Kramer adding framework support.

To compile, adjust the makefile so the SDK version matches with your
target device. After obtaining the resulted `fairplay.dylib`, transfer
it to your jailbroken device, and use it like:

```sh
DYLD_INSERT_LIBRARIES=fairplay.dylib <image>
```

> [!IMPORTANT]
> This tool is only meant for security research purposes, not
> for application crackers.
