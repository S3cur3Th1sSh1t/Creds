# Some of my experiments with [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) templates

To not popup the Nim binaries console window compile them with the `--app:gui` parameter.

For the best size:

```
nim c -d:danger -d:strip --opt:size --passc=-flto --passl=-flto executable.nim
```

To compile the DLL:

```
nim c -d=mingw --app=lib --nomain --cpu=amd64 DLLHijack.nim
```
