# Test Fixtures

Simple C binaries cross-compiled with Zig for testing node-lief.

## Prerequisites

- [Zig](https://ziglang.org/download/)
- `llvm-lipo-20` (or `lipo` on macOS) for universal binary

## Build

Use `ZIG_GLOBAL_CACHE_DIR` to avoid embedding your home directory path in the binaries:

```bash
cd test/fixtures
export ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache

# ELF
zig cc -target x86_64-linux-gnu -o elf/hello-linux-x64 src/hello.c
zig cc -target aarch64-linux-gnu -o elf/hello-linux-arm64 src/hello.c

# PE
zig cc -target x86_64-windows-gnu -o pe/hello-windows-x64.exe src/hello.c
zig cc -target x86-windows-gnu -o pe/hello-windows-x86.exe src/hello.c
zig cc -target aarch64-windows-gnu -o pe/hello-windows-arm64.exe src/hello.c

# Mach-O
zig cc -target x86_64-macos -o macho/hello-macos-x64 src/hello.c
zig cc -target aarch64-macos -o macho/hello-macos-arm64 src/hello.c
llvm-lipo-20 -create -output macho/hello-macos-universal macho/hello-macos-x64 macho/hello-macos-arm64
```

## Verify

```bash
readelf -s elf/hello-linux-x64 | grep FUNC      # symbols
readelf -r elf/hello-linux-x64                   # relocations
```
