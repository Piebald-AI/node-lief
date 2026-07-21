# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

Node.js native bindings for LIEF (Library to Instrument Executable Formats). This package allows Node.js applications to parse, modify, and write executable binary formats: ELF (Linux), PE (Windows), and Mach-O (macOS/iOS).

## Build System Architecture

### Two-Stage Build Process

1. **LIEF C++ Library Build** (`pnpm build:lief`)
   - Runs `scripts/build-lief.sh`
   - Uses CMake + Ninja to build the LIEF submodule
   - Produces `lief-build/libLIEF.a` (or `LIEF.lib` on Windows)
   - Configured for minimal build: disables Python/Rust APIs, OAT, DEX, VDEX, ART, ASM
   - Must complete before native addon build

2. **Native Addon Build** (`node-gyp rebuild`)
   - Uses `binding.gyp` configuration
   - Links against the pre-built LIEF static library
   - Compiles C++ sources in `src/` directory
   - Requires C++17, RTTI enabled
   - Produces `build/Release/node_lief.node`

### Build Commands

```bash
# Full build (LIEF + addon)
pnpm build

# Clean build artifacts
pnpm clean

# Build only LIEF library
pnpm build:lief

# Create prebuilt binaries for distribution
pnpm prebuildify
```

### Dependencies

- **LIEF**: Git submodule at `./LIEF` (https://github.com/lief-project/LIEF.git)
- **node-addon-api**: N-API C++ wrapper classes
- **node-gyp-build**: Load prebuilt binaries or fallback to building

## Naming Conventions

**JavaScript/TypeScript API**: All method and property names use **camelCase**:
- `binary.sections()` (not `binary.get_sections()`)
- `binary.getSymbol(name)` (not `binary.get_symbol(name)`)
- `binary.patchAddress(addr, data)` (not `binary.patch_address(addr, data)`)

This applies to all exposed APIs across all binary formats (Abstract, PE, ELF, MachO).

## Code Structure

### JavaScript Layer (`lib/`)

- `lib/index.js`: Entry point, loads native addon
- `lib/index.d.ts`: TypeScript definitions for all APIs

### Native C++ Layer (`src/`)

Three-tier architecture leveraging LIEF's C++ inheritance:

1. **Implementation Base** (`src/binary_impl.{h,cpp}`)
   - Non-ObjectWrap base class providing DRY shared implementations
   - Contains all common Binary method implementations (sections, symbols, write, etc.)
   - Uses non-owning `LIEF::Binary*` pointer to polymorphic LIEF binary
   - Derived classes inherit from both `Napi::ObjectWrap<T>` and `BinaryImpl`

2. **Abstract Layer** (`src/abstract/`)
   - Format-agnostic interfaces
   - `binary.{h,cpp}`: Base Binary class, forwards to BinaryImpl
   - `section.{h,cpp}`: Generic section representation
   - `segment.{h,cpp}`: Generic segment (used by MachO)
   - `symbol.{h,cpp}`: Symbol representation

3. **Format-Specific Layers**
   - `src/elf/binary.{h,cpp}`: ELF-specific operations
   - `src/pe/binary.{h,cpp}`: PE-specific operations
   - `src/macho/`: MachO-specific implementation
     - `binary.{h,cpp}`: MachO binary operations
     - `fat_binary.{h,cpp}`: Universal/Fat binary wrapper (multiple architectures)
     - `parse.cpp`: MachO-specific parse function
   - Each inherits from BinaryImpl for common functionality
   - Adds format-specific methods and properties

4. **Initialization** (`src/init.cpp`)
   - Module entry point: `NODE_API_MODULE(node_lief, Init)`
   - Exports namespace structure: `LIEF.Abstract`, `LIEF.ELF`, `LIEF.PE`, `LIEF.MachO`
   - Registers all classes and functions

### Key Design Patterns

**Ownership Model**: Native classes use `std::unique_ptr<LIEF::*>` for owned pointers, with factory methods (`NewInstance()`) to create JS objects from parsed binaries. Each format-specific class owns the appropriate type (e.g., `PEBinary` owns `std::unique_ptr<LIEF::PE::Binary>`) and sets the inherited `BinaryImpl::binary_` pointer to it for polymorphic access.

**DRY Inheritance Architecture**:
- `BinaryImpl` contains all shared method implementations
- Format-specific classes (PE, ELF, MachO) inherit from both `Napi::ObjectWrap<T>` and `BinaryImpl`
- Common methods are simple inline forwarders in headers (e.g., `GetSections(info) { return GetSectionsImpl(info.Env()); }`)
- No code duplication across format implementations

**Dual Parse Functions**:
- `LIEF.parse(filename)`: Returns format-specific binary (ELF.Binary, PE.Binary, MachO.Binary, or Abstract.Binary)
- `LIEF.MachO.parse(filename)`: Returns MachO.FatBinary (can contain multiple architectures)

**MachO Fat Binary Handling**: MachO files may be "fat binaries" containing multiple architectures. Use `FatBinary.at(index)` to access individual architecture binaries.

## Testing

```bash
# Run test suite
pnpm test

# Test with specific binary (MachO example)
node test/test-bun-repack.js /path/to/macho/binary
```

Test file demonstrates:
- Parsing binaries across formats
- Extracting sections/segments
- Modifying binary content
- Writing modified binaries

## Common Development Tasks

### Adding a New Method to Abstract Binary

1. Add implementation in `src/binary_impl.{h,cpp}` (e.g., `GetFooImpl()`)
2. Add inline forwarder in `src/abstract/binary.h`:
   ```cpp
   Napi::Value GetFoo(const Napi::CallbackInfo& info) {
     return GetFooImpl(info.Env(), info);
   }
   ```
3. Register in `AbstractBinary::Init()` using `InstanceMethod<&AbstractBinary::GetFoo>("fooMethod")` (use camelCase!)
4. Repeat steps 2-3 for format-specific classes (PE, ELF, MachO) - they automatically inherit the implementation
5. Update TypeScript definitions in `lib/index.d.ts`

### Adding Format-Specific Functionality

Example for PE-specific feature:
1. Add method declaration and implementation in `src/pe/binary.{h,cpp}`
2. Register in `PEBinary::Init()` using `InstanceMethod<&PEBinary::MethodName>("methodName")` (use camelCase!)
3. Update TypeScript definitions under `namespace PE`
4. Format-specific methods can access `pe_binary_` (typed pointer) directly

### Working with LIEF Types

Common conversions:
- LIEF addresses are `uint64_t` → use `Napi::BigInt` in JS
- LIEF strings are `std::string` → use `Napi::String`
- LIEF vectors → convert to `Napi::Array`
- LIEF sections/symbols → wrap in ObjectWrap classes

## Platform-Specific Notes

### macOS
- Minimum deployment target: macOS 13.0 (set in binding.gyp and build-lief.sh)
- Uses libc++ standard library
- Requires Xcode command line tools

### Linux
- Requires `-fPIC` for static library linking
- GCC/Clang with C++17 support

### Windows
- Uses LIEF.lib instead of libLIEF.a
- MSVC toolchain with `/std:c++17`

## File Organization

- `binding.gyp`: node-gyp build configuration (sources, include paths, libraries)
- `scripts/build-lief.sh`: LIEF CMake configuration script
- `prebuilds/`: Prebuildify output for binary distribution
- `LIEF/`: Git submodule (LIEF upstream library)
- `lief-build/`: CMake build directory for LIEF library (gitignored)
- `build/`: node-gyp output directory (gitignored)
