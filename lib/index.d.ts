// Copyright 2025-2026 Piebald LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * LIEF Node.js Bindings - TypeScript Definitions
 *
 * Provides TypeScript support for LIEF binary parsing and manipulation.
 * Supports ELF, PE, Mach-O, and other executable formats.
 */

declare namespace LIEF {
  /**
   * Generic abstract header returned by ELF and PE binaries.
   * This is a plain object (not a class instance).
   */
  interface AbstractHeader {
    readonly architecture: number;
    readonly entrypoint: bigint;
    readonly is_32: boolean;
    readonly is_64: boolean;
  }

  /**
   * Represents a section in a binary.
   * Provides read/write access to section properties and content.
   *
   * Used by ELF and MachO binaries. For PE-specific sections, see {@link PE.Section}.
   */
  class Section {
    readonly name: string;
    readonly virtualAddress: bigint;
    size: bigint;
    readonly fileOffset: bigint;
    /**
     * Section content as a Buffer.
     * Getter returns Buffer. Setter accepts Buffer or number[].
     */
    get content(): Buffer;
    set content(value: Buffer | number[]);
    readonly offset: bigint;
  }

  interface Symbol {
    name: string;
    value: bigint;
    size: bigint;
  }

  interface Relocation {
    address: bigint;
    size: number;
  }

  namespace ELF {
    type SegmentType =
      | 'PT_NULL_'
      | 'LOAD'
      | 'DYNAMIC'
      | 'INTERP'
      | 'NOTE'
      | 'SHLIB'
      | 'PHDR'
      | 'TLS'
      | 'GNU_EH_FRAME'
      | 'GNU_STACK'
      | 'GNU_PROPERTY'
      | 'GNU_RELRO'
      | 'PAX_FLAGS'
      | 'ARM_ARCHEXT'
      | 'ARM_EXIDX'
      | 'AARCH64_MEMTAG_MTE'
      | 'MIPS_REGINFO'
      | 'MIPS_RTPROC'
      | 'MIPS_OPTIONS'
      | 'MIPS_ABIFLAGS'
      | 'RISCV_ATTRIBUTES'
      | 'IA_64_EXT'
      | 'IA_64_UNWIND'
      | 'HP_TLS'
      | 'HP_CORE_NONE'
      | 'HP_CORE_VERSION'
      | 'HP_CORE_KERNEL'
      | 'HP_CORE_COMM'
      | 'HP_CORE_PROC'
      | 'HP_CORE_LOADABLE'
      | 'HP_CORE_STACK'
      | 'HP_CORE_SHM'
      | 'HP_CORE_MMF'
      | 'HP_PARALLEL'
      | 'HP_FASTBIND'
      | 'HP_OPT_ANNOT'
      | 'HP_HSL_ANNOT'
      | 'HP_STACK'
      | 'HP_CORE_UTSNAME'
      | 'UNKNOWN';

    /**
     * Represents an ELF segment (program header) with full read-write access.
     */
    class Segment {
      /** Segment type (e.g. LIEF.ELF.Segment.TYPE.LOAD). */
      type: SegmentType;
      /** Segment flags bitmask (R=4, W=2, X=1) */
      flags: number;
      /** Virtual address of the segment */
      virtualAddress: bigint;
      /** In-memory size of the segment */
      virtualSize: bigint;
      /** File offset of the segment data */
      fileOffset: bigint;
      /** On-disk size of the segment data */
      fileSize: bigint;
      /** Physical address of the segment */
      physicalAddress: bigint;
      /** Alignment of the segment */
      alignment: bigint;
      /**
       * Segment content as a Buffer.
       * Getter returns Buffer. Setter accepts Buffer or number[].
       */
      get content(): Buffer;
      set content(value: Buffer | number[]);

      /** Returns sections contained within this segment */
      sections(): ELF.Section[];

      static readonly TYPE: {
        readonly PT_NULL_: 'PT_NULL_';
        readonly LOAD: 'LOAD';
        readonly DYNAMIC: 'DYNAMIC';
        readonly INTERP: 'INTERP';
        readonly NOTE: 'NOTE';
        readonly SHLIB: 'SHLIB';
        readonly PHDR: 'PHDR';
        readonly TLS: 'TLS';
        readonly GNU_EH_FRAME: 'GNU_EH_FRAME';
        readonly GNU_STACK: 'GNU_STACK';
        readonly GNU_PROPERTY: 'GNU_PROPERTY';
        readonly GNU_RELRO: 'GNU_RELRO';
        readonly PAX_FLAGS: 'PAX_FLAGS';
        readonly ARM_ARCHEXT: 'ARM_ARCHEXT';
        readonly ARM_EXIDX: 'ARM_EXIDX';
        readonly AARCH64_MEMTAG_MTE: 'AARCH64_MEMTAG_MTE';
        readonly MIPS_REGINFO: 'MIPS_REGINFO';
        readonly MIPS_RTPROC: 'MIPS_RTPROC';
        readonly MIPS_OPTIONS: 'MIPS_OPTIONS';
        readonly MIPS_ABIFLAGS: 'MIPS_ABIFLAGS';
        readonly RISCV_ATTRIBUTES: 'RISCV_ATTRIBUTES';
        readonly IA_64_EXT: 'IA_64_EXT';
        readonly IA_64_UNWIND: 'IA_64_UNWIND';
        readonly HP_TLS: 'HP_TLS';
        readonly HP_CORE_NONE: 'HP_CORE_NONE';
        readonly HP_CORE_VERSION: 'HP_CORE_VERSION';
        readonly HP_CORE_KERNEL: 'HP_CORE_KERNEL';
        readonly HP_CORE_COMM: 'HP_CORE_COMM';
        readonly HP_CORE_PROC: 'HP_CORE_PROC';
        readonly HP_CORE_LOADABLE: 'HP_CORE_LOADABLE';
        readonly HP_CORE_STACK: 'HP_CORE_STACK';
        readonly HP_CORE_SHM: 'HP_CORE_SHM';
        readonly HP_CORE_MMF: 'HP_CORE_MMF';
        readonly HP_PARALLEL: 'HP_PARALLEL';
        readonly HP_FASTBIND: 'HP_FASTBIND';
        readonly HP_OPT_ANNOT: 'HP_OPT_ANNOT';
        readonly HP_HSL_ANNOT: 'HP_HSL_ANNOT';
        readonly HP_STACK: 'HP_STACK';
        readonly HP_CORE_UTSNAME: 'HP_CORE_UTSNAME';
      };
    }

    type SectionType =
      | 'SHT_NULL_'
      | 'PROGBITS'
      | 'SYMTAB'
      | 'STRTAB'
      | 'RELA'
      | 'HASH'
      | 'DYNAMIC'
      | 'NOTE'
      | 'NOBITS'
      | 'REL'
      | 'SHLIB'
      | 'DYNSYM'
      | 'INIT_ARRAY'
      | 'FINI_ARRAY'
      | 'PREINIT_ARRAY'
      | 'GROUP'
      | 'SYMTAB_SHNDX'
      | 'RELR'
      | 'ANDROID_REL'
      | 'ANDROID_RELA'
      | 'LLVM_ADDRSIG'
      | 'ANDROID_RELR'
      | 'GNU_ATTRIBUTES'
      | 'GNU_HASH'
      | 'GNU_VERDEF'
      | 'GNU_VERNEED'
      | 'GNU_VERSYM'
      | 'ARM_EXIDX'
      | 'ARM_PREEMPTMAP'
      | 'ARM_ATTRIBUTES'
      | 'ARM_DEBUGOVERLAY'
      | 'ARM_OVERLAYSECTION'
      | 'HEX_ORDERED'
      | 'X86_64_UNWIND'
      | 'MIPS_LIBLIST'
      | 'MIPS_MSYM'
      | 'MIPS_CONFLICT'
      | 'MIPS_GPTAB'
      | 'MIPS_UCODE'
      | 'MIPS_DEBUG'
      | 'MIPS_REGINFO'
      | 'MIPS_PACKAGE'
      | 'MIPS_PACKSYM'
      | 'MIPS_RELD'
      | 'MIPS_IFACE'
      | 'MIPS_CONTENT'
      | 'MIPS_OPTIONS'
      | 'MIPS_SHDR'
      | 'MIPS_FDESC'
      | 'MIPS_EXTSYM'
      | 'MIPS_DENSE'
      | 'MIPS_PDESC'
      | 'MIPS_LOCSYM'
      | 'MIPS_AUXSYM'
      | 'MIPS_OPTSYM'
      | 'MIPS_LOCSTR'
      | 'MIPS_LINE'
      | 'MIPS_RFDESC'
      | 'MIPS_DELTASYM'
      | 'MIPS_DELTAINST'
      | 'MIPS_DELTACLASS'
      | 'MIPS_DWARF'
      | 'MIPS_DELTADECL'
      | 'MIPS_SYMBOL_LIB'
      | 'MIPS_EVENTS'
      | 'MIPS_TRANSLATE'
      | 'MIPS_PIXIE'
      | 'MIPS_XLATE'
      | 'MIPS_XLATE_DEBUG'
      | 'MIPS_WHIRL'
      | 'MIPS_EH_REGION'
      | 'MIPS_XLATE_OLD'
      | 'MIPS_ABIFLAGS'
      | 'MIPS_XHASH'
      | 'RISCV_ATTRIBUTES'
      | 'UNKNOWN';

    /**
     * Represents an ELF section with ELF-specific read-write access.
     */
    class Section {
      name: string;
      type: SectionType;
      flags: bigint;
      virtualAddress: bigint;
      fileOffset: bigint;
      size: bigint;
      alignment: bigint;
      /** Backward-compatible alias for fileOffset. */
      readonly offset: bigint;
      /**
       * Section content as a Buffer.
       * Getter returns Buffer. Setter accepts Buffer or number[].
       */
      get content(): Buffer;
      set content(value: Buffer | number[]);

      static readonly TYPE: {
        readonly SHT_NULL_: 'SHT_NULL_';
        readonly PROGBITS: 'PROGBITS';
        readonly SYMTAB: 'SYMTAB';
        readonly STRTAB: 'STRTAB';
        readonly RELA: 'RELA';
        readonly HASH: 'HASH';
        readonly DYNAMIC: 'DYNAMIC';
        readonly NOTE: 'NOTE';
        readonly NOBITS: 'NOBITS';
        readonly REL: 'REL';
        readonly SHLIB: 'SHLIB';
        readonly DYNSYM: 'DYNSYM';
        readonly INIT_ARRAY: 'INIT_ARRAY';
        readonly FINI_ARRAY: 'FINI_ARRAY';
        readonly PREINIT_ARRAY: 'PREINIT_ARRAY';
        readonly GROUP: 'GROUP';
        readonly SYMTAB_SHNDX: 'SYMTAB_SHNDX';
        readonly RELR: 'RELR';
        readonly ANDROID_REL: 'ANDROID_REL';
        readonly ANDROID_RELA: 'ANDROID_RELA';
        readonly LLVM_ADDRSIG: 'LLVM_ADDRSIG';
        readonly ANDROID_RELR: 'ANDROID_RELR';
        readonly GNU_ATTRIBUTES: 'GNU_ATTRIBUTES';
        readonly GNU_HASH: 'GNU_HASH';
        readonly GNU_VERDEF: 'GNU_VERDEF';
        readonly GNU_VERNEED: 'GNU_VERNEED';
        readonly GNU_VERSYM: 'GNU_VERSYM';
        readonly ARM_EXIDX: 'ARM_EXIDX';
        readonly ARM_PREEMPTMAP: 'ARM_PREEMPTMAP';
        readonly ARM_ATTRIBUTES: 'ARM_ATTRIBUTES';
        readonly ARM_DEBUGOVERLAY: 'ARM_DEBUGOVERLAY';
        readonly ARM_OVERLAYSECTION: 'ARM_OVERLAYSECTION';
        readonly HEX_ORDERED: 'HEX_ORDERED';
        readonly X86_64_UNWIND: 'X86_64_UNWIND';
        readonly MIPS_LIBLIST: 'MIPS_LIBLIST';
        readonly MIPS_MSYM: 'MIPS_MSYM';
        readonly MIPS_CONFLICT: 'MIPS_CONFLICT';
        readonly MIPS_GPTAB: 'MIPS_GPTAB';
        readonly MIPS_UCODE: 'MIPS_UCODE';
        readonly MIPS_DEBUG: 'MIPS_DEBUG';
        readonly MIPS_REGINFO: 'MIPS_REGINFO';
        readonly MIPS_PACKAGE: 'MIPS_PACKAGE';
        readonly MIPS_PACKSYM: 'MIPS_PACKSYM';
        readonly MIPS_RELD: 'MIPS_RELD';
        readonly MIPS_IFACE: 'MIPS_IFACE';
        readonly MIPS_CONTENT: 'MIPS_CONTENT';
        readonly MIPS_OPTIONS: 'MIPS_OPTIONS';
        readonly MIPS_SHDR: 'MIPS_SHDR';
        readonly MIPS_FDESC: 'MIPS_FDESC';
        readonly MIPS_EXTSYM: 'MIPS_EXTSYM';
        readonly MIPS_DENSE: 'MIPS_DENSE';
        readonly MIPS_PDESC: 'MIPS_PDESC';
        readonly MIPS_LOCSYM: 'MIPS_LOCSYM';
        readonly MIPS_AUXSYM: 'MIPS_AUXSYM';
        readonly MIPS_OPTSYM: 'MIPS_OPTSYM';
        readonly MIPS_LOCSTR: 'MIPS_LOCSTR';
        readonly MIPS_LINE: 'MIPS_LINE';
        readonly MIPS_RFDESC: 'MIPS_RFDESC';
        readonly MIPS_DELTASYM: 'MIPS_DELTASYM';
        readonly MIPS_DELTAINST: 'MIPS_DELTAINST';
        readonly MIPS_DELTACLASS: 'MIPS_DELTACLASS';
        readonly MIPS_DWARF: 'MIPS_DWARF';
        readonly MIPS_DELTADECL: 'MIPS_DELTADECL';
        readonly MIPS_SYMBOL_LIB: 'MIPS_SYMBOL_LIB';
        readonly MIPS_EVENTS: 'MIPS_EVENTS';
        readonly MIPS_TRANSLATE: 'MIPS_TRANSLATE';
        readonly MIPS_PIXIE: 'MIPS_PIXIE';
        readonly MIPS_XLATE: 'MIPS_XLATE';
        readonly MIPS_XLATE_DEBUG: 'MIPS_XLATE_DEBUG';
        readonly MIPS_WHIRL: 'MIPS_WHIRL';
        readonly MIPS_EH_REGION: 'MIPS_EH_REGION';
        readonly MIPS_XLATE_OLD: 'MIPS_XLATE_OLD';
        readonly MIPS_ABIFLAGS: 'MIPS_ABIFLAGS';
        readonly MIPS_XHASH: 'MIPS_XHASH';
        readonly RISCV_ATTRIBUTES: 'RISCV_ATTRIBUTES';
      };
    }

    /**
     * ELF-specific binary class.
     * Used for Linux/Unix executable manipulation.
     */
    class Binary {
      // Properties
      readonly format: 'ELF';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;
      /** Generic abstract header with architecture info */
      readonly header: AbstractHeader;

      // ELF-specific properties
      readonly hasOverlay: boolean;
      /** Overlay content as a Buffer. */
      overlay: Buffer;

      // Methods inherited from abstract Binary
      sections(): ELF.Section[];
      symbols(): Symbol[];
      relocations(): Relocation[];
      getSymbol(name: string): Symbol | null;
      patchAddress(address: bigint | number, patch: Buffer | number[]): void;
      write(outputPath: string): void;

      // ELF-specific methods
      segments(): Segment[];
      /**
       * Get a section by name.
       * @param name - Section name (e.g. ".text", ".data", ".rodata")
       * @returns The section, or null if not found.
       */
      getSection(name: string): ELF.Section | null;
      /**
       * Get a segment by its type name (e.g. LIEF.ELF.Segment.TYPE.LOAD).
       * Returns the first segment matching the given type, or null if not found.
       */
      getSegment(type: SegmentType): Segment | null;
      extend(segment: Segment, size: bigint | number): Segment | null;
      lastOffsetSection(): bigint;
      lastOffsetSegment(): bigint;
      nextVirtualAddress(): bigint;
      pageSize(): bigint;
    }
  }

  namespace PE {
    /**
     * PE-specific section class.
     * Provides proper virtualSize support and PE-specific properties.
     */
    class Section {
      readonly name: string;
      readonly virtualAddress: bigint;
      size: bigint;
      readonly fileOffset: bigint;
      /** PE sections have a distinct virtualSize (not just an alias for size) */
      virtualSize: bigint;
      /**
       * Section content as a Buffer.
       * Getter returns Buffer. Setter accepts Buffer or number[].
       */
      get content(): Buffer;
      set content(value: Buffer | number[]);
      readonly offset: bigint;
      readonly characteristics: number;
    }

    /**
     * PE (Windows Portable Executable) binary class.
     * Used for Windows .exe and .dll manipulation.
     */
    class Binary {
      // Properties
      readonly format: 'PE';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;
      /** Generic abstract header with architecture info */
      readonly header: AbstractHeader;

      // PE-specific properties
      readonly optionalHeader: OptionalHeader;

      // Methods inherited from abstract Binary
      sections(): Section[];
      symbols(): Symbol[];
      relocations(): Relocation[];
      /** Returns an empty array for PE binaries (segments are ELF/MachO-specific) */
      segments(): any[];
      getSymbol(name: string): Symbol | null;
      patchAddress(address: bigint | number, patch: Buffer | number[]): void;
      write(outputPath: string): void;

      // PE-specific methods
      /**
       * Get a section by name.
       * @param name - Section name (e.g. ".text", ".rdata")
       * @returns The PE section, or null if not found.
       */
      getSection(name: string): Section | null;
    }

    /**
     * PE Optional Header.
     * Contains critical PE file metadata (despite the name, it's mandatory for PE files).
     */
    class OptionalHeader {
      readonly magic: 'PE32' | 'PE32_PLUS' | 'UNKNOWN';
      readonly majorLinkerVersion: number;
      readonly minorLinkerVersion: number;
      readonly sizeOfCode: number;
      readonly sizeOfInitializedData: number;
      readonly sizeOfUninitializedData: number;
      readonly addressOfEntrypoint: number;
      readonly baseOfCode: number;
      readonly baseOfData: number;
      readonly imagebase: bigint;
      readonly sectionAlignment: number;
      readonly fileAlignment: number;
      readonly majorOperatingSystemVersion: number;
      readonly minorOperatingSystemVersion: number;
      readonly majorImageVersion: number;
      readonly minorImageVersion: number;
      readonly majorSubsystemVersion: number;
      readonly minorSubsystemVersion: number;
      readonly win32VersionValue: number;
      readonly sizeOfImage: number;
      readonly sizeOfHeaders: number;
      readonly checksum: number;
      readonly subsystem: number;
      readonly dllCharacteristics: number;
      readonly sizeOfStackReserve: bigint;
      readonly sizeOfStackCommit: bigint;
      readonly sizeOfHeapReserve: bigint;
      readonly sizeOfHeapCommit: bigint;
    }
  }

  namespace MachO {
    /**
     * MachO Header.
     * Contains critical metadata about the Mach-O binary.
     */
    class Header {
      readonly cpuType: number;
      readonly cpuSubtype: number;
      readonly fileType: number;
      readonly flags: number;
      readonly magic: number;
      readonly nbCmds: number;
      readonly sizeofCmds: number;
      readonly is32Bit: boolean;
      readonly is64Bit: boolean;

      /**
       * CPU Architecture Type Constants.
       * These values combine the base architecture with the ABI64 flag (0x01000000).
       *
       * @example
       * if (binary.header.cpuType === LIEF.MachO.Header.CPU_TYPE.ARM64) {
       *   console.log('This is an ARM64 binary');
       * }
       */
      static readonly CPU_TYPE: {
        readonly ANY: -1;
        readonly X86: 7;
        readonly X86_64: 16777223; // 7 | ABI64
        readonly MIPS: 8;
        readonly MC98000: 10;
        readonly HPPA: 11;
        readonly ARM: 12;
        readonly ARM64: 16777228; // 12 | ABI64
        readonly MC88000: 13;
        readonly SPARC: 14;
        readonly I860: 15;
        readonly ALPHA: 16;
        readonly POWERPC: 18;
        readonly POWERPC64: 16777234; // 18 | ABI64
        readonly APPLE_GPU: 16777235; // 19 | ABI64
        readonly AMD_GPU: 16777236; // 20 | ABI64
        readonly INTEL_GPU: 16777237; // 21 | ABI64
        readonly AIR64: 16777239; // 23 | ABI64
      };
    }

    /**
     * Represents a MachO segment (SegmentCommand).
     * All properties are read-only.
     */
    class Segment {
      readonly name: string;
      readonly virtualAddress: bigint;
      readonly virtualSize: bigint;
      readonly fileOffset: bigint;
      readonly fileSize: bigint;

      /** Returns sections contained within this segment */
      sections(): Section[];
      /**
       * Get a section within this segment by name.
       * @param name - Section name
       * @returns The section, or null if not found.
       */
      getSection(name: string): Section | null;
    }

    /**
     * MachO symbol — only the name is exposed (no value/size).
     */
    interface MachOSymbol {
      name: string;
    }

    /**
     * Mach-O (macOS/iOS) binary class.
     * Used for macOS executable manipulation.
     *
     * Note: Unlike ELF and PE binaries, MachO binaries do not expose
     * `relocations()`, `getSymbol()`, `patchAddress()`, or `segments()`.
     */
    class Binary {
      // Properties
      readonly format: 'MachO';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;

      // MachO-specific properties
      readonly hasCodeSignature: boolean;
      readonly header: Header;

      // Methods
      sections(): Section[];
      /**
       * Returns symbols with only the `name` property.
       */
      symbols(): MachOSymbol[];
      write(outputPath: string): void;

      // MachO-specific methods
      /**
       * Get a segment by name (e.g. "__TEXT", "__DATA", "__LINKEDIT").
       * @returns The segment, or null if not found.
       */
      getSegment(name: string): Segment | null;
      removeSignature(): void;
      extendSegment(segment: Segment, size: bigint | number): boolean;
    }

    /**
     * Represents a MachO Fat/Universal binary.
     * Can contain multiple architectures.
     */
    class FatBinary {
      /** Returns the number of architectures in this fat binary */
      size(): number;
      /**
       * Get a non-owning reference to the binary at the given index.
       * The returned binary is only valid while the FatBinary is alive.
       */
      at(index: number): Binary;
      /**
       * Take ownership of the binary at the given index.
       * The binary is moved out of the FatBinary.
       */
      take(index: number): Binary;
    }

    /**
     * Parse a MachO binary file.
     * @param filename - Path to the MachO binary file
     * @returns FatBinary object (may contain single or multiple architectures)
     */
    function parse(filename: string): FatBinary;
  }

  namespace logging {
    /** Disable LIEF logging */
    function disable(): void;
    /** Enable LIEF logging */
    function enable(): void;
  }

  /**
   * Parse a binary file and return a format-specific binary object.
   * Auto-detects the format (ELF, PE, or MachO) from file contents.
   *
   * @param filename - Path to the binary file
   * @returns Binary object — the concrete type depends on the detected format
   */
  function parse(filename: string): ELF.Binary | PE.Binary | MachO.Binary;
}

export = LIEF;
