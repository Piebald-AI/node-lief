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
  namespace Abstract {
    /**
     * Generic binary executable interface
     * Works with ELF, PE, Mach-O, and other formats
     */
    class Binary {
      constructor(filename: string);

      // Properties
      readonly format: 'ELF' | 'PE' | 'MachO' | 'UNKNOWN';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;
      // Note: header property is format-specific - see ELF.Binary, PE.Binary, MachO.Binary

      // Methods
      sections(): Section[];
      symbols(): Symbol[];
      relocations(): Relocation[];
      segments(): any[]; // Empty array - format-specific binaries should override
      getSymbol(name: string): Symbol | null;
      patchAddress(address: bigint | number, patch: Buffer | number[]): void;
      write(outputPath: string): void;
    }

    /**
     * Represents a section in a binary
     * Provides read/write access to section properties and content
     *
     * Note: For PE-specific sections with virtualSize support, use PE.Section.
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
  }

  namespace ELF {
    /**
     * Represents an ELF segment (program header) with full read-write access
     */
    class Segment {
      /** Segment type as a string (e.g. "LOAD", "DYNAMIC", "INTERP", "NOTE", "PHDR", "GNU_STACK", "GNU_RELRO", etc.) */
      readonly type: string;
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
      sections(): Abstract.Section[];
    }

    /**
     * ELF-specific binary class
     * Used for Linux/Unix executable manipulation
     */
    class Binary extends Abstract.Binary {
      constructor(filename: string);

      // Override format type
      readonly format: 'ELF';

      // ELF-specific properties
      readonly hasOverlay: boolean;
      /**
       * Overlay content as a Buffer.
       */
      overlay: Buffer;

      // Override to return ELF-specific segments
      segments(): Segment[];

      // ELF-specific methods
      /**
       * Get a segment by its type name (e.g. "LOAD", "DYNAMIC")
       * Returns the first segment matching the given type, or null if not found.
       */
      getSegment(type: string): Segment | null;
    }
  }

  namespace PE {
    /**
     * PE-specific section class
     * Provides proper virtualSize support and PE-specific properties
     */
    class Section extends Abstract.Section {
      // PE sections have proper virtual_size support (not just an alias for size)
      virtualSize: bigint;

      // PE-specific properties
      readonly characteristics: number;
    }

    /**
     * PE (Windows Portable Executable) binary class
     * Used for Windows .exe and .dll manipulation
     */
    class Binary extends Abstract.Binary {
      constructor(filename: string);

      // Override format type
      readonly format: 'PE';

      // PE-specific properties
      readonly optionalHeader: OptionalHeader;

      // Override to return PE-specific sections
      sections(): Section[];

      // PE-specific methods
      getSection(name: string): Section | null;
    }

    /**
     * PE Optional Header
     * Contains critical PE file metadata (despite the name, it's mandatory for PE files)
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
     * MachO Header
     * Contains critical metadata about the Mach-O binary
     * This is a format-specific header, separate from Abstract.Header
     */
    class Header {
      readonly cpuType: number; // CPU_TYPE enum value
      readonly cpuSubtype: number;
      readonly fileType: number;
      readonly flags: number;
      readonly magic: number;
      readonly nbCmds: number;
      readonly sizeofCmds: number;
      readonly is32Bit: boolean;
      readonly is64Bit: boolean;

      /**
       * CPU Architecture Type Constants
       * These values combine the base architecture with the ABI64 flag (0x01000000)
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
     * Mach-O (macOS/iOS) binary class
     * Used for macOS executable manipulation
     */
    class Binary extends Abstract.Binary {
      constructor(filename: string);

      // Override format type
      readonly format: 'MachO';

      // MachO-specific properties
      readonly hasCodeSignature: boolean;
      readonly header: Header;

      // MachO-specific methods
      getSegment(name: string): Segment | null;
      removeSignature(): void;
      extendSegment(segment: Segment, size: bigint | number): boolean;
    }

    /**
     * Represents a MachO segment (SegmentCommand)
     */
    class Segment {
      readonly name: string;
      readonly virtualAddress: bigint;
      readonly virtualSize: bigint;
      readonly fileOffset: bigint;
      readonly fileSize: bigint;

      sections(): Abstract.Section[];
      getSection(name: string): Abstract.Section | null;
    }

    /**
     * Represents a MachO Fat/Universal binary
     * Can contain multiple architectures
     */
    class FatBinary {
      size(): number;
      at(index: number): Binary | null;
      take(index: number): Binary | null;
    }

    /**
     * Parse a MachO binary file
     * @param filename - Path to the MachO binary file
     * @returns FatBinary object (may contain single or multiple architectures)
     */
    function parse(filename: string): FatBinary;
  }

  namespace logging {
    /**
     * Disable LIEF logging
     */
    function disable(): void;

    /**
     * Enable LIEF logging
     */
    function enable(): void;
  }

  /**
   * Parse a binary file and return format-specific binary object
   * @param filename - Path to the binary file
   * @returns Binary object (type depends on detected format: ELF.Binary, PE.Binary, MachO.Binary, or Abstract.Binary)
   */
  function parse(filename: string): Abstract.Binary | ELF.Binary | PE.Binary | MachO.Binary;
}

export = LIEF;
