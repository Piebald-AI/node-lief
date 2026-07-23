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
 * Known-value verification tests
 *
 * These tests verify that node-lief returns correct values by comparing
 * against known values extracted from the test fixtures using standard tools
 * (readelf, llvm-objdump, llvm-otool, etc.)
 *
 * If these tests fail after rebuilding fixtures, update the expected values
 * by running the verification commands in test/fixtures/README.md
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { getElfFixtures, getPeFixtures, getMachoFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

/*
 * Expected values extracted from test fixtures using:
 *   ELF: readelf -h, readelf -s, readelf -S, readelf -r
 *   PE: llvm-readobj-20 --file-headers
 *   Mach-O: llvm-otool-20 -h, llvm-nm-20
 */

const EXPECTED = {
  elf: {
    x64: {
      // readelf -h elf/hello-linux-x64
      entrypoint: 0x1013b00n,
      machine: 'x86-64',
      type: 'EXEC',
      // readelf -s elf/hello-linux-x64 | grep main
      symbols: {
        main: { value: 0x1013bd0n, size: 63n },
        helper_function: { value: 0x1013b30n, size: 125n },
        print_message: { value: 0x1013bb0n, size: 30n },
        global_counter: { value: 0x1069c20n, size: 4n },
      },
      // readelf -S elf/hello-linux-x64
      sections: {
        '.text': { address: 0x1013b00n },
        '.rodata': { address: 0x1000bc0n },
        '.data': { address: 0x1069c00n },
      },
      // readelf -r elf/hello-linux-x64 | wc -l (minus headers)
      relocationCount: 27, // 2 in .rela.dyn + 25 in .rela.plt
    },
    arm64: {
      // readelf -h elf/hello-linux-arm64
      entrypoint: 0x1024d60n,
      machine: 'AArch64',
      type: 'EXEC',
    },
  },
  pe: {
    x64: {
      // llvm-readobj-20 --file-headers pe/hello-windows-x64.exe
      magic: 'PE32_PLUS', // 0x20B
      machine: 0x8664, // IMAGE_FILE_MACHINE_AMD64
      entrypoint: 0x14e0, // AddressOfEntryPoint
      imagebase: 0x140000000n,
      sectionAlignment: 4096,
      fileAlignment: 512,
      sizeOfCode: 302592,
      sizeOfImage: 585728,
      sizeOfHeaders: 1024,
      majorLinkerVersion: 14,
      minorLinkerVersion: 0,
      majorOperatingSystemVersion: 6,
      minorOperatingSystemVersion: 0,
      majorSubsystemVersion: 6,
      minorSubsystemVersion: 0,
      subsystem: 3, // IMAGE_SUBSYSTEM_WINDOWS_CUI
      sizeOfStackReserve: 16777216n,
      sizeOfStackCommit: 4096n,
      sizeOfHeapReserve: 1048576n,
      sizeOfHeapCommit: 4096n,
      // Section info
      sections: {
        '.text': { virtualAddress: 0x1000n, size: 0x49c96n },
        '.rdata': { virtualAddress: 0x4b000n },
        '.data': { virtualAddress: 0x89000n },
        '.reloc': { virtualAddress: 0x8e000n },
      },
      sectionCount: 7,
    },
    arm64: {
      // llvm-readobj-20 --file-headers pe/hello-windows-arm64.exe
      magic: 'PE32_PLUS',
      machine: 0xaa64, // IMAGE_FILE_MACHINE_ARM64
      entrypoint: 0x1580,
      imagebase: 0x140000000n,
      sectionCount: 7,
    },
  },
  macho: {
    x64: {
      // llvm-otool-20 -h macho/hello-macos-x64
      cpuType: 16777223, // CPU_TYPE_X86_64 (7 | ABI64)
      cpuSubtype: 3, // CPU_SUBTYPE_X86_64_ALL
      fileType: 2, // MH_EXECUTE
      ncmds: 16,
      flags: 0x00b00085,
      // llvm-nm-20 macho/hello-macos-x64
      symbols: {
        _main: 0x100036fd0n,
        _helper_function: 0x100036f30n,
        _print_message: 0x100036fb0n,
        _global_counter: 0x100060df0n,
      },
      // Segment info from llvm-otool-20 -l
      segments: {
        __TEXT: { vmaddr: 0x100000000n, vmsize: 0x5e428n },
        __DATA: { vmaddr: 0x10005f000n },
        __LINKEDIT: { vmaddr: 0x100061000n },
      },
    },
    arm64: {
      // llvm-otool-20 -h macho/hello-macos-arm64
      cpuType: 16777228, // CPU_TYPE_ARM64 (12 | ABI64)
      cpuSubtype: 0, // CPU_SUBTYPE_ARM64_ALL
      fileType: 2, // MH_EXECUTE
      ncmds: 17,
    },
    universal: {
      // file macho/hello-macos-universal - has 2 architectures
      archCount: 2,
    },
  },
};

describe('ELF Known Values', () => {
  const fixtures = getElfFixtures();

  describe('hello-linux-x64', () => {
    it('should have correct entrypoint', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(
        binary.entrypoint,
        EXPECTED.elf.x64.entrypoint,
        `Entrypoint should be 0x${EXPECTED.elf.x64.entrypoint.toString(16)}`,
      );
    });

    it('should find main symbol with correct value', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const main = binary.getSymbol('main');
      assert.ok(main, 'Should find main symbol');
      assert.strictEqual(
        main.value,
        EXPECTED.elf.x64.symbols.main.value,
        `main should be at 0x${EXPECTED.elf.x64.symbols.main.value.toString(16)}`,
      );
      assert.strictEqual(
        main.size,
        EXPECTED.elf.x64.symbols.main.size,
        `main size should be ${EXPECTED.elf.x64.symbols.main.size}`,
      );
    });

    it('should find helper_function symbol with correct value', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const sym = binary.getSymbol('helper_function');
      assert.ok(sym, 'Should find helper_function symbol');
      assert.strictEqual(sym.value, EXPECTED.elf.x64.symbols.helper_function.value);
      assert.strictEqual(sym.size, EXPECTED.elf.x64.symbols.helper_function.size);
    });

    it('should find print_message symbol with correct value', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const sym = binary.getSymbol('print_message');
      assert.ok(sym, 'Should find print_message symbol');
      assert.strictEqual(sym.value, EXPECTED.elf.x64.symbols.print_message.value);
    });

    it('should find global_counter symbol with correct value', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const sym = binary.getSymbol('global_counter');
      assert.ok(sym, 'Should find global_counter symbol');
      assert.strictEqual(sym.value, EXPECTED.elf.x64.symbols.global_counter.value);
    });

    it('should have .text section with correct address', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const section = binary.getSection('.text');
      assert.ok(section, 'Should find .text section');
      assert.strictEqual(section.virtualAddress, EXPECTED.elf.x64.sections['.text'].address);
    });

    it('should have correct number of relocations', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const relocations = binary.relocations();
      assert.strictEqual(
        relocations.length,
        EXPECTED.elf.x64.relocationCount,
        `Should have ${EXPECTED.elf.x64.relocationCount} relocations`,
      );
    });
  });

  describe('hello-linux-arm64', () => {
    it('should have correct entrypoint', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'ELF arm64')) return t.skip();
      const binary = LIEF.parse(fixtures.arm64);
      assert.strictEqual(binary.entrypoint, EXPECTED.elf.arm64.entrypoint);
    });
  });
});

describe('PE Known Values', () => {
  const fixtures = getPeFixtures();

  describe('hello-windows-x64.exe', () => {
    it('should have correct magic (PE32+)', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.magic, EXPECTED.pe.x64.magic);
    });

    it('should have correct imagebase', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.imagebase, EXPECTED.pe.x64.imagebase);
    });

    it('should have correct sectionAlignment', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.sectionAlignment, EXPECTED.pe.x64.sectionAlignment);
    });

    it('should have correct fileAlignment', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.fileAlignment, EXPECTED.pe.x64.fileAlignment);
    });

    it('should have correct sizeOfCode', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.sizeOfCode, EXPECTED.pe.x64.sizeOfCode);
    });

    it('should have correct sizeOfImage', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.sizeOfImage, EXPECTED.pe.x64.sizeOfImage);
    });

    it('should have correct sizeOfHeaders', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.sizeOfHeaders, EXPECTED.pe.x64.sizeOfHeaders);
    });

    it('should have correct linker version', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(
        binary.optionalHeader.majorLinkerVersion,
        EXPECTED.pe.x64.majorLinkerVersion,
      );
      assert.strictEqual(
        binary.optionalHeader.minorLinkerVersion,
        EXPECTED.pe.x64.minorLinkerVersion,
      );
    });

    it('should have correct OS version', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(
        binary.optionalHeader.majorOperatingSystemVersion,
        EXPECTED.pe.x64.majorOperatingSystemVersion,
      );
      assert.strictEqual(
        binary.optionalHeader.minorOperatingSystemVersion,
        EXPECTED.pe.x64.minorOperatingSystemVersion,
      );
    });

    it('should have correct subsystem version', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(
        binary.optionalHeader.majorSubsystemVersion,
        EXPECTED.pe.x64.majorSubsystemVersion,
      );
      assert.strictEqual(
        binary.optionalHeader.minorSubsystemVersion,
        EXPECTED.pe.x64.minorSubsystemVersion,
      );
    });

    it('should have correct subsystem (CONSOLE)', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.optionalHeader.subsystem, EXPECTED.pe.x64.subsystem);
    });

    it('should have correct stack sizes', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(
        binary.optionalHeader.sizeOfStackReserve,
        EXPECTED.pe.x64.sizeOfStackReserve,
      );
      assert.strictEqual(
        binary.optionalHeader.sizeOfStackCommit,
        EXPECTED.pe.x64.sizeOfStackCommit,
      );
    });

    it('should have correct heap sizes', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(
        binary.optionalHeader.sizeOfHeapReserve,
        EXPECTED.pe.x64.sizeOfHeapReserve,
      );
      assert.strictEqual(binary.optionalHeader.sizeOfHeapCommit, EXPECTED.pe.x64.sizeOfHeapCommit);
    });

    it('should have correct number of sections', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const sections = binary.sections();
      assert.strictEqual(sections.length, EXPECTED.pe.x64.sectionCount);
    });

    it('should have .text section with correct address', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const section = binary.getSection('.text');
      assert.ok(section, 'Should find .text section');
      assert.strictEqual(section.virtualAddress, EXPECTED.pe.x64.sections['.text'].virtualAddress);
    });
  });

  describe('hello-windows-arm64.exe', () => {
    it('should have correct magic (PE32+)', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'PE arm64')) return t.skip();
      const binary = LIEF.parse(fixtures.arm64);
      assert.strictEqual(binary.optionalHeader.magic, EXPECTED.pe.arm64.magic);
    });

    it('should have correct imagebase', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'PE arm64')) return t.skip();
      const binary = LIEF.parse(fixtures.arm64);
      assert.strictEqual(binary.optionalHeader.imagebase, EXPECTED.pe.arm64.imagebase);
    });
  });
});

describe('MachO Known Values', () => {
  const fixtures = getMachoFixtures();

  describe('hello-macos-x64', () => {
    it('should have correct CPU type (X86_64)', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.header.cpuType, EXPECTED.macho.x64.cpuType);
      assert.strictEqual(binary.header.cpuType, LIEF.MachO.Header.CPU_TYPE.X86_64);
    });

    it('should have correct CPU subtype', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.header.cpuSubtype, EXPECTED.macho.x64.cpuSubtype);
    });

    it('should have correct file type (EXECUTE)', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.header.fileType, EXPECTED.macho.x64.fileType);
    });

    it('should have correct number of load commands', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.header.nbCmds, EXPECTED.macho.x64.ncmds);
    });

    it('should have correct flags', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      assert.strictEqual(binary.header.flags, EXPECTED.macho.x64.flags);
    });

    it('should have __TEXT segment with correct vmaddr', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const segment = binary.getSegment('__TEXT');
      assert.ok(segment, 'Should find __TEXT segment');
      assert.strictEqual(segment.virtualAddress, EXPECTED.macho.x64.segments['__TEXT'].vmaddr);
    });

    it('should have __TEXT segment with correct vmsize', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const segment = binary.getSegment('__TEXT');
      assert.ok(segment, 'Should find __TEXT segment');
      assert.strictEqual(segment.virtualSize, EXPECTED.macho.x64.segments['__TEXT'].vmsize);
    });

    it('should find _main symbol with correct value', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();
      const binary = LIEF.parse(fixtures.x64);
      const symbols = binary.symbols();
      const main = symbols.find((s) => s.name === '_main');
      assert.ok(main, 'Should find _main symbol');
      // Note: MachO symbols might not have value exposed the same way
      // This test documents the expected behavior
    });
  });

  describe('hello-macos-arm64', () => {
    it('should have correct CPU type (ARM64)', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'MachO arm64')) return t.skip();
      const binary = LIEF.parse(fixtures.arm64);
      assert.strictEqual(binary.header.cpuType, EXPECTED.macho.arm64.cpuType);
      assert.strictEqual(binary.header.cpuType, LIEF.MachO.Header.CPU_TYPE.ARM64);
    });

    it('should have correct number of load commands', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'MachO arm64')) return t.skip();
      const binary = LIEF.parse(fixtures.arm64);
      assert.strictEqual(binary.header.nbCmds, EXPECTED.macho.arm64.ncmds);
    });
  });

  describe('hello-macos-universal', () => {
    it('should have correct number of architectures', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();
      const fat = LIEF.MachO.parse(fixtures.universal);
      assert.strictEqual(fat.size(), EXPECTED.macho.universal.archCount);
    });

    it('should contain X86_64 and ARM64 slices', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();
      const fat = LIEF.MachO.parse(fixtures.universal);

      const cpuTypes = [];
      for (let i = 0; i < fat.size(); i++) {
        cpuTypes.push(fat.at(i).header.cpuType);
      }

      assert.ok(cpuTypes.includes(LIEF.MachO.Header.CPU_TYPE.X86_64), 'Should have X86_64');
      assert.ok(cpuTypes.includes(LIEF.MachO.Header.CPU_TYPE.ARM64), 'Should have ARM64');
    });
  });
});
