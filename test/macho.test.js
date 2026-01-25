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
 * MachO (macOS/iOS) specific tests
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { getMachoFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('MachO.Binary', () => {
  const fixtures = getMachoFixtures();

  describe('MachO-specific properties', () => {
    it('should have hasCodeSignature property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.hasCodeSignature, 'boolean', 'hasCodeSignature should be boolean');
    });

    it('should have header property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.ok(binary.header, 'Should have header property');
    });

    it('should have correct format', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(binary.format, 'MachO', 'Format should be MachO');
    });
  });

  describe('MachO.Header', () => {
    it('should have cpuType property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.cpuType, 'number', 'cpuType should be number');
    });

    it('should have cpuSubtype property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.cpuSubtype, 'number', 'cpuSubtype should be number');
    });

    it('should have fileType property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.fileType, 'number', 'fileType should be number');
    });

    it('should have flags property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.flags, 'number', 'flags should be number');
    });

    it('should have magic property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.magic, 'number', 'magic should be number');
    });

    it('should have nbCmds property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.nbCmds, 'number', 'nbCmds should be number');
      assert.ok(header.nbCmds > 0, 'Should have at least one load command');
    });

    it('should have sizeofCmds property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.sizeofCmds, 'number', 'sizeofCmds should be number');
      assert.ok(header.sizeofCmds > 0, 'sizeofCmds should be positive');
    });

    it('should have is32Bit and is64Bit properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.strictEqual(typeof header.is32Bit, 'boolean', 'is32Bit should be boolean');
      assert.strictEqual(typeof header.is64Bit, 'boolean', 'is64Bit should be boolean');
      // A binary should be either 32-bit or 64-bit, not both
      assert.notStrictEqual(header.is32Bit, header.is64Bit, 'Binary should be either 32-bit or 64-bit');
    });

    it('should detect x64 CPU type correctly', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();

      const binary = LIEF.parse(fixtures.x64);
      const header = binary.header;

      assert.strictEqual(header.cpuType, LIEF.MachO.Header.CPU_TYPE.X86_64, 'Should be X86_64 CPU type');
      assert.strictEqual(header.is64Bit, true, 'Should be 64-bit');
    });

    it('should detect arm64 CPU type correctly', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'MachO arm64')) return t.skip();

      const binary = LIEF.parse(fixtures.arm64);
      const header = binary.header;

      assert.strictEqual(header.cpuType, LIEF.MachO.Header.CPU_TYPE.ARM64, 'Should be ARM64 CPU type');
      assert.strictEqual(header.is64Bit, true, 'Should be 64-bit');
    });
  });

  describe('MachO.Header.CPU_TYPE constants', () => {
    it('should have X86 constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.X86, 7, 'X86 should be 7');
    });

    it('should have X86_64 constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.X86_64, 16777223, 'X86_64 should be 16777223 (7 | ABI64)');
    });

    it('should have ARM constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.ARM, 12, 'ARM should be 12');
    });

    it('should have ARM64 constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.ARM64, 16777228, 'ARM64 should be 16777228 (12 | ABI64)');
    });

    it('should have POWERPC constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.POWERPC, 18, 'POWERPC should be 18');
    });

    it('should have POWERPC64 constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.POWERPC64, 16777234, 'POWERPC64 should be 16777234 (18 | ABI64)');
    });

    it('should have ANY constant', () => {
      assert.strictEqual(LIEF.MachO.Header.CPU_TYPE.ANY, -1, 'ANY should be -1');
    });
  });

  describe('MachO segments', () => {
    it('should get segment by name with getSegment()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      // MachO binaries should have __TEXT segment
      const textSegment = binary.getSegment('__TEXT');

      assert.ok(textSegment, 'Should find __TEXT segment');
      assert.strictEqual(textSegment.name, '__TEXT', 'Segment name should be __TEXT');
    });

    it('should return null for non-existent segment', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSegment('__NONEXISTENT__');

      assert.strictEqual(result, null, 'Should return null for non-existent segment');
    });

    it('should have standard MachO segments', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      const textSegment = binary.getSegment('__TEXT');
      const linkeditSegment = binary.getSegment('__LINKEDIT');

      assert.ok(textSegment, 'Should have __TEXT segment');
      assert.ok(linkeditSegment, 'Should have __LINKEDIT segment');
    });
  });

  describe('MachO.Segment', () => {
    it('should have name property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      assert.strictEqual(typeof segment.name, 'string', 'name should be string');
      assert.strictEqual(segment.name, '__TEXT', 'name should be __TEXT');
    });

    it('should have virtualAddress property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      assert.strictEqual(typeof segment.virtualAddress, 'bigint', 'virtualAddress should be bigint');
    });

    it('should have virtualSize property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      assert.strictEqual(typeof segment.virtualSize, 'bigint', 'virtualSize should be bigint');
    });

    it('should have fileOffset property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      assert.strictEqual(typeof segment.fileOffset, 'bigint', 'fileOffset should be bigint');
    });

    it('should have fileSize property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      assert.strictEqual(typeof segment.fileSize, 'bigint', 'fileSize should be bigint');
    });

    it('should have sections() method', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      const sections = segment.sections();

      assert.ok(Array.isArray(sections), 'sections() should return array');
      // __TEXT segment typically has sections like __text, __stubs, etc.
      assert.ok(sections.length > 0, '__TEXT should have sections');
    });

    it('should have getSection() method', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      // Try to get __text section (main code section)
      const textSection = segment.getSection('__text');

      // Note: Section might not exist in all binaries
      if (textSection) {
        assert.strictEqual(textSection.name, '__text', 'Section name should be __text');
      }
    });

    it('should return null for non-existent section in segment', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segment = binary.getSegment('__TEXT');

      if (!segment) return t.skip('No __TEXT segment');

      const result = segment.getSection('__nonexistent__');

      assert.strictEqual(result, null, 'Should return null for non-existent section');
    });
  });

  describe('MachO sections', () => {
    it('should return array of sections', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      assert.ok(Array.isArray(sections), 'sections() should return array');
      assert.ok(sections.length > 0, 'Should have at least one section');
    });

    it('should have standard MachO sections', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();
      const sectionNames = sections.map(s => s.name);

      // MachO binaries typically have __text section
      assert.ok(
        sectionNames.some(name => name === '__text' || name === '__stubs'),
        'Should have code sections'
      );
    });
  });

  describe('MachO symbols', () => {
    it('should return array of symbols', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      assert.ok(Array.isArray(symbols), 'symbols() should return array');
    });

    it('should have name property on symbols', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      const symbol = symbols[0];
      assert.strictEqual(typeof symbol.name, 'string', 'Symbol name should be string');
    });
  });

  describe('MachO code signature operations', () => {
    it('should be able to call removeSignature()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      // This should not throw, regardless of whether the binary has a signature
      assert.doesNotThrow(() => {
        binary.removeSignature();
      }, 'removeSignature() should not throw');
    });
  });

  describe('Abstract Binary properties on MachO', () => {
    it('should have entrypoint', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.entrypoint, 'bigint', 'Entrypoint should be bigint');
    });

    it('should have isPie property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.isPie, 'boolean', 'isPie should be boolean');
    });

    it('should have hasNx property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.hasNx, 'boolean', 'hasNx should be boolean');
    });
  });
});

describe('MachO.FatBinary', () => {
  const fixtures = getMachoFixtures();

  describe('FatBinary for single-arch binary', () => {
    it('should have size() method returning 1', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'single-arch MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);

      assert.strictEqual(typeof fat.size, 'function', 'size should be a function');
      assert.strictEqual(fat.size(), 1, 'Single-arch should have size 1');
    });
  });

  describe('FatBinary for universal binary', () => {
    it('should have size() >= 2', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

      const fat = LIEF.MachO.parse(fixtures.universal);

      assert.ok(fat.size() >= 2, 'Universal binary should have at least 2 architectures');
    });

    it('should access different architectures via at()', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

      const fat = LIEF.MachO.parse(fixtures.universal);
      const first = fat.at(0);
      const second = fat.at(1);

      assert.ok(first, 'Should get first binary');
      assert.ok(second, 'Should get second binary');

      // The two architectures should have different CPU types
      assert.notStrictEqual(
        first.header.cpuType,
        second.header.cpuType,
        'Different slices should have different CPU types'
      );
    });

    it('should contain x64 and arm64 slices', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

      const fat = LIEF.MachO.parse(fixtures.universal);
      const cpuTypes = [];

      for (let i = 0; i < fat.size(); i++) {
        const binary = fat.at(i);
        cpuTypes.push(binary.header.cpuType);
      }

      const hasX64 = cpuTypes.includes(LIEF.MachO.Header.CPU_TYPE.X86_64);
      const hasArm64 = cpuTypes.includes(LIEF.MachO.Header.CPU_TYPE.ARM64);

      assert.ok(hasX64, 'Should contain x86_64 slice');
      assert.ok(hasArm64, 'Should contain arm64 slice');
    });
  });

  describe('FatBinary take() method', () => {
    it('should take ownership of binary', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);
      const binary = fat.take(0);

      assert.ok(binary, 'Should take binary');
      assert.strictEqual(binary.format, 'MachO', 'Taken binary should be MachO');
    });

    it('should throw RangeError for out-of-bounds take()', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

      const fat = LIEF.MachO.parse(fixtures.universal);

      assert.throws(() => {
        fat.take(999);
      }, /RangeError|out of range/i, 'Should throw for invalid index');
    });
  });
});
