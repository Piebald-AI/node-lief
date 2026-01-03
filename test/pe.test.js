/**
 * PE (Windows Portable Executable) specific tests
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { getPeFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('PE.Binary', () => {
  const fixtures = getPeFixtures();

  describe('PE-specific properties', () => {
    it('should have optionalHeader property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.ok(binary.optionalHeader, 'Should have optionalHeader');
    });

    it('should have correct format', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(binary.format, 'PE', 'Format should be PE');
    });

    it('should have segments() returning empty array (PE uses sections)', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();

      assert.ok(Array.isArray(segments), 'segments() should return array');
      assert.strictEqual(segments.length, 0, 'PE segments() should be empty (PE uses sections, not segments)');
    });
  });

  describe('PE.OptionalHeader', () => {
    it('should have magic property (PE32 or PE32_PLUS)', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.ok(['PE32', 'PE32_PLUS', 'UNKNOWN'].includes(header.magic), 'Magic should be valid PE type');
    });

    it('should have PE32_PLUS magic for 64-bit PE', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(header.magic, 'PE32_PLUS', '64-bit PE should have PE32_PLUS magic');
    });

    it('should have PE32 magic for 32-bit PE', async (t) => {
      if (skipIfNoFixture(fixtures.x86, '32-bit PE')) return t.skip();

      const binary = LIEF.parse(fixtures.x86);
      const header = binary.optionalHeader;

      assert.strictEqual(header.magic, 'PE32', '32-bit PE should have PE32 magic');
    });

    it('should have linker version properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.majorLinkerVersion, 'number', 'majorLinkerVersion should be number');
      assert.strictEqual(typeof header.minorLinkerVersion, 'number', 'minorLinkerVersion should be number');
    });

    it('should have size properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.sizeOfCode, 'number', 'sizeOfCode should be number');
      assert.strictEqual(typeof header.sizeOfInitializedData, 'number', 'sizeOfInitializedData should be number');
      assert.strictEqual(typeof header.sizeOfUninitializedData, 'number', 'sizeOfUninitializedData should be number');
      assert.strictEqual(typeof header.sizeOfImage, 'number', 'sizeOfImage should be number');
      assert.strictEqual(typeof header.sizeOfHeaders, 'number', 'sizeOfHeaders should be number');
    });

    it('should have address properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.addressOfEntrypoint, 'number', 'addressOfEntrypoint should be number');
      assert.strictEqual(typeof header.baseOfCode, 'number', 'baseOfCode should be number');
      // baseOfData might be 0 for PE32+ (64-bit)
      assert.strictEqual(typeof header.baseOfData, 'number', 'baseOfData should be number');
      assert.strictEqual(typeof header.imagebase, 'bigint', 'imagebase should be bigint');
    });

    it('should have alignment properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.sectionAlignment, 'number', 'sectionAlignment should be number');
      assert.strictEqual(typeof header.fileAlignment, 'number', 'fileAlignment should be number');
      // Common values are 4096 (0x1000) for section alignment and 512 (0x200) for file alignment
      assert.ok(header.sectionAlignment > 0, 'sectionAlignment should be positive');
      assert.ok(header.fileAlignment > 0, 'fileAlignment should be positive');
    });

    it('should have version properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.majorOperatingSystemVersion, 'number', 'majorOperatingSystemVersion should be number');
      assert.strictEqual(typeof header.minorOperatingSystemVersion, 'number', 'minorOperatingSystemVersion should be number');
      assert.strictEqual(typeof header.majorImageVersion, 'number', 'majorImageVersion should be number');
      assert.strictEqual(typeof header.minorImageVersion, 'number', 'minorImageVersion should be number');
      assert.strictEqual(typeof header.majorSubsystemVersion, 'number', 'majorSubsystemVersion should be number');
      assert.strictEqual(typeof header.minorSubsystemVersion, 'number', 'minorSubsystemVersion should be number');
    });

    it('should have checksum and subsystem properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.checksum, 'number', 'checksum should be number');
      assert.strictEqual(typeof header.subsystem, 'number', 'subsystem should be number');
      assert.strictEqual(typeof header.dllCharacteristics, 'number', 'dllCharacteristics should be number');
    });

    it('should have stack and heap size properties as BigInt', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.sizeOfStackReserve, 'bigint', 'sizeOfStackReserve should be bigint');
      assert.strictEqual(typeof header.sizeOfStackCommit, 'bigint', 'sizeOfStackCommit should be bigint');
      assert.strictEqual(typeof header.sizeOfHeapReserve, 'bigint', 'sizeOfHeapReserve should be bigint');
      assert.strictEqual(typeof header.sizeOfHeapCommit, 'bigint', 'sizeOfHeapCommit should be bigint');
    });

    it('should have win32VersionValue property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.optionalHeader;

      assert.strictEqual(typeof header.win32VersionValue, 'number', 'win32VersionValue should be number');
    });
  });

  describe('PE sections', () => {
    it('should have standard PE sections', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();
      const sectionNames = sections.map(s => s.name);

      // PE binaries typically have .text section
      assert.ok(
        sectionNames.some(name => name === '.text' || name === '.code'),
        'Should have code section'
      );
    });

    it('should get section by name with getSection()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const firstSection = sections[0];
      const retrieved = binary.getSection(firstSection.name);

      assert.ok(retrieved, `Should find section ${firstSection.name}`);
      assert.strictEqual(retrieved.name, firstSection.name, 'Retrieved section name should match');
    });

    it('should return null for non-existent section', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSection('__nonexistent_section_12345__');

      assert.strictEqual(result, null, 'Should return null for non-existent section');
    });
  });

  describe('PE.Section', () => {
    it('should have virtualSize property (distinct from size)', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections[0];

      assert.strictEqual(typeof section.virtualSize, 'bigint', 'virtualSize should be bigint');
      assert.strictEqual(typeof section.size, 'bigint', 'size should be bigint');
    });

    it('should have characteristics property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections[0];

      assert.strictEqual(typeof section.characteristics, 'number', 'characteristics should be number');
    });

    it('should have standard section properties', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections[0];

      assert.strictEqual(typeof section.name, 'string', 'name should be string');
      assert.strictEqual(typeof section.virtualAddress, 'bigint', 'virtualAddress should be bigint');
      assert.strictEqual(typeof section.fileOffset, 'bigint', 'fileOffset should be bigint');
    });
  });

  describe('Abstract Binary properties on PE', () => {
    it('should have entrypoint', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.entrypoint, 'bigint', 'Entrypoint should be bigint');
    });

    it('should have isPie property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.isPie, 'boolean', 'isPie should be boolean');
    });

    it('should have hasNx property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.hasNx, 'boolean', 'hasNx should be boolean');
    });
  });

  describe('PE symbols', () => {
    it('should return array of symbols', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      assert.ok(Array.isArray(symbols), 'symbols() should return array');
    });
  });

  describe('PE relocations', () => {
    it('should return array of relocations', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      assert.ok(Array.isArray(relocations), 'relocations() should return array');
    });
  });

  describe('PE.Section setters', () => {
    it('should allow setting size property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections.find(s => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const originalSize = section.size;
      const newSize = 0x2000n;

      // Set size
      assert.doesNotThrow(() => {
        section.size = newSize;
      }, 'Setting size should not throw');

      // Note: The actual value may be clamped by LIEF
      assert.strictEqual(typeof section.size, 'bigint', 'size should still be bigint after setting');
    });

    it('should allow setting virtualSize property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections.find(s => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const newVirtualSize = 0x3000n;

      // Set virtualSize
      assert.doesNotThrow(() => {
        section.virtualSize = newVirtualSize;
      }, 'Setting virtualSize should not throw');

      assert.strictEqual(typeof section.virtualSize, 'bigint', 'virtualSize should still be bigint after setting');
    });

    it('should allow setting content with Buffer', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections.find(s => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const newContent = Buffer.from([0x90, 0x90, 0x90, 0x90]); // NOP sled

      assert.doesNotThrow(() => {
        section.content = newContent;
      }, 'Setting content with Buffer should not throw');
    });

    it('should allow setting content with Array', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections.find(s => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const newContent = [0xCC, 0xCC, 0xCC, 0xCC]; // INT3 breakpoints

      assert.doesNotThrow(() => {
        section.content = newContent;
      }, 'Setting content with Array should not throw');
    });

    it('should have offset property (alias for fileOffset)', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections[0];

      assert.strictEqual(typeof section.offset, 'bigint', 'offset should be bigint');
      assert.strictEqual(section.offset, section.fileOffset, 'offset should equal fileOffset');
    });
  });

  describe('Abstract header property on PE', () => {
    it('should have header property with architecture info', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.ok(header, 'Should have header property');
      assert.strictEqual(typeof header.architecture, 'number', 'header.architecture should be number');
      assert.strictEqual(typeof header.entrypoint, 'bigint', 'header.entrypoint should be bigint');
      assert.strictEqual(typeof header.is_32, 'boolean', 'header.is_32 should be boolean');
      assert.strictEqual(typeof header.is_64, 'boolean', 'header.is_64 should be boolean');
    });
  });
});
