/**
 * ELF-specific tests
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { getElfFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('ELF.Binary', () => {
  const fixtures = getElfFixtures();

  describe('ELF-specific properties', () => {
    it('should have hasOverlay property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.hasOverlay, 'boolean', 'hasOverlay should be boolean');
    });

    it('should have overlay property (getter)', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const overlay = binary.overlay;

      // Overlay should be a Buffer (possibly empty)
      assert.ok(Buffer.isBuffer(overlay), 'overlay should be a Buffer');
    });

    it('should allow setting overlay property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const testData = Buffer.from([0x41, 0x42, 0x43, 0x44]); // "ABCD"

      binary.overlay = testData;
      const overlay = binary.overlay;

      assert.ok(Buffer.isBuffer(overlay), 'overlay should be a Buffer');
      assert.strictEqual(overlay.length, testData.length, 'overlay length should match');
      assert.deepStrictEqual([...overlay], [...testData], 'overlay content should match');
    });
  });

  describe('ELF sections', () => {
    it('should have standard ELF sections', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();
      const sectionNames = sections.map(s => s.name);

      // Most ELF binaries should have at least .text
      assert.ok(
        sectionNames.some(name => name === '.text' || name === '.init' || name === '.plt'),
        'Should have code sections'
      );
    });

    it('should get section by name with getSection()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      // Try to get the first section by name
      const firstSection = sections[0];
      const retrieved = binary.getSection(firstSection.name);

      assert.ok(retrieved, `Should find section ${firstSection.name}`);
      assert.strictEqual(retrieved.name, firstSection.name, 'Retrieved section name should match');
    });

    it('should return null for non-existent section', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSection('__nonexistent_section_12345__');

      assert.strictEqual(result, null, 'Should return null for non-existent section');
    });
  });

  describe('ELF symbols', () => {
    it('should return array of symbols', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      assert.ok(Array.isArray(symbols), 'symbols() should return array');
    });

    it('should find symbol by name with getSymbol()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      // Find a symbol that has a name
      const namedSymbol = symbols.find(s => s.name && s.name.length > 0);
      if (!namedSymbol) return t.skip('No named symbols in binary');

      const found = binary.getSymbol(namedSymbol.name);

      assert.ok(found, `Should find symbol ${namedSymbol.name}`);
      assert.strictEqual(found.name, namedSymbol.name, 'Found symbol name should match');
    });

    it('should return null for non-existent symbol', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSymbol('__nonexistent_symbol_12345__');

      assert.strictEqual(result, null, 'Should return null for non-existent symbol');
    });
  });

  describe('ELF relocations', () => {
    it('should return array of relocations', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      assert.ok(Array.isArray(relocations), 'relocations() should return array');
    });

    it('should have address and size on relocations', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      if (relocations.length === 0) return t.skip('No relocations in binary');

      const reloc = relocations[0];
      assert.strictEqual(typeof reloc.address, 'bigint', 'Relocation address should be bigint');
      assert.strictEqual(typeof reloc.size, 'number', 'Relocation size should be number');
    });
  });

  describe('ELF segments', () => {
    it('should return array from segments()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();

      assert.ok(Array.isArray(segments), 'segments() should return array');
      // Note: The abstract segments() returns empty by default
      // Format-specific segment access is through format-specific APIs
    });
  });

  describe('Abstract Binary properties on ELF', () => {
    it('should have correct format', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(binary.format, 'ELF', 'Format should be ELF');
    });

    it('should have entrypoint', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.entrypoint, 'bigint', 'Entrypoint should be bigint');
      // For executable ELF files, entrypoint should typically be non-zero
      // But shared libraries might have 0
    });

    it('should have isPie property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.isPie, 'boolean', 'isPie should be boolean');
    });

    it('should have hasNx property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.strictEqual(typeof binary.hasNx, 'boolean', 'hasNx should be boolean');
    });

    it('should have abstract header property', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const header = binary.header;

      assert.ok(header, 'Should have header property');
      assert.strictEqual(typeof header.architecture, 'number', 'header.architecture should be number');
      assert.strictEqual(typeof header.entrypoint, 'bigint', 'header.entrypoint should be bigint');
      assert.strictEqual(typeof header.is_32, 'boolean', 'header.is_32 should be boolean');
      assert.strictEqual(typeof header.is_64, 'boolean', 'header.is_64 should be boolean');
    });
  });

  describe('ELF Section setters', () => {
    it('should allow setting size property on abstract section', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();

      if (sections.length === 0) return t.skip('No sections in binary');

      const section = sections.find(s => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const newSize = 0x1000n;

      // Set size
      assert.doesNotThrow(() => {
        section.size = newSize;
      }, 'Setting size should not throw');

      // Note: The actual value may be adjusted by LIEF
      assert.strictEqual(typeof section.size, 'bigint', 'size should still be bigint after setting');
    });
  });
});
