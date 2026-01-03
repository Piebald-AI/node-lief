/**
 * Core parsing tests for LIEF.parse() and format-specific parsers
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { getElfFixtures, getPeFixtures, getMachoFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('LIEF.parse()', () => {
  describe('ELF parsing', () => {
    const fixtures = getElfFixtures();

    it('should parse ELF x64 binary and detect format', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'ELF x64')) return t.skip();

      const binary = LIEF.parse(fixtures.x64);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'ELF', 'Format should be ELF');
    });

    it('should parse ELF arm64 binary and detect format', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'ELF arm64')) return t.skip();

      const binary = LIEF.parse(fixtures.arm64);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'ELF', 'Format should be ELF');
    });

    it('should return ELF.Binary instance for ELF files', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // ELF.Binary should have ELF-specific properties
      assert.strictEqual(typeof binary.hasOverlay, 'boolean', 'Should have hasOverlay property');
    });
  });

  describe('PE parsing', () => {
    const fixtures = getPeFixtures();

    it('should parse PE x64 binary and detect format', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'PE x64')) return t.skip();

      const binary = LIEF.parse(fixtures.x64);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'PE', 'Format should be PE');
    });

    it('should parse PE arm64 binary and detect format', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'PE arm64')) return t.skip();

      const binary = LIEF.parse(fixtures.arm64);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'PE', 'Format should be PE');
    });

    it('should return PE.Binary instance for PE files', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      // PE.Binary should have PE-specific properties
      assert.ok(binary.optionalHeader, 'Should have optionalHeader property');
    });
  });

  describe('MachO parsing', () => {
    const fixtures = getMachoFixtures();

    it('should parse MachO x64 binary and detect format', async (t) => {
      if (skipIfNoFixture(fixtures.x64, 'MachO x64')) return t.skip();

      const binary = LIEF.parse(fixtures.x64);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'MachO', 'Format should be MachO');
    });

    it('should parse MachO arm64 binary and detect format', async (t) => {
      if (skipIfNoFixture(fixtures.arm64, 'MachO arm64')) return t.skip();

      const binary = LIEF.parse(fixtures.arm64);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'MachO', 'Format should be MachO');
    });

    it('should parse MachO universal binary (takes first architecture)', async (t) => {
      if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

      const binary = LIEF.parse(fixtures.universal);

      assert.ok(binary, 'Binary should be parsed');
      assert.strictEqual(binary.format, 'MachO', 'Format should be MachO');
    });

    it('should return MachO.Binary instance for MachO files', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      // MachO.Binary should have MachO-specific properties
      assert.strictEqual(typeof binary.hasCodeSignature, 'boolean', 'Should have hasCodeSignature property');
      assert.ok(binary.header, 'Should have header property');
    });
  });
});

describe('LIEF.MachO.parse()', () => {
  const fixtures = getMachoFixtures();

  it('should return FatBinary for single-arch MachO', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'single-arch MachO')) return t.skip();

    const fat = LIEF.MachO.parse(fixture);

    assert.ok(fat, 'FatBinary should be returned');
    assert.strictEqual(typeof fat.size, 'function', 'Should have size() method');
    assert.strictEqual(fat.size(), 1, 'Single-arch should have size 1');
  });

  it('should return FatBinary with multiple architectures for universal binary', async (t) => {
    if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

    const fat = LIEF.MachO.parse(fixtures.universal);

    assert.ok(fat, 'FatBinary should be returned');
    assert.ok(fat.size() >= 2, 'Universal binary should have at least 2 architectures');
  });

  it('should access individual binaries via at()', async (t) => {
    if (skipIfNoFixture(fixtures.universal, 'MachO universal')) return t.skip();

    const fat = LIEF.MachO.parse(fixtures.universal);
    const first = fat.at(0);
    const second = fat.at(1);

    assert.ok(first, 'Should get first binary');
    assert.ok(second, 'Should get second binary');
    assert.strictEqual(first.format, 'MachO', 'First should be MachO');
    assert.strictEqual(second.format, 'MachO', 'Second should be MachO');
  });

  it('should throw RangeError for out-of-bounds index', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const fat = LIEF.MachO.parse(fixture);

    assert.throws(() => {
      fat.at(999);
    }, /RangeError|out of range/i, 'Should throw for invalid index');
  });

  it('should take ownership of binary via take()', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const fat = LIEF.MachO.parse(fixture);
    const binary = fat.take(0);

    assert.ok(binary, 'Should take binary');
    assert.strictEqual(binary.format, 'MachO', 'Should be MachO');
  });
});

describe('Abstract Binary interface', () => {
  // Test with any available format
  let binary = null;
  let fixturePath = null;

  before(() => {
    const elfFixtures = getElfFixtures();
    const peFixtures = getPeFixtures();
    const machoFixtures = getMachoFixtures();

    fixturePath = elfFixtures.x64 || elfFixtures.arm64 ||
                  peFixtures.x64 || peFixtures.arm64 ||
                  machoFixtures.x64 || machoFixtures.arm64;

    if (fixturePath) {
      binary = LIEF.parse(fixturePath);
    }
  });

  it('should have format property', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    assert.ok(['ELF', 'PE', 'MachO', 'UNKNOWN'].includes(binary.format), 'Format should be valid');
  });

  it('should have entrypoint as BigInt', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    assert.strictEqual(typeof binary.entrypoint, 'bigint', 'Entrypoint should be BigInt');
    assert.ok(binary.entrypoint >= 0n, 'Entrypoint should be non-negative');
  });

  it('should have isPie boolean property', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    assert.strictEqual(typeof binary.isPie, 'boolean', 'isPie should be boolean');
  });

  it('should have hasNx boolean property', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    assert.strictEqual(typeof binary.hasNx, 'boolean', 'hasNx should be boolean');
  });

  it('should return array from sections()', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    const sections = binary.sections();

    assert.ok(Array.isArray(sections), 'sections() should return array');
    assert.ok(sections.length > 0, 'Should have at least one section');
  });

  it('should return array from symbols()', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    const symbols = binary.symbols();

    assert.ok(Array.isArray(symbols), 'symbols() should return array');
    // Note: Some binaries might be stripped, so we don't require symbols > 0
  });

  it('should return array from relocations()', async (t) => {
    if (!binary) return t.skip('No fixtures available');

    const relocations = binary.relocations();

    assert.ok(Array.isArray(relocations), 'relocations() should return array');
  });
});
