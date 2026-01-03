/**
 * Symbol API tests - works across all formats
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { getElfFixtures, getPeFixtures, getMachoFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('Abstract.Symbol', () => {
  describe('Symbol enumeration', () => {
    it('should return array from symbols() for ELF', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      assert.ok(Array.isArray(symbols), 'symbols() should return array');
    });

    it('should return array from symbols() for PE', async (t) => {
      const fixtures = getPeFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      assert.ok(Array.isArray(symbols), 'symbols() should return array');
    });

    it('should return array from symbols() for MachO', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      assert.ok(Array.isArray(symbols), 'symbols() should return array');
    });
  });

  describe('Symbol properties', () => {
    it('should have name property (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      const symbol = symbols[0];
      assert.strictEqual(typeof symbol.name, 'string', 'name should be string');
    });

    it('should have value property as BigInt (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      const symbol = symbols[0];
      assert.strictEqual(typeof symbol.value, 'bigint', 'value should be bigint');
    });

    it('should have size property as BigInt (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      const symbol = symbols[0];
      assert.strictEqual(typeof symbol.size, 'bigint', 'size should be bigint');
    });

    it('should have name property (MachO)', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      const symbol = symbols[0];
      assert.strictEqual(typeof symbol.name, 'string', 'name should be string');
    });
  });

  describe('getSymbol() method', () => {
    it('should find symbol by name (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      // Find a symbol with a name
      const namedSymbol = symbols.find(s => s.name && s.name.length > 0);
      if (!namedSymbol) return t.skip('No named symbols');

      const found = binary.getSymbol(namedSymbol.name);

      assert.ok(found, `Should find symbol "${namedSymbol.name}"`);
      assert.strictEqual(found.name, namedSymbol.name, 'Found symbol name should match');
    });

    it('should return null for non-existent symbol (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSymbol('__this_symbol_definitely_does_not_exist_12345__');

      assert.strictEqual(result, null, 'Should return null for non-existent symbol');
    });

    it('should find symbol by name (PE)', async (t) => {
      const fixtures = getPeFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      if (symbols.length === 0) return t.skip('No symbols in binary');

      const namedSymbol = symbols.find(s => s.name && s.name.length > 0);
      if (!namedSymbol) return t.skip('No named symbols');

      const found = binary.getSymbol(namedSymbol.name);

      assert.ok(found, `Should find symbol "${namedSymbol.name}"`);
    });

    it('should return null for non-existent symbol (PE)', async (t) => {
      const fixtures = getPeFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSymbol('__this_symbol_definitely_does_not_exist_12345__');

      assert.strictEqual(result, null, 'Should return null for non-existent symbol');
    });
  });

  describe('Common symbols', () => {
    it('should find main or _main symbol if present (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // Try to find main or _main (naming varies by platform)
      const main = binary.getSymbol('main');
      const _main = binary.getSymbol('_main');

      // At least note if we found it
      if (main) {
        assert.strictEqual(main.name, 'main', 'Should be main');
        assert.strictEqual(typeof main.value, 'bigint', 'value should be bigint');
      } else if (_main) {
        assert.strictEqual(_main.name, '_main', 'Should be _main');
        assert.strictEqual(typeof _main.value, 'bigint', 'value should be bigint');
      }
      // If neither found, that's okay for stripped binaries
    });

    it('should find _main symbol if present (MachO)', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      // MachO.Binary doesn't expose getSymbol() directly
      // Symbols should be accessed via symbols() iteration
      assert.strictEqual(typeof binary.getSymbol, 'undefined',
        'MachO.Binary does not have getSymbol method - use symbols() instead');

      // Instead, verify we can get symbols and find _main by iteration
      const symbols = binary.symbols();
      const mainSymbol = symbols.find(s => s.name === '_main' || s.name === 'main');
      if (mainSymbol) {
        assert.ok(mainSymbol.name, 'Found main symbol should have name');
      }
      // If not found, that's okay - binary might be stripped
    });
  });

  describe('Symbol iteration', () => {
    it('should be able to iterate all symbols (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      let count = 0;
      for (const symbol of symbols) {
        assert.ok('name' in symbol, 'Each symbol should have name property');
        count++;
      }

      assert.strictEqual(count, symbols.length, 'Should iterate all symbols');
    });

    it('should be able to filter symbols by name pattern (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      // Filter symbols that start with underscore
      const underscoreSymbols = symbols.filter(s => s.name.startsWith('_'));

      assert.ok(Array.isArray(underscoreSymbols), 'Filter should return array');
    });

    it('should be able to map symbol names', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const symbols = binary.symbols();

      const symbolNames = symbols.map(s => s.name);

      assert.ok(Array.isArray(symbolNames), 'Map should return array');
      assert.strictEqual(symbolNames.length, symbols.length, 'Should have same length');

      for (const name of symbolNames) {
        assert.strictEqual(typeof name, 'string', 'Each name should be string');
      }
    });
  });
});

describe('Relocation API', () => {
  describe('Relocation enumeration', () => {
    it('should return array from relocations() for ELF', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      assert.ok(Array.isArray(relocations), 'relocations() should return array');
    });

    it('should return array from relocations() for PE', async (t) => {
      const fixtures = getPeFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      assert.ok(Array.isArray(relocations), 'relocations() should return array');
    });

    it('should note that MachO.Binary does not expose relocations() directly', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      // MachO.Binary doesn't expose relocations() at the binary level
      // Relocations are accessed per-section in MachO
      assert.strictEqual(typeof binary.relocations, 'undefined',
        'MachO.Binary does not have relocations method');
    });
  });

  describe('Relocation properties', () => {
    it('should have address property as BigInt', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      if (relocations.length === 0) return t.skip('No relocations in binary');

      const reloc = relocations[0];
      assert.strictEqual(typeof reloc.address, 'bigint', 'address should be bigint');
    });

    it('should have size property as number', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const relocations = binary.relocations();

      if (relocations.length === 0) return t.skip('No relocations in binary');

      const reloc = relocations[0];
      assert.strictEqual(typeof reloc.size, 'number', 'size should be number');
    });
  });
});
