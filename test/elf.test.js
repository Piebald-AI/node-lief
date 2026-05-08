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
    it('should return non-empty array from segments()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();

      assert.ok(Array.isArray(segments), 'segments() should return array');
      assert.ok(segments.length > 0, 'ELF binaries should have at least one segment');
    });

    it('should have LOAD segments', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();
      const loadSegments = segments.filter(s => s.type === 'LOAD');

      assert.ok(loadSegments.length > 0, 'ELF executables should have at least one LOAD segment');
    });

    it('should have correct segment property types', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();

      if (segments.length === 0) return t.skip('No segments');

      const segment = segments[0];

      assert.strictEqual(typeof segment.type, 'string', 'type should be string');
      assert.strictEqual(typeof segment.flags, 'number', 'flags should be number');
      assert.strictEqual(typeof segment.virtualAddress, 'bigint', 'virtualAddress should be bigint');
      assert.strictEqual(typeof segment.virtualSize, 'bigint', 'virtualSize should be bigint');
      assert.strictEqual(typeof segment.fileOffset, 'bigint', 'fileOffset should be bigint');
      assert.strictEqual(typeof segment.fileSize, 'bigint', 'fileSize should be bigint');
      assert.strictEqual(typeof segment.physicalAddress, 'bigint', 'physicalAddress should be bigint');
      assert.strictEqual(typeof segment.alignment, 'bigint', 'alignment should be bigint');
    });

    it('should have content as Buffer', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();
      const loadSegment = segments.find(s => s.type === 'LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const content = loadSegment.content;
      assert.ok(Buffer.isBuffer(content), 'content should be a Buffer');
      assert.ok(content.length > 0, 'LOAD segment content should not be empty');
    });

    it('should return sections within a segment', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();
      const loadSegment = segments.find(s => s.type === 'LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const sections = loadSegment.sections();
      assert.ok(Array.isArray(sections), 'sections() should return array');
      // LOAD segments typically contain sections
    });

    it('should find segment by type with getSegment()', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      assert.ok(loadSegment, 'Should find a LOAD segment');
      assert.strictEqual(loadSegment.type, 'LOAD', 'Segment type should be LOAD');
    });

    it('should return null for non-existent segment type', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const result = binary.getSegment('NONEXISTENT_TYPE');

      assert.strictEqual(result, null, 'Should return null for non-existent segment type');
    });

    it('should have readable flags with R/W/X bitmask', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const flags = loadSegment.flags;
      // Flags should be a valid bitmask (R=4, W=2, X=1)
      assert.ok(flags >= 0 && flags <= 7, `Flags should be between 0 and 7, got ${flags}`);
    });

    it('should expose segment type constants', () => {
      assert.strictEqual(LIEF.ELF.Segment.TYPE.LOAD, 'LOAD');
      assert.strictEqual(LIEF.ELF.Segment.TYPE.NOTE, 'NOTE');
      assert.ok(Object.isFrozen(LIEF.ELF.Segment.TYPE), 'Segment.TYPE should be frozen');
    });

    it('should allow setting type', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment(LIEF.ELF.Segment.TYPE.LOAD);

      if (!loadSegment) return t.skip('No LOAD segment');

      const originalType = loadSegment.type;

      loadSegment.type = LIEF.ELF.Segment.TYPE.NOTE;
      assert.strictEqual(loadSegment.type, LIEF.ELF.Segment.TYPE.NOTE, 'type should be set to NOTE');

      loadSegment.type = originalType;
      assert.strictEqual(loadSegment.type, originalType, 'type should be restored');
    });

    it('should silently ignore invalid type assignments', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const originalType = loadSegment.type;

      assert.doesNotThrow(() => {
        loadSegment.type = 'NOT_A_REAL_SEGMENT_TYPE';
      }, 'Setting type with an unknown string should not throw');

      assert.doesNotThrow(() => {
        loadSegment.type = 12345;
      }, 'Setting type with a non-string should not throw');

      assert.strictEqual(loadSegment.type, originalType, 'type should not change with invalid input');
    });

    it('should allow setting flags', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const originalFlags = loadSegment.flags;

      // Set to read-only (R=4)
      loadSegment.flags = 4;
      assert.strictEqual(loadSegment.flags, 4, 'Flags should be set to 4 (R)');

      // Restore original flags
      loadSegment.flags = originalFlags;
      assert.strictEqual(loadSegment.flags, originalFlags, 'Flags should be restored');
    });

    it('should allow setting virtualAddress', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const newAddr = 0x500000n;
      loadSegment.virtualAddress = newAddr;
      assert.strictEqual(loadSegment.virtualAddress, newAddr, 'virtualAddress should be updated');
    });

    it('should allow setting virtualSize', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const newSize = 0x2000n;
      loadSegment.virtualSize = newSize;
      assert.strictEqual(loadSegment.virtualSize, newSize, 'virtualSize should be updated');
    });

    it('should allow setting alignment', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const newAlignment = 0x1000n;
      loadSegment.alignment = newAlignment;
      assert.strictEqual(loadSegment.alignment, newAlignment, 'alignment should be updated');
    });

    it('should allow setting fileOffset', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const newOffset = 0x3000n;
      loadSegment.fileOffset = newOffset;
      assert.strictEqual(loadSegment.fileOffset, newOffset, 'fileOffset should be updated');
    });

    it('should allow setting fileSize', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const newSize = 0x4000n;
      loadSegment.fileSize = newSize;
      assert.strictEqual(loadSegment.fileSize, newSize, 'fileSize should be updated');
    });

    it('should allow setting physicalAddress', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const newAddr = 0x600000n;
      loadSegment.physicalAddress = newAddr;
      assert.strictEqual(loadSegment.physicalAddress, newAddr, 'physicalAddress should be updated');
    });

    it('should allow setting content with Buffer', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const originalContent = loadSegment.content;
      const newContent = Buffer.alloc(originalContent.length, 0x90); // NOP sled, same size

      loadSegment.content = newContent;
      const updated = loadSegment.content;
      assert.ok(Buffer.isBuffer(updated), 'content should be a Buffer after setting');
      assert.strictEqual(updated[0], 0x90, 'first byte should be updated');
      assert.strictEqual(updated[1], 0x90, 'second byte should be updated');
    });

    it('should allow setting content with array', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const loadSegment = binary.getSegment('LOAD');

      if (!loadSegment) return t.skip('No LOAD segment');

      const originalContent = loadSegment.content;
      // Create array of same length as original content
      const newContent = new Array(originalContent.length).fill(0xCC); // INT3

      loadSegment.content = newContent;
      const updated = loadSegment.content;
      assert.ok(Buffer.isBuffer(updated), 'content should be a Buffer after setting');
      assert.strictEqual(updated[0], 0xCC, 'first byte should be updated');
      assert.strictEqual(updated[1], 0xCC, 'second byte should be updated');
    });

    it('should return empty Buffer for segment with no content', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const segments = binary.segments();

      // Find a segment with no file content (e.g. GNU_STACK typically has no content)
      const emptySegment = segments.find(s => s.type === 'GNU_STACK');

      if (!emptySegment) return t.skip('No GNU_STACK segment');

      const content = emptySegment.content;
      assert.ok(Buffer.isBuffer(content), 'content should be a Buffer');
      assert.strictEqual(content.length, 0, 'GNU_STACK segment should have empty content');
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
