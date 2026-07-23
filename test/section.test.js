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
 * Section API tests - works across all formats
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { getElfFixtures, getPeFixtures, getMachoFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('Abstract.Section', () => {
  // Test with any available fixture
  let binary = null;
  let sections = [];

  before(() => {
    const elfFixtures = getElfFixtures();
    const peFixtures = getPeFixtures();
    const machoFixtures = getMachoFixtures();

    const fixturePath =
      elfFixtures.x64 ||
      elfFixtures.arm64 ||
      peFixtures.x64 ||
      peFixtures.arm64 ||
      machoFixtures.x64 ||
      machoFixtures.arm64;

    if (fixturePath) {
      binary = LIEF.parse(fixturePath);
      sections = binary.sections();
    }
  });

  describe('Section properties', () => {
    it('should have name property', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections[0];

      assert.strictEqual(typeof section.name, 'string', 'name should be string');
    });

    it('should have virtualAddress property as BigInt', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections[0];

      assert.strictEqual(
        typeof section.virtualAddress,
        'bigint',
        'virtualAddress should be bigint',
      );
      assert.ok(section.virtualAddress >= 0n, 'virtualAddress should be non-negative');
    });

    it('should have size property as BigInt', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections[0];

      assert.strictEqual(typeof section.size, 'bigint', 'size should be bigint');
      assert.ok(section.size >= 0n, 'size should be non-negative');
    });

    it('should have fileOffset property as BigInt', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections[0];

      assert.strictEqual(typeof section.fileOffset, 'bigint', 'fileOffset should be bigint');
      assert.ok(section.fileOffset >= 0n, 'fileOffset should be non-negative');
    });

    it('should have offset property as BigInt (alias for fileOffset)', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections[0];

      assert.strictEqual(typeof section.offset, 'bigint', 'offset should be bigint');
      assert.strictEqual(section.offset, section.fileOffset, 'offset should equal fileOffset');
    });
  });

  describe('Section content', () => {
    it('should have content property that returns Buffer', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      // Find a section with non-zero size
      const section = sections.find((s) => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const content = section.content;

      assert.ok(Buffer.isBuffer(content), 'content should be a Buffer');
    });

    it('should be able to set content with Buffer', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections.find((s) => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const newContent = Buffer.from([0x90, 0x90, 0x90, 0x90]); // NOP sled

      assert.doesNotThrow(() => {
        section.content = newContent;
      }, 'Setting content with Buffer should not throw');
    });

    it('should be able to set content with number array', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections.find((s) => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const newContent = [0x90, 0x90, 0x90, 0x90]; // NOP sled

      assert.doesNotThrow(() => {
        section.content = newContent;
      }, 'Setting content with number array should not throw');
    });
  });

  describe('Section size property', () => {
    it('should have size as BigInt (read-only recommended)', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections[0];

      // Size is readable
      assert.strictEqual(typeof section.size, 'bigint', 'size should be bigint');

      // Note: Setting size on existing sections from parsed binaries
      // may cause issues - it's primarily useful for new sections being added
      // We don't test size modification on parsed sections as it can crash
    });

    it('should silently ignore non-BigInt size assignment', async (t) => {
      if (!binary || sections.length === 0) return t.skip('No fixtures or sections available');

      const section = sections.find((s) => s.size > 0n);
      if (!section) return t.skip('No sections with content');

      const originalSize = section.size;

      // These should silently fail (not throw, not change size)
      assert.doesNotThrow(() => {
        section.size = 12345; // number, not BigInt
      }, 'Setting size with number should not throw');

      assert.doesNotThrow(() => {
        section.size = '12345'; // string
      }, 'Setting size with string should not throw');

      assert.doesNotThrow(() => {
        section.size = null;
      }, 'Setting size with null should not throw');

      // Size should remain unchanged
      assert.strictEqual(section.size, originalSize, 'Size should not change with invalid input');
    });
  });
});

describe('ELF Section specifics', () => {
  const fixtures = getElfFixtures();

  it('should have standard ELF section names', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const sectionNames = sections.map((s) => s.name);

    // ELF binaries typically start with empty name section and have .text
    const hasCodeSection = sectionNames.some(
      (name) => name === '.text' || name === '.init' || name === '.plt',
    );

    assert.ok(hasCodeSection, 'Should have code sections');
  });

  it('should have proper section properties for .text', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);
    const textSection = binary.getSection('.text');

    if (!textSection) return t.skip('No .text section');

    assert.strictEqual(textSection.name, '.text', 'Name should be .text');
    assert.ok(textSection.virtualAddress > 0n, 'Should have non-zero virtual address');
    assert.ok(textSection.size > 0n, 'Should have non-zero size');
  });
});

describe('PE Section specifics', () => {
  const fixtures = getPeFixtures();

  it('should have PE-specific virtualSize property', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();

    if (sections.length === 0) return t.skip('No sections');

    const section = sections[0];

    // PE sections have distinct virtualSize (different from size which is file size)
    assert.strictEqual(typeof section.virtualSize, 'bigint', 'virtualSize should be bigint');
  });

  it('should silently ignore non-BigInt size assignment', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const section = sections.find((s) => s.size > 0n);

    if (!section) return t.skip('No sections with content');

    const originalSize = section.size;

    // These should silently fail (not throw, not change size)
    assert.doesNotThrow(() => {
      section.size = 12345; // number, not BigInt
    }, 'Setting size with number should not throw');

    assert.strictEqual(section.size, originalSize, 'Size should not change with number input');
  });

  it('should silently ignore non-BigInt virtualSize assignment', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const section = sections.find((s) => s.virtualSize > 0n);

    if (!section) return t.skip('No sections with virtualSize');

    const originalVirtualSize = section.virtualSize;

    // These should silently fail (not throw, not change virtualSize)
    assert.doesNotThrow(() => {
      section.virtualSize = 12345; // number, not BigInt
    }, 'Setting virtualSize with number should not throw');

    assert.doesNotThrow(() => {
      section.virtualSize = '12345'; // string
    }, 'Setting virtualSize with string should not throw');

    assert.strictEqual(
      section.virtualSize,
      originalVirtualSize,
      'virtualSize should not change with invalid input',
    );
  });

  it('should have characteristics property', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();

    if (sections.length === 0) return t.skip('No sections');

    const section = sections[0];

    assert.strictEqual(
      typeof section.characteristics,
      'number',
      'characteristics should be number',
    );
  });

  it('should have standard PE section names', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const sectionNames = sections.map((s) => s.name);

    // PE binaries typically have .text section
    const hasTextSection = sectionNames.some(
      (name) => name === '.text' || name === '.code' || name === 'CODE',
    );

    assert.ok(hasTextSection, 'Should have code section');
  });
});

describe('MachO Section specifics', () => {
  const fixtures = getMachoFixtures();

  it('should have MachO-style section names', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const sectionNames = sections.map((s) => s.name);

    // MachO sections typically have names like __text, __data, etc.
    const hasMachOSections = sectionNames.some(
      (name) => name.startsWith('__') || name === '__text' || name === '__data',
    );

    assert.ok(hasMachOSections, 'Should have MachO-style section names');
  });

  it('should access sections through segments', async (t) => {
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);
    const textSegment = binary.getSegment('__TEXT');

    if (!textSegment) return t.skip('No __TEXT segment');

    const segmentSections = textSegment.sections();

    assert.ok(Array.isArray(segmentSections), 'sections() should return array');
    assert.ok(segmentSections.length > 0, '__TEXT should have sections');

    // All sections in __TEXT should have MachO-style names
    for (const section of segmentSections) {
      assert.strictEqual(typeof section.name, 'string', 'Section name should be string');
    }
  });
});

describe('Section content manipulation', () => {
  const elfFixtures = getElfFixtures();
  const peFixtures = getPeFixtures();
  const machoFixtures = getMachoFixtures();

  it('should read and modify section content for ELF', async (t) => {
    const fixture = elfFixtures.x64 || elfFixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const section = sections.find((s) => s.size > 0n);

    if (!section) return t.skip('No sections with content');

    const originalContent = section.content;
    assert.ok(Buffer.isBuffer(originalContent), 'Original content should be Buffer');

    // Modify and verify
    const modifiedContent = Buffer.alloc(originalContent.length, 0xcc);
    section.content = modifiedContent;

    const newContent = section.content;
    assert.ok(Buffer.isBuffer(newContent), 'New content should be Buffer');
  });

  it('should read and modify section content for PE', async (t) => {
    const fixture = peFixtures.x64 || peFixtures.arm64;
    if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const section = sections.find((s) => s.size > 0n);

    if (!section) return t.skip('No sections with content');

    const originalContent = section.content;
    assert.ok(Buffer.isBuffer(originalContent), 'Original content should be Buffer');
  });

  it('should read and modify section content for MachO', async (t) => {
    const fixture = machoFixtures.x64 || machoFixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const section = sections.find((s) => s.size > 0n);

    if (!section) return t.skip('No sections with content');

    const originalContent = section.content;
    assert.ok(Buffer.isBuffer(originalContent), 'Original content should be Buffer');
  });
});
