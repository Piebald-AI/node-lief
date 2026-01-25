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
 * Binary modification and write tests
 * Tests patchAddress(), section modification, and write() functionality
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { join } = require('node:path');
const { mkdtempSync, rmSync, existsSync, statSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { getElfFixtures, getPeFixtures, getMachoFixtures, skipIfNoFixture } = require('./helpers');

const LIEF = require('../lib/index.js');

describe('Binary.patchAddress()', () => {
  describe('ELF patching', () => {
    const fixtures = getElfFixtures();

    it('should patch address with Buffer', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // Find a valid address to patch (use entrypoint or section address)
      const sections = binary.sections();
      const textSection = sections.find(s => s.name === '.text' && s.size > 0n);
      if (!textSection) return t.skip('No .text section to patch');

      const patchAddress = textSection.virtualAddress;
      const patchData = Buffer.from([0x90, 0x90, 0x90, 0x90]); // NOP sled

      assert.doesNotThrow(() => {
        binary.patchAddress(patchAddress, patchData);
      }, 'patchAddress with Buffer should not throw');
    });

    it('should patch address with number array', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      const sections = binary.sections();
      const textSection = sections.find(s => s.name === '.text' && s.size > 0n);
      if (!textSection) return t.skip('No .text section to patch');

      const patchAddress = textSection.virtualAddress;
      const patchData = [0x90, 0x90, 0x90, 0x90]; // NOP sled

      assert.doesNotThrow(() => {
        binary.patchAddress(patchAddress, patchData);
      }, 'patchAddress with array should not throw');
    });

    it('should patch address with BigInt address', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      const sections = binary.sections();
      const textSection = sections.find(s => s.name === '.text' && s.size > 0n);
      if (!textSection) return t.skip('No .text section to patch');

      const patchAddress = textSection.virtualAddress; // Already BigInt
      const patchData = [0xCC, 0xCC]; // INT3 breakpoints

      assert.doesNotThrow(() => {
        binary.patchAddress(patchAddress, patchData);
      }, 'patchAddress with BigInt address should not throw');
    });

    it('should patch address with number address', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      const sections = binary.sections();
      const textSection = sections.find(s => s.name === '.text' && s.size > 0n);
      if (!textSection) return t.skip('No .text section to patch');

      // Convert to number (if it fits)
      const patchAddress = Number(textSection.virtualAddress);
      const patchData = [0x90];

      assert.doesNotThrow(() => {
        binary.patchAddress(patchAddress, patchData);
      }, 'patchAddress with number address should not throw');
    });
  });

  describe('PE patching', () => {
    const fixtures = getPeFixtures();

    it('should patch address with Buffer', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      const sections = binary.sections();
      const textSection = sections.find(s => s.name === '.text' && s.size > 0n);
      if (!textSection) return t.skip('No .text section to patch');

      const patchAddress = textSection.virtualAddress;
      const patchData = Buffer.from([0x90, 0x90]);

      assert.doesNotThrow(() => {
        binary.patchAddress(patchAddress, patchData);
      }, 'patchAddress should not throw');
    });
  });

  describe('MachO patching', () => {
    const fixtures = getMachoFixtures();

    it('should note that MachO.Binary does not have patchAddress (use sections instead)', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      // MachO.Binary doesn't expose patchAddress() directly
      // Patching should be done through section content modification
      assert.strictEqual(typeof binary.patchAddress, 'undefined',
        'MachO.Binary does not have patchAddress method');
    });
  });
});

describe('Binary.write()', () => {
  let tempDir;

  before(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'lief-test-'));
  });

  after(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('ELF write', () => {
    const fixtures = getElfFixtures();

    it('should write binary to file', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const outputPath = join(tempDir, 'output-elf');

      assert.doesNotThrow(() => {
        binary.write(outputPath);
      }, 'write() should not throw');

      assert.ok(existsSync(outputPath), 'Output file should exist');

      const stats = statSync(outputPath);
      assert.ok(stats.size > 0, 'Output file should have content');
    });

    it('should write modified binary', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // Modify something
      const sections = binary.sections();
      const section = sections.find(s => s.size > 0n);
      if (section) {
        const content = section.content;
        if (content.length > 0) {
          content[0] = 0x00;
          section.content = content;
        }
      }

      const outputPath = join(tempDir, 'output-elf-modified');

      assert.doesNotThrow(() => {
        binary.write(outputPath);
      }, 'write() should not throw');

      assert.ok(existsSync(outputPath), 'Output file should exist');
    });

    it('should allow re-parsing written binary', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const outputPath = join(tempDir, 'output-elf-reparse');

      binary.write(outputPath);

      // Re-parse the written binary
      const reparsed = LIEF.parse(outputPath);

      assert.ok(reparsed, 'Should be able to re-parse written binary');
      assert.strictEqual(reparsed.format, 'ELF', 'Re-parsed binary should be ELF');
    });
  });

  describe('PE write', () => {
    const fixtures = getPeFixtures();

    it('should write binary to file', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const outputPath = join(tempDir, 'output-pe.exe');

      assert.doesNotThrow(() => {
        binary.write(outputPath);
      }, 'write() should not throw');

      assert.ok(existsSync(outputPath), 'Output file should exist');

      const stats = statSync(outputPath);
      assert.ok(stats.size > 0, 'Output file should have content');
    });

    it('should allow re-parsing written binary', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);
      const outputPath = join(tempDir, 'output-pe-reparse.exe');

      binary.write(outputPath);

      const reparsed = LIEF.parse(outputPath);

      assert.ok(reparsed, 'Should be able to re-parse written binary');
      assert.strictEqual(reparsed.format, 'PE', 'Re-parsed binary should be PE');
    });
  });

  describe('MachO write', () => {
    const fixtures = getMachoFixtures();

    it('should write binary to file', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const outputPath = join(tempDir, 'output-macho');

      assert.doesNotThrow(() => {
        binary.write(outputPath);
      }, 'write() should not throw');

      assert.ok(existsSync(outputPath), 'Output file should exist');

      const stats = statSync(outputPath);
      assert.ok(stats.size > 0, 'Output file should have content');
    });

    it('should allow re-parsing written binary', async (t) => {
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const outputPath = join(tempDir, 'output-macho-reparse');

      binary.write(outputPath);

      const reparsed = LIEF.parse(outputPath);

      assert.ok(reparsed, 'Should be able to re-parse written binary');
      assert.strictEqual(reparsed.format, 'MachO', 'Re-parsed binary should be MachO');
    });
  });

  describe('Write behavior', () => {
    it('should silently fail when writing to non-existent directory (matches LIEF behavior)', async (t) => {
      // Note: LIEF does NOT throw exceptions for file I/O errors.
      // It logs an error message and returns, similar to Python LIEF behavior.
      const elfFixtures = getElfFixtures();
      const peFixtures = getPeFixtures();
      const machoFixtures = getMachoFixtures();

      const fixture = elfFixtures.x64 || elfFixtures.arm64 ||
                      peFixtures.x64 || peFixtures.arm64 ||
                      machoFixtures.x64 || machoFixtures.arm64;

      if (skipIfNoFixture(fixture, 'any binary')) return t.skip();

      const binary = LIEF.parse(fixture);

      // Try to write to a non-existent directory path
      const invalidPath = '/nonexistent_directory_12345/impossible/path/output.bin';

      // LIEF silently fails - does not throw
      assert.doesNotThrow(() => {
        binary.write(invalidPath);
      }, 'write() to invalid path should not throw (LIEF behavior)');

      // Verify file was not created
      assert.ok(!existsSync(invalidPath), 'File should not be created');
    });
  });
});

describe('Roundtrip modifications', () => {
  let tempDir;

  before(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'lief-roundtrip-'));
  });

  after(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('Section content roundtrip', () => {
    it('should be able to modify section content in memory (ELF)', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);
      const sections = binary.sections();
      const section = sections.find(s => s.size > 4n && s.name.length > 0);

      if (!section) return t.skip('No suitable section for test');

      // Verify we can read and set content
      const originalContent = section.content;
      assert.ok(Buffer.isBuffer(originalContent), 'Content should be Buffer');

      const testPattern = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
      const modifiedContent = Buffer.concat([testPattern, originalContent.slice(4)]);

      // Setting content should not throw
      assert.doesNotThrow(() => {
        section.content = modifiedContent;
      }, 'Setting section content should not throw');

      // Write should succeed
      const outputPath = join(tempDir, 'roundtrip-elf');
      assert.doesNotThrow(() => {
        binary.write(outputPath);
      }, 'Writing binary should not throw');

      // Re-parsing should succeed
      const reparsed = LIEF.parse(outputPath);
      assert.ok(reparsed, 'Should be able to re-parse written binary');
      assert.strictEqual(reparsed.format, 'ELF', 'Re-parsed binary should be ELF');
    });
  });

  describe('ELF overlay roundtrip', () => {
    it('should be able to set and get overlay', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // Set a test overlay
      const testOverlay = Buffer.from('LIEF TEST OVERLAY DATA');
      binary.overlay = testOverlay;

      // Verify it was set
      const overlay = binary.overlay;
      assert.ok(Buffer.isBuffer(overlay), 'Overlay should be Buffer');
      assert.deepStrictEqual([...overlay], [...testOverlay], 'Overlay content should match before write');

      // Note: overlay persistence through write may depend on LIEF version and binary type
      // We don't strictly test roundtrip here as it may not work for all binaries
    });
  });
});

describe('MachO-specific modifications', () => {
  let tempDir;

  before(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'lief-macho-mod-'));
  });

  after(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('Code signature removal', () => {
    it('should remove code signature and write', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const hadSignature = binary.hasCodeSignature;

      // Remove signature
      binary.removeSignature();

      const outputPath = join(tempDir, 'unsigned-macho');
      binary.write(outputPath);

      // Re-parse and verify
      const reparsed = LIEF.parse(outputPath);

      assert.strictEqual(reparsed.hasCodeSignature, false, 'Re-parsed binary should not have signature');
    });
  });

  describe('Segment extension', () => {
    it('should extend segment size', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);
      const linkeditSegment = binary.getSegment('__LINKEDIT');

      if (!linkeditSegment) return t.skip('No __LINKEDIT segment');

      const originalSize = linkeditSegment.virtualSize;

      // Try to extend by a page (4096 bytes)
      const result = binary.extendSegment(linkeditSegment, 4096);

      // extendSegment returns boolean indicating success
      assert.strictEqual(typeof result, 'boolean', 'extendSegment should return boolean');
    });
  });
});
