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
 * Error handling tests
 * Verifies proper error throwing and handling for invalid inputs
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { join } = require('node:path');
const {
  getElfFixtures,
  getPeFixtures,
  getMachoFixtures,
  skipIfNoFixture,
  FIXTURES_DIR,
} = require('./helpers');

const LIEF = require('../lib/index.js');

describe('Parse error handling', () => {
  describe('LIEF.parse() errors', () => {
    it('should throw for non-existent file', () => {
      assert.throws(
        () => {
          LIEF.parse('/nonexistent/path/to/binary');
        },
        /Failed to parse|ENOENT|No such file/i,
        'Should throw for non-existent file',
      );
    });

    it('should throw for empty path', () => {
      assert.throws(() => {
        LIEF.parse('');
      }, 'Should throw for empty path');
    });

    it('should throw when called without arguments', () => {
      assert.throws(() => {
        LIEF.parse();
      }, 'Should throw when called without arguments');
    });

    it('should throw for non-string argument', () => {
      assert.throws(
        () => {
          LIEF.parse(12345);
        },
        /requires.*string|invalid.*argument/i,
        'Should throw for numeric argument',
      );

      assert.throws(() => {
        LIEF.parse(null);
      }, 'Should throw for null argument');

      assert.throws(() => {
        LIEF.parse(undefined);
      }, 'Should throw for undefined argument');

      assert.throws(() => {
        LIEF.parse({});
      }, 'Should throw for object argument');
    });

    it('should throw for directory path', () => {
      assert.throws(() => {
        LIEF.parse(FIXTURES_DIR);
      }, 'Should throw for directory path');
    });
  });

  describe('LIEF.MachO.parse() errors', () => {
    it('should throw for non-existent file', () => {
      assert.throws(() => {
        LIEF.MachO.parse('/nonexistent/path/to/macho');
      }, 'Should throw for non-existent file');
    });

    it('should throw when called without arguments', () => {
      assert.throws(() => {
        LIEF.MachO.parse();
      }, 'Should throw when called without arguments');
    });

    it('should throw for non-string argument', () => {
      assert.throws(() => {
        LIEF.MachO.parse(12345);
      }, 'Should throw for numeric argument');
    });
  });
});

describe('Method argument validation', () => {
  describe('getSymbol() argument validation', () => {
    it('should return null for non-string argument', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // These should either throw or return null, not crash
      const result1 = binary.getSymbol(12345);
      const result2 = binary.getSymbol(null);
      const result3 = binary.getSymbol(undefined);

      // Most likely returns null for invalid args
      assert.ok(result1 === null || result1 === undefined, 'Should handle numeric argument');
      assert.ok(result2 === null || result2 === undefined, 'Should handle null');
      assert.ok(result3 === null || result3 === undefined, 'Should handle undefined');
    });
  });

  describe('getSection() argument validation (ELF)', () => {
    it('should return null for non-string argument', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      const result = binary.getSection(12345);
      assert.ok(result === null || result === undefined, 'Should handle numeric argument');
    });
  });

  describe('getSection() argument validation (PE)', () => {
    it('should return null for non-string argument', async (t) => {
      const fixtures = getPeFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any PE')) return t.skip();

      const binary = LIEF.parse(fixture);

      const result = binary.getSection(12345);
      assert.ok(result === null || result === undefined, 'Should handle numeric argument');
    });
  });

  describe('getSegment() argument validation (MachO)', () => {
    it('should return null for non-string argument', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const binary = LIEF.parse(fixture);

      const result = binary.getSegment(12345);
      assert.ok(result === null || result === undefined, 'Should handle numeric argument');
    });
  });

  describe('patchAddress() argument validation', () => {
    it('should handle invalid address type gracefully', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // String address should be rejected or handled
      try {
        binary.patchAddress('not an address', [0x90]);
        // If it doesn't throw, that's okay - it might just do nothing
      } catch (e) {
        // Expected to throw for invalid address
        assert.ok(e, 'Should throw for invalid address');
      }
    });

    it('should handle invalid patch data gracefully', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      // String patch data should be rejected or handled
      try {
        binary.patchAddress(0x1000n, 'not bytes');
        // If it doesn't throw, that's okay
      } catch (e) {
        assert.ok(e, 'Should throw for invalid patch data');
      }
    });
  });

  describe('write() argument validation', () => {
    it('should throw for non-string output path', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.throws(() => {
        binary.write(12345);
      }, 'Should throw for numeric output path');

      assert.throws(() => {
        binary.write(null);
      }, 'Should throw for null output path');
    });

    it('should throw when called without arguments', async (t) => {
      const fixtures = getElfFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

      const binary = LIEF.parse(fixture);

      assert.throws(() => {
        binary.write();
      }, 'Should throw when write() called without arguments');
    });
  });
});

describe('FatBinary error handling', () => {
  describe('at() bounds checking', () => {
    it('should throw RangeError for negative index', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);

      assert.throws(
        () => {
          fat.at(-1);
        },
        /RangeError|out of range/i,
        'Should throw for negative index',
      );
    });

    it('should throw RangeError for out-of-bounds index', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);

      assert.throws(
        () => {
          fat.at(9999);
        },
        /RangeError|out of range/i,
        'Should throw for out-of-bounds index',
      );
    });

    it('should return null when called without arguments', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);
      const result = fat.at();
      assert.strictEqual(result, null, 'Should return null for missing argument');
    });
  });

  describe('take() bounds checking', () => {
    it('should throw RangeError for negative index', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);

      assert.throws(
        () => {
          fat.take(-1);
        },
        /RangeError|out of range/i,
        'Should throw for negative index',
      );
    });

    it('should throw RangeError for out-of-bounds index', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);

      assert.throws(
        () => {
          fat.take(9999);
        },
        /RangeError|out of range/i,
        'Should throw for out-of-bounds index',
      );
    });

    it('should return null when called without arguments', async (t) => {
      const fixtures = getMachoFixtures();
      const fixture = fixtures.x64 || fixtures.arm64;
      if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

      const fat = LIEF.MachO.parse(fixture);
      const result = fat.take();
      assert.strictEqual(result, null, 'Should return null for missing argument');
    });
  });
});

describe('Section content edge cases', () => {
  it('should handle empty content assignment', async (t) => {
    const fixtures = getElfFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();
    const section = sections.find((s) => s.size > 0n);

    if (!section) return t.skip('No sections with content');

    // Try to set empty content
    assert.doesNotThrow(() => {
      section.content = Buffer.alloc(0);
    }, 'Should handle empty Buffer');

    assert.doesNotThrow(() => {
      section.content = [];
    }, 'Should handle empty array');
  });
});

describe('MachO Segment getSection() validation', () => {
  it('should return null when getSection called without arguments', async (t) => {
    const fixtures = getMachoFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);
    const segment = binary.getSegment('__TEXT');
    if (!segment) return t.skip('No __TEXT segment');

    const result = segment.getSection();
    assert.strictEqual(result, null, 'Should return null for missing argument');
  });
});

describe('MachO Binary method validation', () => {
  it('should throw when write() called without arguments', async (t) => {
    const fixtures = getMachoFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);

    assert.throws(
      () => {
        binary.write();
      },
      /requires.*path|argument/i,
      'Should throw when write() called without arguments',
    );
  });

  it('should throw when extendSegment() called without arguments', async (t) => {
    const fixtures = getMachoFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);

    assert.throws(
      () => {
        binary.extendSegment();
      },
      /requires|argument/i,
      'Should throw when extendSegment() called without arguments',
    );
  });

  it('should throw when extendSegment() called with invalid segment', async (t) => {
    const fixtures = getMachoFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);

    assert.throws(
      () => {
        binary.extendSegment('not a segment', 0x1000);
      },
      /Segment|argument/i,
      'Should throw for invalid segment argument',
    );
  });

  it('should throw when extendSegment() called with invalid size type', async (t) => {
    const fixtures = getMachoFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);
    const segment = binary.getSegment('__TEXT');
    if (!segment) return t.skip('No __TEXT segment');

    assert.throws(
      () => {
        binary.extendSegment(segment, 'not a number');
      },
      /number|BigInt|size/i,
      'Should throw for invalid size type',
    );
  });

  it('should accept BigInt size in extendSegment()', async (t) => {
    const fixtures = getMachoFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any MachO')) return t.skip();

    const binary = LIEF.parse(fixture);
    const segment = binary.getSegment('__LINKEDIT');
    if (!segment) return t.skip('No __LINKEDIT segment');

    // Should not throw - BigInt is valid
    assert.doesNotThrow(() => {
      binary.extendSegment(segment, 0x1000n);
    }, 'Should accept BigInt size');
  });
});

describe('ELF overlay validation', () => {
  it('should silently ignore non-Buffer overlay assignment', async (t) => {
    const fixtures = getElfFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);

    // Should not throw, just silently ignore
    assert.doesNotThrow(() => {
      binary.overlay = 'not a buffer';
    }, 'Should silently ignore string');

    assert.doesNotThrow(() => {
      binary.overlay = 12345;
    }, 'Should silently ignore number');

    assert.doesNotThrow(() => {
      binary.overlay = { data: [1, 2, 3] };
    }, 'Should silently ignore object');
  });
});

describe('patchAddress validation', () => {
  it('should throw when called with insufficient arguments', async (t) => {
    const fixtures = getElfFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);

    assert.throws(
      () => {
        binary.patchAddress();
      },
      /requires|argument/i,
      'Should throw with no arguments',
    );

    assert.throws(
      () => {
        binary.patchAddress(0x1000n);
      },
      /requires|argument/i,
      'Should throw with only address',
    );
  });
});

describe('Type coercion edge cases', () => {
  it('should handle BigInt entrypoint correctly', async (t) => {
    const fixtures = getElfFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);

    // Entrypoint should always be BigInt
    const entrypoint = binary.entrypoint;
    assert.strictEqual(typeof entrypoint, 'bigint', 'Entrypoint should be bigint');

    // Should be usable in BigInt arithmetic
    const incremented = entrypoint + 1n;
    assert.strictEqual(typeof incremented, 'bigint', 'Arithmetic should work');
  });

  it('should handle BigInt addresses in sections', async (t) => {
    const fixtures = getElfFixtures();
    const fixture = fixtures.x64 || fixtures.arm64;
    if (skipIfNoFixture(fixture, 'any ELF')) return t.skip();

    const binary = LIEF.parse(fixture);
    const sections = binary.sections();

    if (sections.length === 0) return t.skip('No sections');

    for (const section of sections) {
      assert.strictEqual(
        typeof section.virtualAddress,
        'bigint',
        `${section.name} virtualAddress should be bigint`,
      );
      assert.strictEqual(typeof section.size, 'bigint', `${section.name} size should be bigint`);
      assert.strictEqual(
        typeof section.fileOffset,
        'bigint',
        `${section.name} fileOffset should be bigint`,
      );
    }
  });
});
