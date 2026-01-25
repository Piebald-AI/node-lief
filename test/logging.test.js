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
 * Logging API tests
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');

const LIEF = require('../lib/index.js');

describe('LIEF.logging', () => {
  describe('logging namespace', () => {
    it('should have logging object', () => {
      assert.ok(LIEF.logging, 'Should have logging namespace');
      assert.strictEqual(typeof LIEF.logging, 'object', 'logging should be object');
    });

    it('should have disable function', () => {
      assert.ok(LIEF.logging.disable, 'Should have disable function');
      assert.strictEqual(typeof LIEF.logging.disable, 'function', 'disable should be function');
    });

    it('should have enable function', () => {
      assert.ok(LIEF.logging.enable, 'Should have enable function');
      assert.strictEqual(typeof LIEF.logging.enable, 'function', 'enable should be function');
    });
  });

  describe('logging.disable()', () => {
    it('should not throw when called', () => {
      assert.doesNotThrow(() => {
        LIEF.logging.disable();
      }, 'disable() should not throw');
    });

    it('should return undefined', () => {
      const result = LIEF.logging.disable();
      assert.strictEqual(result, undefined, 'disable() should return undefined');
    });

    it('should be callable multiple times', () => {
      assert.doesNotThrow(() => {
        LIEF.logging.disable();
        LIEF.logging.disable();
        LIEF.logging.disable();
      }, 'Multiple disable() calls should not throw');
    });
  });

  describe('logging.enable()', () => {
    it('should not throw when called', () => {
      assert.doesNotThrow(() => {
        LIEF.logging.enable();
      }, 'enable() should not throw');
    });

    it('should return undefined', () => {
      const result = LIEF.logging.enable();
      assert.strictEqual(result, undefined, 'enable() should return undefined');
    });

    it('should be callable multiple times', () => {
      assert.doesNotThrow(() => {
        LIEF.logging.enable();
        LIEF.logging.enable();
        LIEF.logging.enable();
      }, 'Multiple enable() calls should not throw');
    });
  });

  describe('logging toggle', () => {
    it('should toggle between enable and disable', () => {
      assert.doesNotThrow(() => {
        LIEF.logging.disable();
        LIEF.logging.enable();
        LIEF.logging.disable();
        LIEF.logging.enable();
      }, 'Toggling logging should not throw');
    });
  });

  // Clean up: disable logging after tests to avoid noise
  after(() => {
    LIEF.logging.disable();
  });
});
