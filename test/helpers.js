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
 * Test helpers and fixture utilities
 */

const { existsSync } = require('node:fs');
const { join } = require('node:path');

const FIXTURES_DIR = join(__dirname, 'fixtures');

/**
 * Get the path to a test fixture
 * @param {string} relativePath - Path relative to fixtures directory
 * @returns {string} Absolute path to the fixture
 */
function getFixture(relativePath) {
  return join(FIXTURES_DIR, relativePath);
}

/**
 * Check if a fixture exists
 * @param {string} relativePath - Path relative to fixtures directory
 * @returns {boolean}
 */
function hasFixture(relativePath) {
  return existsSync(getFixture(relativePath));
}

/**
 * Get available ELF fixtures
 * @returns {{x64: string|null, arm64: string|null}}
 */
function getElfFixtures() {
  return {
    x64: hasFixture('elf/hello-linux-x64') ? getFixture('elf/hello-linux-x64') : null,
    arm64: hasFixture('elf/hello-linux-arm64') ? getFixture('elf/hello-linux-arm64') : null,
  };
}

/**
 * Get available PE fixtures
 * @returns {{x64: string|null, x86: string|null, arm64: string|null}}
 */
function getPeFixtures() {
  return {
    x64: hasFixture('pe/hello-windows-x64.exe') ? getFixture('pe/hello-windows-x64.exe') : null,
    x86: hasFixture('pe/hello-windows-x86.exe') ? getFixture('pe/hello-windows-x86.exe') : null,
    arm64: hasFixture('pe/hello-windows-arm64.exe') ? getFixture('pe/hello-windows-arm64.exe') : null,
  };
}

/**
 * Get available MachO fixtures
 * @returns {{x64: string|null, arm64: string|null, universal: string|null}}
 */
function getMachoFixtures() {
  return {
    x64: hasFixture('macho/hello-macos-x64') ? getFixture('macho/hello-macos-x64') : null,
    arm64: hasFixture('macho/hello-macos-arm64') ? getFixture('macho/hello-macos-arm64') : null,
    universal: hasFixture('macho/hello-macos-universal') ? getFixture('macho/hello-macos-universal') : null,
  };
}

/**
 * Get any available fixture of a specific format
 * @param {'elf'|'pe'|'macho'} format
 * @returns {string|null}
 */
function getAnyFixture(format) {
  switch (format) {
    case 'elf': {
      const elf = getElfFixtures();
      return elf.x64 || elf.arm64;
    }
    case 'pe': {
      const pe = getPeFixtures();
      return pe.x64 || pe.arm64;
    }
    case 'macho': {
      const macho = getMachoFixtures();
      return macho.x64 || macho.arm64 || macho.universal;
    }
    default:
      return null;
  }
}

/**
 * Skip test if fixture is not available
 * @param {string|null} fixture
 * @param {string} description
 */
function skipIfNoFixture(fixture, description) {
  if (!fixture) {
    console.log(`  ⏭  Skipping: ${description} (fixture not available)`);
    return true;
  }
  return false;
}

module.exports = {
  FIXTURES_DIR,
  getFixture,
  hasFixture,
  getElfFixtures,
  getPeFixtures,
  getMachoFixtures,
  getAnyFixture,
  skipIfNoFixture,
};
