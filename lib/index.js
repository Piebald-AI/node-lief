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
 * LIEF Node.js Bindings
 *
 * This is the main JavaScript entry point that loads the native addon
 * and exports the LIEF API for use from JavaScript/TypeScript.
 */

const { existsSync } = require('node:fs');
const { platform } = require('node:os');
const { join } = require('node:path');

const binding = process.versions.bun
  ? require(
      `../prebuilds/${process.platform}-${process.arch}/node-lief${process.libc ? '.' + process.libc : ''}.node`
    )
  : require('node-gyp-build')(join(__dirname, '..'));

// Add MachO.Header.CPU_TYPE constants
// These mirror LIEF::MachO::Header::CPU_TYPE enum values
binding.MachO.Header.CPU_TYPE = Object.freeze({
  ANY: -1,
  X86: 7,
  X86_64: 16777223, // 7 | ABI64 (0x01000000)
  MIPS: 8,
  MC98000: 10,
  HPPA: 11,
  ARM: 12,
  ARM64: 16777228, // 12 | ABI64
  MC88000: 13,
  SPARC: 14,
  I860: 15,
  ALPHA: 16,
  POWERPC: 18,
  POWERPC64: 16777234, // 18 | ABI64
  APPLE_GPU: 16777235, // 19 | ABI64
  AMD_GPU: 16777236, // 20 | ABI64
  INTEL_GPU: 16777237, // 21 | ABI64
  AIR64: 16777239, // 23 | ABI64
});

module.exports = binding;
