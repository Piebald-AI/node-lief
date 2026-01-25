#!/usr/bin/env node

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

const { execSync } = require('child_process');
const { mkdirSync, existsSync } = require('fs');
const path = require('path');

// Build LIEF library with CMake before building the Node addon

const BUILD_DIR = 'lief-build';
const LIEF_SRC = 'LIEF';
const rootDir = path.join(__dirname, '..');

console.log('Building LIEF library...');

// Create build directory
const buildPath = path.join(rootDir, BUILD_DIR);
if (!existsSync(buildPath)) {
  mkdirSync(buildPath, { recursive: true });
}

// Configure LIEF with CMake (minimal build for speed)
const cmakeArgs = [
  `../${LIEF_SRC}`,
  '-GNinja',
  '-DCMAKE_BUILD_TYPE=Release',
  '-DLIEF_PYTHON_API=OFF',
  '-DLIEF_RUST_API=OFF',
  '-DLIEF_C_API=OFF',
  '-DLIEF_OAT=OFF',
  '-DLIEF_DEX=OFF',
  '-DLIEF_VDEX=OFF',
  '-DLIEF_ART=OFF',
  '-DLIEF_ASM=OFF',
  '-DLIEF_TESTS=OFF',
  '-DLIEF_EXAMPLES=OFF',
  '-DLIEF_DOC=OFF',
  '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
];

// Configure sccache if available in PATH
// This works both in CI (with SCCACHE_GHA_ENABLED) and locally if sccache is installed
try {
  execSync('sccache --version', { stdio: 'ignore' });
  let sccachePath = 'sccache';
  // On Windows, we need the full path to sccache to avoid CMake finding other compilers like ccache from Strawberry
  if (process.platform === 'win32') {
    try {
      sccachePath = execSync('where sccache', { encoding: 'utf-8' }).trim().split('\n')[0];
    } catch (e) {
      // Fallback to just 'sccache' if where command fails
    }
  }
  cmakeArgs.push(`-DCMAKE_C_COMPILER_LAUNCHER=${sccachePath}`);
  cmakeArgs.push(`-DCMAKE_CXX_COMPILER_LAUNCHER=${sccachePath}`);
  console.log(`sccache detected at ${sccachePath}, enabling compiler caching`);
} catch (e) {
  // sccache not available, continue without it
}

// Add macOS-specific deployment target
if (process.platform === 'darwin') {
  cmakeArgs.push('-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0');
}

// Add Windows-specific runtime library setting to match node-gyp (/MT)
if (process.platform === 'win32') {
  cmakeArgs.push('-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded');
  // On Windows, disable LIEF's built-in ccache search (which finds Strawberry's ccache)
  // and rely on CMAKE_*_COMPILER_LAUNCHER variables instead
  cmakeArgs.push('-DLIEF_USE_CCACHE=OFF');
}

const configureCmd = `cmake ${cmakeArgs.join(' ')}`;
const buildCmd = 'cmake --build . --config Release';

try {
  console.log('Configuring LIEF...');
  execSync(configureCmd, { stdio: 'inherit', cwd: buildPath });

  console.log('Building LIEF...');
  execSync(buildCmd, { stdio: 'inherit', cwd: buildPath });

  console.log('LIEF build complete!');
} catch (error) {
  console.error('LIEF build failed!');
  process.exit(error.status || 1);
}
