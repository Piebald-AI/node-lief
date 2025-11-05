#!/usr/bin/env node

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

// Add macOS-specific deployment target
if (process.platform === 'darwin') {
  cmakeArgs.push('-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0');
}

// Add Windows-specific runtime library setting to match node-gyp (/MT)
if (process.platform === 'win32') {
  cmakeArgs.push('-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded');
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
