#!/bin/bash
set -e

# Build LIEF library with CMake before building the Node addon

BUILD_DIR="lief-build"
LIEF_SRC="LIEF"

# Initialize submodules if running in GitHub Actions or /usr/workspace exists
if [ -n "$GITHUB_ACTIONS" ] || [ -d "/usr/workspace" ]; then
  echo "Running in CI environment, configuring git and initializing submodules..."
  git config --global --add safe.directory /usr/workspace
  git config --global --add safe.directory /usr/workspace/LIEF
  git submodule update --init --recursive

  # Install CMake on Linux if needed
  if [[ $(uname -s) == "Linux" ]]; then
    echo "Detected Linux, checking for Alpine..."
    if [ -f /etc/alpine-release ]; then
      echo "Detected Alpine Linux, installing CMake via apk..."
      apk add --no-cache cmake
    else
      echo "Installing CMake 4.2.0-rc2..."
      mkdir /cmake
      curl -fsSL https://github.com/Kitware/CMake/releases/download/v4.2.0-rc2/cmake-4.2.0-rc2-linux-x86_64.sh -o install-cmake.sh
      chmod +x install-cmake.sh
      ./install-cmake.sh --skip-license --prefix=/cmake
      rm install-cmake.sh
      export PATH="/cmake/bin:$PATH"
      echo "CMake installed to /cmake"
    fi
  fi
fi

echo "Building LIEF library..."

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure LIEF with CMake (minimal build for speed)
cmake "../$LIEF_SRC" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DLIEF_PYTHON_API=OFF \
  -DLIEF_RUST_API=OFF \
  -DLIEF_C_API=OFF \
  -DLIEF_OAT=OFF \
  -DLIEF_DEX=OFF \
  -DLIEF_VDEX=OFF \
  -DLIEF_ART=OFF \
  -DLIEF_ASM=OFF \
  -DLIEF_TESTS=OFF \
  -DLIEF_EXAMPLES=OFF \
  -DLIEF_DOC=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON

# Build LIEF (Ninja handles parallelization automatically)
cmake --build . --config Release

cd ..

echo "LIEF build complete!"
