# Copyright 2025-2026 Piebald LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

<#
.SYNOPSIS
Generates a C++ code coverage report using LLVM tools.

.DESCRIPTION
Builds an instrumented native prebuild, runs the test suite, and writes:
  - coverage/coverage.profdata
  - coverage/coverage.json
  - coverage/html/
  - coverage/coverage-summary.txt

Requires llvm-profdata, llvm-cov, pnpm, Visual Studio Build Tools, and Visual Studio's C++ Clang tools for Windows component.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
  foreach ($command in 'llvm-profdata', 'llvm-cov', 'pnpm') {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
      throw "$command is required but not installed or available in PATH."
    }
  }

  $coverageDir = Join-Path $repoRoot 'coverage'
  $profdata = Join-Path $coverageDir 'coverage.profdata'
  $coverageJson = Join-Path $coverageDir 'coverage.json'
  $htmlDir = Join-Path $coverageDir 'html'

  Write-Host '=== Building with coverage instrumentation ==='
  Remove-Item (Join-Path $repoRoot 'build') -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item $coverageDir -Recurse -Force -ErrorAction SilentlyContinue
  New-Item $coverageDir -ItemType Directory | Out-Null

  $savedCoverage = [Environment]::GetEnvironmentVariable('npm_config_coverage', 'Process')
  try {
    $env:npm_config_coverage = '1'
    pnpm prebuildify
    if ($LASTEXITCODE -ne 0) {
      throw "pnpm prebuildify failed with exit code $LASTEXITCODE. Install Visual Studio's C++ Clang tools for Windows component and retry."
    }
  }
  finally {
    if ($null -eq $savedCoverage) {
      Remove-Item Env:npm_config_coverage -ErrorAction SilentlyContinue
    }
    else {
      $env:npm_config_coverage = $savedCoverage
    }
  }

  $binaries = @(Get-ChildItem (Join-Path $repoRoot 'prebuilds') -Filter '*.node' -File -Recurse)
  if ($binaries.Count -ne 1) {
    throw "Expected exactly one .node file in prebuilds, found $($binaries.Count)."
  }
  $binary = $binaries[0].FullName

  Write-Host ''
  Write-Host '=== Running tests ==='
  $savedProfileFile = [Environment]::GetEnvironmentVariable('LLVM_PROFILE_FILE', 'Process')
  try {
    $env:LLVM_PROFILE_FILE = Join-Path $coverageDir 'coverage-%p.profraw'
    pnpm test
    if ($LASTEXITCODE -ne 0) {
      throw "pnpm test failed with exit code $LASTEXITCODE."
    }
  }
  finally {
    if ($null -eq $savedProfileFile) {
      Remove-Item Env:LLVM_PROFILE_FILE -ErrorAction SilentlyContinue
    }
    else {
      $env:LLVM_PROFILE_FILE = $savedProfileFile
    }
  }

  Write-Host ''
  Write-Host '=== Generating coverage report ==='

  $rawProfiles = @(Get-ChildItem $coverageDir -Filter 'coverage-*.profraw' -File)
  if ($rawProfiles.Count -eq 0) {
    throw "No raw profiles were generated in $coverageDir."
  }

  $profileArguments = @('merge') + $rawProfiles.FullName + @('-o', $profdata)
  & llvm-profdata @profileArguments
  if ($LASTEXITCODE -ne 0) {
    throw "llvm-profdata failed with exit code $LASTEXITCODE."
  }

  & llvm-cov export $binary "-instr-profile=$profdata" -sources 'src/' |
    Set-Content $coverageJson -Encoding utf8
  if ($LASTEXITCODE -ne 0) {
    throw "llvm-cov export failed with exit code $LASTEXITCODE."
  }

  & llvm-cov show $binary "-instr-profile=$profdata" '-format=html' "-output-dir=$htmlDir" -sources 'src/'
  if ($LASTEXITCODE -ne 0) {
    throw "llvm-cov show failed with exit code $LASTEXITCODE."
  }

  $coverage = Get-Content $coverageJson -Raw | ConvertFrom-Json
  $totals = $coverage.data[0].totals
  $linesPercent = [Math]::Round([double]$totals.lines.percent, 2)
  $functionsPercent = [Math]::Round([double]$totals.functions.percent, 2)
  $regionsPercent = [Math]::Round([double]$totals.regions.percent, 2)

  Write-Host ''
  Write-Host '=== Coverage Summary ==='
  Write-Host "Lines:     $linesPercent%"
  Write-Host "Functions: $functionsPercent%"
  Write-Host "Regions:   $regionsPercent%"

  $color = if ($linesPercent -ge 90) {
    'brightgreen'
  }
  elseif ($linesPercent -ge 75) {
    'green'
  }
  elseif ($linesPercent -ge 60) {
    'yellowgreen'
  }
  elseif ($linesPercent -ge 40) {
    'yellow'
  }
  else {
    'red'
  }

  $linesPercent, $color | Set-Content (Join-Path $coverageDir 'coverage-summary.txt') -Encoding utf8

  Write-Host ''
  Write-Host "HTML report: $htmlDir/index.html"
  Write-Host "JSON data:   $coverageJson"
  Write-Host "Badge color: $color"
}
finally {
  Pop-Location
}
