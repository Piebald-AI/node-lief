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
const { platform } = require('node:process');

const isMusl =
  process.env.LIBC === 'musl' || (platform === 'linux' && existsSync('/etc/alpine-release'));

const binding = require(
  `../prebuilds/${process.platform}-${process.arch}/node-lief${isMusl ? '.musl' : ''}.node`,
);

// Add ELF.Segment.TYPE constants
// These mirror LIEF::ELF::Segment::TYPE names exposed by the native binding.
binding.ELF.Segment.TYPE = Object.freeze({
  PT_NULL_: 'PT_NULL_',
  LOAD: 'LOAD',
  DYNAMIC: 'DYNAMIC',
  INTERP: 'INTERP',
  NOTE: 'NOTE',
  SHLIB: 'SHLIB',
  PHDR: 'PHDR',
  TLS: 'TLS',
  GNU_EH_FRAME: 'GNU_EH_FRAME',
  GNU_STACK: 'GNU_STACK',
  GNU_PROPERTY: 'GNU_PROPERTY',
  GNU_RELRO: 'GNU_RELRO',
  PAX_FLAGS: 'PAX_FLAGS',
  ARM_ARCHEXT: 'ARM_ARCHEXT',
  ARM_EXIDX: 'ARM_EXIDX',
  AARCH64_MEMTAG_MTE: 'AARCH64_MEMTAG_MTE',
  MIPS_REGINFO: 'MIPS_REGINFO',
  MIPS_RTPROC: 'MIPS_RTPROC',
  MIPS_OPTIONS: 'MIPS_OPTIONS',
  MIPS_ABIFLAGS: 'MIPS_ABIFLAGS',
  RISCV_ATTRIBUTES: 'RISCV_ATTRIBUTES',
  IA_64_EXT: 'IA_64_EXT',
  IA_64_UNWIND: 'IA_64_UNWIND',
  HP_TLS: 'HP_TLS',
  HP_CORE_NONE: 'HP_CORE_NONE',
  HP_CORE_VERSION: 'HP_CORE_VERSION',
  HP_CORE_KERNEL: 'HP_CORE_KERNEL',
  HP_CORE_COMM: 'HP_CORE_COMM',
  HP_CORE_PROC: 'HP_CORE_PROC',
  HP_CORE_LOADABLE: 'HP_CORE_LOADABLE',
  HP_CORE_STACK: 'HP_CORE_STACK',
  HP_CORE_SHM: 'HP_CORE_SHM',
  HP_CORE_MMF: 'HP_CORE_MMF',
  HP_PARALLEL: 'HP_PARALLEL',
  HP_FASTBIND: 'HP_FASTBIND',
  HP_OPT_ANNOT: 'HP_OPT_ANNOT',
  HP_HSL_ANNOT: 'HP_HSL_ANNOT',
  HP_STACK: 'HP_STACK',
  HP_CORE_UTSNAME: 'HP_CORE_UTSNAME',
});

// Add ELF.Section.TYPE constants
// These mirror LIEF::ELF::Section::TYPE names exposed by the native binding.
binding.ELF.Section.TYPE = Object.freeze({
  SHT_NULL_: 'SHT_NULL_',
  PROGBITS: 'PROGBITS',
  SYMTAB: 'SYMTAB',
  STRTAB: 'STRTAB',
  RELA: 'RELA',
  HASH: 'HASH',
  DYNAMIC: 'DYNAMIC',
  NOTE: 'NOTE',
  NOBITS: 'NOBITS',
  REL: 'REL',
  SHLIB: 'SHLIB',
  DYNSYM: 'DYNSYM',
  INIT_ARRAY: 'INIT_ARRAY',
  FINI_ARRAY: 'FINI_ARRAY',
  PREINIT_ARRAY: 'PREINIT_ARRAY',
  GROUP: 'GROUP',
  SYMTAB_SHNDX: 'SYMTAB_SHNDX',
  RELR: 'RELR',
  ANDROID_REL: 'ANDROID_REL',
  ANDROID_RELA: 'ANDROID_RELA',
  LLVM_ADDRSIG: 'LLVM_ADDRSIG',
  ANDROID_RELR: 'ANDROID_RELR',
  GNU_ATTRIBUTES: 'GNU_ATTRIBUTES',
  GNU_HASH: 'GNU_HASH',
  GNU_VERDEF: 'GNU_VERDEF',
  GNU_VERNEED: 'GNU_VERNEED',
  GNU_VERSYM: 'GNU_VERSYM',
  ARM_EXIDX: 'ARM_EXIDX',
  ARM_PREEMPTMAP: 'ARM_PREEMPTMAP',
  ARM_ATTRIBUTES: 'ARM_ATTRIBUTES',
  ARM_DEBUGOVERLAY: 'ARM_DEBUGOVERLAY',
  ARM_OVERLAYSECTION: 'ARM_OVERLAYSECTION',
  HEX_ORDERED: 'HEX_ORDERED',
  X86_64_UNWIND: 'X86_64_UNWIND',
  MIPS_LIBLIST: 'MIPS_LIBLIST',
  MIPS_MSYM: 'MIPS_MSYM',
  MIPS_CONFLICT: 'MIPS_CONFLICT',
  MIPS_GPTAB: 'MIPS_GPTAB',
  MIPS_UCODE: 'MIPS_UCODE',
  MIPS_DEBUG: 'MIPS_DEBUG',
  MIPS_REGINFO: 'MIPS_REGINFO',
  MIPS_PACKAGE: 'MIPS_PACKAGE',
  MIPS_PACKSYM: 'MIPS_PACKSYM',
  MIPS_RELD: 'MIPS_RELD',
  MIPS_IFACE: 'MIPS_IFACE',
  MIPS_CONTENT: 'MIPS_CONTENT',
  MIPS_OPTIONS: 'MIPS_OPTIONS',
  MIPS_SHDR: 'MIPS_SHDR',
  MIPS_FDESC: 'MIPS_FDESC',
  MIPS_EXTSYM: 'MIPS_EXTSYM',
  MIPS_DENSE: 'MIPS_DENSE',
  MIPS_PDESC: 'MIPS_PDESC',
  MIPS_LOCSYM: 'MIPS_LOCSYM',
  MIPS_AUXSYM: 'MIPS_AUXSYM',
  MIPS_OPTSYM: 'MIPS_OPTSYM',
  MIPS_LOCSTR: 'MIPS_LOCSTR',
  MIPS_LINE: 'MIPS_LINE',
  MIPS_RFDESC: 'MIPS_RFDESC',
  MIPS_DELTASYM: 'MIPS_DELTASYM',
  MIPS_DELTAINST: 'MIPS_DELTAINST',
  MIPS_DELTACLASS: 'MIPS_DELTACLASS',
  MIPS_DWARF: 'MIPS_DWARF',
  MIPS_DELTADECL: 'MIPS_DELTADECL',
  MIPS_SYMBOL_LIB: 'MIPS_SYMBOL_LIB',
  MIPS_EVENTS: 'MIPS_EVENTS',
  MIPS_TRANSLATE: 'MIPS_TRANSLATE',
  MIPS_PIXIE: 'MIPS_PIXIE',
  MIPS_XLATE: 'MIPS_XLATE',
  MIPS_XLATE_DEBUG: 'MIPS_XLATE_DEBUG',
  MIPS_WHIRL: 'MIPS_WHIRL',
  MIPS_EH_REGION: 'MIPS_EH_REGION',
  MIPS_XLATE_OLD: 'MIPS_XLATE_OLD',
  MIPS_ABIFLAGS: 'MIPS_ABIFLAGS',
  MIPS_XHASH: 'MIPS_XHASH',
  RISCV_ATTRIBUTES: 'RISCV_ATTRIBUTES',
});

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
