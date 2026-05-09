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

/*
 * LIEF ELF Section Binding
 *
 * Provides ELF-specific read-write access to sections.
 */

#include "section.h"
#include <string>
#include <unordered_map>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* elf_section_constructor = nullptr;

Napi::Object ELFSection::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Section", {
    InstanceAccessor<&ELFSection::GetName, &ELFSection::SetName>("name"),
    InstanceAccessor<&ELFSection::GetType, &ELFSection::SetType>("type"),
    InstanceAccessor<&ELFSection::GetFlags, &ELFSection::SetFlags>("flags"),
    InstanceAccessor<&ELFSection::GetVirtualAddress, &ELFSection::SetVirtualAddress>("virtualAddress"),
    InstanceAccessor<&ELFSection::GetFileOffset, &ELFSection::SetFileOffset>("fileOffset"),
    InstanceAccessor<&ELFSection::GetSize, &ELFSection::SetSize>("size"),
    InstanceAccessor<&ELFSection::GetAlignment, &ELFSection::SetAlignment>("alignment"),
    InstanceAccessor<&ELFSection::GetContent, &ELFSection::SetContent>("content"),
    InstanceAccessor<&ELFSection::GetOffset>("offset"),
  });

  elf_section_constructor = new Napi::FunctionReference();
  *elf_section_constructor = Napi::Persistent(constructor);

  return constructor;
}

ELFSection::ELFSection(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<ELFSection>(info), section_(nullptr) {}

Napi::Object ELFSection::NewInstance(Napi::Env env, LIEF::ELF::Section* section) {
  Napi::Object obj = elf_section_constructor->New({});
  ELFSection* unwrapped = Napi::ObjectWrap<ELFSection>::Unwrap(obj);
  unwrapped->section_ = section;
  return obj;
}

Napi::Value ELFSection::GetName(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), section_->name());
}

void ELFSection::SetName(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsString()) return;
  section_->name(value.As<Napi::String>().Utf8Value());
}

Napi::Value ELFSection::GetType(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), LIEF::ELF::to_string(section_->type()));
}

void ELFSection::SetType(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsString()) return;

  const std::string type = value.As<Napi::String>().Utf8Value();
  using SectionType = LIEF::ELF::Section::TYPE;

  static const std::unordered_map<std::string, SectionType> types = {
    {"SHT_NULL_", SectionType::SHT_NULL_},
    {"PROGBITS", SectionType::PROGBITS},
    {"SYMTAB", SectionType::SYMTAB},
    {"STRTAB", SectionType::STRTAB},
    {"RELA", SectionType::RELA},
    {"HASH", SectionType::HASH},
    {"DYNAMIC", SectionType::DYNAMIC},
    {"NOTE", SectionType::NOTE},
    {"NOBITS", SectionType::NOBITS},
    {"REL", SectionType::REL},
    {"SHLIB", SectionType::SHLIB},
    {"DYNSYM", SectionType::DYNSYM},
    {"INIT_ARRAY", SectionType::INIT_ARRAY},
    {"FINI_ARRAY", SectionType::FINI_ARRAY},
    {"PREINIT_ARRAY", SectionType::PREINIT_ARRAY},
    {"GROUP", SectionType::GROUP},
    {"SYMTAB_SHNDX", SectionType::SYMTAB_SHNDX},
    {"RELR", SectionType::RELR},
    {"ANDROID_REL", SectionType::ANDROID_REL},
    {"ANDROID_RELA", SectionType::ANDROID_RELA},
    {"LLVM_ADDRSIG", SectionType::LLVM_ADDRSIG},
    {"ANDROID_RELR", SectionType::ANDROID_RELR},
    {"GNU_ATTRIBUTES", SectionType::GNU_ATTRIBUTES},
    {"GNU_HASH", SectionType::GNU_HASH},
    {"GNU_VERDEF", SectionType::GNU_VERDEF},
    {"GNU_VERNEED", SectionType::GNU_VERNEED},
    {"GNU_VERSYM", SectionType::GNU_VERSYM},
    {"ARM_EXIDX", SectionType::ARM_EXIDX},
    {"ARM_PREEMPTMAP", SectionType::ARM_PREEMPTMAP},
    {"ARM_ATTRIBUTES", SectionType::ARM_ATTRIBUTES},
    {"ARM_DEBUGOVERLAY", SectionType::ARM_DEBUGOVERLAY},
    {"ARM_OVERLAYSECTION", SectionType::ARM_OVERLAYSECTION},
    {"HEX_ORDERED", SectionType::HEX_ORDERED},
    {"X86_64_UNWIND", SectionType::X86_64_UNWIND},
    {"MIPS_LIBLIST", SectionType::MIPS_LIBLIST},
    {"MIPS_MSYM", SectionType::MIPS_MSYM},
    {"MIPS_CONFLICT", SectionType::MIPS_CONFLICT},
    {"MIPS_GPTAB", SectionType::MIPS_GPTAB},
    {"MIPS_UCODE", SectionType::MIPS_UCODE},
    {"MIPS_DEBUG", SectionType::MIPS_DEBUG},
    {"MIPS_REGINFO", SectionType::MIPS_REGINFO},
    {"MIPS_PACKAGE", SectionType::MIPS_PACKAGE},
    {"MIPS_PACKSYM", SectionType::MIPS_PACKSYM},
    {"MIPS_RELD", SectionType::MIPS_RELD},
    {"MIPS_IFACE", SectionType::MIPS_IFACE},
    {"MIPS_CONTENT", SectionType::MIPS_CONTENT},
    {"MIPS_OPTIONS", SectionType::MIPS_OPTIONS},
    {"MIPS_SHDR", SectionType::MIPS_SHDR},
    {"MIPS_FDESC", SectionType::MIPS_FDESC},
    {"MIPS_EXTSYM", SectionType::MIPS_EXTSYM},
    {"MIPS_DENSE", SectionType::MIPS_DENSE},
    {"MIPS_PDESC", SectionType::MIPS_PDESC},
    {"MIPS_LOCSYM", SectionType::MIPS_LOCSYM},
    {"MIPS_AUXSYM", SectionType::MIPS_AUXSYM},
    {"MIPS_OPTSYM", SectionType::MIPS_OPTSYM},
    {"MIPS_LOCSTR", SectionType::MIPS_LOCSTR},
    {"MIPS_LINE", SectionType::MIPS_LINE},
    {"MIPS_RFDESC", SectionType::MIPS_RFDESC},
    {"MIPS_DELTASYM", SectionType::MIPS_DELTASYM},
    {"MIPS_DELTAINST", SectionType::MIPS_DELTAINST},
    {"MIPS_DELTACLASS", SectionType::MIPS_DELTACLASS},
    {"MIPS_DWARF", SectionType::MIPS_DWARF},
    {"MIPS_DELTADECL", SectionType::MIPS_DELTADECL},
    {"MIPS_SYMBOL_LIB", SectionType::MIPS_SYMBOL_LIB},
    {"MIPS_EVENTS", SectionType::MIPS_EVENTS},
    {"MIPS_TRANSLATE", SectionType::MIPS_TRANSLATE},
    {"MIPS_PIXIE", SectionType::MIPS_PIXIE},
    {"MIPS_XLATE", SectionType::MIPS_XLATE},
    {"MIPS_XLATE_DEBUG", SectionType::MIPS_XLATE_DEBUG},
    {"MIPS_WHIRL", SectionType::MIPS_WHIRL},
    {"MIPS_EH_REGION", SectionType::MIPS_EH_REGION},
    {"MIPS_XLATE_OLD", SectionType::MIPS_XLATE_OLD},
    {"MIPS_ABIFLAGS", SectionType::MIPS_ABIFLAGS},
    {"MIPS_XHASH", SectionType::MIPS_XHASH},
    {"RISCV_ATTRIBUTES", SectionType::RISCV_ATTRIBUTES},
  };

  auto it = types.find(type);
  if (it == types.end()) return;

  section_->type(it->second);
}

Napi::Value ELFSection::GetFlags(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->flags());
}

void ELFSection::SetFlags(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  section_->flags(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSection::GetVirtualAddress(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->virtual_address());
}

void ELFSection::SetVirtualAddress(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  section_->virtual_address(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSection::GetFileOffset(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->file_offset());
}

void ELFSection::SetFileOffset(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  section_->file_offset(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSection::GetSize(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->size());
}

void ELFSection::SetSize(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  section_->size(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSection::GetAlignment(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->alignment());
}

void ELFSection::SetAlignment(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  section_->alignment(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSection::GetContent(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto content = section_->content();
  if (content.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  return Napi::Buffer<uint8_t>::Copy(env, content.data(), content.size());
}

void ELFSection::SetContent(const Napi::CallbackInfo& info, const Napi::Value& value) {
  std::vector<uint8_t> new_content;

  if (value.IsArray()) {
    auto arr = value.As<Napi::Array>();
    new_content.reserve(arr.Length());
    for (uint32_t i = 0; i < arr.Length(); i++) {
      auto val = arr.Get(i);
      if (val.IsNumber()) {
        new_content.push_back(static_cast<uint8_t>(val.As<Napi::Number>().Uint32Value()));
      }
    }
  } else if (value.IsBuffer()) {
    auto buffer = value.As<Napi::Buffer<uint8_t>>();
    new_content.assign(buffer.Data(), buffer.Data() + buffer.Length());
  }

  if (!new_content.empty()) {
    section_->content(new_content);
  }
}

Napi::Value ELFSection::GetOffset(const Napi::CallbackInfo& info) {
  return GetFileOffset(info);
}

} // namespace node_lief
