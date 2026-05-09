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
 * LIEF ELF Segment Binding
 *
 * Provides read-write access to ELF segments (program headers)
 */

#include "segment.h"
#include "section.h"
#include <LIEF/ELF.hpp>
#include <string>
#include <unordered_map>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* elf_segment_constructor = nullptr;

Napi::Object ELFSegment::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Segment", {
    InstanceAccessor<&ELFSegment::GetType, &ELFSegment::SetType>("type"),
    InstanceAccessor<&ELFSegment::GetFlags, &ELFSegment::SetFlags>("flags"),
    InstanceAccessor<&ELFSegment::GetVirtualAddress, &ELFSegment::SetVirtualAddress>("virtualAddress"),
    InstanceAccessor<&ELFSegment::GetVirtualSize, &ELFSegment::SetVirtualSize>("virtualSize"),
    InstanceAccessor<&ELFSegment::GetFileOffset, &ELFSegment::SetFileOffset>("fileOffset"),
    InstanceAccessor<&ELFSegment::GetFileSize, &ELFSegment::SetFileSize>("fileSize"),
    InstanceAccessor<&ELFSegment::GetPhysicalAddress, &ELFSegment::SetPhysicalAddress>("physicalAddress"),
    InstanceAccessor<&ELFSegment::GetAlignment, &ELFSegment::SetAlignment>("alignment"),
    InstanceAccessor<&ELFSegment::GetContent, &ELFSegment::SetContent>("content"),
    InstanceMethod<&ELFSegment::GetSections>("sections"),
  });

  elf_segment_constructor = new Napi::FunctionReference();
  *elf_segment_constructor = Napi::Persistent(constructor);

  return constructor;
}

ELFSegment::ELFSegment(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<ELFSegment>(info), segment_(nullptr) {}

Napi::Object ELFSegment::NewInstance(Napi::Env env, LIEF::ELF::Segment* segment) {
  Napi::Object obj = elf_segment_constructor->New({});
  ELFSegment* unwrapped = Napi::ObjectWrap<ELFSegment>::Unwrap(obj);
  unwrapped->segment_ = segment;
  return obj;
}

bool ELFSegment::IsInstance(const Napi::Value& value) {
  return value.IsObject() && value.As<Napi::Object>().InstanceOf(elf_segment_constructor->Value());
}

// Read-only properties

Napi::Value ELFSegment::GetType(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), LIEF::ELF::to_string(segment_->type()));
}

void ELFSegment::SetType(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsString()) return;

  const std::string type = value.As<Napi::String>().Utf8Value();
  using SegmentType = LIEF::ELF::Segment::TYPE;

  static const std::unordered_map<std::string, SegmentType> types = {
    {"PT_NULL_", SegmentType::PT_NULL_},
    {"LOAD", SegmentType::LOAD},
    {"DYNAMIC", SegmentType::DYNAMIC},
    {"INTERP", SegmentType::INTERP},
    {"NOTE", SegmentType::NOTE},
    {"SHLIB", SegmentType::SHLIB},
    {"PHDR", SegmentType::PHDR},
    {"TLS", SegmentType::TLS},
    {"GNU_EH_FRAME", SegmentType::GNU_EH_FRAME},
    {"GNU_STACK", SegmentType::GNU_STACK},
    {"GNU_PROPERTY", SegmentType::GNU_PROPERTY},
    {"GNU_RELRO", SegmentType::GNU_RELRO},
    {"PAX_FLAGS", SegmentType::PAX_FLAGS},
    {"ARM_ARCHEXT", SegmentType::ARM_ARCHEXT},
    {"ARM_EXIDX", SegmentType::ARM_EXIDX},
    {"AARCH64_MEMTAG_MTE", SegmentType::AARCH64_MEMTAG_MTE},
    {"MIPS_REGINFO", SegmentType::MIPS_REGINFO},
    {"MIPS_RTPROC", SegmentType::MIPS_RTPROC},
    {"MIPS_OPTIONS", SegmentType::MIPS_OPTIONS},
    {"MIPS_ABIFLAGS", SegmentType::MIPS_ABIFLAGS},
    {"RISCV_ATTRIBUTES", SegmentType::RISCV_ATTRIBUTES},
    {"IA_64_EXT", SegmentType::IA_64_EXT},
    {"IA_64_UNWIND", SegmentType::IA_64_UNWIND},
    {"HP_TLS", SegmentType::HP_TLS},
    {"HP_CORE_NONE", SegmentType::HP_CORE_NONE},
    {"HP_CORE_VERSION", SegmentType::HP_CORE_VERSION},
    {"HP_CORE_KERNEL", SegmentType::HP_CORE_KERNEL},
    {"HP_CORE_COMM", SegmentType::HP_CORE_COMM},
    {"HP_CORE_PROC", SegmentType::HP_CORE_PROC},
    {"HP_CORE_LOADABLE", SegmentType::HP_CORE_LOADABLE},
    {"HP_CORE_STACK", SegmentType::HP_CORE_STACK},
    {"HP_CORE_SHM", SegmentType::HP_CORE_SHM},
    {"HP_CORE_MMF", SegmentType::HP_CORE_MMF},
    {"HP_PARALLEL", SegmentType::HP_PARALLEL},
    {"HP_FASTBIND", SegmentType::HP_FASTBIND},
    {"HP_OPT_ANNOT", SegmentType::HP_OPT_ANNOT},
    {"HP_HSL_ANNOT", SegmentType::HP_HSL_ANNOT},
    {"HP_STACK", SegmentType::HP_STACK},
    {"HP_CORE_UTSNAME", SegmentType::HP_CORE_UTSNAME},
  };

  auto it = types.find(type);
  if (it == types.end()) return;

  segment_->type(it->second);
}

Napi::Value ELFSegment::GetFlags(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), static_cast<uint32_t>(segment_->flags()));
}

void ELFSegment::SetFlags(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsNumber()) return;
  segment_->flags(value.As<Napi::Number>().Uint32Value());
}

Napi::Value ELFSegment::GetVirtualAddress(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->virtual_address());
}

void ELFSegment::SetVirtualAddress(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  segment_->virtual_address(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSegment::GetVirtualSize(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->virtual_size());
}

void ELFSegment::SetVirtualSize(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  segment_->virtual_size(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSegment::GetFileOffset(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->file_offset());
}

void ELFSegment::SetFileOffset(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  segment_->file_offset(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSegment::GetFileSize(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->physical_size());
}

void ELFSegment::SetFileSize(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  segment_->physical_size(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSegment::GetPhysicalAddress(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->physical_address());
}

void ELFSegment::SetPhysicalAddress(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  segment_->physical_address(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSegment::GetAlignment(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->alignment());
}

void ELFSegment::SetAlignment(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  segment_->alignment(value.As<Napi::BigInt>().Uint64Value(&lossless));
}

Napi::Value ELFSegment::GetContent(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto content = segment_->content();
  if (content.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  return Napi::Buffer<uint8_t>::Copy(env, content.data(), content.size());
}

void ELFSegment::SetContent(const Napi::CallbackInfo& info, const Napi::Value& value) {
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
    segment_->content(new_content);
  }
}

// Methods

Napi::Value ELFSegment::GetSections(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array sections_array = Napi::Array::New(env);

  auto sections = segment_->sections();
  uint32_t idx = 0;
  for (auto& sec : sections) {
    sections_array[idx++] = ELFSection::NewInstance(env, &sec);
  }

  return sections_array;
}

} // namespace node_lief
