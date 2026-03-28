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
#include "../abstract/section.h"
#include <LIEF/ELF.hpp>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* elf_segment_constructor = nullptr;

Napi::Object ELFSegment::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Segment", {
    InstanceAccessor<&ELFSegment::GetType>("type"),
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

// Read-only properties

Napi::Value ELFSegment::GetType(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), LIEF::ELF::to_string(segment_->type()));
}

// Read-write properties

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
    sections_array[idx++] = Section::NewInstance(env, &sec);
  }

  return sections_array;
}

} // namespace node_lief
