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
 * LIEF ELF Binary Binding
 *
 * Provides ELF format-specific functionality for Linux/Unix binaries
 */

#include "binary.h"
#include "segment.h"
#include "../abstract/section.h"

namespace node_lief {

// Static storage for ELF Binary constructor
static Napi::FunctionReference* elf_binary_constructor = nullptr;

Napi::Object ELFBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Abstract properties
    InstanceAccessor<&ELFBinary::GetFormat>("format"),
    InstanceAccessor<&ELFBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&ELFBinary::GetIsPie>("isPie"),
    InstanceAccessor<&ELFBinary::GetHasNx>("hasNx"),
    InstanceAccessor<&ELFBinary::GetHeader>("header"),
    // ELF-specific properties
    InstanceAccessor<&ELFBinary::GetHasOverlay>("hasOverlay"),
    InstanceAccessor<&ELFBinary::GetOverlay, &ELFBinary::SetOverlay>("overlay"),
    // Abstract methods
    InstanceMethod<&ELFBinary::GetSections>("sections"),
    InstanceMethod<&ELFBinary::GetSymbols>("symbols"),
    InstanceMethod<&ELFBinary::GetRelocations>("relocations"),
    InstanceMethod<&ELFBinary::GetSegments>("segments"),
    InstanceMethod<&ELFBinary::GetSymbol>("getSymbol"),
    InstanceMethod<&ELFBinary::PatchAddress>("patchAddress"),
    InstanceMethod<&ELFBinary::Write>("write"),
    // ELF-specific methods
    InstanceMethod<&ELFBinary::GetSection>("getSection"),
    InstanceMethod<&ELFBinary::GetSegment>("getSegment"),
  });

  elf_binary_constructor = new Napi::FunctionReference();
  *elf_binary_constructor = Napi::Persistent(constructor);

  exports.Set("Binary", constructor);
  return exports;
}

Napi::Value ELFBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::ELF::Binary> binary) {
  Napi::Object obj = elf_binary_constructor->New({});
  ELFBinary* wrapper = ELFBinary::Unwrap(obj);
  wrapper->elf_binary_ = std::move(binary);
  wrapper->binary_ = wrapper->elf_binary_.get();
  return obj;
}

ELFBinary::ELFBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<ELFBinary>(info), BinaryImpl() {}

Napi::Value ELFBinary::GetHasOverlay(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), elf_binary_->has_overlay());
}

Napi::Value ELFBinary::GetOverlay(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto overlay = elf_binary_->overlay();
  if (overlay.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  return Napi::Buffer<uint8_t>::Copy(env, overlay.data(), overlay.size());
}

void ELFBinary::SetOverlay(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBuffer()) {
    return;
  }

  auto buffer = value.As<Napi::Buffer<uint8_t>>();
  std::vector<uint8_t> new_overlay(buffer.Data(), buffer.Data() + buffer.Length());
  elf_binary_->overlay(new_overlay);
}

Napi::Value ELFBinary::GetSegments(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array segments_array = Napi::Array::New(env);
  uint32_t idx = 0;

  for (auto& segment : elf_binary_->segments()) {
    segments_array[idx++] = ELFSegment::NewInstance(env, &segment);
  }

  return segments_array;
}

Napi::Value ELFBinary::GetSegment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string type_name = info[0].As<Napi::String>();

  for (auto& segment : elf_binary_->segments()) {
    if (LIEF::ELF::to_string(segment.type()) == type_name) {
      return ELFSegment::NewInstance(env, &segment);
    }
  }

  return env.Null();
}

Napi::Value ELFBinary::GetSection(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string section_name = info[0].As<Napi::String>();
  auto* section = elf_binary_->get_section(section_name);

  if (!section) {
    return env.Null();
  }

  return Section::NewInstance(env, section);
}

} // namespace node_lief
