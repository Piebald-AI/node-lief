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

#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/ELF.hpp>
#include "../binary_impl.h"

namespace node_lief {

/**
 * ELF-specific Binary wrapper
 * Provides ELF format-specific functionality
 */
class ELFBinary : public Napi::ObjectWrap<ELFBinary>, protected BinaryImpl {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Value NewInstance(Napi::Env env, std::unique_ptr<LIEF::ELF::Binary> binary);
  explicit ELFBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::ELF::Binary> elf_binary_;

  // Abstract properties - forward to BinaryImpl
  Napi::Value GetFormat(const Napi::CallbackInfo& info) {
    return GetFormatImpl(info.Env());
  }
  Napi::Value GetEntrypoint(const Napi::CallbackInfo& info) {
    return GetEntrypointImpl(info.Env());
  }
  Napi::Value GetIsPie(const Napi::CallbackInfo& info) {
    return GetIsPieImpl(info.Env());
  }
  Napi::Value GetHasNx(const Napi::CallbackInfo& info) {
    return GetHasNxImpl(info.Env());
  }
  Napi::Value GetHeader(const Napi::CallbackInfo& info) {
    return GetHeaderImpl(info.Env());
  }

  // Abstract methods - forward to BinaryImpl
  Napi::Value GetSections(const Napi::CallbackInfo& info);
  Napi::Value GetSymbols(const Napi::CallbackInfo& info) {
    return GetSymbolsImpl(info.Env());
  }
  Napi::Value GetRelocations(const Napi::CallbackInfo& info) {
    return GetRelocationsImpl(info.Env());
  }
  Napi::Value GetSegments(const Napi::CallbackInfo& info);

  Napi::Value GetSymbol(const Napi::CallbackInfo& info) {
    return GetSymbolImpl(info.Env(), info);
  }
  Napi::Value PatchAddress(const Napi::CallbackInfo& info) {
    return PatchAddressImpl(info.Env(), info);
  }
  Napi::Value Write(const Napi::CallbackInfo& info) {
    return WriteImpl(info.Env(), info);
  }

  // ELF-specific property getters
  Napi::Value GetHasOverlay(const Napi::CallbackInfo& info);
  Napi::Value GetOverlay(const Napi::CallbackInfo& info);
  void SetOverlay(const Napi::CallbackInfo& info, const Napi::Value& value);

  // ELF-specific methods
  Napi::Value GetSection(const Napi::CallbackInfo& info);
  Napi::Value GetSegment(const Napi::CallbackInfo& info);
  Napi::Value Extend(const Napi::CallbackInfo& info);
  Napi::Value LastOffsetSection(const Napi::CallbackInfo& info);
  Napi::Value LastOffsetSegment(const Napi::CallbackInfo& info);
  Napi::Value NextVirtualAddress(const Napi::CallbackInfo& info);
  Napi::Value PageSize(const Napi::CallbackInfo& info);
};

} // namespace node_lief
