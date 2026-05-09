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
#include <LIEF/ELF.hpp>

namespace node_lief {

/**
 * Wrapper for LIEF::ELF::Section
 * Represents an ELF section with ELF-specific read-write access.
 */
class ELFSection : public Napi::ObjectWrap<ELFSection> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from LIEF ELF section
  static Napi::Object NewInstance(Napi::Env env, LIEF::ELF::Section* section);

  // Constructor (must be public for ObjectWrap)
  explicit ELFSection(const Napi::CallbackInfo& info);

 private:
  LIEF::ELF::Section* section_;

  // Read-write properties
  Napi::Value GetName(const Napi::CallbackInfo& info);
  void SetName(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetType(const Napi::CallbackInfo& info);
  void SetType(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetFlags(const Napi::CallbackInfo& info);
  void SetFlags(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetVirtualAddress(const Napi::CallbackInfo& info);
  void SetVirtualAddress(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetFileOffset(const Napi::CallbackInfo& info);
  void SetFileOffset(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetSize(const Napi::CallbackInfo& info);
  void SetSize(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetAlignment(const Napi::CallbackInfo& info);
  void SetAlignment(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetContent(const Napi::CallbackInfo& info);
  void SetContent(const Napi::CallbackInfo& info, const Napi::Value& value);

  Napi::Value GetOffset(const Napi::CallbackInfo& info);
};

} // namespace node_lief
