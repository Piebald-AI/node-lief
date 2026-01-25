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
#include <LIEF/PE.hpp>

namespace node_lief {

/**
 * Wrapper for LIEF::PE::Section
 * PE-specific section with virtualSize support
 */
class PESection : public Napi::ObjectWrap<PESection> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from LIEF PE section
  static Napi::Object NewInstance(Napi::Env env, LIEF::PE::Section* section);

  // Constructor (must be public for ObjectWrap)
  explicit PESection(const Napi::CallbackInfo& info);

 private:

  LIEF::PE::Section* section_;

  // Properties (read-only and read-write)
  Napi::Value GetName(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualAddress(const Napi::CallbackInfo& info);
  Napi::Value GetSize(const Napi::CallbackInfo& info);
  void SetSize(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetFileOffset(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualSize(const Napi::CallbackInfo& info);
  void SetVirtualSize(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetContent(const Napi::CallbackInfo& info);
  void SetContent(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetOffset(const Napi::CallbackInfo& info);

  // PE-specific properties
  Napi::Value GetCharacteristics(const Napi::CallbackInfo& info);
};

} // namespace node_lief
