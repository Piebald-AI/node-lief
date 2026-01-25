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
#include <LIEF/Abstract/Section.hpp>

namespace node_lief {

/**
 * Wrapper for LIEF::Section
 * Represents a section in a binary with full read/write access
 */
class Section : public Napi::ObjectWrap<Section> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from LIEF section
  static Napi::Object NewInstance(Napi::Env env, LIEF::Section* section);

  // Constructor (must be public for ObjectWrap)
  explicit Section(const Napi::CallbackInfo& info);

 private:

  LIEF::Section* section_;

  // Properties (read-only and read-write)
  Napi::Value GetName(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualAddress(const Napi::CallbackInfo& info);
  Napi::Value GetSize(const Napi::CallbackInfo& info);
  void SetSize(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetFileOffset(const Napi::CallbackInfo& info);
  Napi::Value GetContent(const Napi::CallbackInfo& info);
  void SetContent(const Napi::CallbackInfo& info, const Napi::Value& value);
  Napi::Value GetOffset(const Napi::CallbackInfo& info);
};

} // namespace node_lief
