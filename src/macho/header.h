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
#include <LIEF/MachO/Header.hpp>

namespace node_lief {

/**
 * Wrapper for LIEF::MachO::Header
 * Represents a MachO binary header
 */
class MachOHeader : public Napi::ObjectWrap<MachOHeader> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from LIEF header
  static Napi::Object NewInstance(Napi::Env env, const LIEF::MachO::Header* header);

  // Constructor (must be public for ObjectWrap)
  explicit MachOHeader(const Napi::CallbackInfo& info);

 private:
  const LIEF::MachO::Header* header_;

  // MachO-specific properties (read-only)
  Napi::Value GetCpuType(const Napi::CallbackInfo& info);
  Napi::Value GetCpuSubtype(const Napi::CallbackInfo& info);
  Napi::Value GetFileType(const Napi::CallbackInfo& info);
  Napi::Value GetFlags(const Napi::CallbackInfo& info);
  Napi::Value GetMagic(const Napi::CallbackInfo& info);
  Napi::Value GetNbCmds(const Napi::CallbackInfo& info);
  Napi::Value GetSizeofCmds(const Napi::CallbackInfo& info);
  Napi::Value GetIs32Bit(const Napi::CallbackInfo& info);
  Napi::Value GetIs64Bit(const Napi::CallbackInfo& info);
};

} // namespace node_lief
