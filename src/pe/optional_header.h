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
 * PE OptionalHeader wrapper
 * Provides access to PE Optional Header fields
 */
class OptionalHeader : public Napi::ObjectWrap<OptionalHeader> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Value NewInstance(Napi::Env env, const LIEF::PE::OptionalHeader* header);

  explicit OptionalHeader(const Napi::CallbackInfo& info);

 private:
  const LIEF::PE::OptionalHeader* header_;

  // Getter methods for properties
  Napi::Value GetMagic(const Napi::CallbackInfo& info);
  Napi::Value GetMajorLinkerVersion(const Napi::CallbackInfo& info);
  Napi::Value GetMinorLinkerVersion(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfCode(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfInitializedData(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfUninitializedData(const Napi::CallbackInfo& info);
  Napi::Value GetAddressOfEntrypoint(const Napi::CallbackInfo& info);
  Napi::Value GetBaseOfCode(const Napi::CallbackInfo& info);
  Napi::Value GetBaseOfData(const Napi::CallbackInfo& info);
  Napi::Value GetImagebase(const Napi::CallbackInfo& info);
  Napi::Value GetSectionAlignment(const Napi::CallbackInfo& info);
  Napi::Value GetFileAlignment(const Napi::CallbackInfo& info);
  Napi::Value GetMajorOperatingSystemVersion(const Napi::CallbackInfo& info);
  Napi::Value GetMinorOperatingSystemVersion(const Napi::CallbackInfo& info);
  Napi::Value GetMajorImageVersion(const Napi::CallbackInfo& info);
  Napi::Value GetMinorImageVersion(const Napi::CallbackInfo& info);
  Napi::Value GetMajorSubsystemVersion(const Napi::CallbackInfo& info);
  Napi::Value GetMinorSubsystemVersion(const Napi::CallbackInfo& info);
  Napi::Value GetWin32VersionValue(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfImage(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfHeaders(const Napi::CallbackInfo& info);
  Napi::Value GetChecksum(const Napi::CallbackInfo& info);
  Napi::Value GetSubsystem(const Napi::CallbackInfo& info);
  Napi::Value GetDllCharacteristics(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfStackReserve(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfStackCommit(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfHeapReserve(const Napi::CallbackInfo& info);
  Napi::Value GetSizeOfHeapCommit(const Napi::CallbackInfo& info);
};

} // namespace node_lief
