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
#include <LIEF/MachO.hpp>

namespace node_lief {

/**
 * MachO FatBinary wrapper
 * Represents a MachO Fat/Universal binary (or single architecture)
 */
class MachOFatBinary : public Napi::ObjectWrap<MachOFatBinary> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from parsed FatBinary
  static Napi::Object NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::FatBinary> fat);

  // Constructor (must be public for ObjectWrap)
  explicit MachOFatBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::MachO::FatBinary> fat_binary_;

  // Methods
  Napi::Value Size(const Napi::CallbackInfo& info);
  Napi::Value At(const Napi::CallbackInfo& info);
  Napi::Value Take(const Napi::CallbackInfo& info);
};

} // namespace node_lief
