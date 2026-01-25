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
#include <LIEF/LIEF.hpp>

namespace node_lief {

/**
 * Base implementation class providing common Binary functionality
 *
 * This class is not an ObjectWrap itself, but provides shared implementations
 * for all format-specific Binary wrappers (Abstract, PE, ELF, MachO).
 *
 * Design: Each derived ObjectWrap class holds a std::unique_ptr to the appropriate
 * LIEF::Binary subclass and sets binary_ to point to it. All common method
 * implementations use the polymorphic binary_ pointer to call LIEF methods.
 */
class BinaryImpl {
protected:
  // Non-owning pointer to the LIEF binary (owned by derived classes)
  LIEF::Binary* binary_;

  BinaryImpl() : binary_(nullptr) {}
  virtual ~BinaryImpl() = default;

  // Common property implementations
  Napi::Value GetFormatImpl(Napi::Env env);
  Napi::Value GetEntrypointImpl(Napi::Env env);
  Napi::Value GetIsPieImpl(Napi::Env env);
  Napi::Value GetHasNxImpl(Napi::Env env);
  Napi::Value GetHeaderImpl(Napi::Env env);

  // Common method implementations
  Napi::Value GetSectionsImpl(Napi::Env env);
  Napi::Value GetSymbolsImpl(Napi::Env env);
  Napi::Value GetRelocationsImpl(Napi::Env env);
  Napi::Value GetSegmentsImpl(Napi::Env env);
  Napi::Value GetSymbolImpl(Napi::Env env, const Napi::CallbackInfo& info);
  Napi::Value PatchAddressImpl(Napi::Env env, const Napi::CallbackInfo& info);
  Napi::Value WriteImpl(Napi::Env env, const Napi::CallbackInfo& info);
};

} // namespace node_lief
