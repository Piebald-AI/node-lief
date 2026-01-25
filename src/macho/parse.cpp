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
 * LIEF MachO parse() function
 */

#include "fat_binary.h"
#include "binary.h"
#include <napi.h>
#include <LIEF/MachO.hpp>

namespace node_lief {

Napi::Value MachOParse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "parse() requires a file path string")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file - returns FatBinary which may contain multiple architectures
  auto fat_binary = LIEF::MachO::Parser::parse(filename);
  if (!fat_binary) {
    Napi::Error::New(env, "Failed to parse MachO binary file").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Return the FatBinary wrapper
  return MachOFatBinary::NewInstance(env, std::move(fat_binary));
}

} // namespace node_lief
