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
 * LIEF MachO FatBinary Binding
 *
 * Represents a Fat/Universal Mach-O binary (or single architecture)
 */

#include "fat_binary.h"
#include "binary.h"

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* fat_binary_constructor = nullptr;

Napi::Object MachOFatBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "FatBinary", {
    InstanceMethod<&MachOFatBinary::Size>("size"),
    InstanceMethod<&MachOFatBinary::At>("at"),
    InstanceMethod<&MachOFatBinary::Take>("take"),
  });

  fat_binary_constructor = new Napi::FunctionReference();
  *fat_binary_constructor = Napi::Persistent(constructor);

  return constructor;
}

MachOFatBinary::MachOFatBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<MachOFatBinary>(info), fat_binary_(nullptr) {}

Napi::Object MachOFatBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::FatBinary> fat) {
  Napi::Object obj = fat_binary_constructor->New({});
  MachOFatBinary* wrapper = Napi::ObjectWrap<MachOFatBinary>::Unwrap(obj);
  wrapper->fat_binary_ = std::move(fat);
  return obj;
}

Napi::Value MachOFatBinary::Size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), fat_binary_->size());
}

Napi::Value MachOFatBinary::At(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    return env.Null();
  }

  size_t index = info[0].As<Napi::Number>().Uint32Value();

  if (index >= fat_binary_->size()) {
    Napi::RangeError::New(env, "Index out of range").ThrowAsJavaScriptException();
    return env.Null();
  }

  auto* binary_ptr = fat_binary_->at(index);
  return MachOBinary::NewInstanceNonOwning(env, binary_ptr);
}

Napi::Value MachOFatBinary::Take(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    return env.Null();
  }

  size_t index = info[0].As<Napi::Number>().Uint32Value();

  if (index >= fat_binary_->size()) {
    Napi::RangeError::New(env, "Index out of range").ThrowAsJavaScriptException();
    return env.Null();
  }

  auto binary = fat_binary_->take(index);
  return MachOBinary::NewInstance(env, std::move(binary));
}

} // namespace node_lief
