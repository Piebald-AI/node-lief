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
 * LIEF Section Binding with full read/write support
 */

#include "section.h"

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* section_constructor = nullptr;

Napi::Object Section::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Section", {
    InstanceAccessor<&Section::GetName>("name"),
    InstanceAccessor<&Section::GetVirtualAddress>("virtualAddress"),
    InstanceAccessor<&Section::GetSize, &Section::SetSize>("size"),
    InstanceAccessor<&Section::GetFileOffset>("fileOffset"),
    InstanceAccessor<&Section::GetContent, &Section::SetContent>("content"),
    InstanceAccessor<&Section::GetOffset>("offset"),
  });

  section_constructor = new Napi::FunctionReference();
  *section_constructor = Napi::Persistent(constructor);

  return constructor;
}

Section::Section(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Section>(info), section_(nullptr) {}

Napi::Object Section::NewInstance(Napi::Env env, LIEF::Section* section) {
  Napi::Object obj = section_constructor->New({});
  Section* unwrapped = Napi::ObjectWrap<Section>::Unwrap(obj);
  unwrapped->section_ = section;
  return obj;
}

Napi::Value Section::GetName(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), section_->name());
}

Napi::Value Section::GetVirtualAddress(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->virtual_address());
}

Napi::Value Section::GetSize(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->size());
}

void Section::SetSize(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBigInt()) return;
  bool lossless = false;
  uint64_t new_size = value.As<Napi::BigInt>().Uint64Value(&lossless);
  section_->size(new_size);
}

Napi::Value Section::GetFileOffset(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->offset());
}

Napi::Value Section::GetContent(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto content = section_->content();
  if (content.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  return Napi::Buffer<uint8_t>::Copy(env, content.data(), content.size());
}

void Section::SetContent(const Napi::CallbackInfo& info, const Napi::Value& value) {
  std::vector<uint8_t> new_content;

  if (value.IsArray()) {
    auto arr = value.As<Napi::Array>();
    new_content.reserve(arr.Length());
    for (uint32_t i = 0; i < arr.Length(); i++) {
      auto val = arr.Get(i);
      if (val.IsNumber()) {
        new_content.push_back(static_cast<uint8_t>(val.As<Napi::Number>().Uint32Value()));
      }
    }
  } else if (value.IsBuffer()) {
    auto buffer = value.As<Napi::Buffer<uint8_t>>();
    new_content.assign(buffer.Data(), buffer.Data() + buffer.Length());
  }

  if (!new_content.empty()) {
    section_->content(new_content);
  }
}

Napi::Value Section::GetOffset(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), section_->offset());
}

} // namespace node_lief
