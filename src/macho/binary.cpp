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
 * LIEF MachO Binary Binding
 *
 * Provides MachO-specific binary manipulation
 */

#include "binary.h"
#include "header.h"
#include "../abstract/segment.h"
#include "../abstract/section.h"

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* macho_binary_constructor = nullptr;

Napi::Object MachOBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Abstract properties
    InstanceAccessor<&MachOBinary::GetFormat>("format"),
    InstanceAccessor<&MachOBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&MachOBinary::GetIsPie>("isPie"),
    InstanceAccessor<&MachOBinary::GetHasNx>("hasNx"),
    // MachO-specific properties
    InstanceAccessor<&MachOBinary::GetHasCodeSignature>("hasCodeSignature"),
    InstanceAccessor<&MachOBinary::GetHeader>("header"),
    // Methods
    InstanceMethod<&MachOBinary::GetSegment>("getSegment"),
    InstanceMethod<&MachOBinary::GetSections>("sections"),
    InstanceMethod<&MachOBinary::GetSymbols>("symbols"),
    InstanceMethod<&MachOBinary::RemoveSignature>("removeSignature"),
    InstanceMethod<&MachOBinary::ExtendSegment>("extendSegment"),
    InstanceMethod<&MachOBinary::Write>("write"),
  });

  macho_binary_constructor = new Napi::FunctionReference();
  *macho_binary_constructor = Napi::Persistent(constructor);

  return constructor;
}

MachOBinary::MachOBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<MachOBinary>(info),
      binary_(nullptr),
      binary_ptr_(nullptr),
      owns_binary_(false) {}

Napi::Object MachOBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::Binary> binary) {
  Napi::Object obj = macho_binary_constructor->New({});
  MachOBinary* wrapper = Napi::ObjectWrap<MachOBinary>::Unwrap(obj);
  wrapper->binary_ = std::move(binary);
  wrapper->binary_ptr_ = nullptr;
  wrapper->owns_binary_ = true;
  return obj;
}

Napi::Object MachOBinary::NewInstanceNonOwning(Napi::Env env, LIEF::MachO::Binary* binary) {
  Napi::Object obj = macho_binary_constructor->New({});
  MachOBinary* wrapper = Napi::ObjectWrap<MachOBinary>::Unwrap(obj);
  wrapper->binary_ = nullptr;
  wrapper->binary_ptr_ = binary;
  wrapper->owns_binary_ = false;
  return obj;
}

Napi::Value MachOBinary::GetFormat(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), "MachO");
}

Napi::Value MachOBinary::GetEntrypoint(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), GetBinary()->entrypoint());
}

Napi::Value MachOBinary::GetIsPie(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), GetBinary()->is_pie());
}

Napi::Value MachOBinary::GetHasNx(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), GetBinary()->has_nx());
}

Napi::Value MachOBinary::GetHasCodeSignature(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), GetBinary()->has_code_signature());
}

Napi::Value MachOBinary::GetHeader(const Napi::CallbackInfo& info) {
  return MachOHeader::NewInstance(info.Env(), &GetBinary()->header());
}

Napi::Value MachOBinary::GetSegment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string segment_name = info[0].As<Napi::String>();
  auto* segment = GetBinary()->get_segment(segment_name);

  if (!segment) {
    return env.Null();
  }

  return Segment::NewInstance(env, segment);
}

Napi::Value MachOBinary::GetSections(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array sections_array = Napi::Array::New(env);
  uint32_t idx = 0;

  for (auto& section : GetBinary()->sections()) {
    sections_array[idx++] = Section::NewInstance(env, &section);
  }

  return sections_array;
}

Napi::Value MachOBinary::GetSymbols(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array symbols_array = Napi::Array::New(env);
  uint32_t idx = 0;

  for (auto& symbol : GetBinary()->symbols()) {
    Napi::Object symbol_obj = Napi::Object::New(env);
    symbol_obj.Set("name", Napi::String::New(env, symbol.name()));
    symbols_array[idx++] = symbol_obj;
  }

  return symbols_array;
}

Napi::Value MachOBinary::RemoveSignature(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  try {
    GetBinary()->remove_signature();
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to remove signature: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

Napi::Value MachOBinary::ExtendSegment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2) {
    Napi::TypeError::New(env, "extendSegment requires a segment and size")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  // First argument must be an object (Segment wrapper)
  if (!info[0].IsObject()) {
    Napi::TypeError::New(env, "First argument must be a Segment object")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  // Get segment from first argument (must be a Segment wrapper)
  Napi::Object seg_obj = info[0].As<Napi::Object>();
  Segment* seg_wrapper = nullptr;

  try {
    seg_wrapper = Napi::ObjectWrap<Segment>::Unwrap(seg_obj);
  } catch (...) {
    Napi::TypeError::New(env, "First argument must be a Segment object")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  LIEF::MachO::SegmentCommand* segment = seg_wrapper->GetSegment();

  // Get size from second argument
  uint64_t size = 0;
  if (info[1].IsBigInt()) {
    bool lossless = false;
    size = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
  } else if (info[1].IsNumber()) {
    size = static_cast<uint64_t>(info[1].As<Napi::Number>().Uint32Value());
  } else {
    Napi::TypeError::New(env, "Size must be a number or BigInt")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  try {
    bool result = GetBinary()->extend_segment(*segment, size);
    return Napi::Boolean::New(env, result);
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to extend segment: ") + e.what())
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }
}

Napi::Value MachOBinary::Write(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "write() requires an output file path")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string output_path = info[0].As<Napi::String>();

  try {
    LIEF::MachO::Builder::write(*GetBinary(), output_path);
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to write binary: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

} // namespace node_lief
