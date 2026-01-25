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
 * Binary Implementation Base
 *
 * Provides shared implementations for ELF and PE Binary format wrappers.
 * Note: MachO uses its own MachOBinary class with separate implementations.
 */

#include "binary_impl.h"
#include "abstract/section.h"
#include <LIEF/LIEF.hpp>

namespace node_lief {

Napi::Value BinaryImpl::GetFormatImpl(Napi::Env env) {
  // This is only called by ELF and PE binaries (MachO has its own GetFormat)
  if (binary_->format() == LIEF::Binary::FORMATS::ELF) {
    return Napi::String::New(env, "ELF");
  }
  return Napi::String::New(env, "PE");
}

Napi::Value BinaryImpl::GetEntrypointImpl(Napi::Env env) {
  return Napi::BigInt::New(env, static_cast<uint64_t>(binary_->entrypoint()));
}

Napi::Value BinaryImpl::GetIsPieImpl(Napi::Env env) {
  return Napi::Boolean::New(env, binary_->is_pie());
}

Napi::Value BinaryImpl::GetHasNxImpl(Napi::Env env) {
  return Napi::Boolean::New(env, binary_->has_nx());
}

Napi::Value BinaryImpl::GetHeaderImpl(Napi::Env env) {
  auto header = binary_->header();

  Napi::Object header_obj = Napi::Object::New(env);
  header_obj.Set("architecture", Napi::Number::New(env, static_cast<uint32_t>(header.architecture())));
  header_obj.Set("entrypoint", Napi::BigInt::New(env, header.entrypoint()));
  header_obj.Set("is_32", Napi::Boolean::New(env, header.is_32()));
  header_obj.Set("is_64", Napi::Boolean::New(env, header.is_64()));

  return header_obj;
}

Napi::Value BinaryImpl::GetSectionsImpl(Napi::Env env) {
  Napi::Array sections_array = Napi::Array::New(env);
  uint32_t idx = 0;

  for (auto& section : binary_->sections()) {
    sections_array[idx++] = Section::NewInstance(env, &section);
  }

  return sections_array;
}

Napi::Value BinaryImpl::GetSymbolsImpl(Napi::Env env) {
  Napi::Array symbols_array = Napi::Array::New(env);
  auto symbols = binary_->symbols();

  uint32_t idx = 0;
  for (auto& symbol : symbols) {
    Napi::Object symbol_obj = Napi::Object::New(env);
    symbol_obj.Set("name", Napi::String::New(env, symbol.name()));
    symbol_obj.Set("value", Napi::BigInt::New(env, symbol.value()));
    symbol_obj.Set("size", Napi::BigInt::New(env, symbol.size()));

    symbols_array[idx++] = symbol_obj;
  }

  return symbols_array;
}

Napi::Value BinaryImpl::GetRelocationsImpl(Napi::Env env) {
  Napi::Array relocations_array = Napi::Array::New(env);
  auto relocations = binary_->relocations();

  uint32_t idx = 0;
  for (auto& reloc : relocations) {
    Napi::Object reloc_obj = Napi::Object::New(env);
    reloc_obj.Set("address", Napi::BigInt::New(env, reloc.address()));
    reloc_obj.Set("size", Napi::Number::New(env, reloc.size()));

    relocations_array[idx++] = reloc_obj;
  }

  return relocations_array;
}

Napi::Value BinaryImpl::GetSegmentsImpl(Napi::Env env) {
  // Segments are format-specific (MachO has segments, PE/ELF use sections)
  // Return empty array by default; format-specific classes can override
  return Napi::Array::New(env);
}

Napi::Value BinaryImpl::GetSymbolImpl(Napi::Env env, const Napi::CallbackInfo& info) {
  if (info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string symbol_name = info[0].As<Napi::String>();
  auto symbol = binary_->get_symbol(symbol_name);

  if (!symbol) {
    return env.Null();
  }

  Napi::Object symbol_obj = Napi::Object::New(env);
  symbol_obj.Set("name", Napi::String::New(env, symbol->name()));
  symbol_obj.Set("value", Napi::BigInt::New(env, symbol->value()));
  symbol_obj.Set("size", Napi::BigInt::New(env, symbol->size()));

  return symbol_obj;
}

Napi::Value BinaryImpl::PatchAddressImpl(Napi::Env env, const Napi::CallbackInfo& info) {
  if (info.Length() < 2) {
    Napi::TypeError::New(env, "patchAddress requires address and patch data")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get address (supports both Number and BigInt)
  uint64_t address = 0;
  if (info[0].IsBigInt()) {
    bool lossless = false;
    address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
  } else if (info[0].IsNumber()) {
    address = static_cast<uint64_t>(info[0].As<Napi::Number>().Uint32Value());
  } else {
    Napi::TypeError::New(env, "Address must be a number or BigInt")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get patch data (as Buffer or Array)
  std::vector<uint8_t> patch;
  if (info[1].IsBuffer()) {
    auto buffer = info[1].As<Napi::Buffer<uint8_t>>();
    patch.assign(buffer.Data(), buffer.Data() + buffer.Length());
  } else if (info[1].IsArray()) {
    auto arr = info[1].As<Napi::Array>();
    for (uint32_t i = 0; i < arr.Length(); i++) {
      auto val = arr.Get(i).As<Napi::Number>();
      patch.push_back(static_cast<uint8_t>(val.Uint32Value()));
    }
  } else {
    Napi::TypeError::New(env, "Patch data must be a Buffer or Array")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Apply the patch
  binary_->patch_address(address, patch);

  return env.Undefined();
}

Napi::Value BinaryImpl::WriteImpl(Napi::Env env, const Napi::CallbackInfo& info) {
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "write() requires an output file path")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string output_path = info[0].As<Napi::String>();

  try {
    // Use format-specific builders to write the binary
    // Note: MachO binaries use MachOBinary::Write() directly, not this method
    if (binary_->format() == LIEF::Binary::FORMATS::ELF) {
      auto* elf_bin = dynamic_cast<LIEF::ELF::Binary*>(binary_);
      LIEF::ELF::Builder builder(*elf_bin);
      builder.build();
      builder.write(output_path);
    } else {
      // PE format
      auto* pe_bin = dynamic_cast<LIEF::PE::Binary*>(binary_);
      LIEF::PE::Builder::config_t config;
      LIEF::PE::Builder builder(*pe_bin, config);
      builder.build();
      builder.write(output_path);
    }
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to write binary: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

} // namespace node_lief
