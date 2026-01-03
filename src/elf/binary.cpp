/*
 * LIEF ELF Binary Binding
 *
 * Provides ELF format-specific functionality for Linux/Unix binaries
 */

#include "binary.h"
#include "../abstract/section.h"

namespace node_lief {

// Static storage for ELF Binary constructor
static Napi::FunctionReference* elf_binary_constructor = nullptr;

Napi::Object ELFBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Abstract properties
    InstanceAccessor<&ELFBinary::GetFormat>("format"),
    InstanceAccessor<&ELFBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&ELFBinary::GetIsPie>("isPie"),
    InstanceAccessor<&ELFBinary::GetHasNx>("hasNx"),
    InstanceAccessor<&ELFBinary::GetHeader>("header"),
    // ELF-specific properties
    InstanceAccessor<&ELFBinary::GetHasOverlay>("hasOverlay"),
    InstanceAccessor<&ELFBinary::GetOverlay, &ELFBinary::SetOverlay>("overlay"),
    // Abstract methods
    InstanceMethod<&ELFBinary::GetSections>("sections"),
    InstanceMethod<&ELFBinary::GetSymbols>("symbols"),
    InstanceMethod<&ELFBinary::GetRelocations>("relocations"),
    InstanceMethod<&ELFBinary::GetSegments>("segments"),
    InstanceMethod<&ELFBinary::GetSymbol>("getSymbol"),
    InstanceMethod<&ELFBinary::PatchAddress>("patchAddress"),
    InstanceMethod<&ELFBinary::Write>("write"),
    // ELF-specific methods
    InstanceMethod<&ELFBinary::GetSection>("getSection"),
  });

  elf_binary_constructor = new Napi::FunctionReference();
  *elf_binary_constructor = Napi::Persistent(constructor);

  exports.Set("Binary", constructor);
  return exports;
}

Napi::Value ELFBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::ELF::Binary> binary) {
  Napi::Object obj = elf_binary_constructor->New({});
  ELFBinary* wrapper = ELFBinary::Unwrap(obj);
  wrapper->elf_binary_ = std::move(binary);
  wrapper->binary_ = wrapper->elf_binary_.get();
  return obj;
}

ELFBinary::ELFBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<ELFBinary>(info), BinaryImpl() {}

Napi::Value ELFBinary::GetHasOverlay(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), elf_binary_->has_overlay());
}

Napi::Value ELFBinary::GetOverlay(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto overlay = elf_binary_->overlay();
  if (overlay.empty()) {
    return Napi::Buffer<uint8_t>::New(env, 0);
  }
  return Napi::Buffer<uint8_t>::Copy(env, overlay.data(), overlay.size());
}

void ELFBinary::SetOverlay(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!value.IsBuffer()) {
    return;
  }

  auto buffer = value.As<Napi::Buffer<uint8_t>>();
  std::vector<uint8_t> new_overlay(buffer.Data(), buffer.Data() + buffer.Length());
  elf_binary_->overlay(new_overlay);
}

Napi::Value ELFBinary::GetSection(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string section_name = info[0].As<Napi::String>();
  auto* section = elf_binary_->get_section(section_name);

  if (!section) {
    return env.Null();
  }

  return Section::NewInstance(env, section);
}

} // namespace node_lief
