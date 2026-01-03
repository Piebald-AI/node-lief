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
