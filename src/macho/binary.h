#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/MachO.hpp>

namespace node_lief {

/**
 * MachO-specific Binary wrapper
 * Provides MachO format-specific functionality
 */
class MachOBinary : public Napi::ObjectWrap<MachOBinary> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory methods to create from LIEF binary
  static Napi::Object NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::Binary> binary);
  static Napi::Object NewInstanceNonOwning(Napi::Env env, LIEF::MachO::Binary* binary);

  // Constructor (must be public for ObjectWrap)
  explicit MachOBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::MachO::Binary> binary_;
  LIEF::MachO::Binary* binary_ptr_;  // For non-owning references
  bool owns_binary_;

  // Abstract properties (inherited from LIEF::Binary)
  Napi::Value GetFormat(const Napi::CallbackInfo& info);
  Napi::Value GetEntrypoint(const Napi::CallbackInfo& info);
  Napi::Value GetIsPie(const Napi::CallbackInfo& info);
  Napi::Value GetHasNx(const Napi::CallbackInfo& info);

  // MachO-specific properties
  Napi::Value GetHasCodeSignature(const Napi::CallbackInfo& info);
  Napi::Value GetHeader(const Napi::CallbackInfo& info);

  // Methods
  Napi::Value GetSegment(const Napi::CallbackInfo& info);
  Napi::Value GetSections(const Napi::CallbackInfo& info);
  Napi::Value GetSymbols(const Napi::CallbackInfo& info);
  Napi::Value RemoveSignature(const Napi::CallbackInfo& info);
  Napi::Value ExtendSegment(const Napi::CallbackInfo& info);
  Napi::Value Write(const Napi::CallbackInfo& info);

  // Helper to get the current binary pointer
  LIEF::MachO::Binary* GetBinary() const {
    return owns_binary_ ? binary_.get() : binary_ptr_;
  }
};

} // namespace node_lief
