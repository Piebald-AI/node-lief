/*
 * LIEF PE OptionalHeader Binding
 *
 * Provides access to PE Optional Header fields
 */

#include "optional_header.h"

namespace node_lief {

// Static storage for OptionalHeader constructor
static Napi::FunctionReference* optional_header_constructor = nullptr;

Napi::Object OptionalHeader::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "OptionalHeader", {
    InstanceAccessor<&OptionalHeader::GetMagic>("magic"),
    InstanceAccessor<&OptionalHeader::GetMajorLinkerVersion>("majorLinkerVersion"),
    InstanceAccessor<&OptionalHeader::GetMinorLinkerVersion>("minorLinkerVersion"),
    InstanceAccessor<&OptionalHeader::GetSizeOfCode>("sizeOfCode"),
    InstanceAccessor<&OptionalHeader::GetSizeOfInitializedData>("sizeOfInitializedData"),
    InstanceAccessor<&OptionalHeader::GetSizeOfUninitializedData>("sizeOfUninitializedData"),
    InstanceAccessor<&OptionalHeader::GetAddressOfEntrypoint>("addressOfEntrypoint"),
    InstanceAccessor<&OptionalHeader::GetBaseOfCode>("baseOfCode"),
    InstanceAccessor<&OptionalHeader::GetBaseOfData>("baseOfData"),
    InstanceAccessor<&OptionalHeader::GetImagebase>("imagebase"),
    InstanceAccessor<&OptionalHeader::GetSectionAlignment>("sectionAlignment"),
    InstanceAccessor<&OptionalHeader::GetFileAlignment>("fileAlignment"),
    InstanceAccessor<&OptionalHeader::GetMajorOperatingSystemVersion>("majorOperatingSystemVersion"),
    InstanceAccessor<&OptionalHeader::GetMinorOperatingSystemVersion>("minorOperatingSystemVersion"),
    InstanceAccessor<&OptionalHeader::GetMajorImageVersion>("majorImageVersion"),
    InstanceAccessor<&OptionalHeader::GetMinorImageVersion>("minorImageVersion"),
    InstanceAccessor<&OptionalHeader::GetMajorSubsystemVersion>("majorSubsystemVersion"),
    InstanceAccessor<&OptionalHeader::GetMinorSubsystemVersion>("minorSubsystemVersion"),
    InstanceAccessor<&OptionalHeader::GetWin32VersionValue>("win32VersionValue"),
    InstanceAccessor<&OptionalHeader::GetSizeOfImage>("sizeOfImage"),
    InstanceAccessor<&OptionalHeader::GetSizeOfHeaders>("sizeOfHeaders"),
    InstanceAccessor<&OptionalHeader::GetChecksum>("checksum"),
    InstanceAccessor<&OptionalHeader::GetSubsystem>("subsystem"),
    InstanceAccessor<&OptionalHeader::GetDllCharacteristics>("dllCharacteristics"),
    InstanceAccessor<&OptionalHeader::GetSizeOfStackReserve>("sizeOfStackReserve"),
    InstanceAccessor<&OptionalHeader::GetSizeOfStackCommit>("sizeOfStackCommit"),
    InstanceAccessor<&OptionalHeader::GetSizeOfHeapReserve>("sizeOfHeapReserve"),
    InstanceAccessor<&OptionalHeader::GetSizeOfHeapCommit>("sizeOfHeapCommit"),
  });

  optional_header_constructor = new Napi::FunctionReference();
  *optional_header_constructor = Napi::Persistent(constructor);

  exports.Set("OptionalHeader", constructor);
  return exports;
}

Napi::Value OptionalHeader::NewInstance(Napi::Env env, const LIEF::PE::OptionalHeader* header) {
  Napi::Object obj = optional_header_constructor->New({});
  OptionalHeader* wrapper = OptionalHeader::Unwrap(obj);
  wrapper->header_ = header;
  return obj;
}

OptionalHeader::OptionalHeader(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<OptionalHeader>(info), header_(nullptr) {
  // This constructor is called from NewInstance, header_ will be set afterwards
}

Napi::Value OptionalHeader::GetMagic(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  // PE_TYPE enum only has PE32 and PE32_PLUS values
  if (header_->magic() == LIEF::PE::PE_TYPE::PE32) {
    return Napi::String::New(env, "PE32");
  }
  return Napi::String::New(env, "PE32_PLUS");
}

Napi::Value OptionalHeader::GetMajorLinkerVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->major_linker_version());
}

Napi::Value OptionalHeader::GetMinorLinkerVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->minor_linker_version());
}

Napi::Value OptionalHeader::GetSizeOfCode(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->sizeof_code());
}

Napi::Value OptionalHeader::GetSizeOfInitializedData(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->sizeof_initialized_data());
}

Napi::Value OptionalHeader::GetSizeOfUninitializedData(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->sizeof_uninitialized_data());
}

Napi::Value OptionalHeader::GetAddressOfEntrypoint(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->addressof_entrypoint());
}

Napi::Value OptionalHeader::GetBaseOfCode(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->baseof_code());
}

Napi::Value OptionalHeader::GetBaseOfData(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->baseof_data());
}

Napi::Value OptionalHeader::GetImagebase(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), header_->imagebase());
}

Napi::Value OptionalHeader::GetSectionAlignment(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->section_alignment());
}

Napi::Value OptionalHeader::GetFileAlignment(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->file_alignment());
}

Napi::Value OptionalHeader::GetMajorOperatingSystemVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->major_operating_system_version());
}

Napi::Value OptionalHeader::GetMinorOperatingSystemVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->minor_operating_system_version());
}

Napi::Value OptionalHeader::GetMajorImageVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->major_image_version());
}

Napi::Value OptionalHeader::GetMinorImageVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->minor_image_version());
}

Napi::Value OptionalHeader::GetMajorSubsystemVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->major_subsystem_version());
}

Napi::Value OptionalHeader::GetMinorSubsystemVersion(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->minor_subsystem_version());
}

Napi::Value OptionalHeader::GetWin32VersionValue(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->win32_version_value());
}

Napi::Value OptionalHeader::GetSizeOfImage(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->sizeof_image());
}

Napi::Value OptionalHeader::GetSizeOfHeaders(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->sizeof_headers());
}

Napi::Value OptionalHeader::GetChecksum(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->checksum());
}

Napi::Value OptionalHeader::GetSubsystem(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), static_cast<uint32_t>(header_->subsystem()));
}

Napi::Value OptionalHeader::GetDllCharacteristics(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->dll_characteristics());
}

Napi::Value OptionalHeader::GetSizeOfStackReserve(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), header_->sizeof_stack_reserve());
}

Napi::Value OptionalHeader::GetSizeOfStackCommit(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), header_->sizeof_stack_commit());
}

Napi::Value OptionalHeader::GetSizeOfHeapReserve(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), header_->sizeof_heap_reserve());
}

Napi::Value OptionalHeader::GetSizeOfHeapCommit(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), header_->sizeof_heap_commit());
}

} // namespace node_lief
