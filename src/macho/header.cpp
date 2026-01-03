/*
 * LIEF MachO Header Binding
 */

#include "header.h"

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* macho_header_constructor = nullptr;

Napi::Object MachOHeader::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Header", {
    InstanceAccessor<&MachOHeader::GetCpuType>("cpuType"),
    InstanceAccessor<&MachOHeader::GetCpuSubtype>("cpuSubtype"),
    InstanceAccessor<&MachOHeader::GetFileType>("fileType"),
    InstanceAccessor<&MachOHeader::GetFlags>("flags"),
    InstanceAccessor<&MachOHeader::GetMagic>("magic"),
    InstanceAccessor<&MachOHeader::GetNbCmds>("nbCmds"),
    InstanceAccessor<&MachOHeader::GetSizeofCmds>("sizeofCmds"),
    InstanceAccessor<&MachOHeader::GetIs32Bit>("is32Bit"),
    InstanceAccessor<&MachOHeader::GetIs64Bit>("is64Bit"),
  });

  macho_header_constructor = new Napi::FunctionReference();
  *macho_header_constructor = Napi::Persistent(constructor);

  return constructor;
}

MachOHeader::MachOHeader(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<MachOHeader>(info), header_(nullptr) {}

Napi::Object MachOHeader::NewInstance(Napi::Env env, const LIEF::MachO::Header* header) {
  Napi::Object obj = macho_header_constructor->New({});
  MachOHeader* unwrapped = Napi::ObjectWrap<MachOHeader>::Unwrap(obj);
  unwrapped->header_ = header;
  return obj;
}

Napi::Value MachOHeader::GetCpuType(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), static_cast<int32_t>(header_->cpu_type()));
}

Napi::Value MachOHeader::GetCpuSubtype(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->cpu_subtype());
}

Napi::Value MachOHeader::GetFileType(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), static_cast<uint32_t>(header_->file_type()));
}

Napi::Value MachOHeader::GetFlags(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->flags());
}

Napi::Value MachOHeader::GetMagic(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), static_cast<uint32_t>(header_->magic()));
}

Napi::Value MachOHeader::GetNbCmds(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->nb_cmds());
}

Napi::Value MachOHeader::GetSizeofCmds(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), header_->sizeof_cmds());
}

Napi::Value MachOHeader::GetIs32Bit(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), header_->is_32bit());
}

Napi::Value MachOHeader::GetIs64Bit(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), header_->is_64bit());
}

} // namespace node_lief
