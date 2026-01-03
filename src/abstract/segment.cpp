/*
 * LIEF Segment Binding (MachO-specific)
 */

#include "segment.h"
#include "section.h"
#include <LIEF/MachO.hpp>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* segment_constructor = nullptr;

Napi::Object Segment::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Segment", {
    InstanceAccessor<&Segment::GetName>("name"),
    InstanceAccessor<&Segment::GetVirtualAddress>("virtualAddress"),
    InstanceAccessor<&Segment::GetVirtualSize>("virtualSize"),
    InstanceAccessor<&Segment::GetFileOffset>("fileOffset"),
    InstanceAccessor<&Segment::GetFileSize>("fileSize"),
    InstanceMethod<&Segment::GetSections>("sections"),
    InstanceMethod<&Segment::GetSection>("getSection"),
  });

  segment_constructor = new Napi::FunctionReference();
  *segment_constructor = Napi::Persistent(constructor);

  return constructor;
}

Segment::Segment(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Segment>(info), segment_(nullptr) {}

Napi::Object Segment::NewInstance(Napi::Env env, LIEF::MachO::SegmentCommand* segment) {
  Napi::Object obj = segment_constructor->New({});
  Segment* unwrapped = Napi::ObjectWrap<Segment>::Unwrap(obj);
  unwrapped->segment_ = segment;
  return obj;
}

Napi::Value Segment::GetName(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), segment_->name());
}

Napi::Value Segment::GetVirtualAddress(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->virtual_address());
}

Napi::Value Segment::GetVirtualSize(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->virtual_size());
}

Napi::Value Segment::GetFileOffset(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->file_offset());
}

Napi::Value Segment::GetFileSize(const Napi::CallbackInfo& info) {
  return Napi::BigInt::New(info.Env(), segment_->file_size());
}

Napi::Value Segment::GetSections(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array sections_array = Napi::Array::New(env);

  auto sections = segment_->sections();
  uint32_t idx = 0;
  for (auto& sec : sections) {
    sections_array[idx++] = Section::NewInstance(env, &sec);
  }

  return sections_array;
}

Napi::Value Segment::GetSection(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string name = info[0].As<Napi::String>();
  auto* section = segment_->get_section(name);

  if (section) {
    return Section::NewInstance(env, section);
  }

  return env.Null();
}

} // namespace node_lief
