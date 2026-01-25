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

#pragma once

#include <napi.h>
#include <LIEF/MachO.hpp>

namespace node_lief {

/**
 * Wrapper for LIEF::MachO::SegmentCommand
 * Represents a MachO segment
 */
class Segment : public Napi::ObjectWrap<Segment> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from LIEF MachO segment
  static Napi::Object NewInstance(Napi::Env env, LIEF::MachO::SegmentCommand* segment);

  // Get underlying segment
  LIEF::MachO::SegmentCommand* GetSegment() const { return segment_; }

  // Constructor (must be public for ObjectWrap)
  explicit Segment(const Napi::CallbackInfo& info);

 private:
  LIEF::MachO::SegmentCommand* segment_;

  // Properties
  Napi::Value GetName(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualAddress(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualSize(const Napi::CallbackInfo& info);
  Napi::Value GetFileOffset(const Napi::CallbackInfo& info);
  Napi::Value GetFileSize(const Napi::CallbackInfo& info);

  // Methods
  Napi::Value GetSections(const Napi::CallbackInfo& info);
  Napi::Value GetSection(const Napi::CallbackInfo& info);
};

} // namespace node_lief
