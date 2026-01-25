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

namespace node_lief {

/**
 * Top-level parse function that auto-detects format and returns
 * the appropriate format-specific Binary wrapper (ELF, PE, or MachO)
 */
Napi::Value Parse(const Napi::CallbackInfo& info);

} // namespace node_lief
