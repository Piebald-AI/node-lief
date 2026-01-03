#pragma once

#include <napi.h>

namespace node_lief {

/**
 * Top-level parse function that auto-detects format and returns
 * the appropriate format-specific Binary wrapper (ELF, PE, or MachO)
 */
Napi::Value Parse(const Napi::CallbackInfo& info);

} // namespace node_lief
