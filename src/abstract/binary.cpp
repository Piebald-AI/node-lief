/*
 * LIEF Parse Function
 *
 * Top-level parsing that auto-detects format and returns format-specific wrappers
 */

#include "binary.h"
#include "../elf/binary.h"
#include "../macho/binary.h"
#include "../pe/binary.h"
#include <LIEF/LIEF.hpp>

namespace node_lief {

Napi::Value Parse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "parse() requires a file path string")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file to detect format
  auto parsed = LIEF::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse binary file").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Return the concrete type based on format
  auto format = parsed->format();

  if (format == LIEF::Binary::FORMATS::MACHO) {
    // The generic LIEF::Parser::parse already validated this is a MachO file
    // using is_macho(), so MachO::Parser::parse will succeed
    auto fat_binary = LIEF::MachO::Parser::parse(filename);
    return MachOBinary::NewInstance(env, fat_binary->take(0));
  }

  if (format == LIEF::Binary::FORMATS::PE) {
    // The generic LIEF::Parser::parse already validated this is a PE file
    // using is_pe(), so PE::Parser::parse will succeed
    return PEBinary::NewInstance(env, LIEF::PE::Parser::parse(filename));
  }

  if (format == LIEF::Binary::FORMATS::ELF) {
    // The generic LIEF::Parser::parse already validated this is an ELF file
    // using is_elf(), so ELF::Parser::parse will succeed
    return ELFBinary::NewInstance(env, LIEF::ELF::Parser::parse(filename));
  }

  Napi::Error::New(env, "Unsupported binary format").ThrowAsJavaScriptException();
  return env.Null();
}

} // namespace node_lief
