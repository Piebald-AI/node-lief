{
  "variables": {
    "openssl_fips": ""
  },	  
  "targets": [
    {
      "target_name": "node_lief",
      "sources": [
        "src/init.cpp",
        "src/abstract/binary.cpp",
        "src/abstract/section.cpp",
        "src/abstract/segment.cpp",
        "src/abstract/symbol.cpp",
        "src/elf/binary.cpp",
        "src/pe/binary.cpp",
        "src/macho/binary.cpp",
        "src/macho/fat_binary.cpp",
        "src/macho/parse.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src",
        "LIEF/include",
        "lief-build/include",
        "LIEF/api/c/include",
        "lief-build/api/c"
      ],
      "cflags!": [ "-fno-exceptions", "-fno-rtti" ],
      "cflags_cc!": [ "-fno-exceptions", "-fno-rtti" ],
      "cflags_cc": [ "-std=c++17", "-frtti" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        ["OS=='linux'", {
          "libraries": [
            "<(module_root_dir)/lief-build/libLIEF.a"
          ],
          "cflags_cc": [ "-std=c++17", "-fPIC", "-frtti" ]
        }],
        ["OS=='mac'", {
          "libraries": [
            "<(module_root_dir)/lief-build/libLIEF.a"
          ],
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "13.0",
            "GCC_ENABLE_CPP_RTTI": "YES",
            "OTHER_CPLUSPLUSFLAGS": [ "-std=c++17", "-frtti" ]
          }
        }],
        ["OS=='win'", {
          "libraries": [
            "<(module_root_dir)/lief-build/LIEF.lib"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalOptions": [ "/std:c++17" ]
            }
          }
        }]
      ]
    }
  ]
}
