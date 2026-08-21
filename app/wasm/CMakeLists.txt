# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.21)
project(sd_cwt_wasm LANGUAGES C CXX)

if(NOT EMSCRIPTEN)
  message(FATAL_ERROR "Configure this target with emcmake")
endif()

set(APP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(REPO_ROOT ${APP_ROOT}/..)
set(EVERCBOR_ROOT ${REPO_ROOT}/third_party/CCF/3rdparty/internal)

add_executable(
  sd_cwt_wasm
  bindings.cpp
  ${APP_ROOT}/src/token/cbor.cpp
  ${APP_ROOT}/src/token/cbor_value.cpp
  ${APP_ROOT}/src/token/cose.cpp
  ${APP_ROOT}/src/token/presentation.cpp
  ${APP_ROOT}/src/token/verification.cpp
  ${EVERCBOR_ROOT}/evercbor/CBORNondet.c
)

target_compile_features(sd_cwt_wasm PRIVATE cxx_std_20)
target_compile_definitions(sd_cwt_wasm PRIVATE SDCWT_PORTABLE=1)
target_include_directories(
  sd_cwt_wasm
  PRIVATE
  ${APP_ROOT}/src
  ${EVERCBOR_ROOT}
  ${EVERCBOR_ROOT}/evercbor
)
target_compile_options(
  sd_cwt_wasm
  PRIVATE
  $<$<COMPILE_LANGUAGE:C>:-Wno-everything>
  $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Werror;-fexceptions>
)
target_link_options(
  sd_cwt_wasm
  PRIVATE
  --bind
  -fexceptions
  -sALLOW_MEMORY_GROWTH=1
  -sDISABLE_EXCEPTION_CATCHING=0
  -sENVIRONMENT=web,node
  -sEXPORT_ES6=1
  -sFILESYSTEM=0
  -sMODULARIZE=1
)
set_target_properties(
  sd_cwt_wasm
  PROPERTIES
  OUTPUT_NAME sd_cwt
  SUFFIX .mjs
)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/webcrypto.mjs
  ${CMAKE_CURRENT_BINARY_DIR}/sd_cwt_webcrypto.mjs
  COPYONLY
)
