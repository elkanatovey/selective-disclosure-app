# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.21)

project(selective_disclosure_app LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

# --- Vendored dependencies -------------------------------------------------
include(FetchContent)

# The token core (CBOR/COSE/SD-CWT construction), shared by the enclave app and
# the host unit tests.
set(TOKEN_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/cbor_value.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/cose.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/sd_cwt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/statement.cpp
)

# App-level pure logic (CBOR submission parsing, ...), unit-testable without CCF
# KV/endpoints; shared by the enclave app and the host unit tests.
set(APP_LOGIC_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/report_parse.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/disclosure_store.cpp
)

# --- The CCF application ----------------------------------------------------
# CBOR encode/decode uses CCF's own evercbor-backed `ccf::cbor` (header
# ccf/_private/crypto/cbor.h, symbols in ccfcrypto), so no CBOR library is
# vendored here. The header is under `_private`, so CCF makes no API-stability
# promise for it; the pinned CCF release in third_party/CCF is what keeps that
# safe, and a break would be a compile error rather than silent misbehaviour.
add_ccf_app(
  selective_disclosure
  SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/app.cpp
       ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
       ${TOKEN_SRCS}
       ${APP_LOGIC_SRCS}
  INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# --- Host unit tests (no enclave, no chain) --------------------------------
option(BUILD_TESTS "Build the host-side C++ unit tests (no enclave, no chain)" OFF)
if(BUILD_TESTS)
  set(INSTALL_GTEST OFF)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        release-1.12.1
  )
  FetchContent_MakeAvailable(googletest)

  enable_testing()

  file(GLOB UNIT_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/unit-tests/*.cpp)
  add_executable(unit_tests ${UNIT_TEST_SOURCES} ${TOKEN_SRCS} ${APP_LOGIC_SRCS})
  target_include_directories(unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  # The ccfcrypto imported target only exposes its quickjs 3rdparty include; the
  # main CCF headers live under the install prefix, so add them explicitly.
  target_include_directories(
    unit_tests SYSTEM PRIVATE
    ${CCF_DIR}/include
    ${CCF_DIR}/include/ccf
    ${CCF_DIR}/include/3rdparty
  )
  target_link_libraries(
    unit_tests PRIVATE ccfcrypto ccf GTest::gtest GTest::gmock
  )
  add_test(NAME unit_tests COMMAND unit_tests)
endif()
