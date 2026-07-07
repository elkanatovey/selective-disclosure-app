# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.21)

project(selective_disclosure_app LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

# --- Vendored dependencies -------------------------------------------------
# QCBOR is vendored (as SCITT does) for CBOR encode/decode in the token core.
# Declared before add_ccf_app so the app can link + include it.
include(FetchContent)

set(BUILD_QCBOR_TEST OFF CACHE STRING "" FORCE)
FetchContent_Declare(
  qcbor
  GIT_REPOSITORY https://github.com/laurencelundblade/QCBOR.git
  GIT_TAG        v1.6.1
)
FetchContent_MakeAvailable(qcbor)
set_property(TARGET qcbor PROPERTY SYSTEM TRUE)

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
)

# --- The CCF application ----------------------------------------------------
add_ccf_app(
  selective_disclosure
  SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/app.cpp
       ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
       ${TOKEN_SRCS}
       ${APP_LOGIC_SRCS}
  INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src
  LINK_LIBS qcbor
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
    unit_tests PRIVATE ccfcrypto ccf qcbor GTest::gtest GTest::gmock
  )
  add_test(NAME unit_tests COMMAND unit_tests)
endif()
