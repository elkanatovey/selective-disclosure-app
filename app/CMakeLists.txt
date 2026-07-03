# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.21)

project(selective_disclosure_app LANGUAGES C CXX)

set(CCF_PROJECT "ccf")

if(NOT TARGET "ccf")
  find_package(${CCF_PROJECT} REQUIRED)
endif()

add_ccf_app(
  selective_disclosure
  SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/app.cpp
       ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

# --- Token core (C++) + host unit tests -----------------------------------
# The token core (CBOR/COSE/SD-CWT construction) is built as plain sources so
# it can compile both into the enclave app and into a standalone host test
# binary. QCBOR is vendored the same way SCITT does.
include(FetchContent)

set(BUILD_QCBOR_TEST OFF CACHE STRING "" FORCE)
FetchContent_Declare(
  qcbor
  GIT_REPOSITORY https://github.com/laurencelundblade/QCBOR.git
  GIT_TAG        v1.6.1
)
FetchContent_MakeAvailable(qcbor)
set_property(TARGET qcbor PROPERTY SYSTEM TRUE)

# Sources for the token core, shared by the app and the unit tests.
set(TOKEN_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/cose.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/sd_cwt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/token/statement.cpp
)

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
  add_executable(unit_tests ${UNIT_TEST_SOURCES} ${TOKEN_SRCS})
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
