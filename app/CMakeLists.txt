# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

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
