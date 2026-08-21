// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "token/cbor.h"

#include <gtest/gtest.h>
#include <vector>

namespace
{
  std::vector<uint8_t> bytes(std::initializer_list<int> vs)
  {
    std::vector<uint8_t> out;
    for (const auto v : vs)
    {
      out.push_back(static_cast<uint8_t>(v));
    }
    return out;
  }
}

TEST(Cbor, RejectsDuplicateMapKeys)
{
  // a2 01 01 01 02 = {1: 1, 1: 2} -- duplicate key 1 (draft-08 s5.4)
  EXPECT_THROW(
    (void)sdcwt::cbor::parse(bytes({0xa2, 0x01, 0x01, 0x01, 0x02})),
    std::exception);
}

TEST(Cbor, RejectsNestingDeeperThanMaxDepth)
{
  // draft-08 s5.5 caps nesting at 16.
  std::vector<uint8_t> deep;
  for (int i = 0; i < 40; i++)
  {
    deep.push_back(0x81); // array(1)
  }
  deep.push_back(0x00); // innermost: 0

  EXPECT_THROW(sdcwt::cbor::parse(deep), std::exception);
}
