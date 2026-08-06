// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Guards the two `ccf::cbor` behaviours this app would silently miscompile on
// if they regressed; other CBOR behaviour we rely on is asserted where it is
// used. The header is under `ccf/_private/` (no API-stability promise), pinned
// to ccf-7.0.5, so a break there is a compile error, not silent misbehaviour.

#include <ccf/_private/crypto/cbor.h>
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

TEST(CcfCbor, RejectsDuplicateMapKeys)
{
  // a2 01 01 01 02 = {1: 1, 1: 2} -- duplicate key 1 (draft-08 s5.4)
  EXPECT_THROW(
    (void)ccf::cbor::parse(bytes({0xa2, 0x01, 0x01, 0x01, 0x02})),
    std::exception);
}

TEST(CcfCbor, RejectsNestingDeeperThanMaxDepth)
{
  // draft-08 s5.5 caps nesting at 16; ccf::cbor defaults max_depth to 16 too.
  std::vector<uint8_t> deep;
  for (int i = 0; i < 40; i++)
  {
    deep.push_back(0x81); // array(1)
  }
  deep.push_back(0x00); // innermost: 0

  EXPECT_THROW(ccf::cbor::parse(deep), std::exception);
}
