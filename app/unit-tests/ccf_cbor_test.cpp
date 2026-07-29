// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The three properties of CCF's evercbor-backed `ccf::cbor` that this app
// would silently lose correctness on if they ever changed. Everything else
// about the library is CCF's to test, and every other CBOR behaviour we depend
// on is asserted where it is used -- the CDE map-key order and the simple(59)
// entry in CborValue.CdeOrdersMapKeysAndPutsSimple59Last, tag(60) in
// SdCwt.ArrayElementRedaction, indefinite-length rejection in
// SdCwt.PresentRejectsIndefiniteLengthUnprotectedHeader.
//
// The header lives under `ccf/_private/` — CCF makes no API-stability promise
// for it. The repo pins ccf-7.0.5, so it is stable until that pin moves; a
// break here is a compile error, not silent misbehaviour.

#include "token/cbor_value.h"

#include <ccf/_private/crypto/cbor.h>
#include <gtest/gtest.h>
#include <span>
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

// Regression guard for sdcwt::bytes_value (see cbor_value.h): an empty byte
// string must still encode, and non-empty input must borrow, not copy.
TEST(CcfCbor, BytesValueEncodesEmpty)
{
  const std::vector<uint8_t> empty;
  EXPECT_EQ(ccf::cbor::serialize(sdcwt::bytes_value(empty)), bytes({0x40}));
  EXPECT_EQ(
    ccf::cbor::serialize(sdcwt::bytes_value(std::span<const uint8_t>{})),
    bytes({0x40}));

  // Non-empty is passed straight through, and still borrows rather than copies.
  const auto src = bytes({0xaa, 0xbb});
  EXPECT_EQ(sdcwt::bytes_value(src)->as_bytes().data(), src.data());
}
