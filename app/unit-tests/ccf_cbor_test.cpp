// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Characterisation tests for CCF's evercbor-backed CBOR API (`ccf::cbor`),
// pinned before any of the token core migrates onto it. These assert what the
// library actually does, not what we hope it does: the QCBOR code being
// replaced hand-enforces several draft-08 encoding rules, and this file records
// which of those `ccf::cbor` gives us for free and which we must keep enforcing
// ourselves.
//
// The header lives under `ccf/_private/` — CCF makes no API-stability promise
// for it. The repo pins ccf-7.0.5, so it is stable until that pin moves; a
// break here is a compile error, not silent misbehaviour.

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

// --- Baseline: does it encode what we expect, byte for byte? ---------------

TEST(CcfCbor, SerializeProducesExpectedBytes)
{
  const auto fp = bytes({0xde, 0xad, 0xbe, 0xef});
  const auto m = ccf::cbor::make_map(
    {{ccf::cbor::make_signed(1), ccf::cbor::make_string("hi")},
     {ccf::cbor::make_signed(2), ccf::cbor::make_bytes(fp)}});

  // a2            map(2)
  //   01 62 6869    1: "hi"
  //   02 44 ....    2: h'DEADBEEF'
  EXPECT_EQ(
    ccf::cbor::serialize(m),
    bytes({0xa2, 0x01, 0x62, 0x68, 0x69, 0x02, 0x44, 0xde, 0xad, 0xbe, 0xef}));
}

TEST(CcfCbor, ParseRoundTripsMapAndAccessors)
{
  const auto encoded = ccf::cbor::serialize(ccf::cbor::make_map(
    {{ccf::cbor::make_signed(1), ccf::cbor::make_string("hi")},
     {ccf::cbor::make_signed(-7), ccf::cbor::make_signed(42)}}));

  const auto v = ccf::cbor::parse(encoded);
  EXPECT_EQ(v->map_at(ccf::cbor::make_signed(1))->as_string(), "hi");
  EXPECT_EQ(v->map_at(ccf::cbor::make_signed(-7))->as_signed(), 42);
  EXPECT_EQ(v->size(), 2u);
}

// --- HAZARD 1: map key ordering -------------------------------------------
// The token core needs CBOR Common Deterministic Encoding (RFC 8949 s4.2) key
// order, because the Python oracle and the C++ signer must agree byte for byte.
// cbor_value.cpp currently sorts keys itself. This pins whether `serialize`
// does it for us or preserves insertion order (in which case we keep sorting).

TEST(CcfCbor, SerializeMapKeyOrderIsCharacterised)
{
  // Insert deliberately out of CDE order: 10 before 1.
  const auto m = ccf::cbor::make_map(
    {{ccf::cbor::make_signed(10), ccf::cbor::make_signed(0)},
     {ccf::cbor::make_signed(1), ccf::cbor::make_signed(0)}});
  const auto out = ccf::cbor::serialize(m);

  // CDE order would emit key 1 (0x01) before key 10 (0x0a).
  const bool sorted_by_library = (out[1] == 0x01);
  RecordProperty("sorts_map_keys", sorted_by_library ? "yes" : "no");
  std::cout << "[characterisation] serialize() "
            << (sorted_by_library ? "SORTS map keys into CDE order" :
                                    "PRESERVES insertion order")
            << std::endl;
  SUCCEED();
}

// --- HAZARD 2: draft-08 encoding MUSTs -------------------------------------
// draft-ietf-spice-sd-cwt s5 requires rejecting indefinite-length items and
// duplicate map keys. Our QCBOR paths check these today.

TEST(CcfCbor, IndefiniteLengthHandlingIsCharacterised)
{
  // 0x9f ... 0xff = indefinite-length array [1, 2]
  const auto indef = bytes({0x9f, 0x01, 0x02, 0xff});
  try
  {
    const auto v = ccf::cbor::parse(indef);
    std::cout << "[characterisation] indefinite-length array: ACCEPTED (size="
              << v->size() << ")" << std::endl;
  }
  catch (const std::exception& e)
  {
    std::cout << "[characterisation] indefinite-length array: REJECTED -> "
              << e.what() << std::endl;
  }
  SUCCEED();
}

TEST(CcfCbor, DuplicateMapKeyHandlingIsCharacterised)
{
  // a2 01 01 01 02 = {1: 1, 1: 2} -- duplicate key 1
  const auto dup = bytes({0xa2, 0x01, 0x01, 0x01, 0x02});
  try
  {
    const auto v = ccf::cbor::parse(dup);
    std::cout << "[characterisation] duplicate map key: ACCEPTED (size="
              << v->size() << ")" << std::endl;
  }
  catch (const std::exception& e)
  {
    std::cout << "[characterisation] duplicate map key: REJECTED -> "
              << e.what() << std::endl;
  }
  SUCCEED();
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

// --- HAZARD 3: Bytes is a non-owning span ----------------------------------
// `ccf::cbor::Bytes` is `std::span<const uint8_t>`, so a parsed byte string
// aliases the caller's buffer rather than copying it. Every migrated decode
// path must keep the source buffer alive for as long as the parsed Value, or
// copy out eagerly. This pins that aliasing so the constraint is visible.

TEST(CcfCbor, ParsedBytesAliasTheInputBuffer)
{
  // 0x44 = bstr(4)
  const auto raw = bytes({0x44, 0xde, 0xad, 0xbe, 0xef});
  const auto v = ccf::cbor::parse(raw);
  const auto view = v->as_bytes();

  ASSERT_EQ(view.size(), 4u);
  // Same storage, not a copy: the Value borrows from `raw`.
  EXPECT_EQ(view.data(), raw.data() + 1);
}
