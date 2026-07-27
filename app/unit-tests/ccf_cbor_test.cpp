// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Tests for the properties of CCF's evercbor-backed CBOR API (`ccf::cbor`)
// that the token core depends on. Each one either pins a guarantee we removed
// hand-written code in favour of, or documents a gap we work around — there is
// no coverage here of the library working in general, which is CCF's business
// rather than ours.
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

// --- draft-08 encoding MUSTs we now rely on the library to enforce ---------
// The decode paths used to check these by hand; they were deleted when
// report_parse and disclosure_store moved to ccf::cbor, so these assert the
// guarantees that replaced them. Indefinite-length rejection is covered where
// it matters, in SdCwt.PresentRejectsIndefiniteLengthUnprotectedHeader.

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

// --- HAZARD 3: Bytes is a non-owning span ----------------------------------
// `ccf::cbor::Bytes` is `std::span<const uint8_t>`, so a parsed byte string
// aliases the caller's buffer rather than copying it. Every migrated decode
// path must keep the source buffer alive for as long as the parsed Value, or
// copy out eagerly. This pins that aliasing so the constraint is visible.

TEST(CcfCbor, ValuesBorrowRatherThanCopy)
{
  // Parsed: the Value points into the input buffer. 0x44 = bstr(4).
  const auto raw = bytes({0x44, 0xde, 0xad, 0xbe, 0xef});
  const auto parsed = ccf::cbor::parse(raw);
  ASSERT_EQ(parsed->as_bytes().size(), 4u);
  EXPECT_EQ(parsed->as_bytes().data(), raw.data() + 1);

  // Built: make_bytes/make_string store the span/view they are handed, so a
  // built Value borrows from its arguments exactly as a parsed one does.
  const auto src = bytes({0x01, 0x02, 0x03});
  EXPECT_EQ(ccf::cbor::make_bytes(src)->as_bytes().data(), src.data());

  const std::string text = "borrowed";
  EXPECT_EQ(ccf::cbor::make_string(text)->as_string().data(), text.data());
}

// --- SD-CWT wire shapes ----------------------------------------------------
// The token core needs two encodings the generic API is not obviously built
// for: the simple(59) redacted-claim-keys map key, and the tag(60) redacted
// array element.

TEST(CcfCbor, EncodesSimpleValue59AsMapKey)
{
  // draft-08: redacted claim keys sit under the simple(59) label.
  const auto digest = bytes({0xaa, 0xbb});
  const auto m = ccf::cbor::make_map(
    {{ccf::cbor::make_simple(static_cast<ccf::cbor::SimpleValue>(59)),
      ccf::cbor::make_array({ccf::cbor::make_bytes(digest)})}});

  // a1          map(1)
  //   f8 3b       simple(59)
  //   81 42 aabb  [h'AABB']
  EXPECT_EQ(
    ccf::cbor::serialize(m), bytes({0xa1, 0xf8, 0x3b, 0x81, 0x42, 0xaa, 0xbb}));
}

// GAP in ccf::cbor: `map_at` cannot look up a simple-value key. Its comparison
// visitor handles Signed, Bytes and String and returns false for every other
// alternative, so a simple(59) key never matches and lookup throws
// KEY_NOT_FOUND -- even though `serialize` emits, and `parse` accepts, that
// exact key. Migrated code must iterate `Map::items` for such keys instead.
// Worth fixing upstream alongside the request to make this header public.
TEST(CcfCbor, MapAtCannotFindSimpleValueKeys)
{
  const auto encoded = bytes({0xa1, 0xf8, 0x3b, 0x81, 0x42, 0xaa, 0xbb});
  const auto parsed = ccf::cbor::parse(encoded);

  EXPECT_THROW(
    (void)parsed->map_at(
      ccf::cbor::make_simple(static_cast<ccf::cbor::SimpleValue>(59))),
    std::exception);

  // The entry is present and reachable by walking the map directly.
  const auto& items = std::get<ccf::cbor::Map>(parsed->value).items;
  ASSERT_EQ(items.size(), 1u);
  EXPECT_EQ(items[0].first->as_simple(), 59);
  EXPECT_EQ(items[0].second->array_at(0)->as_bytes()[0], 0xaa);
}

TEST(CcfCbor, SupportsTag60RedactedArrayElement)
{
  // draft-08: a redacted array element is tag(60) wrapping its claim hash.
  const auto digest = bytes({0xde, 0xad});
  const auto tagged = ccf::cbor::make_tagged(60, ccf::cbor::make_bytes(digest));

  // d8 3c 42 dead = tag(60) h'DEAD'
  const auto encoded = ccf::cbor::serialize(tagged);
  EXPECT_EQ(encoded, bytes({0xd8, 0x3c, 0x42, 0xde, 0xad}));

  const auto parsed = ccf::cbor::parse(encoded);
  EXPECT_EQ(parsed->tag_at(60)->as_bytes()[1], 0xad);
}

// GAP in ccf::cbor: an empty byte string cannot be encoded from a NULL data
// pointer. The check is on the pointer, not the length -- {valid_ptr, 0} emits
// 0x40 (empty bstr) correctly, but a default-constructed span or an empty
// std::vector (whose data() is typically nullptr) throws "Encoding bytes string
// failed". Empty byte strings are legal CBOR and we do emit them (an empty COSE
// external_aad, for one), so sdcwt::bytes_value() normalises the pointer.
// Worth fixing upstream: it is a null check where a length check was meant.
TEST(CcfCbor, CannotEncodeEmptyBytesFromNullPointer)
{
  EXPECT_THROW(
    ccf::cbor::serialize(ccf::cbor::make_bytes(std::span<const uint8_t>{})),
    std::exception);

  // Same zero length, non-null pointer: fine.
  const auto anchor = bytes({0x00});
  EXPECT_EQ(
    ccf::cbor::serialize(
      ccf::cbor::make_bytes(std::span<const uint8_t>{anchor.data(), 0})),
    bytes({0x40}));
}

TEST(CcfCbor, BytesValueHelperEncodesEmpty)
{
  // sdcwt::bytes_value works where make_bytes alone does not.
  const std::vector<uint8_t> empty;
  EXPECT_EQ(ccf::cbor::serialize(sdcwt::bytes_value(empty)), bytes({0x40}));
  EXPECT_EQ(
    ccf::cbor::serialize(sdcwt::bytes_value(std::span<const uint8_t>{})),
    bytes({0x40}));

  // Non-empty is unaffected, and still borrows rather than copies.
  const auto src = bytes({0xaa, 0xbb});
  EXPECT_EQ(sdcwt::bytes_value(src)->as_bytes().data(), src.data());
}
