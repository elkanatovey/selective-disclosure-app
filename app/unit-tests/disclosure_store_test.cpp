// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "disclosure_store.h"

#include "token/cbor.h"

#include <functional>
#include <gtest/gtest.h>

using sdcwt::Disclosure;
using selectivedisclosure::decode_disclosure_store;
using selectivedisclosure::disclosure_key_id;
using selectivedisclosure::encode_disclosure_store;
using selectivedisclosure::select_disclosures;

namespace
{
  Disclosure disc(std::vector<uint8_t> encoded)
  {
    Disclosure d;
    d.encoded = std::move(encoded);
    return d;
  }

  // Encode a salted map-entry disclosure `[salt, value, key]` with a text
  // value.
  std::vector<uint8_t> entry(int64_t key, const char* value)
  {
    return sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
      QCBOREncode_OpenArray(&c);
      const std::vector<uint8_t> salt = {0xaa, 0xbb};
      QCBOREncode_AddBytes(&c, sdcwt::to_ubc(salt));
      QCBOREncode_AddSZString(&c, value);
      QCBOREncode_AddInt64(&c, key);
      QCBOREncode_CloseArray(&c);
    });
  }

  // Encode a salted map-entry disclosure whose value is itself an array (e.g.
  // the `references` field) — exercises value-subtree skipping.
  std::vector<uint8_t> entry_array_value(int64_t key)
  {
    return sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
      QCBOREncode_OpenArray(&c);
      const std::vector<uint8_t> salt = {0xaa, 0xbb};
      QCBOREncode_AddBytes(&c, sdcwt::to_ubc(salt));
      QCBOREncode_OpenArray(&c);
      QCBOREncode_AddSZString(&c, "CVE-1");
      QCBOREncode_AddSZString(&c, "CVE-2");
      QCBOREncode_CloseArray(&c);
      QCBOREncode_AddInt64(&c, key);
      QCBOREncode_CloseArray(&c);
    });
  }
}

// The store round-trips: whatever encoded disclosures go in come back out, in
// order, byte-for-byte.
TEST(DisclosureStore, RoundTrips)
{
  std::vector<Disclosure> in = {
    disc({0x83, 0x01, 0x02, 0x03}), // [1,2,3]-shaped bytes
    disc({0x82, 0xaa, 0xbb}),
    disc({0x81, 0x00}),
  };

  const auto blob = encode_disclosure_store(in);
  const auto out = decode_disclosure_store(blob);

  ASSERT_EQ(out.size(), in.size());
  for (size_t i = 0; i < in.size(); ++i)
  {
    EXPECT_EQ(out[i], in[i].encoded);
  }
}

// The stored bytes are exactly what present() consumes: a real issued
// statement's disclosures survive the store and can be re-presented.
TEST(DisclosureStore, PreservesRealDisclosures)
{
  const std::vector<uint8_t> real = {0x84, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44,
                                     0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                     0xcc, 0xdd, 0xee, 0xff, 0x65, 0x68, 0x65,
                                     0x6c, 0x6c, 0x6f, 0x19, 0x03, 0xe9};
  std::vector<Disclosure> in = {disc(real)};

  const auto out = decode_disclosure_store(encode_disclosure_store(in));
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0], real);
}

// An empty disclosure set round-trips to an empty list (a valid CBOR array).
TEST(DisclosureStore, EmptyRoundTrips)
{
  const auto blob = encode_disclosure_store({});
  EXPECT_EQ(decode_disclosure_store(blob).size(), 0u);
}

// Order is preserved (the store is a sequence, not a set).
TEST(DisclosureStore, PreservesOrder)
{
  std::vector<Disclosure> in = {
    disc({0x81, 0x01}), disc({0x81, 0x02}), disc({0x81, 0x03})};
  const auto out = decode_disclosure_store(encode_disclosure_store(in));
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0], (std::vector<uint8_t>{0x81, 0x01}));
  EXPECT_EQ(out[1], (std::vector<uint8_t>{0x81, 0x02}));
  EXPECT_EQ(out[2], (std::vector<uint8_t>{0x81, 0x03}));
}

// Decoding rejects input that is not a CBOR array.
TEST(DisclosureStore, RejectsNonArray)
{
  const std::vector<uint8_t> a_map = {0xa0}; // {}
  EXPECT_THROW(decode_disclosure_store(a_map), std::invalid_argument);
}

// Decoding rejects an array element that is not a byte-string.
TEST(DisclosureStore, RejectsNonByteStringElement)
{
  // [ 1 ] — a single integer, not a bstr.
  const std::vector<uint8_t> bad = {0x81, 0x01};
  EXPECT_THROW(decode_disclosure_store(bad), std::invalid_argument);
}

// Decoding rejects trailing garbage after the array.
TEST(DisclosureStore, RejectsTrailingBytes)
{
  auto blob = encode_disclosure_store({disc({0x81, 0x01})});
  blob.push_back(0xff);
  EXPECT_THROW(decode_disclosure_store(blob), std::invalid_argument);
}

// disclosure_key_id reads the integer claim key of a `[salt, value, key]`
// entry.
TEST(DisclosureStore, KeyIdReadsIntegerKey)
{
  EXPECT_EQ(disclosure_key_id(entry(1001, "heap overflow")), 1001);
  EXPECT_EQ(disclosure_key_id(entry(1008, "patched")), 1008);
}

// A value that is itself an array is skipped whole; the key still resolves.
TEST(DisclosureStore, KeyIdSkipsArrayValue)
{
  EXPECT_EQ(disclosure_key_id(entry_array_value(1006)), 1006);
}

// No key for a redacted array element (`[salt, value]`) or a decoy (`[salt]`).
TEST(DisclosureStore, KeyIdAbsentForKeylessEntries)
{
  const auto array_elem = sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
    QCBOREncode_OpenArray(&c);
    const std::vector<uint8_t> salt = {0x01};
    QCBOREncode_AddBytes(&c, sdcwt::to_ubc(salt));
    QCBOREncode_AddSZString(&c, "value");
    QCBOREncode_CloseArray(&c);
  });
  const auto decoy = sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
    QCBOREncode_OpenArray(&c);
    const std::vector<uint8_t> salt = {0x01};
    QCBOREncode_AddBytes(&c, sdcwt::to_ubc(salt));
    QCBOREncode_CloseArray(&c);
  });
  EXPECT_FALSE(disclosure_key_id(array_elem).has_value());
  EXPECT_FALSE(disclosure_key_id(decoy).has_value());
}

// Non-array input yields no key rather than throwing.
TEST(DisclosureStore, KeyIdAbsentForNonArray)
{
  const std::vector<uint8_t> a_map = {0xa0};
  EXPECT_FALSE(disclosure_key_id(a_map).has_value());
}

// select_disclosures returns exactly the requested fields, in stored order.
TEST(DisclosureStore, SelectsRequestedFieldsInOrder)
{
  const std::vector<std::vector<uint8_t>> all = {
    entry(1000, "parent"),
    entry(1001, "title"),
    entry(1002, "body"),
    entry(1003, "component"),
  };
  const auto picked = select_disclosures(all, {1001, 1003});
  ASSERT_EQ(picked.size(), 2u);
  EXPECT_EQ(picked[0], entry(1001, "title"));
  EXPECT_EQ(picked[1], entry(1003, "component"));
}

// Requesting a field that was not redacted (no disclosure) selects nothing for
// it; the rest are unaffected.
TEST(DisclosureStore, SelectsNothingForAbsentField)
{
  const std::vector<std::vector<uint8_t>> all = {entry(1001, "title")};
  EXPECT_TRUE(select_disclosures(all, {1004}).empty());
  EXPECT_EQ(select_disclosures(all, {1001}).size(), 1u);
}

// An empty request selects nothing.
TEST(DisclosureStore, EmptySelectionSelectsNothing)
{
  const std::vector<std::vector<uint8_t>> all = {entry(1001, "title")};
  EXPECT_TRUE(select_disclosures(all, {}).empty());
}
