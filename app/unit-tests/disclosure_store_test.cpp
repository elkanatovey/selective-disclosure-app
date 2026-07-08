// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "disclosure_store.h"

#include "token/cbor.h"

#include <functional>
#include <gtest/gtest.h>

using sdcwt::Disclosure;
using selectivedisclosure::decode_disclosure_store;
using selectivedisclosure::encode_disclosure_store;

namespace
{
  Disclosure disc(std::vector<uint8_t> encoded)
  {
    Disclosure d;
    d.encoded = std::move(encoded);
    return d;
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
