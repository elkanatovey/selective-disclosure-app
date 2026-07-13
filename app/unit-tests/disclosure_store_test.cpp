// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "disclosure_store.h"

#include "cbor.h"

#include <functional>
#include <gtest/gtest.h>
#include <stdexcept>

using sdcwt::Disclosure;
using sdcwt::Path;
using sdcwt::PathElem;
using selectivedisclosure::decode_disclosure_store;
using selectivedisclosure::encode_disclosure_store;
using selectivedisclosure::select_disclosures;
using selectivedisclosure::StoredDisclosure;

namespace
{
  Path path(std::vector<int64_t> elems)
  {
    Path p;
    for (auto e : elems)
    {
      p.emplace_back(e);
    }
    return p;
  }

  Disclosure disc(std::vector<int64_t> p, std::vector<uint8_t> encoded)
  {
    Disclosure d;
    d.path = path(std::move(p));
    d.encoded = std::move(encoded);
    return d;
  }

  // A distinct encoded blob per path, so selections are identifiable.
  std::vector<uint8_t> blob(uint8_t tag)
  {
    return {0x81, tag};
  }
}

// The store round-trips: paths and encoded bytes come back, in order.
TEST(DisclosureStore, RoundTrips)
{
  std::vector<Disclosure> in = {
    disc({1001}, blob(0x01)),
    disc({1006}, blob(0x06)),
    disc({1006, 0}, blob(0x60)),
    disc({1006, 1}, blob(0x61)),
  };

  const auto out = decode_disclosure_store(encode_disclosure_store(in));
  ASSERT_EQ(out.size(), in.size());
  for (size_t i = 0; i < in.size(); ++i)
  {
    EXPECT_EQ(out[i].path, in[i].path);
    EXPECT_EQ(out[i].encoded, in[i].encoded);
  }
}

// A text path element survives the round-trip (paths are general, not
// int-only).
TEST(DisclosureStore, RoundTripsTextPathElement)
{
  Disclosure d;
  d.path = Path{PathElem(int64_t{503}), PathElem(std::string("region"))};
  d.encoded = blob(0xaa);

  const auto out = decode_disclosure_store(encode_disclosure_store({d}));
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].path, d.path);
  EXPECT_EQ(out[0].encoded, d.encoded);
}

// An empty disclosure set round-trips to an empty list.
TEST(DisclosureStore, EmptyRoundTrips)
{
  EXPECT_TRUE(decode_disclosure_store(encode_disclosure_store({})).empty());
}

// Decoding rejects input that is not a CBOR array.
TEST(DisclosureStore, RejectsNonArray)
{
  const std::vector<uint8_t> a_map = {0xa0};
  EXPECT_THROW(decode_disclosure_store(a_map), std::invalid_argument);
}

// Decoding rejects an entry that is not a [path, encoded] pair.
TEST(DisclosureStore, RejectsMalformedEntry)
{
  // [ 1 ] — a bare integer where a pair is expected.
  const std::vector<uint8_t> bad = {0x81, 0x01};
  EXPECT_THROW(decode_disclosure_store(bad), std::invalid_argument);
}

// --- selection ------------------------------------------------------------

// A whole top-level field selects exactly its disclosure.
TEST(DisclosureStore, SelectsWholeTopLevelField)
{
  const std::vector<StoredDisclosure> stored =
    decode_disclosure_store(encode_disclosure_store(
      {disc({1001}, blob(0x01)), disc({1002}, blob(0x02))}));

  const auto picked = select_disclosures(stored, {path({1001})});
  ASSERT_EQ(picked.size(), 1u);
  EXPECT_EQ(picked[0], blob(0x01));
}

// A decoy (salt-only padding) disclosure has an empty path. It must NOT be
// pulled in by a field target — otherwise disclosing one field would leak which
// top-level hashes are decoys, defeating decoy padding. Decoys are only ever
// presented in the Operator's own full unredacted view.
TEST(DisclosureStore, DecoyNotSelectedByFieldTarget)
{
  std::vector<StoredDisclosure> stored;
  stored.push_back({path({1001}), blob(0x01)}); // a real field
  stored.push_back({Path{}, blob(0xDD)}); // a decoy (empty path)

  const auto picked = select_disclosures(stored, {path({1001})});
  ASSERT_EQ(picked.size(), 1u);
  EXPECT_EQ(picked[0], blob(0x01)); // only the real field, never the decoy
}

// Disclosing a nested element pulls in its ancestor (the ancestor rule) but not
// its siblings.
TEST(DisclosureStore, NestedElementPullsAncestorNotSiblings)
{
  const std::vector<StoredDisclosure> stored =
    decode_disclosure_store(encode_disclosure_store({
      disc({1006}, blob(0x06)),
      disc({1006, 0}, blob(0x60)),
      disc({1006, 1}, blob(0x61)),
      disc({1006, 2}, blob(0x62)),
    }));

  const auto picked = select_disclosures(stored, {path({1006, 1})});
  // Ancestor {1006} + the target {1006,1}; siblings {1006,0}/{1006,2} excluded.
  ASSERT_EQ(picked.size(), 2u);
  EXPECT_EQ(picked[0], blob(0x06)); // shallowest first: the ancestor
  EXPECT_EQ(picked[1], blob(0x61));
}

// Disclosing a whole array field reveals its nested elements too (descendants).
TEST(DisclosureStore, WholeArrayFieldPullsDescendants)
{
  const std::vector<StoredDisclosure> stored =
    decode_disclosure_store(encode_disclosure_store({
      disc({1006}, blob(0x06)),
      disc({1006, 0}, blob(0x60)),
      disc({1006, 1}, blob(0x61)),
    }));

  const auto picked = select_disclosures(stored, {path({1006})});
  ASSERT_EQ(picked.size(), 3u);
  EXPECT_EQ(picked[0], blob(0x06)); // the field itself, shallowest first
}

// Unrelated branches and an empty target set select nothing.
TEST(DisclosureStore, SelectsNothingForUnrelatedOrEmpty)
{
  const std::vector<StoredDisclosure> stored =
    decode_disclosure_store(encode_disclosure_store(
      {disc({1001}, blob(0x01)), disc({1006}, blob(0x06))}));

  EXPECT_TRUE(select_disclosures(stored, {path({1004})}).empty());
  EXPECT_TRUE(select_disclosures(stored, {}).empty());
}

// An out-of-range element index resolves to nothing and must NOT pull the array
// container (revealing a leaf that does not exist).
TEST(DisclosureStore, OutOfRangeElementSelectsNothing)
{
  const std::vector<StoredDisclosure> stored =
    decode_disclosure_store(encode_disclosure_store({
      disc({1006}, blob(0x06)),
      disc({1006, 0}, blob(0x60)),
      disc({1006, 1}, blob(0x61)),
    }));

  // Element 5 does not exist: no ancestor container, nothing selected.
  EXPECT_TRUE(select_disclosures(stored, {path({1006, 5})}).empty());
}

// A target deeper than anything stored resolves to nothing.
TEST(DisclosureStore, TargetDeeperThanStoredSelectsNothing)
{
  const std::vector<StoredDisclosure> stored = decode_disclosure_store(
    encode_disclosure_store({disc({1001}, blob(0x01))}));

  // {1001} is a scalar with no children; {1001,0} matches nothing.
  EXPECT_TRUE(select_disclosures(stored, {path({1001, 0})}).empty());
}

// Multiple targets select the union.
TEST(DisclosureStore, MultipleTargetsSelectUnion)
{
  const std::vector<StoredDisclosure> stored =
    decode_disclosure_store(encode_disclosure_store({
      disc({1001}, blob(0x01)),
      disc({1003}, blob(0x03)),
      disc({1006}, blob(0x06)),
      disc({1006, 0}, blob(0x60)),
    }));

  const auto picked =
    select_disclosures(stored, {path({1001}), path({1006, 0})});
  ASSERT_EQ(picked.size(), 3u); // {1001}, {1006} (ancestor), {1006,0}
}
