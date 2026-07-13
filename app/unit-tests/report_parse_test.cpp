// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "report_parse.h"

#include "cbor.h"

#include <functional>
#include <gtest/gtest.h>
#include <stdexcept>

using selectivedisclosure::parse_report_fields;

namespace
{
  // Encode a submission CBOR map for the tests, mirroring what a client sends.
  std::vector<uint8_t> body(const std::function<void(QCBOREncodeContext&)>& add)
  {
    return sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      add(ctx);
      QCBOREncode_CloseMap(&ctx);
    });
  }
}

// A full, well-typed CBOR submission maps onto Fields with native types.
TEST(ReportParse, DecodesAllFields)
{
  const std::vector<uint8_t> fp = {0xde, 0xad, 0xbe, 0xef};
  const auto cbor = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_AddSZStringToMap(&ctx, "title", "heap overflow");
    QCBOREncode_AddSZStringToMap(&ctx, "body", "details");
    QCBOREncode_AddSZStringToMap(&ctx, "component", "parser");
    QCBOREncode_AddSZStringToMap(&ctx, "severity", "high");
    QCBOREncode_AddSZStringToMap(&ctx, "patch", "fixed");
    QCBOREncode_AddBytesToMap(&ctx, "fingerprint", sdcwt::to_ubc(fp));
    QCBOREncode_OpenArrayInMap(&ctx, "references");
    QCBOREncode_AddSZString(&ctx, "CVE-2025-1");
    QCBOREncode_AddSZString(&ctx, "CVE-2025-2");
    QCBOREncode_CloseArray(&ctx);
    QCBOREncode_AddInt64ToMap(&ctx, "patch_date", 1700100000);
  });

  const auto f = parse_report_fields(cbor);
  EXPECT_EQ(f.title, "heap overflow");
  EXPECT_EQ(f.body, "details");
  EXPECT_EQ(f.component, "parser");
  EXPECT_EQ(f.severity, "high");
  EXPECT_EQ(f.patch, "fixed");
  ASSERT_TRUE(f.fingerprint.has_value());
  EXPECT_EQ(*f.fingerprint, fp);
  ASSERT_TRUE(f.references.has_value());
  EXPECT_EQ(
    *f.references, (std::vector<std::string>{"CVE-2025-1", "CVE-2025-2"}));
  EXPECT_EQ(f.patch_date, 1700100000);
}

// All fields are optional: an empty map yields an all-empty Fields.
TEST(ReportParse, MissingFieldsAreNullopt)
{
  const auto cbor = body([](QCBOREncodeContext&) {});
  const auto f = parse_report_fields(cbor);
  EXPECT_FALSE(f.title.has_value());
  EXPECT_FALSE(f.fingerprint.has_value());
  EXPECT_FALSE(f.references.has_value());
  EXPECT_FALSE(f.patch_date.has_value());
}

// fingerprint is a native byte string, not hex text.
TEST(ReportParse, FingerprintIsBytes)
{
  const std::vector<uint8_t> fp = {0x00, 0x01, 0x02, 0xff};
  const auto cbor = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_AddBytesToMap(&ctx, "fingerprint", sdcwt::to_ubc(fp));
  });
  const auto f = parse_report_fields(cbor);
  ASSERT_TRUE(f.fingerprint.has_value());
  EXPECT_EQ(*f.fingerprint, fp);
}

// A wrong-typed field is rejected (title as int, not text).
TEST(ReportParse, WrongFieldTypeThrows)
{
  const auto cbor = body([](QCBOREncodeContext& ctx) {
    QCBOREncode_AddInt64ToMap(&ctx, "title", 42);
  });
  EXPECT_THROW(parse_report_fields(cbor), std::invalid_argument);
}

// A non-map body is rejected.
TEST(ReportParse, NonMapBodyThrows)
{
  const auto cbor = sdcwt::cbor_encode([](QCBOREncodeContext& ctx) {
    QCBOREncode_AddSZString(&ctx, "not a map");
  });
  EXPECT_THROW(parse_report_fields(cbor), std::invalid_argument);
}

// references with a non-string element is rejected.
TEST(ReportParse, ReferencesMustBeStrings)
{
  const auto cbor = body([](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArrayInMap(&ctx, "references");
    QCBOREncode_AddInt64(&ctx, 7);
    QCBOREncode_CloseArray(&ctx);
  });
  EXPECT_THROW(parse_report_fields(cbor), std::invalid_argument);
}

// --- content_field_id: the name<->id source of truth ----------------------
TEST(ContentFieldId, MapsEveryContentField)
{
  using selectivedisclosure::content_field_id;
  namespace st = sdcwt::statement;
  EXPECT_EQ(content_field_id("parent"), st::PARENT);
  EXPECT_EQ(content_field_id("title"), st::TITLE);
  EXPECT_EQ(content_field_id("body"), st::BODY);
  EXPECT_EQ(content_field_id("component"), st::COMPONENT);
  EXPECT_EQ(content_field_id("severity"), st::SEVERITY);
  EXPECT_EQ(content_field_id("fingerprint"), st::FINGERPRINT);
  EXPECT_EQ(content_field_id("references"), st::REFERENCES);
  EXPECT_EQ(content_field_id("patch"), st::PATCH);
  EXPECT_EQ(content_field_id("patch_date"), st::PATCH_DATE);
}

TEST(ContentFieldId, RejectsUnknownName)
{
  using selectivedisclosure::content_field_id;
  EXPECT_FALSE(content_field_id("nope").has_value());
  EXPECT_FALSE(content_field_id("iss").has_value());
  EXPECT_FALSE(content_field_id("").has_value());
}

// --- parse_disclosure_selection: the Operator disclosure request ----------
TEST(FieldSelection, ParsesBareNames)
{
  using selectivedisclosure::parse_disclosure_selection;
  const auto req = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArrayInMap(&ctx, "fields");
    QCBOREncode_AddSZString(&ctx, "title");
    QCBOREncode_AddSZString(&ctx, "component");
    QCBOREncode_CloseArray(&ctx);
  });
  const auto sel = parse_disclosure_selection(req);
  ASSERT_EQ(sel.size(), 2u);
  EXPECT_EQ(sel[0].name, "title");
  EXPECT_TRUE(sel[0].indices.empty());
  EXPECT_EQ(sel[1].name, "component");
}

TEST(FieldSelection, ParsesNestedPath)
{
  using selectivedisclosure::parse_disclosure_selection;
  const auto req = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArrayInMap(&ctx, "fields");
    QCBOREncode_AddSZString(&ctx, "title"); // bare name
    QCBOREncode_OpenArray(&ctx); // ["references", 2]
    QCBOREncode_AddSZString(&ctx, "references");
    QCBOREncode_AddInt64(&ctx, 2);
    QCBOREncode_CloseArray(&ctx);
    QCBOREncode_CloseArray(&ctx);
  });
  const auto sel = parse_disclosure_selection(req);
  ASSERT_EQ(sel.size(), 2u);
  EXPECT_EQ(sel[0].name, "title");
  EXPECT_TRUE(sel[0].indices.empty());
  EXPECT_EQ(sel[1].name, "references");
  ASSERT_EQ(sel[1].indices.size(), 1u);
  EXPECT_EQ(sel[1].indices[0], 2);
}

TEST(FieldSelection, ParsesEmptyFieldsArray)
{
  using selectivedisclosure::parse_disclosure_selection;
  const auto req = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArrayInMap(&ctx, "fields");
    QCBOREncode_CloseArray(&ctx);
  });
  EXPECT_TRUE(parse_disclosure_selection(req).empty());
}

TEST(FieldSelection, RejectsMissingFields)
{
  using selectivedisclosure::parse_disclosure_selection;
  const auto req = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_AddSZStringToMap(&ctx, "other", "x");
  });
  EXPECT_THROW(parse_disclosure_selection(req), std::invalid_argument);
}

TEST(FieldSelection, RejectsBareIntEntry)
{
  using selectivedisclosure::parse_disclosure_selection;
  const auto req = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArrayInMap(&ctx, "fields");
    QCBOREncode_AddInt64(&ctx, 7);
    QCBOREncode_CloseArray(&ctx);
  });
  EXPECT_THROW(parse_disclosure_selection(req), std::invalid_argument);
}

TEST(FieldSelection, RejectsPathWithoutName)
{
  using selectivedisclosure::parse_disclosure_selection;
  const auto req = body([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArrayInMap(&ctx, "fields");
    QCBOREncode_OpenArray(&ctx); // [0] — index without a leading name
    QCBOREncode_AddInt64(&ctx, 0);
    QCBOREncode_CloseArray(&ctx);
    QCBOREncode_CloseArray(&ctx);
  });
  EXPECT_THROW(parse_disclosure_selection(req), std::invalid_argument);
}
