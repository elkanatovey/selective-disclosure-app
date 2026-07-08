// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/statement.h"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace selectivedisclosure
{
  // Decode a report/follow-up submission CBOR map into statement Fields. The
  // map is keyed by field name (decoupled from the internal claim numbers) with
  // native CBOR types: title/body/component/severity/patch (tstr),
  // fingerprint (bstr), references ([tstr]), patch_date (int). All fields are
  // optional; unknown keys are ignored. `parent` is never taken from the body
  // (it is derived server-side for follow-ups).
  //
  // Throws std::invalid_argument on a non-map body, malformed CBOR, or a field
  // with the wrong type.
  sdcwt::statement::Fields parse_report_fields(std::span<const uint8_t> cbor);

  // Map a submission/disclosure field name to its statement claim id, or
  // nullopt if the name is not a content field. This is the single source of
  // truth for the name<->id mapping shared by submission parsing and Operator
  // disclosure. Includes `parent` (disclosable though never submitted).
  std::optional<int64_t> content_field_id(std::string_view name);

  // One entry of an Operator disclosure request: a top-level content field name
  // plus optional deeper array indices addressing a nested element. E.g. the
  // request entry `"title"` -> {"title", {}}; `["references", 0]` ->
  // {"references", {0}}.
  struct FieldPath
  {
    std::string name;
    std::vector<int64_t> indices;
  };

  // Decode an Operator disclosure request `{"fields": [ entry, ... ]}` where
  // each entry is either a field name (tstr) or a path array `[name, idx, ...]`
  // (a tstr followed by integer array indices). Returns the requested paths in
  // request order. Throws std::invalid_argument on a non-map body, a
  // missing/!array `fields`, or a malformed entry.
  std::vector<FieldPath> parse_disclosure_selection(
    std::span<const uint8_t> cbor);
}
