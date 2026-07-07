// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/statement.h"

#include <span>

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
}
