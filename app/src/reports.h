// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/statement.h"

#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/pem.h>
#include <ccf/kv/value.h>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

namespace selectivedisclosure
{
  // Stores the redacted SD-CWT for a submission, per transaction; retrieved by
  // transaction id via historical query.
  using StatementTable = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto STATEMENT_TABLE = "public:sd.statement";

  // The app's issuer signing key (private key PEM), in a PRIVATE (encrypted,
  // replicated) table so whichever node is primary can sign. See DESIGN.md §4
  // for why the app manages its own key rather than the CCF service identity.
  using SigningKeyTable = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto SIGNING_KEY_TABLE = "sd.signing_key";

  // Value written as the clear `iss` claim of every statement.
  static constexpr auto SERVICE_ISS =
    "https://selective-disclosure.example/service";

  inline ccf::crypto::ECKeyPairPtr load_signing_key(
    const std::vector<uint8_t>& pem_bytes)
  {
    return ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(pem_bytes));
  }
}
