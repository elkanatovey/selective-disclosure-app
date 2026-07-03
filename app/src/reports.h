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
  // Public ledger entry: the redacted, service-signed SD-CWT for a submission.
  // Stored per-transaction and retrieved by transaction id via historical
  // query.
  using StatementTable = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto STATEMENT_TABLE = "public:sd.statement";

  // The app's own signing key (private key PEM). Held in a PRIVATE (encrypted,
  // replicated) table so whichever node is primary can sign. The CCF service
  // identity key is not app-accessible, so the app manages its own issuer key;
  // the receipt (service-identity-signed) independently proves inclusion.
  using SigningKeyTable = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto SIGNING_KEY_TABLE = "sd.signing_key";

  // Clear `iss` carried by every statement: the service identity, not a caller.
  static constexpr auto SERVICE_ISS =
    "https://selective-disclosure.example/service";

  inline ccf::crypto::ECKeyPairPtr load_signing_key(
    const std::vector<uint8_t>& pem_bytes)
  {
    return ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(pem_bytes));
  }

  // Decode a lowercase/uppercase hex string to bytes; std::nullopt if invalid.
  inline std::optional<std::vector<uint8_t>> from_hex(const std::string& s)
  {
    if (s.size() % 2 != 0)
    {
      return std::nullopt;
    }
    const auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2)
    {
      const int hi = nibble(s[i]);
      const int lo = nibble(s[i + 1]);
      if (hi < 0 || lo < 0)
      {
        return std::nullopt;
      }
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
  }
}
