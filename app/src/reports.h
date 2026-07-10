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

  // The confidential store: the submission's disclosures (the encoded
  // `[salt, value, key]` openings for every redacted field), in a PRIVATE
  // (encrypted) per-transaction table. Written once on submit and never read on
  // the submit path (segregation invariant, DESIGN.md s8) — read only by the
  // Operator egress path to produce duplicate-proofs. The service currently
  // always retains these openings; an Operator-self-custody mode (not storing
  // them here, a.k.a. `store_unredacted` OFF) is deferred hardening (DESIGN §12).
  using DisclosureTable = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto DISCLOSURE_TABLE = "sd.disclosures";

  // The app's issuer signing key (private key PEM), in a PRIVATE (encrypted,
  // replicated) table so whichever node is primary can sign. See DESIGN.md §4
  // for why the app manages its own key rather than the CCF service identity.
  using SigningKeyTable = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto SIGNING_KEY_TABLE = "sd.signing_key";

  // The issuer PUBLIC key(s), written on registration so the transaction's
  // receipt (claims digest = hash(pubkey)) endorses the key against the service
  // identity (DESIGN.md §4/§12). Public + seqno-indexed so GET /signing-key can
  // return the registration receipt; rotation appends new writes.
  using SigningKeyHistory = ccf::kv::Value<std::vector<uint8_t>>;
  static constexpr auto SIGNING_KEY_HISTORY = "public:sd.signing_key_history";

  // Value written as the clear `iss` claim of every statement.
  static constexpr auto SERVICE_ISS =
    "https://selective-disclosure.example/service";

  inline ccf::crypto::ECKeyPairPtr load_signing_key(
    const std::vector<uint8_t>& pem_bytes)
  {
    return ccf::crypto::make_ec_key_pair(ccf::crypto::Pem(pem_bytes));
  }
}
