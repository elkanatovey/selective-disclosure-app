// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <ccf/crypto/ec_key_pair.h>
#include <cstdint>
#include <span>
#include <vector>

namespace sdcwt
{
  // COSE algorithm identifier for ECDSA w/ SHA-256 (RFC 9053).
  inline constexpr int64_t COSE_ALG_ES256 = -7;

  // Encode a minimal protected-header map {1: alg}. Extended later with the
  // SD-CWT `sd_alg` (170) and `typ` (16) headers.
  std::vector<uint8_t> encode_protected_header(int64_t alg = COSE_ALG_ES256);

  // Build and sign a tagged COSE_Sign1 (CBOR tag 18) over `payload`, using the
  // already-CBOR-encoded protected-header bytes and an ES256 (P-256) key.
  //
  // The signature is computed over the RFC 9052 Sig_structure and encoded as a
  // fixed-length r||s (IEEE P1363) value, as COSE requires.
  //
  // Throws std::invalid_argument if `key` is not a P-256 key, or
  // std::runtime_error on a CBOR encoding failure. Callers running inside a CCF
  // endpoint handler MUST catch these so malformed input cannot crash the
  // enclave transaction.
  std::vector<uint8_t> sign_cose_sign1_es256(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload);
}
