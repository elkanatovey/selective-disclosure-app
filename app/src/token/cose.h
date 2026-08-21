// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

#if !defined(SDCWT_PORTABLE)
#  include <ccf/crypto/ec_key_pair.h>
#endif

namespace sdcwt
{
  // COSE ECDSA signing algorithm identifiers (RFC 9053).
  inline constexpr int64_t COSE_ALG_ES256 = -7;
  inline constexpr int64_t COSE_ALG_ES384 = -35;
  inline constexpr int64_t COSE_ALG_ES512 = -36;

  // COSE Elliptic Curve identifiers (RFC 9053, "COSE Elliptic Curves").
  inline constexpr int64_t COSE_CRV_P256 = 1;
  inline constexpr int64_t COSE_CRV_P384 = 2;
  inline constexpr int64_t COSE_CRV_P521 = 3;

  // Encode a minimal protected-header map {1: alg}. Extended by the SD-CWT
  // layer with the `sd_alg` (170) and `typ` (16) headers.
  std::vector<uint8_t> encode_protected_header(int64_t alg = COSE_ALG_ES256);

  // Build the RFC 9052 Sig_structure bytes for asynchronous signing.
  std::vector<uint8_t> prepare_cose_sign1_signature(
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad = {});

  // Assemble a COSE_Sign1 from a raw IEEE P1363 signature returned by
  // WebCrypto or the native CCF signer.
  std::vector<uint8_t> finalize_cose_sign1_signature(
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature);

#if !defined(SDCWT_PORTABLE)
  int64_t cose_es_alg_for_curve(ccf::crypto::CurveID curve);
  int64_t cose_ec_curve_id(ccf::crypto::CurveID curve);

  // Build and sign a tagged COSE_Sign1 (CBOR tag 18) over `payload`, using the
  // already-CBOR-encoded protected-header bytes and an ECDSA key. The signing
  // algorithm and message digest are derived from the key's curve (P-256 ->
  // ES256/SHA-256, P-384 -> ES384/SHA-384, P-521 -> ES512/SHA-512), so the
  // caller must ensure the protected header advertises the matching `alg` (the
  // SD-CWT layer does this via cose_es_alg_for_curve).
  //
  // The signature is computed over the RFC 9052 Sig_structure and encoded as a
  // fixed-length r||s (IEEE P1363) value, as COSE requires. `external_aad` is
  // the COSE externally-supplied data bound into the signature (empty by
  // default).
  //
  // Throws std::invalid_argument for an unsupported curve, or
  // std::runtime_error on a CBOR encoding failure.
  std::vector<uint8_t> sign_cose_sign1(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad = {});
#endif
}
