// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cose.h"

#include "token/cbor_value.h"

#include <stdexcept>

#if !defined(SDCWT_PORTABLE)
#  include <ccf/crypto/curve.h>
#  include <ccf/crypto/ecdsa.h>
#  include <ccf/crypto/hash_provider.h>
#endif

namespace sdcwt
{
#if !defined(SDCWT_PORTABLE)
  int64_t cose_es_alg_for_curve(ccf::crypto::CurveID curve)
  {
    switch (curve)
    {
      case ccf::crypto::CurveID::SECP256R1:
        return COSE_ALG_ES256;
      case ccf::crypto::CurveID::SECP384R1:
        return COSE_ALG_ES384;
      case ccf::crypto::CurveID::SECP521R1:
        return COSE_ALG_ES512;
      case ccf::crypto::CurveID::NONE:
      case ccf::crypto::CurveID::CURVE25519:
      case ccf::crypto::CurveID::X25519:
      default:
        throw std::invalid_argument(
          "unsupported signing curve (expected P-256/P-384/P-521)");
    }
  }

  int64_t cose_ec_curve_id(ccf::crypto::CurveID curve)
  {
    switch (curve)
    {
      case ccf::crypto::CurveID::SECP256R1:
        return COSE_CRV_P256;
      case ccf::crypto::CurveID::SECP384R1:
        return COSE_CRV_P384;
      case ccf::crypto::CurveID::SECP521R1:
        return COSE_CRV_P521;
      case ccf::crypto::CurveID::NONE:
      case ccf::crypto::CurveID::CURVE25519:
      case ccf::crypto::CurveID::X25519:
      default:
        throw std::invalid_argument(
          "unsupported EC curve (expected P-256/P-384/P-521)");
    }
  }
#endif

  std::vector<uint8_t> encode_protected_header(int64_t alg)
  {
    return cbor::serialize(cbor::make_map(
      // COSE header label 1 = alg
      {{cbor::make_signed(1), cbor::make_signed(alg)}}));
  }

  std::vector<uint8_t> prepare_cose_sign1_signature(
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad)
  {
    return cbor::serialize(cbor::make_array(
      {cbor::make_string("Signature1"),
       bytes_value(protected_header_cbor),
       bytes_value(external_aad),
       bytes_value(payload)}));
  }

  std::vector<uint8_t> finalize_cose_sign1_signature(
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature)
  {
    return cbor::serialize(cbor::make_tagged(
      cbor::COSE_SIGN_1_TAG,
      cbor::make_array(
        {bytes_value(protected_header_cbor),
         cbor::make_map({}),
         bytes_value(payload),
         bytes_value(signature)})));
  }

#if !defined(SDCWT_PORTABLE)
  std::vector<uint8_t> sign_cose_sign1(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad)
  {
    // Reject an unsupported curve up front, before any signing.
    const auto curve = key.get_curve_id();
    cose_es_alg_for_curve(curve); // validates the curve
    const auto md = ccf::crypto::get_md_for_ec(curve);

    // RFC 9052 Sig_structure for a COSE_Sign1:
    //   [ "Signature1", protected, external_aad, payload ]
    const auto to_be_signed = prepare_cose_sign1_signature(
      protected_header_cbor, payload, external_aad);

    const auto digest = ccf::crypto::make_hash_provider()->hash(
      to_be_signed.data(), to_be_signed.size(), md);
    const auto der_sig = key.sign_hash(digest.data(), digest.size());
    // COSE requires the raw r||s form, not OpenSSL's DER.
    const auto raw_sig = ccf::crypto::ecdsa_sig_der_to_p1363(der_sig, curve);

    // COSE_Sign1 = 18([ protected, unprotected {}, payload, signature ]).
    return finalize_cose_sign1_signature(
      protected_header_cbor, payload, raw_sig);
  }
#endif
}
