// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cose.h"

#include "token/cbor.h"

#include <ccf/crypto/curve.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/hash_provider.h>
#include <stdexcept>

namespace sdcwt
{
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

  std::vector<uint8_t> encode_protected_header(int64_t alg)
  {
    return cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      QCBOREncode_AddInt64ToMapN(&ctx, 1, alg); // COSE header label 1 = alg
      QCBOREncode_CloseMap(&ctx);
    });
  }

  std::vector<uint8_t> sign_cose_sign1(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> external_aad)
  {
    // Derive the digest from the key's curve; an unsupported curve throws here
    // (before any signing) rather than emitting a malformed signature.
    const auto curve = key.get_curve_id();
    cose_es_alg_for_curve(curve); // validates the curve
    const auto md = ccf::crypto::get_md_for_ec(curve);

    // RFC 9052 Sig_structure for a COSE_Sign1:
    //   [ "Signature1", protected, external_aad, payload ]
    const auto to_be_signed = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      QCBOREncode_AddSZString(&ctx, "Signature1");
      QCBOREncode_AddBytes(&ctx, to_ubc(protected_header_cbor));
      QCBOREncode_AddBytes(&ctx, to_ubc(external_aad));
      QCBOREncode_AddBytes(&ctx, to_ubc(payload));
      QCBOREncode_CloseArray(&ctx);
    });

    const auto digest = ccf::crypto::make_hash_provider()->hash(
      to_be_signed.data(), to_be_signed.size(), md);
    const auto der_sig = key.sign_hash(digest.data(), digest.size());
    // COSE requires the raw r||s form, not OpenSSL's DER.
    const auto raw_sig = ccf::crypto::ecdsa_sig_der_to_p1363(der_sig, curve);

    // COSE_Sign1 = 18([ protected, unprotected {}, payload, signature ]).
    return cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_AddTag(&ctx, 18);
      QCBOREncode_OpenArray(&ctx);
      QCBOREncode_AddBytes(&ctx, to_ubc(protected_header_cbor));
      QCBOREncode_OpenMap(&ctx); // empty unprotected header
      QCBOREncode_CloseMap(&ctx);
      QCBOREncode_AddBytes(&ctx, to_ubc(payload));
      QCBOREncode_AddBytes(&ctx, to_ubc(raw_sig));
      QCBOREncode_CloseArray(&ctx);
    });
  }
}
