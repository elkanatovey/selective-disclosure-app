// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cose.h"

#include "token/cbor.h"

#include <ccf/crypto/curve.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/sha256.h>

namespace sdcwt
{
  std::vector<uint8_t> encode_protected_header(int64_t alg)
  {
    return cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      QCBOREncode_AddInt64ToMapN(&ctx, 1, alg); // COSE header label 1 = alg
      QCBOREncode_CloseMap(&ctx);
    });
  }

  std::vector<uint8_t> sign_cose_sign1_es256(
    const ccf::crypto::ECKeyPair& key,
    std::span<const uint8_t> protected_header_cbor,
    std::span<const uint8_t> payload)
  {
    // RFC 9052 Sig_structure for a COSE_Sign1:
    //   [ "Signature1", protected, external_aad (empty), payload ]
    const auto to_be_signed = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      QCBOREncode_AddSZString(&ctx, "Signature1");
      QCBOREncode_AddBytes(&ctx, to_ubc(protected_header_cbor));
      QCBOREncode_AddBytes(&ctx, UsefulBufC{"", 0}); // external_aad
      QCBOREncode_AddBytes(&ctx, to_ubc(payload));
      QCBOREncode_CloseArray(&ctx);
    });

    const auto digest = ccf::crypto::sha256(to_be_signed);
    const auto der_sig = key.sign_hash(digest.data(), digest.size());
    // COSE requires the raw r||s form, not OpenSSL's DER.
    const auto raw_sig = ccf::crypto::ecdsa_sig_der_to_p1363(
      der_sig, ccf::crypto::CurveID::SECP256R1);

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
