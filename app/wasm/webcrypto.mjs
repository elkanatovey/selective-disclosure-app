// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

export async function validatePresentedToken(
  sdCwt,
  token,
  issuerPublicKey,
  crypto = globalThis.crypto,
) {
  const stableToken = new Uint8Array(token);
  const plan = sdCwt.prepareVerification(stableToken);
  const signatureValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: plan.signatureHash },
    issuerPublicKey,
    plan.signature,
    plan.toBeSigned,
  );
  const disclosureDigests = await Promise.all(
    plan.disclosureHashInputs.map(async (input) =>
      new Uint8Array(
        await crypto.subtle.digest(plan.disclosureHash, input),
      )),
  );
  return sdCwt.finalizeVerification(
    stableToken,
    disclosureDigests,
    signatureValid,
  );
}
