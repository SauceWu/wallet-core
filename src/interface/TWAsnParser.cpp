// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include <TrustWalletCore/TWAsnParser.h>

#include "AsnParser.h"

using namespace TW;

TWData *_Nullable TWAsnParserEcdsaSignatureFromDer(TWData *_Nonnull encoded) {
    const Data& encodedData = *reinterpret_cast<const Data*>(encoded);
    try {
        auto decoded = ASN::AsnParser::ecdsa_signature_from_der(encodedData);
        if (!decoded) {
            return nullptr;
        }
        return TWDataCreateWithBytes((*decoded).data(), (*decoded).size());
    } catch (...) {
        return nullptr;
    }
}
