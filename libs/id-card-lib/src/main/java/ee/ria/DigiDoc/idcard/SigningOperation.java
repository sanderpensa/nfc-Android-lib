/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package ee.ria.DigiDoc.idcard;

/**
 * The three things this library asks a card's private keys to do, and what each
 * needs in order to ask.
 *
 * <p>They are separated because a key answers differently per operation. The 2020
 * Latvian card's authentication key offers two algorithm rows — raw RSA for
 * signing and a decipher-only row — so "the algorithm for this key" is not a
 * well-formed question; only "the algorithm for this key <em>and this
 * operation</em>" is. Filtering on the wrong one would quietly pick the decipher
 * row to sign with.
 */
enum SigningOperation {

    /** Signing an authentication challenge: {@code MSE:SET AT}, then {@code INTERNAL AUTHENTICATE}. */
    AUTHENTICATE(Idemia.AppletContext.OBERTHUR, CertificateType.AUTHENTICATION,
            Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE, 0xA4),

    /** Signing a document hash: {@code MSE:SET DST}, then {@code PSO: COMPUTE DIGITAL SIGNATURE}. */
    SIGN(Idemia.AppletContext.QSCD, CertificateType.SIGNING,
            Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE, 0xB6),

    /**
     * Decipher: {@code MSE:SET CT}, then {@code PSO: DECIPHER}.
     *
     * <p>Accepts either operation bit, because the two key types advertise this
     * differently and requiring only one of them excludes a whole family. An RSA
     * key offers {@code decipher} — the 2020 Latvian card's row 6 is
     * {@code encipher+decipher+derive-key}. An EC key does the same job by ECDH key
     * agreement and advertises {@code derive-key} alone, which is what the Latvian
     * EC cards' row 13 says. Requiring {@code decipher} by itself meant decrypt
     * could never resolve on an EC card at all.
     *
     * <p><b>This mask does not identify the row on its own.</b> Every signing row
     * on every captured table also advertises {@code derive-key}, so this mask
     * matches all of them and the row has to be chosen by what it does <em>not</em>
     * advertise — see the preference in {@code Idemia.firstUsableEnvironment}.
     * Reading this mask as "the decipher row" is the mistake that once staged the
     * authentication reference for decryption.
     */
    DECRYPT(Idemia.AppletContext.OBERTHUR, CertificateType.AUTHENTICATION,
            Pkcs15SecurityEnvironment.OPERATION_DECIPHER
                    | Pkcs15SecurityEnvironment.OPERATION_DERIVE_KEY, 0xB8);

    /**
     * The signing operation a certificate's key performs.
     *
     * <p>{@link #DECRYPT} also uses the authentication key, so it cannot be found by
     * certificate type alone — this returns the operation that <em>signs</em> with
     * that key, which is what naming an algorithm is about.
     */
    static SigningOperation signingWith(CertificateType type) {
        return type == CertificateType.SIGNING ? SIGN : AUTHENTICATE;
    }

    /** The applet whose key directory describes the key this operation uses. */
    final Idemia.AppletContext context;
    /** The certificate whose key this operation drives — decrypt shares the auth key. */
    final CertificateType certificateType;
    /** Which {@code supportedOperations} bit a usable algorithm row must have. */
    final int operationMask;
    /** {@code P2} of the {@code MSE:SET} that stages this operation. */
    final int mseSetP2;

    SigningOperation(Idemia.AppletContext context, CertificateType certificateType,
                     int operationMask, int mseSetP2) {
        this.context = context;
        this.certificateType = certificateType;
        this.operationMask = operationMask;
        this.mseSetP2 = mseSetP2;
    }
}
