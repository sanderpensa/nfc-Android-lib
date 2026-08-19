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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Checks that a signature the card produced actually verifies under the
 * certificate's public key.
 *
 * <p>This is the last place a wrong {@code MSE:SET} can be caught locally. Since
 * Latvian cards read their algorithm and key references from the card and refuse to
 * guess, the remaining way to get a wrong one is for the card to describe itself
 * incorrectly — which has been observed: the 2020 Latvian card's algorithm table
 * gives rows for SHA-256, SHA-384 and SHA-512 the <em>same</em> {@code algRef}
 * ({@code 0x42}), so a key referencing the SHA-384 row would be named RS384 while
 * the card encoded SHA-256. Every other guard passes that case; only verifying the
 * result catches it.
 *
 * <p>Without this, such a signature is returned looking healthy and rejected by the
 * relying party with nothing to point at. Establishing that a signature was in fact
 * well formed took an offline exercise with the card's public key on 2026-08-19;
 * this does the same thing in microseconds, on the phone.
 *
 * <p><b>What it does not cover.</b> Only authentication. {@code calculateSignature}
 * is not given a certificate and reading one would cost 0.9–1.3 s — the signing
 * certificate is the largest file on the card — which is more than the resolution it
 * would be guarding. See {@code CARD_VARIANTS.md} §8.4.
 *
 * <p>This class reports and does not decide. Whether a mismatch is fatal depends on
 * where the environment came from, which is the caller's knowledge: see
 * {@code Idemia.verifySignature}. Being unable to check — no certificate, an
 * unparseable one, a JCA provider without the algorithm — is never fatal, because it
 * may not turn a tap that would have worked into one that fails.
 */
final class SignatureVerifier {

    private SignatureVerifier() {}

    /** What a verification attempt established. */
    enum Result {
        /** Checked, and the signature verifies under the certificate. */
        MATCHED,
        /** Checked, and it does not. The card did not sign what it said it would. */
        MISMATCHED,
        /**
         * Could not be checked at all — no certificate, one that will not parse, a
         * JCA provider without the algorithm, or a signature of an impossible shape.
         * Says nothing either way about the signature.
         */
        NOT_CHECKED
    }

    /**
     * Verifies {@code signature} over the bytes that were actually sent to the
     * card.
     *
     * @param certificate DER certificate of the key that signed, or {@code null} to
     *                    skip the check.
     * @param environment The environment the operation ran under, which says whether
     *                    the key is RSA and whether the DigestInfo was built here.
     * @param inputSent   The command data as it went out — already padded or wrapped.
     * @param signature   What the card answered.
     */
    static Result verify(byte[] certificate, SecurityEnvironment environment,
                         byte[] inputSent, byte[] signature) {
        if (certificate == null || signature == null || signature.length == 0) {
            return Result.NOT_CHECKED;
        }
        PublicKey key;
        try {
            key = ((X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificate))).getPublicKey();
        } catch (Exception e) {
            return Result.NOT_CHECKED;
        }

        Boolean matched = environment.isRsa()
                ? verifyRsa(key, environment, inputSent, signature)
                : verifyEcdsa(key, inputSent, signature);
        if (matched == null) {
            return Result.NOT_CHECKED;
        }
        return matched ? Result.MATCHED : Result.MISMATCHED;
    }

    /**
     * RSASSA-PKCS1-v1_5 by hand: recover the block with the public exponent and
     * compare it to the encoding that should have been signed.
     *
     * <p>Done this way rather than through {@code Signature} because the card is
     * handed a digest, not a message, so there is nothing for a
     * {@code SHA256withRSA} verifier to hash.
     */
    private static Boolean verifyRsa(PublicKey key, SecurityEnvironment environment,
                                     byte[] inputSent, byte[] signature) {
        if (!(key instanceof RSAPublicKey rsa)) {
            return null;
        }
        try {
            byte[] expectedPayload = environment.needsHostDigestInfo()
                    // The DigestInfo was built here, so it is what the card padded.
                    ? inputSent
                    // The card built the DigestInfo around the bare digest.
                    : DigestInfo.wrap(inputSent);

            byte[] recovered = new BigInteger(1, signature)
                    .modPow(rsa.getPublicExponent(), rsa.getModulus()).toByteArray();
            int modulusBytes = (rsa.getModulus().bitLength() + 7) / 8;
            byte[] block = leftPad(recovered, modulusBytes);

            byte[] expected = pkcs1Block(expectedPayload, modulusBytes);
            return expected != null && Arrays.equals(block, expected);
        } catch (Exception e) {
            return null;
        }
    }

    /** {@code 00 01 FF..FF 00 || payload}, the EMSA-PKCS1-v1_5 encoding. */
    private static byte[] pkcs1Block(byte[] payload, int modulusBytes) {
        // At least eight padding bytes are required, per RFC 8017.
        if (payload.length + 11 > modulusBytes) {
            return null;
        }
        byte[] block = new byte[modulusBytes];
        block[0] = 0x00;
        block[1] = 0x01;
        int padTo = modulusBytes - payload.length - 1;
        Arrays.fill(block, 2, padTo, (byte) 0xFF);
        block[padTo] = 0x00;
        System.arraycopy(payload, 0, block, padTo + 1, payload.length);
        return block;
    }

    private static byte[] leftPad(byte[] value, int length) {
        if (value.length == length) {
            return value;
        }
        if (value.length > length) {
            // BigInteger may prepend a sign byte.
            return Arrays.copyOfRange(value, value.length - length, value.length);
        }
        byte[] padded = new byte[length];
        System.arraycopy(value, 0, padded, length - value.length, value.length);
        return padded;
    }

    /**
     * The card returns ECDSA as a bare {@code r || s}; JCA wants the DER SEQUENCE,
     * and {@code NONEwithECDSA} because the input is already a digest.
     */
    private static Boolean verifyEcdsa(PublicKey key, byte[] inputSent, byte[] signature) {
        if (signature.length % 2 != 0) {
            return null;
        }
        try {
            int half = signature.length / 2;
            byte[] der = new DERSequence(new ASN1Integer[] {
                    new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(signature, 0, half))),
                    new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(signature, half,
                            signature.length)))}).getEncoded();

            Signature verifier = Signature.getInstance("NONEwithECDSA");
            verifier.initVerify(key);
            verifier.update(inputSent);
            return verifier.verify(der);
        } catch (Exception e) {
            // No such algorithm on this platform, or a malformed signature: cannot
            // check, so do not claim a mismatch.
            return null;
        }
    }
}
