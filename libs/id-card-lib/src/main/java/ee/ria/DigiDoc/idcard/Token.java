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

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

import java.util.Set;

/**
 * EstEID token interface.
 */
public interface Token {
    /**
     * Identify which card model this token speaks to.
     * <p>
     * Compile-time constant per implementation — no card I/O is performed.
     * Useful for callers that need to branch behavior (e.g. UI labels,
     * country-specific certificate handling) without having to call
     * {@link #personalData()} first or inspect {@link PersonalData#cardType()}.
     *
     * @return Card model.
     */
    CardType cardType();

    /**
     * Read personal information of the cardholder.
     *
     * @return Personal data of the cardholder.
     * @throws SmartCardReaderException When reading failed.
     */
    PersonalData personalData() throws SmartCardReaderException;

    /**
     * Change PIN1/PIN2/PUK code.
     *
     * @param type Code type.
     * @param currentCode Current code.
     * @param newCode New code.
     * @throws SmartCardReaderException When changing failed.
     * @throws CodeVerificationException When current code is wrong.
     */
    void changeCode(CodeType type, byte[] currentCode, byte[] newCode)
            throws SmartCardReaderException;

    /**
     * Unblock PIN1/PIN2 via PUK code and change it to a new value.
     * <p>
     * When PIN1/PIN2 is not blocked yet it will be blocked before unblocking.
     *
     * @param pukCode PUK code.
     * @param type Code type.
     * @param newCode New code.
     * @throws SmartCardReaderException When changing failed.
     * @throws CodeVerificationException When PUK code is wrong.
     */
    void unblockAndChangeCode(byte[] pukCode, CodeType type, byte[] newCode)
            throws SmartCardReaderException;

    int pinChangedFlag(CodeType type) throws SmartCardReaderException;

    /**
     * Read retry counter for PIN1/PIN2/PUK code.
     *
     * @param type Code type.
     * @return Code retry counter.
     */
    int codeRetryCounter(CodeType type) throws SmartCardReaderException;

    /**
     * Read certificate data of the cardholder.
     *
     * @param type Type of the certificate.
     * @return Certificate data.
     * @throws SmartCardReaderException When reading failed.
     */
    byte[] certificate(CertificateType type) throws SmartCardReaderException;

    /**
     * The signature algorithm this token will sign a hash for {@code certificate}
     * with — the JWA name for a token or JWS header, and the hash to compute.
     *
     * <p>Ask this rather than deriving it from the certificate yourself. The
     * name that goes in a token and the algorithm reference this library puts in
     * {@code MSE:SET} are two halves of one decision, and they have to agree;
     * answering here is what keeps them from drifting apart. Pass the bytes
     * {@link #certificate(CertificateType)} already returned.
     *
     * <p><b>Card I/O:</b> none for an EC key — the curve settles it. For an RSA key
     * the certificate settles nothing, so the card is asked which hash that key
     * signs with. That is a PKCS#15 walk — three files and the applet re-select,
     * twelve APDUs, measured at 930–945 ms on a Latvian "TeID2" card — cached for
     * the session, and it leaves the card on the MAIN AID. That is why this
     * declares {@code SmartCardReaderException}.
     *
     * <p>Implementations whose card supports a different set of algorithms
     * override this. The default answers from the certificate alone, which is
     * correct for every card model currently supported.
     *
     * @param type Which of the card's keys this is about. Required because a card's
     *             two keys can name different algorithms — on one Latvian card the
     *             signing key names SHA-256 while the authentication key names no
     *             hash at all — so the certificate bytes alone do not say which
     *             question is being asked.
     * @param certificate DER-encoded certificate of that key, as returned by
     *                    {@link #certificate(CertificateType)}.
     * @return The algorithm to name and the hash to compute.
     * @throws SignatureAlgorithmException When this token cannot sign with that
     *                                     certificate's key.
     */
    default SignatureAlgorithm signatureAlgorithm(CertificateType type, byte[] certificate)
            throws SmartCardReaderException {
        return SignatureAlgorithm.forCertificate(certificate);
    }

    /**
     * Every algorithm this key could sign with, of which
     * {@link #signatureAlgorithm(CertificateType, byte[])} returns the one that will
     * be used. That one is always a member of this set.
     *
     * <p>Usually a single element, and then it is not a choice at all: an EC key is
     * fixed by its curve, and an RSA key whose card names a hash
     * ({@code sha256WithRSAEncryption}) is fixed by the card, which builds the PKCS#1
     * encoding itself.
     *
     * <p>More than one element means the card named no hash for this key — it applies
     * {@code m^d mod n} to whatever it is given, so what fixes the algorithm is the
     * {@code DigestInfo} this library builds, and every member is equally valid. One
     * such key is on record: the authentication key of the 2020 Latvian card, whose
     * row offers only raw {@code rsaEncryption}.
     *
     * <p><b>This is an answer, not a setting.</b> The signing calls take no algorithm
     * argument, so the library uses
     * {@link #signatureAlgorithm(CertificateType, byte[])} regardless of what else is
     * permitted, and requires a digest matching it. Hashing with SHA-384 because
     * RS384 appears here would produce a valid signature labelled RS256 — so it is
     * refused. What this is for is telling you what a key can do, on a card
     * population where that has repeatedly turned out not to follow from the model.
     *
     * <p><b>Overriding:</b> override both this and
     * {@link #signatureAlgorithm(CertificateType, byte[])}, or neither. This default
     * answers in terms of {@code signatureAlgorithm}, and an implementation that knows
     * what a key permits naturally answers {@code signatureAlgorithm} in terms of this
     * — {@code IdemiaWithPace} does — so overriding one alone can close a loop that
     * only shows up as a {@code StackOverflowError} at run time.
     *
     * <p><b>Card I/O:</b> the same as
     * {@link #signatureAlgorithm(CertificateType, byte[])}, and shares its cache, so
     * asking both reads no file twice — it costs two applet selects, not a second
     * walk.
     *
     * <p>For an <b>RSA</b> key, a card that will not describe its own keys raises
     * {@link SecurityEnvironmentException} from here rather than answering. It cannot
     * sign at all — the signing calls raise the same thing — so naming an algorithm
     * for it would be a fiction the caller then hashes for and puts in a token.
     * Failing at the first question is the same outcome two steps earlier, with
     * nothing invented in between.
     *
     * <p>An <b>EC</b> key is answered from the certificate without asking the card, so
     * such a card is not detected here and fails at the signing call instead. That is
     * most Latvian personalisations on record.
     *
     * @param type Which of the card's keys this is about.
     * @param certificate DER-encoded certificate of that key, as returned by
     *                    {@link #certificate(CertificateType)}.
     * @return An unmodifiable, non-empty set, iterating in {@link SignatureAlgorithm}
     *         declaration order — every implementation builds it from an
     *         {@code EnumSet}, which is what makes that true rather than incidental.
     * @throws SignatureAlgorithmException When this token cannot sign with that
     *                                     certificate's key.
     */
    default Set<SignatureAlgorithm> permittedAlgorithms(CertificateType type,
                                                        byte[] certificate)
            throws SmartCardReaderException {
        return SignatureAlgorithm.only(signatureAlgorithm(type, certificate));
    }

    /**
     * Calculate electronic signature with pre-calculated hash.
     *
     * <p>{@code hash} must match the algorithm this key signs with — ask
     * {@link #signatureAlgorithm(CertificateType, byte[])}. A digest of the wrong
     * length for an RSA key is refused before the PIN is verified, so it costs no
     * retry.
     *
     * @param pin2 PIN2 code.
     * @param hash Pre-calculated hash.
     * @param ecc Whether it's a elliptic curve certificate.
     * @return Signed data.
     * @throws SmartCardReaderException When calculating signature failed.
     * @throws SignatureAlgorithmException When the hash does not suit the key.
     * @throws CodeVerificationException When PIN2 code is wrong.
     */
    byte[] calculateSignature(byte[] pin2, byte[] hash, boolean ecc)
            throws SmartCardReaderException;

    /**
     * Signs the authentication token hash
     *
     * <p>Same digest rule as {@link #calculateSignature(byte[], byte[], boolean)}.
     * Additionally, when a certificate for this key has been read in this session,
     * the returned signature is checked against it; a card that signed with
     * something other than what it described raises rather than returning.
     *
     * @param pin1 PIN1 code
     * @param token Authentication token
     * @return authentication token hash signature
     * @throws SmartCardReaderException When signing the token failed
     * @throws SignatureAlgorithmException When the hash does not suit the key, or the
     *                                     signature does not verify under it
     * @throws CodeVerificationException When PIN1 code is wrong
     */
    byte[] authenticate(byte[] pin1, byte[] token)
        throws SmartCardReaderException;

    /**
     * Decrypt data.
     *
     * @param pin1 PIN1 code.
     * @param data Data to decrypt.
     * @param ecc Whether it's a elliptic curve certificate.
     *
     * @return Decrypt result.
     * @throws SmartCardReaderException When decrypting failed.
     * @throws CodeVerificationException When PIN1 code is wrong.
     */
    byte[] decrypt(byte[] pin1, byte[] data, boolean ecc) throws SmartCardReaderException;
}
