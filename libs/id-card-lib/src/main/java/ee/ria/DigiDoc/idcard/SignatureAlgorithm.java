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

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * The signature algorithm a certificate's key commits the caller to, named the
 * way JWA (RFC 7518) names it — the form Web eID tokens and JWS headers carry.
 *
 * <p>This lives in the library rather than in each calling app on purpose. The
 * algorithm is two decisions that have to agree: which name goes in the token,
 * and which algorithm reference the library puts in {@code MSE:SET} when it
 * signs. Deciding the first in the app and the second in the library — in
 * Kotlin and Swift and Java independently — is how you get a token claiming
 * {@code RS256} signed with an EC algorithm reference, which fails at
 * verification with nothing pointing at the cause. One answer, from the layer
 * that owns the APDUs.
 *
 * <p><b>For EC the certificate settles it; for RSA it cannot.</b> A curve implies
 * its hash, so an EC certificate is a complete answer with no card involved. An
 * RSA key is equally valid with SHA-256, SHA-384 or SHA-512, so the certificate
 * narrows nothing — {@link #forCertificate} returns {@link #RS256} there only as
 * the conventional default.
 *
 * <p>The card can often do better, and {@link Token#signatureAlgorithm(CertificateType, byte[])}
 * asks it: a PKCS#15 algorithm row naming {@code sha256WithRSAEncryption} is the
 * card stating which hash that key signs with, and {@link #forOid} turns it into
 * the matching constant. Where the row names no hash — plain
 * {@code rsaEncryption}, which is what both Latvian cards' authentication keys
 * offer — nobody can derive it, because it is decided by which
 * {@code DigestInfo} the caller builds. The default stands there, and it is a
 * choice rather than a guess.
 */
public enum SignatureAlgorithm {

    /** ECDSA on P-256, SHA-256 — the hash is implied by the curve per JWA. */
    ES256("ES256", "SHA-256"),
    /** ECDSA on P-384, SHA-384. Both EE and LV cards in circulation use this. */
    ES384("ES384", "SHA-384"),
    /** ECDSA on P-521, SHA-512. Note P-521, not a typo for 512 — see RFC 7518. */
    ES512("ES512", "SHA-512"),
    /** RSASSA-PKCS1-v1_5 with SHA-256. */
    RS256("RS256", "SHA-256"),
    /** RSASSA-PKCS1-v1_5 with SHA-384. */
    RS384("RS384", "SHA-384"),
    /** RSASSA-PKCS1-v1_5 with SHA-512. */
    RS512("RS512", "SHA-512");

    /**
     * Every RSA algorithm this library can produce a signature for, which is every
     * one it can build a {@code DigestInfo} for.
     *
     * <p>The answer for a key whose algorithm row names no hash: the card applies
     * {@code m^d mod n} to whatever it is handed, so what fixes the algorithm is the
     * encoding built here, and any of these is as valid as the others. Reported by
     * {@link Token#permittedAlgorithms(CertificateType, byte[])}; which one is
     * actually used is {@link #forRsaKey()}.
     */
    private static final Set<SignatureAlgorithm> RSA_ALGORITHMS =
            Collections.unmodifiableSet(EnumSet.of(RS256, RS384, RS512));

    private final String jwaName;
    private final String digestAlgorithm;

    SignatureAlgorithm(String jwaName, String digestAlgorithm) {
        this.jwaName = jwaName;
        this.digestAlgorithm = digestAlgorithm;
    }

    /** The JWA name, for a JWS header or a Web eID token's algorithm field. */
    public String jwaName() {
        return jwaName;
    }

    /** JCA name of the hash this algorithm signs over, e.g. {@code SHA-384}. */
    public String digestAlgorithm() {
        return digestAlgorithm;
    }

    /** Whether this is one of the RSA algorithms. */
    public boolean isRsa() {
        return jwaName.startsWith("RS");
    }

    /** The digest length in bytes this algorithm signs over. */
    int digestLength() {
        return switch (this) {
            case ES256, RS256 -> 32;
            case ES384, RS384 -> 48;
            case ES512, RS512 -> 64;
        };
    }

    /**
     * The algorithm a PKCS#15 {@code AlgorithmInfo} OID names, or {@code null}
     * when the OID names no hash and so settles nothing.
     *
     * <p>That second case is not unusual and not an error: plain
     * {@code rsaEncryption} and bare {@code ecPublicKey} both mean "this key, over
     * whatever you hand me". Both Latvian cards' authentication keys are like
     * that, so for authentication the hash really is the caller's choice — while
     * their signing keys do name one, and there the card decides.
     */
    static SignatureAlgorithm forOid(String oid) {
        if (oid == null) {
            return null;
        }
        return switch (oid) {
            case "1.2.840.113549.1.1.11" -> RS256;
            case "1.2.840.113549.1.1.12" -> RS384;
            case "1.2.840.113549.1.1.13" -> RS512;
            case "1.2.840.10045.4.3.2" -> ES256;
            case "1.2.840.10045.4.3.3" -> ES384;
            case "1.2.840.10045.4.3.4" -> ES512;
            default -> null;
        };
    }

    /**
     * A fresh {@link MessageDigest} for {@link #digestAlgorithm()}, so callers
     * do not have to map the name themselves.
     */
    public MessageDigest digest() throws SignatureAlgorithmException {
        try {
            return MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            // Only reachable if the platform lacks a SHA-2 variant.
            throw new SignatureAlgorithmException(
                    "No " + digestAlgorithm + " implementation available", e);
        }
    }

    /**
     * The algorithm the key in {@code certificate} must be signed with.
     *
     * <p>For an EC key the curve fixes the hash, so the answer is complete. An
     * RSA key answers {@link #RS256} on an assumption the card has not yet
     * confirmed — see the class documentation.
     *
     * @param certificate DER-encoded X.509 certificate, as returned by
     *                    {@link Token#certificate(CertificateType)}.
     * @throws SignatureAlgorithmException When the certificate does not parse,
     *                                     or its key is one this library cannot
     *                                     sign with.
     */
    public static SignatureAlgorithm forCertificate(byte[] certificate)
            throws SignatureAlgorithmException {
        PublicKey key = publicKey(certificate);
        if (key instanceof ECPublicKey ecKey) {
            return forEcKey(ecKey);
        }
        if ("RSA".equals(key.getAlgorithm())) {
            return forRsaKey();
        }
        throw new SignatureAlgorithmException(
                "Cannot sign with a " + key.getAlgorithm() + " key: this library has no "
                        + key.getAlgorithm() + " algorithm reference for MSE:SET. Only"
                        + " EC and RSA keys are supported.");
    }

    /**
     * An EC key settles it on its own: JWA ties each curve to one hash, so there is
     * nothing left to ask the card.
     *
     * <p>Selected on the order's bit length rather than a nominal key size, because
     * the order is what distinguishes P-521 from anything calling itself 512.
     */
    private static SignatureAlgorithm forEcKey(ECPublicKey key)
            throws SignatureAlgorithmException {
        int bits = key.getParams().getOrder().bitLength();
        return switch (bits) {
            case 256 -> ES256;
            case 384 -> ES384;
            case 521 -> ES512;
            default -> throw new SignatureAlgorithmException(
                    "Unsupported EC curve: order is " + bits + " bits, expected 256, 384"
                            + " or 521");
        };
    }

    /**
     * An RSA key settles nothing, so this is the conventional default and not an
     * answer: {@link #RS256} for a 2048-bit key whose certificate is signed
     * {@code sha256WithRSAEncryption}.
     *
     * <p>A token that can ask the card refines it per key — see
     * {@link Token#signatureAlgorithm(CertificateType, byte[])} — and keeps this only
     * when that key's algorithm row names no hash either. Nothing on the card
     * constrains the choice there: the {@code DigestInfo} is built host-side from the
     * digest handed in, so RS384 would be just as self-consistent and would verify
     * just as well.
     *
     * <p>The library nonetheless fixes it at RS256 rather than offering the choice,
     * because the choice cannot be made twice. Whatever is reported here is what
     * {@code Idemia} then requires the digest length to match, so a caller free to
     * hash with SHA-384 while the token still said RS256 would produce a signature
     * whose stated algorithm is wrong. RS256 for such a key is therefore this
     * library's answer, not the card's — {@code DigestLengthGuardTest} pins it.
     *
     * <p>Package-visible because {@code Idemia} checks digest lengths against this
     * same choice: if the two disagreed, the library would report one algorithm and
     * sign another, which is precisely the mismatch the check exists to prevent.
     */
    static SignatureAlgorithm forRsaKey() {
        return RS256;
    }

    /** See {@link #RSA_ALGORITHMS}. */
    static Set<SignatureAlgorithm> rsaAlgorithms() {
        return RSA_ALGORITHMS;
    }

    /**
     * The one-element answer for a key whose algorithm is settled, as an
     * {@link EnumSet} rather than {@code Set.of}.
     *
     * <p>The difference is not visible in a single-element set, which is the point of
     * having this: every set
     * {@link Token#permittedAlgorithms(CertificateType, byte[])} returns is built here
     * or from {@link #RSA_ALGORITHMS}, so its documented iteration order holds by
     * construction. {@code Set.of} leaves iteration order unspecified, so a later
     * two-element {@code Set.of} would break that promise without anything failing.
     */
    static Set<SignatureAlgorithm> only(SignatureAlgorithm algorithm) {
        return Collections.unmodifiableSet(EnumSet.of(algorithm));
    }

    private static PublicKey publicKey(byte[] certificate) throws SignatureAlgorithmException {
        if (certificate == null || certificate.length == 0) {
            throw new SignatureAlgorithmException(
                    "Cannot determine a signature algorithm without a certificate");
        }
        try {
            X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificate));
            return x509.getPublicKey();
        } catch (Exception e) {
            throw new SignatureAlgorithmException(
                    "Could not read the public key out of the certificate", e);
        }
    }
}
