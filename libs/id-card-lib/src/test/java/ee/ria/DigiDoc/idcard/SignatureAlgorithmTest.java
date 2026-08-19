package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/**
 * Which algorithm a certificate's key commits us to, and — as much the point —
 * which keys are refused.
 *
 * <p>The keys here are generated rather than captured. What is being tested is
 * the mapping, and a synthetic key exercises it exactly as a card's does, while
 * a captured certificate would drag a real cardholder's name and personal code
 * into the assertions. Real-card coverage of the P-384 case already exists in
 * {@link LatviaIdemiaSeIdSessionReplayTest}, which verifies a captured signature
 * against its captured certificate.
 */
public final class SignatureAlgorithmTest {

    @ParameterizedTest(name = "{0} → {1}")
    @CsvSource({
            "secp256r1, ES256, SHA-256",
            "secp384r1, ES384, SHA-384",
            "secp521r1, ES512, SHA-512",
    })
    public void forCertificate_namesTheAlgorithmTheCurveImplies(
            String curve, String expectedJwa, String expectedDigest) throws Exception {
        SignatureAlgorithm algorithm =
                SignatureAlgorithm.forCertificate(certificateWithEcKey(curve));

        assertThat(algorithm.jwaName()).isEqualTo(expectedJwa);
        assertThat(algorithm.digestAlgorithm()).isEqualTo(expectedDigest);
        // The digest has to be usable, not just named: callers hash with it.
        assertThat(algorithm.digest().getDigestLength() * 8)
                .isEqualTo(Integer.parseInt(expectedDigest.substring("SHA-".length())));
    }

    /**
     * From the certificate alone an RSA key gets the conventional default, because
     * RSA-2048 is equally valid with RS384 or RS512 and nothing in the certificate
     * narrows it. A token that can ask the card refines this — see
     * {@code IdemiaWithPace.signatureAlgorithm} — so what is pinned here is the
     * card-free answer, not the final one.
     */
    @Test
    public void forCertificate_rsaKey_defaultsToRs256WithoutACard() throws Exception {
        SignatureAlgorithm algorithm =
                SignatureAlgorithm.forCertificate(certificateWithRsaKey());

        assertThat(algorithm).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(algorithm.jwaName()).isEqualTo("RS256");
        assertThat(algorithm.digestAlgorithm()).isEqualTo("SHA-256");
    }

    /**
     * A key that is neither EC nor RSA still has no answer, and the message has
     * to name the key type: "unsupported algorithm" alone sent the last
     * investigation looking at the certificate read instead.
     */
    @Test
    public void forCertificate_nonEcNonRsaKey_isRefusedByName() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(1024);
        byte[] certificate =
                selfSignedCertificate(generator.generateKeyPair(), "SHA256withDSA");

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> SignatureAlgorithm.forCertificate(certificate));

        assertThat(thrown).hasMessageThat().contains("DSA");
        assertThat(thrown).hasMessageThat().contains("MSE:SET");
    }

    /**
     * The mapping that lets a card name its own algorithm instead of us assuming
     * one. A PKCS#15 algorithm row carries the OID; these are the six that settle
     * the question.
     */
    @ParameterizedTest(name = "{0} → {1}")
    @CsvSource({
            "1.2.840.113549.1.1.11, RS256",
            "1.2.840.113549.1.1.12, RS384",
            "1.2.840.113549.1.1.13, RS512",
            "1.2.840.10045.4.3.2,   ES256",
            "1.2.840.10045.4.3.3,   ES384",
            "1.2.840.10045.4.3.4,   ES512",
    })
    public void forOid_namesTheAlgorithmTheCardDeclares(String oid, String expected) {
        assertThat(SignatureAlgorithm.forOid(oid.trim()))
                .isEqualTo(SignatureAlgorithm.valueOf(expected));
    }

    /**
     * An OID naming no hash settles nothing, and saying so is the point: plain
     * {@code rsaEncryption} and bare {@code ecPublicKey} mean "this key, over
     * whatever you hand me". Both Latvian cards' authentication keys are like
     * that, so {@code null} here is a normal answer rather than a failure — and
     * what stops us reporting a hash the card never named.
     */
    @ParameterizedTest(name = "{0} settles nothing")
    @CsvSource({
            "1.2.840.113549.1.1.1",
            "1.2.840.10045.1.2.1",
            "1.2.840.10045.2.1",
            "1.3.132.1.12",
            "1.2.840.113549.1.1.5",
    })
    public void forOid_anOidThatNamesNoHashYieldsNothing(String oid) {
        assertThat(SignatureAlgorithm.forOid(oid)).isNull();
    }

    @Test
    public void forOid_unknownOrMissingYieldsNothing() {
        assertThat(SignatureAlgorithm.forOid("1.2.3.4")).isNull();
        assertThat(SignatureAlgorithm.forOid(null)).isNull();
    }

    /** The RSA family is distinguishable, since it drives how input is prepared. */
    @Test
    public void isRsa_separatesTheTwoFamilies() {
        assertThat(SignatureAlgorithm.RS256.isRsa()).isTrue();
        assertThat(SignatureAlgorithm.RS512.isRsa()).isTrue();
        assertThat(SignatureAlgorithm.ES384.isRsa()).isFalse();
    }

    /** Digest lengths, which the input-length guard compares against. */
    @Test
    public void digestLengthMatchesTheNamedHash() {
        assertThat(SignatureAlgorithm.RS256.digestLength()).isEqualTo(32);
        assertThat(SignatureAlgorithm.RS384.digestLength()).isEqualTo(48);
        assertThat(SignatureAlgorithm.RS512.digestLength()).isEqualTo(64);
        assertThat(SignatureAlgorithm.ES512.digestLength()).isEqualTo(64);
    }

    /**
     * A curve JWA does not name is refused, not approximated by the size of its
     * order.
     *
     * <p>brainpoolP256r1 and secp256k1 both have 256-bit orders and neither is
     * P-256. Labelling either ES256 produces a token that verifies nowhere — the
     * same failure as a wrong algorithm reference, reached from the other end —
     * and these are not hypothetical curves here: PACE runs on brainpoolP256r1 on
     * the Latvian cards this library talks to.
     */
    @ParameterizedTest
    @ValueSource(strings = {"brainpoolP256r1", "brainpoolP384r1", "secp256k1"})
    public void forCertificate_aCurveJwaDoesNotName_isRefused(String curve) throws Exception {
        // Generated through BouncyCastle explicitly: the platform providers do not
        // offer these curves, and falling back to a skip would make this pass
        // without testing anything — which it did, before the provider was named.
        byte[] certificate = certificateWithEcKey(curve, new BouncyCastleProvider());

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> SignatureAlgorithm.forCertificate(certificate));
        assertThat(thrown).hasMessageThat().contains("not P-256, P-384 or P-521");
    }

    /**
     * A certificate that carries explicit domain parameters instead of naming a curve
     * is refused, not labelled from the numbers.
     *
     * <p>Asserted as a refusal rather than by message, because two layers can refuse
     * it and which one does is the platform's business. On this JVM the JCA key
     * extraction rejects such a certificate before the curve check is reached; where a
     * provider accepts it — Android's may — the curve check refuses it for naming no
     * curve. Either way the parameters might well describe P-384 exactly, and a
     * library that inferred that from the numbers would be back to identifying curves
     * by arithmetic.
     */
    @Test
    public void forCertificate_aCertificateThatNamesNoCurve_isRefused() throws Exception {
        X9ECParameters p384 = SECNamedCurves.getByName("secp384r1");
        ECParameterSpec explicit = new ECParameterSpec(
                p384.getCurve(), p384.getG(), p384.getN(), p384.getH());
        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", bc);
        generator.initialize(explicit);
        byte[] certificate = selfSignedCertificate(
                generator.generateKeyPair(), "SHA256withECDSA", bc);

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> SignatureAlgorithm.forCertificate(certificate));
        // Whichever layer refused, the outcome that matters is that no JWA name was
        // handed out for a curve nothing named.
        assertThat(thrown).hasMessageThat().doesNotContain("ES");
    }

    /** The three curves JWA does name still answer, by identity rather than size. */
    @ParameterizedTest
    @CsvSource({
            "secp256r1, ES256",
            "secp384r1, ES384",
            "secp521r1, ES512",
    })
    public void forCertificate_theThreeJwaCurvesAreIdentified(String curve, String expected)
            throws Exception {
        assertThat(SignatureAlgorithm.forCertificate(certificateWithEcKey(curve)).jwaName())
                .isEqualTo(expected);
    }

    @Test
    public void forCertificate_notACertificate_isRefused() {
        assertThrows(SignatureAlgorithmException.class,
                () -> SignatureAlgorithm.forCertificate(new byte[] {0x30, 0x00}));
    }

    /**
     * The 1-byte placeholder EFs on LV cards used to reach callers as
     * "certificates", so empty and null are worth pinning as refusals here too
     * rather than as a NullPointerException from inside a parser.
     */
    @Test
    public void forCertificate_emptyOrNull_isRefused() {
        assertThrows(SignatureAlgorithmException.class,
                () -> SignatureAlgorithm.forCertificate(new byte[0]));
        assertThrows(SignatureAlgorithmException.class,
                () -> SignatureAlgorithm.forCertificate(null));
    }

    /** The default {@link Token} seam answers the same thing the static does. */
    @Test
    public void tokenSignatureAlgorithm_defaultsToTheCertificatesAnswer() throws Exception {
        byte[] certificate = certificateWithEcKey("secp384r1");
        Token token = new Token() {
            @Override public CardType cardType() {
                return CardType.ID1;
            }
            @Override public PersonalData personalData() {
                throw new UnsupportedOperationException();
            }
            @Override public void changeCode(CodeType t, byte[] c, byte[] n) {
                throw new UnsupportedOperationException();
            }
            @Override public void unblockAndChangeCode(byte[] p, CodeType t, byte[] n) {
                throw new UnsupportedOperationException();
            }
            @Override public int pinChangedFlag(CodeType type) {
                throw new UnsupportedOperationException();
            }
            @Override public int codeRetryCounter(CodeType type) {
                throw new UnsupportedOperationException();
            }
            @Override public byte[] certificate(CertificateType type) {
                return certificate;
            }
            @Override public byte[] calculateSignature(byte[] p, byte[] h, boolean e) {
                throw new UnsupportedOperationException();
            }
            @Override public byte[] authenticate(byte[] pin1, byte[] token) {
                throw new UnsupportedOperationException();
            }
            @Override public byte[] decrypt(byte[] pin1, byte[] data, boolean ecc) {
                throw new UnsupportedOperationException();
            }
        };

        assertThat(token.signatureAlgorithm(CertificateType.AUTHENTICATION,
                token.certificate(CertificateType.AUTHENTICATION)))
                .isEqualTo(SignatureAlgorithm.ES384);
    }

    private static byte[] certificateWithEcKey(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return selfSignedCertificate(generator.generateKeyPair(), "SHA256withECDSA");
    }

    /**
     * As above, from a named provider — for curves the platform does not offer.
     * The provider has to sign the certificate as well as generate the key: the
     * default signature implementation refuses a curve it does not know.
     */
    private static byte[] certificateWithEcKey(String curve, java.security.Provider provider)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
        generator.initialize(new ECGenParameterSpec(curve));
        return selfSignedCertificate(generator.generateKeyPair(), "SHA256withECDSA", provider);
    }

    private static byte[] certificateWithRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return selfSignedCertificate(generator.generateKeyPair(), "SHA256withRSA");
    }

    private static byte[] selfSignedCertificate(KeyPair keyPair, String signatureAlgorithm)
            throws Exception {
        return selfSignedCertificate(keyPair, signatureAlgorithm, null);
    }

    private static byte[] selfSignedCertificate(
            KeyPair keyPair, String signatureAlgorithm, java.security.Provider provider)
            throws Exception {
        JcaContentSignerBuilder signer = new JcaContentSignerBuilder(signatureAlgorithm);
        if (provider != null) {
            signer.setProvider(provider);
        }
        X500Principal subject = new X500Principal("CN=Signature Algorithm Test");
        long now = 1_760_000_000_000L;
        return new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                new Date(now),
                new Date(now + 86_400_000L),
                subject,
                keyPair.getPublic())
                .build(signer.build(keyPair.getPrivate()))
                .getEncoded();
    }
}
