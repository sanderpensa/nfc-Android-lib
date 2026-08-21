package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/**
 * The last guard before a signature is handed back: does it verify under the
 * certificate of the key that was supposed to make it?
 *
 * <p>What is done about each verdict is policy and lives in
 * {@code Idemia.verifySignature} — see {@link SignatureVerificationPolicyTest}.
 *
 * <p>Keys are generated here rather than captured. A real card signature is checked
 * end to end by {@link LatviaIdemiaSeIdSessionReplayTest}, which reads a certificate
 * and then authenticates; what these cover is the matrix that one capture cannot —
 * both key types, both DigestInfo arrangements, and the mismatch cases — without
 * dragging a cardholder's certificate into the fixtures.
 */
public final class SignatureVerifierTest {

    private static final byte[] DIGEST = digest("what the card was asked to sign");

    /** ECDSA: the card returns a bare {@code r || s}, which is what we hand in. */
    @Test
    public void ecdsaSignatureOverTheDigestSentVerifies() throws Exception {
        KeyPair keys = ecKeys("secp384r1");
        byte[] certificate = certificate(keys, "SHA256withECDSA");
        byte[] signature = rawEcdsa(keys, DIGEST);

        assertThat(SignatureVerifier.verify(certificate, ec(), DIGEST, signature))
                .isEqualTo(SignatureVerifier.Result.MATCHED);
    }

    @Test
    public void ecdsaSignatureOverSomethingElseIsAMismatch() throws Exception {
        KeyPair keys = ecKeys("secp384r1");
        byte[] certificate = certificate(keys, "SHA256withECDSA");
        byte[] signature = rawEcdsa(keys, digest("a different value"));

        assertThat(SignatureVerifier.verify(certificate, ec(), DIGEST, signature))
                .isEqualTo(SignatureVerifier.Result.MISMATCHED);
    }

    /**
     * RSA where the caller built the DigestInfo — the raw {@code rsaEncryption} row
     * the 2020 Latvian card's authentication key offers. What was sent is the
     * DigestInfo, and that is what the card padded.
     */
    @Test
    public void rsaSignatureOverACallerBuiltDigestInfoVerifies() throws Exception {
        KeyPair keys = rsaKeys();
        byte[] certificate = certificate(keys, "SHA256withRSA");
        byte[] input = DigestInfo.wrap(DIGEST);
        byte[] signature = rawRsa(keys, input);

        assertThat(SignatureVerifier.verify(certificate, rsa(true), input, signature))
                .isEqualTo(SignatureVerifier.Result.MATCHED);
    }

    /**
     * RSA where the card built the DigestInfo — the {@code sha256WithRSAEncryption}
     * row. A bare digest went out, so the expected encoding has to be reconstructed
     * before comparing.
     */
    @Test
    public void rsaSignatureWhereTheCardWrappedTheDigestVerifies() throws Exception {
        KeyPair keys = rsaKeys();
        byte[] certificate = certificate(keys, "SHA256withRSA");
        byte[] signature = rawRsa(keys, DigestInfo.wrap(DIGEST));

        assertThat(SignatureVerifier.verify(certificate, rsa(false), DIGEST, signature))
                .isEqualTo(SignatureVerifier.Result.MATCHED);
    }

    /**
     * The case this guard exists for. The environment says the card builds the
     * DigestInfo — so a bare digest went out and the encoding is expected back — but
     * the card signed the bare digest instead, adding nothing. That is what a
     * mismatched {@code algRef} looks like: the reference named an algorithm whose
     * encoding the card did not apply. Every other guard passes; only this catches it.
     */
    @Test
    public void rsaSignatureOverAnEncodingTheMetadataDidNotImplyIsAMismatch() throws Exception {
        KeyPair keys = rsaKeys();
        byte[] certificate = certificate(keys, "SHA256withRSA");
        // Signed without the DigestInfo the sha256WithRSA row promised.
        byte[] signature = rawRsa(keys, DIGEST);

        assertThat(SignatureVerifier.verify(certificate, rsa(false), DIGEST, signature))
                .isEqualTo(SignatureVerifier.Result.MISMATCHED);
    }

    /** A signature made by another key is a mismatch, not an inability to check. */
    @Test
    public void aSignatureFromADifferentKeyIsAMismatch() throws Exception {
        byte[] certificate = certificate(rsaKeys(), "SHA256withRSA");
        byte[] signature = rawRsa(rsaKeys(), DigestInfo.wrap(DIGEST));

        assertThat(SignatureVerifier.verify(certificate, rsa(true),
                DigestInfo.wrap(DIGEST), signature))
                .isEqualTo(SignatureVerifier.Result.MISMATCHED);
    }

    /**
     * Being unable to check must never fail an operation that worked. No
     * certificate, an unparseable one, or an empty signature all report "not
     * checked" rather than throwing.
     */
    @Test
    public void whatCannotBeCheckedIsNotTreatedAsAMismatch() throws Exception {
        KeyPair keys = rsaKeys();
        byte[] certificate = certificate(keys, "SHA256withRSA");
        byte[] signature = rawRsa(keys, DigestInfo.wrap(DIGEST));

        assertThat(SignatureVerifier.verify(null, rsa(true), DIGEST, signature))
                .isEqualTo(SignatureVerifier.Result.NOT_CHECKED);
        assertThat(SignatureVerifier.verify(new byte[] {0x30, 0x00}, rsa(true), DIGEST, signature))
                .isEqualTo(SignatureVerifier.Result.NOT_CHECKED);
        assertThat(SignatureVerifier.verify(certificate, rsa(true), DIGEST, new byte[0]))
                .isEqualTo(SignatureVerifier.Result.NOT_CHECKED);
    }

    // ---- helpers ----

    private static SecurityEnvironment ec() {
        return new SecurityEnvironment(new byte[] {(byte) 0x80, 0x01, 0x54}, (byte) 0x9e,
                false, false, SignatureAlgorithm.ES384, SecurityEnvironment.Source.CARD);
    }

    private static SecurityEnvironment rsa(boolean callerBuildsDigestInfo) {
        return new SecurityEnvironment(new byte[] {(byte) 0x80, 0x01, 0x42}, (byte) 0x9f,
                true, callerBuildsDigestInfo, SignatureAlgorithm.RS256,
                SecurityEnvironment.Source.CARD);
    }

    private static byte[] digest(String of) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(of.getBytes());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair ecKeys(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static KeyPair rsaKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** A card-style ECDSA signature: DER from the JCA, unwrapped to r || s. */
    private static byte[] rawEcdsa(KeyPair keys, byte[] over) throws Exception {
        Signature signer = Signature.getInstance("NONEwithECDSA");
        signer.initSign(keys.getPrivate());
        signer.update(over);
        byte[] der = signer.sign();

        // SEQUENCE { INTEGER r, INTEGER s } -> fixed-width halves.
        int i = 3;
        int rLength = der[i] & 0xFF;
        BigInteger r = new BigInteger(Arrays.copyOfRange(der, i + 1, i + 1 + rLength));
        i = i + 1 + rLength + 1;
        int sLength = der[i] & 0xFF;
        BigInteger s = new BigInteger(Arrays.copyOfRange(der, i + 1, i + 1 + sLength));

        byte[] raw = new byte[96];
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        System.arraycopy(rb, Math.max(0, rb.length - 48), raw,
                Math.max(0, 48 - rb.length), Math.min(48, rb.length));
        System.arraycopy(sb, Math.max(0, sb.length - 48), raw,
                48 + Math.max(0, 48 - sb.length), Math.min(48, sb.length));
        return raw;
    }

    /** Textbook RSA over a PKCS#1 v1.5 block, the way the card does it. */
    private static byte[] rawRsa(KeyPair keys, byte[] payload) {
        RSAPrivateKey key = (RSAPrivateKey) keys.getPrivate();
        int modulusBytes = (key.getModulus().bitLength() + 7) / 8;
        byte[] block = new byte[modulusBytes];
        block[1] = 0x01;
        int padTo = modulusBytes - payload.length - 1;
        Arrays.fill(block, 2, padTo, (byte) 0xFF);
        System.arraycopy(payload, 0, block, padTo + 1, payload.length);

        byte[] signature = new BigInteger(1, block)
                .modPow(key.getPrivateExponent(), key.getModulus()).toByteArray();
        if (signature.length == modulusBytes) {
            return signature;
        }
        byte[] padded = new byte[modulusBytes];
        System.arraycopy(signature, Math.max(0, signature.length - modulusBytes), padded,
                Math.max(0, modulusBytes - signature.length),
                Math.min(modulusBytes, signature.length));
        return padded;
    }

    private static byte[] certificate(KeyPair keys, String signatureAlgorithm) throws Exception {
        X500Principal subject = new X500Principal("CN=Signature Verifier Test");
        long now = 1_760_000_000_000L;
        return new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, new Date(now),
                new Date(now + 86_400_000L), subject, keys.getPublic())
                .build(new JcaContentSignerBuilder(signatureAlgorithm).build(keys.getPrivate()))
                .getEncoded();
    }
}
