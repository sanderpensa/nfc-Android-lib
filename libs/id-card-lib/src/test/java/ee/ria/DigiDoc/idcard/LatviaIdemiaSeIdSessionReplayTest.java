package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.Arrays;

/**
 * One whole tap of the LV "SeID" card, captured 2026-08-06: read the
 * authentication certificate, then authenticate with PIN1 over a 48-byte
 * hash.
 *
 * <p>What this covers that the per-step tests do not is the seam between them.
 * The certificate is not where {@code CERT_MAP} says, so the read ends up in
 * the Oberthur applet by way of the fallback chain; the authentication that
 * follows assumes the card was handed back on the MAIN AID. If that hand-back
 * regresses, every per-step test still passes and this one fails.
 *
 * <p>The closing assertion is the strong one: the captured signature is
 * verified against the public key of the captured certificate. It only holds
 * if both fixtures really came from the same card — no arrangement of correct
 * APDUs can fake it — so it also rules out the two halves having drifted apart
 * during transcription.
 */
public final class LatviaIdemiaSeIdSessionReplayTest {

    static final String CAPTURED_AUTH_SIGNATURE =
            "ab30b4c15f38bb6cd99b21a7ddec2c11d2eea3c969c07c225ae9ed4e5f8ab9ff"
                    + "265b8a567393b1cc24251d250930ddf3d4c479ea87a44cd980143fd1b7d9efb0"
                    + "1feba78de1f89e1d69b14d7430ea19ae6a14ec352019940a2633b156c91e9dbe";

    @Test
    public void certificateThenAuthenticate_replaysOneSeIdTap() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                // Order matters here: the certificate read and the PKCS#15 reads
                // both use READ BINARY from offset 0, and the reader queues per
                // APDU, so these have to be declared in the order they happen.
                .with(LatviaIdemiaCertLookupReplayTest::loadSeidAuthCertRead)
                .with(LvCardMetadata::scriptOberthur)
                .with(r -> {
                    // Straight into the auth flow — the cert read above left the
                    // card on MAIN, which is what this SELECT assumes.
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800104" + "840182", ok());
                    r.expect("00880000" + "30" + TestApdus.CAPTURED_AUTH_HASH + "00",
                            bytes(CAPTURED_AUTH_SIGNATURE));
                })
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.AUTHENTICATION);
        byte[] signature = fixture.token.authenticate(
                TestPins.PIN1, Hex.decode(TestApdus.CAPTURED_AUTH_HASH));

        assertThat(Hex.toHexString(signature)).isEqualTo(CAPTURED_AUTH_SIGNATURE);
        assertSignedBy(certificate, Hex.decode(TestApdus.CAPTURED_AUTH_HASH), signature);

        // The algorithm named for this key, from a real card's certificate rather
        // than a generated one: the curve is identified by the OID the certificate
        // publishes, so this is the path that has to work on a device where the
        // platform cannot name curves at all. Costs no APDU — an EC key is settled
        // by its curve, so nothing is asked of the card.
        assertThat(fixture.token.signatureAlgorithm(
                CertificateType.AUTHENTICATION, certificate))
                .isEqualTo(SignatureAlgorithm.ES384);
        fixture.assertAllConsumed();
    }

    /**
     * Verify a raw {@code r || s} card signature over an already-hashed input
     * against the certificate's public key. The card returns the two 48-byte
     * halves bare, so they are wrapped into the DER SEQUENCE that
     * {@code NONEwithECDSA} expects.
     */
    private static void assertSignedBy(byte[] certificate, byte[] digest, byte[] rawSignature)
            throws Exception {
        int half = rawSignature.length / 2;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rawSignature, 0, half));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rawSignature, half, rawSignature.length));
        byte[] derSignature = new DERSequence(
                new ASN1Integer[] {new ASN1Integer(r), new ASN1Integer(s)}).getEncoded();

        X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
        Signature verifier = Signature.getInstance("NONEwithECDSA");
        verifier.initVerify(x509.getPublicKey());
        verifier.update(digest);

        assertThat(verifier.verify(derSignature)).isTrue();
    }
}
