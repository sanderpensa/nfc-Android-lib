package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import java.util.Set;

/**
 * Which key {@code signatureAlgorithm} answers about.
 *
 * <p>It used to answer about the authentication key whatever certificate it was
 * given, which was wrong in a way this card makes visible: the 2020 Latvian card's
 * two RSA keys disagree. Its signing key names {@code sha256WithRSAEncryption}, so
 * RS256 there is the card's own statement; its authentication key offers only raw
 * {@code rsaEncryption}, so RS256 there is the library's choice — and with raw RSA
 * that choice is genuinely free, since the DigestInfo is built host-side and RS384
 * would be equally self-consistent.
 *
 * <p>Same answer on this card, arrived at two different ways. The certificate type
 * is what makes the question well formed, so a card whose keys named different
 * hashes would not be misreported.
 */
public final class SignatureAlgorithmPerKeyTest {


    /** The signing key names its hash, so the answer comes from the card. */
    @Test
    public void forTheSigningKeyTheAnswerIsTheCardsOwn() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_QSCD);
                    r.expectFileRead("5031", RsaCardMetadata.QSCD_EF_OD);
                    r.expectFileRead("7012", RsaCardMetadata.SIGN_PRKD);
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    // signatureAlgorithm leaves the card on MAIN.
                    r.expect(TestApdus.SEL_MAIN_AID, ok());
                })
                .tunnel();

        SignatureAlgorithm algorithm = fixture.token.signatureAlgorithm(
                CertificateType.SIGNING, rsaCertificate());

        assertThat(algorithm).isEqualTo(SignatureAlgorithm.RS256);
        // Resolved from the QSCD key's own row, not from the authentication key.
        assertThat(fixture.token.securityEnvironment(SigningOperation.SIGN).namedAlgorithm())
                .isEqualTo(SignatureAlgorithm.RS256);
        fixture.assertAllConsumed();
    }

    /**
     * The authentication key names no hash, so RS256 stands as the library's choice.
     * Asking about it must read the Oberthur applet, not QSCD — before the fix this
     * happened whichever certificate was passed.
     */
    @Test
    public void forTheAuthenticationKeyTheAnswerIsOursAndReadsTheOtherApplet()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_OBERTHUR);
                    r.expectFileRead("5031", RsaCardMetadata.AUTH_EF_OD);
                    r.expectFileRead("7002", RsaCardMetadata.AUTH_PRKD);
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect(TestApdus.SEL_MAIN_AID, ok());
                })
                .tunnel();

        SignatureAlgorithm algorithm = fixture.token.signatureAlgorithm(
                CertificateType.AUTHENTICATION, rsaCertificate());

        assertThat(algorithm).isEqualTo(SignatureAlgorithm.RS256);
        // Its row names no hash — the card did not settle this, we did.
        assertThat(fixture.token.securityEnvironment(SigningOperation.AUTHENTICATE)
                .namedAlgorithm()).isNull();
        fixture.assertAllConsumed();
    }

    /** An EC certificate is settled by its curve, with no card read at all. */
    @Test
    public void anEcCertificateNeedsNoCardRead() throws Exception {
        var fixture = ReplayFixture.lv().tunnel();

        assertThat(fixture.token.signatureAlgorithm(
                CertificateType.SIGNING, ecCertificate())).isEqualTo(SignatureAlgorithm.ES384);
        fixture.assertAllConsumed();
    }

    // ---- what the key could sign with, as opposed to what it will ----

    /**
     * The signing key names {@code sha256WithRSAEncryption}, so the card builds the
     * encoding and there is nothing to choose: one permitted algorithm, the card's.
     */
    @Test
    public void aKeyWhoseCardNamesAHashPermitsOnlyThatOne() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    RsaCardMetadata.scriptSigningKey(r);
                    r.expect(TestApdus.SEL_MAIN_AID, ok());
                })
                .tunnel();

        assertThat(fixture.token.permittedAlgorithms(CertificateType.SIGNING, rsaCertificate()))
                .containsExactly(SignatureAlgorithm.RS256);
        fixture.assertAllConsumed();
    }

    /**
     * The authentication key's row offers only raw {@code rsaEncryption}, so the card
     * fixes nothing and all three RSA algorithms would produce a valid signature —
     * the library still uses RS256, and the reported choice is one of the three.
     *
     * <p>Both questions asked in one session on purpose: the answer to the second is
     * required to be a member of the answer to the first, and the second costs no
     * further metadata read — only the applet selects that leave the card where each
     * call found it.
     */
    @Test
    public void aKeyWhoseCardNamesNoHashPermitsAllThreeAndWeStillChooseRs256()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    RsaCardMetadata.scriptAuthenticationKey(r);
                    r.expect(TestApdus.SEL_MAIN_AID, ok());
                    // Asking again: the environment is cached, so only the two
                    // selects around the question happen.
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect(TestApdus.SEL_MAIN_AID, ok());
                })
                .tunnel();

        byte[] certificate = rsaCertificate();
        Set<SignatureAlgorithm> permitted =
                fixture.token.permittedAlgorithms(CertificateType.AUTHENTICATION, certificate);
        SignatureAlgorithm chosen =
                fixture.token.signatureAlgorithm(CertificateType.AUTHENTICATION, certificate);

        // Declaration order, as the contract states — EnumSet-backed, not Set.of.
        assertThat(permitted).containsExactly(SignatureAlgorithm.RS256,
                SignatureAlgorithm.RS384, SignatureAlgorithm.RS512).inOrder();
        assertThat(chosen).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(permitted).contains(chosen);
        fixture.assertAllConsumed();
    }

    /** An EC key is fixed by its curve, so one is permitted and no card is asked. */
    @Test
    public void anEcKeyPermitsOnlyItsCurvesAlgorithm() throws Exception {
        var fixture = ReplayFixture.lv().tunnel();

        assertThat(fixture.token.permittedAlgorithms(CertificateType.SIGNING, ecCertificate()))
                .containsExactly(SignatureAlgorithm.ES384);
        fixture.assertAllConsumed();
    }

    /**
     * The reported algorithm has to be one of the permitted ones, and a subclass that
     * narrowed the permitted set without saying so is the way that could stop being
     * true. Such a card would be told RS256 while its key signs with neither.
     *
     * <p>Nothing reaches this today — the only plural answer is the RSA set, which
     * contains RS256 — so this pins the contract rather than a reachable defect.
     */
    @Test
    public void theReportedAlgorithmIsAlwaysOneOfThePermittedOnes() throws Exception {
        LatviaIdemiaWithPace token = new LatviaIdemiaWithPace(new ApduReplayReader().build()) {
            @Override
            public Set<SignatureAlgorithm> permittedAlgorithms(CertificateType type,
                                                               byte[] certificate) {
                return Set.of(SignatureAlgorithm.ES256, SignatureAlgorithm.ES384);
            }
        };

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> token.signatureAlgorithm(CertificateType.SIGNING, ecCertificate()));
        assertThat(thrown).hasMessageThat().contains("none of which is the RS256");
    }

    private static byte[] rsaCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return certificate(generator.generateKeyPair(), "SHA256withRSA");
    }

    private static byte[] ecCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        return certificate(generator.generateKeyPair(), "SHA256withECDSA");
    }

    private static byte[] certificate(KeyPair keys, String algorithm) throws Exception {
        X500Principal subject = new X500Principal("CN=Per Key Test");
        long now = 1_760_000_000_000L;
        return new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, new Date(now),
                new Date(now + 86_400_000L), subject, keys.getPublic())
                .build(new JcaContentSignerBuilder(algorithm).build(keys.getPrivate()))
                .getEncoded();
    }

}
