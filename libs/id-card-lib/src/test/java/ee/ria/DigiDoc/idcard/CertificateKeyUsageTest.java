package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Every certificate the fixtures hold, checked against the rule that tells the two
 * kinds apart: an authentication certificate carries {@code digitalSignature}, a
 * signing certificate carries {@code nonRepudiation}, and neither carries the
 * other's bit.
 *
 * <p>The rule is eIDAS's rather than a habit of these cards — {@code nonRepudiation}
 * is what makes a qualified signature qualified — but a rule the library reports
 * against should be pinned to the cards it was read from, so that card five arriving
 * with different bits is a test failure and not a surprise in the field.
 *
 * <p>Four captures, three card models, two chip families. Thales matters more here
 * than another IDEMIA sample would: a different chip and a different applet layout
 * following the same split is what makes this a standard rather than a
 * personalisation convention.
 *
 * <p>Asserted on the bits alone. Nothing here touches a subject, a serial number or
 * anything else that identifies the holder of a test card.
 */
public final class CertificateKeyUsageTest {

    /** X.509 KeyUsage bit 0. */
    private static final int DIGITAL_SIGNATURE = 0;
    /** X.509 KeyUsage bit 1. */
    private static final int NON_REPUDIATION = 1;

    @Test
    public void estonianIdemiaAuthenticationCertificateIsForAuthenticating() throws Exception {
        var fixture = ReplayFixture.ee()
                .with(EstoniaIdemiaPersonalDataReplayTest::loadAuthCertTranscript)
                .tunnel();
        assertAuthentication(fixture.token.certificate(CertificateType.AUTHENTICATION));
    }

    /** A different chip family entirely, and the same split. */
    @Test
    public void estonianThalesAuthenticationCertificateIsForAuthenticating() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(ThalesPersonalDataReplayTest::loadAuthCertTranscript)
                .tunnel();
        assertAuthentication(fixture.token.certificate(CertificateType.AUTHENTICATION));
    }

    @Test
    public void latvianSeIdAuthenticationCertificateIsForAuthenticating() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(LatviaIdemiaCertLookupReplayTest::loadSeidAuthCertRead)
                .tunnel();
        assertAuthentication(fixture.token.certificate(CertificateType.AUTHENTICATION));
    }

    @Test
    public void latvianSigningCertificateIsForSigning() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(LatviaIdemiaSignCertReplayTest::loadSignCertTranscript)
                .tunnel();
        assertSigning(fixture.token.certificate(CertificateType.SIGNING));
    }

    private static void assertAuthentication(byte[] certificate) throws Exception {
        boolean[] usage = keyUsage(certificate);
        assertThat(usage[DIGITAL_SIGNATURE]).isTrue();
        // The half that makes the rule usable: the bits do not overlap, so the
        // presence of one is the absence of the other.
        assertThat(usage[NON_REPUDIATION]).isFalse();
    }

    private static void assertSigning(byte[] certificate) throws Exception {
        boolean[] usage = keyUsage(certificate);
        assertThat(usage[NON_REPUDIATION]).isTrue();
        assertThat(usage[DIGITAL_SIGNATURE]).isFalse();
    }

    private static boolean[] keyUsage(byte[] certificate) throws Exception {
        boolean[] usage = ((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate))).getKeyUsage();
        assertThat(usage).isNotNull();
        return usage;
    }
}
