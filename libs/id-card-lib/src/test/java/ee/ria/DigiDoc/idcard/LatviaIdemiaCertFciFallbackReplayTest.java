package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.okPadded;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Regression cover for older LV IDEMIA cards, which answer the FCI form of
 * the cert SELECT ({@code 00 A4 09 04}) with a well-formed FCP template that
 * nevertheless declares a 1-byte file:
 *
 * <pre>62 24 80 02 00 01 82 01 01 83 02 34 01 88 00 A1 12 … 8A 01 05</pre>
 *
 * <p>Captured from a real card (ATS {@code 00 12 42 8F 53 65 49 44 0F 90 00}).
 * File ID, transparent-EF descriptor and life-cycle byte are all correct —
 * only the size is not. Trusting it read one byte ({@code 0x00}) and handed
 * that to {@code CertificateFactory}, which failed with the useless
 * {@code No certificate found}. The newer card recorded in
 * {@link LatviaIdemiaPersonalDataReplayTest} declares {@code 80 02 04 9E}
 * (1182 bytes) for the same file, so the fast path stays exercised there.
 *
 * <p>Both tests assert the same certificate comes back as on the newer card,
 * via the canonical {@code 00 A4 09 0C} + {@code 6B 00}-terminated read.
 */
public final class LatviaIdemiaCertFciFallbackReplayTest {

    private static final String SELECT_MAIN_AID =
            "00a4040c10a000000077010800070000fe00000100";
    private static final String SELECT_AUTH_CERT_FCI = "00a4090404adf13401";
    private static final String SELECT_AUTH_CERT_NO_FCI = "00a4090c04adf13401";

    @Test
    public void certificate_whenFciDeclaresImplausibleSize_readsViaCanonicalPath()
            throws Exception {
        var fixture = ReplayFixture.lv()
                .expect(SELECT_MAIN_AID, okPadded(""))
                // Older LV card: FCP with tag 80 = 0x0001. No READ BINARY is
                // attempted against that size — we go straight to the fallback.
                .expect(SELECT_AUTH_CERT_FCI, okPadded(
                        "62248002000182010183023401"
                                + "8800a1128c077bffffffff43009c077bffffffff43008a0105"
                                + "80000000000000000000"))
                .with(LatviaIdemiaCertFciFallbackReplayTest::loadCanonicalCertRead)
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.AUTHENTICATION);

        assertCapturedLvAuthCert(certificate);
        fixture.assertAllConsumed();
    }

    /**
     * Second guard: a size that passes the plausibility floor but whose
     * bounded read yields something that is not a DER certificate. The read
     * result is discarded and the canonical path retried, so a card that
     * reports a credible-looking but wrong size cannot produce a truncated
     * "certificate" either.
     */
    @Test
    public void certificate_whenFciBoundedReadIsNotDer_readsViaCanonicalPath()
            throws Exception {
        var fixture = ReplayFixture.lv()
                .expect(SELECT_MAIN_AID, okPadded(""))
                // FCP declaring 0x0400 = 1024 bytes.
                .expect(SELECT_AUTH_CERT_FCI, okPadded(
                        "62248002040082010183023401"
                                + "8800a1128c077bffffffff43009c077bffffffff43008a0105"
                                + "80000000000000000000"))
                // Card delivers 4 non-DER bytes, then EOF — far short of 1024.
                .expect("00b00000e5", okPadded("00000000800000000000000000000000"))
                .expect("00b00004e5", err6B00())
                .with(LatviaIdemiaCertFciFallbackReplayTest::loadCanonicalCertRead)
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.AUTHENTICATION);

        assertCapturedLvAuthCert(certificate);
        fixture.assertAllConsumed();
    }

    private static void assertCapturedLvAuthCert(byte[] certificate) throws Exception {
        assertThat(certificate).hasLength(1182);
        assertThat(Hex.toHexString(certificate, 0, 4)).isEqualTo("3082049a");

        X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
        // Same synthetic test identity as LatviaIdemiaPersonalDataReplayTest.
        assertThat(x509.getSubjectX500Principal().getName())
                .contains("CN=MĀRA PARAUDZIŅA");
    }

    /**
     * The pre-FCI APDU sequence: SELECT MAIN AID, SELECT cert with
     * {@code P2 = 0x0C} (no FCP requested), then {@code Le = 0x00} reads at
     * 256-byte offsets until {@code 6B 00}. Same 1182 certificate bytes as
     * {@link LatviaIdemiaPersonalDataReplayTest}, re-chunked for this form.
     */
    static void loadCanonicalCertRead(ApduReplayReader r) {
        r.expect(SELECT_MAIN_AID, okPadded(""));
        r.expect(SELECT_AUTH_CERT_NO_FCI, okPadded(""));

        r.expect("00b0000000", okPadded(
                "3082049a308203fba00302010202102d9a9078d07b83e06993271b430d94b8300a06082a8648ce3d040303308183310b3009060355040613024c5631393037060355040a0c30564153204c617476696a61732056616c73747320726164696f20756e2074656c6576c4ab7a696a61732063656e747273311a301806035504610c114e54524c562d3430303033303131323033311d301b06035504030c1444454d4f204c5620654944204943412032303234301e170d3236303231363134313830335a170d3331303231363134313830335a306c310b3009060355040613024c56311a301806035504030c114dc4805241205041524155445a49c58541311430128000000000000000"));
        r.expect("00b0010000", okPadded(
                "06035504040c0b5041524155445a49c58541310e300c060355042a0c054dc4805241311b301906035504051312504e4f4c562d3332363330352d31373035323076301006072a8648ce3d020106052b81040022036200045ba231c6013505812886ca50a8ac0476d6eafa07179485b9251f008404aa1c0605fadb0ced3dcfb5f6135b16f0790f72945792595310ab4ea3b8ebb72a5aa903fa628fa7dfec6d86c9e09cf9f8e14b86fe0a7e336bb01704595481335a1cdb35a382024830820244300c0603551d130101ff04023000300e0603551d0f0101ff040403020388301d0603551d250416301406082b0601050507030206082b06010505070304301d06038000000000000000"));
        r.expect("00b0020000", okPadded(
                "551d0e0416041425bb022e632b0215ec225c923e38700e3b86b4ce301f0603551d2304183016801442b3248d335eadd9cabb243e8eb5a98dab701fec3081fb0603551d200481f33081f0303b060604008f7a01023031302f06082b06010505070201162368747470733a2f2f7777772e65706172616b7374732e6c762f7265706f7369746f72793081b0060c2b0601040181fa3d0201020230819f302f06082b06010505070201162368747470733a2f2f7777772e65706172616b7374732e6c762f7265706f7369746f7279306c06082b0601050507020230600c5ec5a0697320736572746966696bc48174732069722069656bc4bc61757473204c617476698000000000000000"));
        r.expect("00b0030000", okPadded(
                "6a61732052657075626c696b617320697a736e69656774c48120706572736f6e752061706c696563696e6fc5a1c48120646f6b756d656e74c481307d06082b060105050701010471306f304206082b060105050730028636687474703a2f2f64656d6f2e65706172616b7374732e6c762f636572742f64656d6f5f4c565f6549445f4943415f323032342e637274302906082b06010505073001861d687474703a2f2f6f6373702e707265702e65706172616b7374732e6c7630480603551d1f0441303f303da03ba0398637687474703a2f2f64656d6f2e65706172616b7374732e6c762f63726c2f64656d6f5f4c565f6549445f4943415f323032345f382e8000000000000000"));
        r.expect("00b0040000", okPadded(
                "63726c300a06082a8648ce3d04030303818c0030818802420138669e93fd16375f950fc4932b38134b515c4135f571e1ccf03fc2cdf7d0443ef0400b11f61bee17e4b889010ce4b47326a98122f2b697123c95b03ee38429ff97024201c924cb7037ecbb32f3574e29b2ddbd224af574a59b85c095f7448ea0bbfd0ea69757429ae0ba3d971adbb02f44547a51a6061b4a603c5d16e3dac682f246c516aa8000000000000000"));
        // Offset 0x049E — past EOF, terminates the loop.
        r.expect("00b0049e00", err6B00());
    }
}
