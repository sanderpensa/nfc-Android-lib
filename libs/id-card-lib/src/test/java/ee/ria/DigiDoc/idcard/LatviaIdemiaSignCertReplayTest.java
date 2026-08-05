package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.okPadded;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;

/**
 * End-to-end replay of the signing certificate read on an LV IDEMIA card
 * (ATS {@code 00 12 42 8F 54 65 49 44 32 0F 90 00}), captured from a real
 * session.
 *
 * <p>Complements {@link LatviaIdemiaPersonalDataReplayTest}, which covers the
 * authentication certificate (EF {@code 34 01}, 1182 bytes). What is new here:
 * <ul>
 *   <li>EF {@code 34 1F} — the signing cert, reached via path
 *       {@code AD F2 34 1F}.</li>
 *   <li>A larger file: FCI declares {@code 80 02 06 25} = 1573 bytes, read as
 *       6 full {@code Le = 0xE5} chunks plus a short {@code Le = 0xC7} tail.
 *       The auth-cert transcript only exercises 5 chunks.</li>
 *   <li>Proof that tag 80 tracks real content length on this card — 1573 for
 *       the sign cert vs 1182 for the auth cert, same FCP shape otherwise.</li>
 * </ul>
 *
 * <p>Outcomes are post-decrypt payloads copied from the log's "Decrypted data"
 * lines, ISO 7816-4 padding included; the shared replay reader strips it.
 * Fixture is a test card — "PARAUDZIŅA MĀRA" is a synthetic identity.
 */
public final class LatviaIdemiaSignCertReplayTest {

    @Test
    public void certificate_signing_replaysLvSession_readsSevenChunks() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(LatviaIdemiaSignCertReplayTest::loadSignCertTranscript)
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.SIGNING);

        assertThat(certificate).hasLength(1573);
        assertThat(Hex.toHexString(certificate, 0, 4)).isEqualTo("30820621");

        X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
        assertThat(x509.getSerialNumber().toString(16))
                .isEqualTo("1ce6d3e490b487ea6993271b07aa1cd6");
        assertThat(x509.getSubjectX500Principal().getName()).contains("CN=MĀRA PARAUDZIŅA");
        assertThat(x509.getNotAfter().toInstant().atZone(ZoneOffset.UTC).toLocalDate().toString())
                .isEqualTo("2031-02-16");
        // KeyUsage 03 02 06 40 — nonRepudiation only, which is what marks this
        // as the QSCD signing cert rather than the auth cert (03 02 03 88).
        assertThat(x509.getKeyUsage()[0]).isFalse();   // digitalSignature
        assertThat(x509.getKeyUsage()[1]).isTrue();    // nonRepudiation
        assertThat(x509.getExtendedKeyUsage()).contains("1.3.6.1.5.5.7.3.4");

        fixture.assertAllConsumed();
    }

    /**
     * Post-PACE signing-cert read transcript: SELECT MAIN AID, SELECT EF
     * {@code 34 1F} with {@code P2 = 0x04} (FCI form), then 7 READ BINARYs
     * bounded by the declared 1573 bytes — no {@code 6B 00} probe.
     */
    static void loadSignCertTranscript(ApduReplayReader r) {
        // selectMainAid() — re-select after PACE
        r.expect("00a4040c10a000000077010800070000fe00000100", okPadded(""));
        // SELECT EF.QSCD sign cert via P1 = 0x09, P2 = 0x04 (FCI form).
        // FCP (tag 62) declares tag 80 = 0x0625 = 1573 bytes, file ID 0x341F,
        // transparent EF, life-cycle activated — same shape as the auth cert's
        // FCP on this card, only the size and file ID differ.
        r.expect("00a4090404adf2341f", okPadded(
                "621e800206258201018302341f88008a0105a10c8c0443ffc3009c0443ffc300"
                        + "80000000000000000000000000000000"));

        // Chunk 1 @ 0x0000 — DER SEQUENCE header, issuer (DEMO LV eID ICA 2024)
        r.expect("00b00000e5", okPadded(
                "3082062130820582a00302010202101ce6d3e490b487ea6993271b07aa1cd6300a06082a8648ce3d040303308183310b3009060355040613024c5631393037060355040a0c30564153204c617476696a61732056616c73747320726164696f20756e2074656c6576c4ab7a696a61732063656e747273311a301806035504610c114e54524c562d3430303033303131323033311d301b06035504030c1444454d4f204c5620654944204943412032303234301e170d3236303231363134313830335a170d3331303231363134313830335a306c310b3009060355040613024c56311a3018068000000000000000000000"));
        // Chunk 2 @ 0x00E5 — subject RDNs + SubjectPublicKeyInfo (P-384)
        r.expect("00b000e5e5", okPadded(
                "035504030c114dc4805241205041524155445a49c585413114301206035504040c0b5041524155445a49c58541310e300c060355042a0c054dc4805241311b301906035504051312504e4f4c562d3332363330352d31373035323076301006072a8648ce3d020106052b8104002203620004615c522e3c1a144379f1165554e158afc2cb44b7f68cadb3ff325ebf2a56916093c93f13044bcae053db1901a9cf1a12e31144514d739bc729f43d77bc28d74af61066e949c2a10609b0ca1f316d31ef7e1f696a0ccb9df5b9a76358c9613d1fa38203cf308203cb300c0603551d130101ff048000000000000000000000"));
        // Chunk 3 @ 0x01CA — KeyUsage (nonRepudiation), SKI, AKI, EKU, policies
        r.expect("00b001cae5", okPadded(
                "023000300e0603551d0f0101ff040403020640301d0603551d0e041604143a5d5aae26014477b57fa69805417f578b5ca44c301f0603551d2304183016801442b3248d335eadd9cabb243e8eb5a98dab701fec301f0603551d2504183016060a2b0601040182370a030c06082b06010505070304308201d20603551d20048201c9308201c5303c060704008bec4001023031302f06082b06010505070201162368747470733a2f2f7777772e65706172616b7374732e6c762f7265706f7369746f727930820183060c2b0601040181fa3d0201020230820171302f06082b060105050702018000000000000000000000"));
        // Chunk 4 @ 0x02AF — policy qualifier user notice (Latvian text)
        r.expect("00b002afe5", okPadded(
                "162368747470733a2f2f7777772e65706172616b7374732e6c762f7265706f7369746f72793082013c06082b060105050702023082012e0c82012ac5a0697320736572746966696bc48174732069722069656bc4bc61757473204c617476696a61732052657075626c696b617320697a736e69656774c48120706572736f6e752061706c696563696e6fc5a1c48120646f6b756d656e74c4812e20536572746966696bc481747520697a646576697320564153204c617476696a61732056616c73747320726164696f20756e2074656c6576c4ab7a696a61732063656e74727320287265c48000000000000000000000"));
        // Chunk 5 @ 0x0394 — user notice continuation + AIA (CA cert, OCSP)
        r.expect("00b00394e5", okPadded(
                "a32e4e722e203430303033303131323033292c206e6f64726fc5a1696e6f7420617462696c7374c4ab627520456c656b74726f6e69736b6f20646f6b756d656e7475206c696b756d616d20756e204569726f706173205061726c616d656e746120756e205061646f6d657320726567756c6169204e722e203931302f32303134307d06082b060105050701010471306f304206082b060105050730028636687474703a2f2f64656d6f2e65706172616b7374732e6c762f636572742f64656d6f5f4c565f6549445f4943415f323032342e637274302906082b06010505073001861d6874748000000000000000000000"));
        // Chunk 6 @ 0x0479 — QCStatements, PDS locations, CRL DP start
        r.expect("00b00479e5", okPadded(
                "703a2f2f6f6373702e707265702e65706172616b7374732e6c763081aa06082b0601050507010304819d30819a3008060604008e4601013008060604008e4601043013060604008e4601063009060704008e46010601301506082b06010505070b023009060704008bec4901013058060604008e460105304e3025161f68747470733a2f2f7777772e65706172616b7374732e6c762f656e2f7064731302656e3025161f68747470733a2f2f7777772e65706172616b7374732e6c762f6c762f70647313026c7630480603551d1f0441303f303da03ba0398637687474703a2f2f64656d6f8000000000000000000000"));
        // Chunk 7 @ 0x055E — CRL URL tail + ECDSA signature (199-byte short read)
        r.expect("00b0055ec7", okPadded(
                "2e65706172616b7374732e6c762f63726c2f64656d6f5f4c565f6549445f4943415f323032345f382e63726c300a06082a8648ce3d04030303818c00308188024200e49ab37a6bfc9cb7ec3584ee617484862fea99cc8e090c011561e20ef39a9b7d97b0f861138efe3612c25ecd38061515897229ba3555af4038c36e4e14ddcd6680024201deb5a15544173f3489b131a3ef5543c0a694d6fd53de903b035bf5194daf5207c06e0a2a8b42973a8ca35d45643d52578431964be5506235e50f578d1c4fd6c68a800000000000000000"));
    }
}
