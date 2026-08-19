package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.okPadded;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.tagLost;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * Where {@code Idemia.certificate()} looks for a certificate, and in what
 * order, on LV IDEMIA cards. Two known EFs per certificate — the model's own
 * ({@code AD F1 34 01} / {@code AD F2 34 1F}) and the one the other
 * personalisation uses ({@code 34 02} / {@code 34 1E}, under the applet owning
 * the key) — tried in whichever order suits the card in hand, and behind them
 * the card's own PKCS#15 certificate directory. Nothing in any of them is a
 * {@link CertificateNotFoundException}, which is a statement about the card
 * rather than about the read.
 *
 * <p>The order is what each fixture's card decides, which is why the fixtures
 * name their card: {@code ReplayFixture.lv()} is the TeID2 card and starts
 * under MAIN, {@code ReplayFixture.lvSeid()} is the SeID card and starts in
 * the applet. Neither ever begins with an EF we expect to be empty.
 *
 * <p>Two physical cards appear here and they are not interchangeable:
 *
 * <ul>
 *   <li><b>"TeID2"</b> (ATS {@code 00 12 42 8F 54 65 49 44 32 0F 90 00}) keeps
 *       its certificates at the hardcoded EFs and declares real sizes, so it
 *       never reaches step 2. It supplies the canonical-read leg below.</li>
 *   <li><b>"SeID"</b> (ATS {@code 00 12 42 8F 53 65 49 44 0F 90 00}) answers
 *       the FCI form for both cert EFs with a well-formed FCP declaring a
 *       1-byte file — {@code 62 24 80 02 00 01 82 01 01 83 02 34 01 …}, file
 *       ID, transparent-EF descriptor and life-cycle all correct — and the
 *       canonical read returns that same single {@code 0x00}. Trusting either
 *       handed one byte to {@code CertificateFactory}, which failed with the
 *       useless {@code No certificate found}. Its real certificates are one
 *       file id over.</li>
 * </ul>
 *
 * <p>All SeID bytes below — FCPs, PKCS#15 directories and both certificates —
 * come from device captures taken on 2026-08-06.
 */
public final class LatviaIdemiaCertLookupReplayTest {

    private static final String SELECT_AUTH_CERT_FCI = "00a4090404adf13401";
    private static final String SELECT_AUTH_CERT_NO_FCI = "00a4090c04adf13401";
    private static final String SELECT_SIGN_CERT_FCI = "00a4090404adf2341f";

    private static final String SELECT_EF_OD = "00a4020c025031";
    private static final String SELECT_ALTERNATE_AUTH_EF = "00a4020c023402";
    private static final String SELECT_ALTERNATE_SIGN_EF = "00a4020c02341e";

    /** FCP of the empty auth cert EF, captured from the LV "SeID" card. */
    private static final String EMPTY_AUTH_CERT_FCI =
            "62248002000182010183023401"
                    + "8800a1128c077bffffffff43009c077bffffffff43008a0105"
                    + "80000000000000000000";
    /** The same for the sign cert EF — identical but for the file id. */
    private static final String EMPTY_SIGN_CERT_FCI =
            "6224800200018201018302341f"
                    + "8800a1128c077bffffffff43009c077bffffffff43008a0105"
                    + "80000000000000000000";

    /** What both empty cert EFs return under the canonical read: one 0x00. */
    private static final String ONE_PLACEHOLDER_BYTE =
            "00800000000000000000000000000000";

    /**
     * EF.OD of the Oberthur AWP applet on the SeID card: {@code [4]} (A4) names
     * CDF {@code 70 05}. Padding included, as captured.
     */
    private static final String OBERTHUR_EF_OD =
            "a806300404027001a006300404027002a106300404027004a406300404027005"
                    + "a7063004040270068000000000000000";
    /**
     * CDF {@code 70 05} from the same capture: one entry, labelled
     * "Authentication 02", whose {@code [1]} typeAttributes Path is
     * {@code 34 02} — not the hardcoded {@code AD F1 34 01}.
     */
    private static final String OBERTHUR_CDF =
            "304d30290c1141757468656e7469636174696f6e20303203020640301030060302"
                    + "07800500300603020640050030160414c5b1c41b9999547969b04c44a4f6a590"
                    + "d319c922a108300630040402340280";

    /** The QSCD applet's EF.OD on the same card: {@code [4]} names CDF 70 15. */
    private static final String QSCD_EF_OD =
            "a806300404027011a006300404027012a106300404027014a406300404027015"
                    + "a7063004040270168000000000000000";
    /** CDF {@code 70 15}: one entry, "Signature 1E", Path {@code 34 1E}. */
    private static final String QSCD_CDF =
            "304830240c0c5369676e617475726520314503020640301030060302078005003006"
                    + "03020640050030160414e32524155df58a682d39df74be43eb77ecc9ea43a1083006"
                    + "30040402341e800000000000";

    /**
     * The auth certificate of the LV "SeID" card, as the six chunks EF
     * {@code 34 02} returned it — 231 bytes each but the last, 1156 in total.
     * Concatenated they are a valid X.509 certificate issued by "LV eID ICA
     * 2025", so this fixture doubles as proof that the EF really holds it.
     */
    private static final String[] SEID_AUTH_CERT_CHUNKS = {
            "30820480308203e1a00302010202104c93ffaf0d4fc9cc692e9a36357d018030"
                    + "0a06082a8648ce3d040303307e310b3009060355040613024c56313930370603"
                    + "55040a0c30564153204c617476696a61732056616c73747320726164696f2075"
                    + "6e2074656c6576c4ab7a696a61732063656e747273311a301806035504610c11"
                    + "4e54524c562d34303030333031313230333118301606035504030c0f4c562065"
                    + "4944204943412032303235301e170d3235313230323037353031345a170d3330"
                    + "313230323037353031345a3068310b3009060355040613024c56311830160603"
                    + "5504030c0f4a41",
            "4e412041525345c5854a4556413113301106035504040c0a41525345c5854a45"
                    + "5641310d300b060355042a0c044a414e41311b301906035504051312504e4f4c"
                    + "562d3033303838372d31313036323076301006072a8648ce3d020106052b8104"
                    + "0022036200049b55c062f20f70e7b3681d04f24cfb098c992519bbb127b91847"
                    + "19da9f59abfd2f9eff157c64079d86cbd0bbf7290ca7a0b1ea627516d961cc70"
                    + "ba2804d27b4b1ef62d86db721c5c4749cadd535bbefc0dd0ccfe9fa7ea078c09"
                    + "86d0574be259a382023830820234300c0603551d130101ff04023000300e0603"
                    + "551d0f0101ff04",
            "0403020388301d0603551d250416301406082b0601050507030206082b060105"
                    + "05070304301d0603551d0e041604145c2a3e67954bd280cf42c18026f3cd1b71"
                    + "2ea996301f0603551d23041830168014db25331c60789730d629bde1f08ec6ab"
                    + "fc015ed13081fb0603551d200481f33081f0303b060604008f7a01023031302f"
                    + "06082b06010505070201162368747470733a2f2f7777772e65706172616b7374"
                    + "732e6c762f7265706f7369746f72793081b0060c2b0601040181fa3d02010202"
                    + "30819f302f06082b06010505070201162368747470733a2f2f7777772e657061"
                    + "72616b7374732e",
            "6c762f7265706f7369746f7279306c06082b0601050507020230600c5ec5a069"
                    + "7320736572746966696bc48174732069722069656bc4bc61757473204c617476"
                    + "696a61732052657075626c696b617320697a736e69656774c48120706572736f"
                    + "6e752061706c696563696e6fc5a1c48120646f6b756d656e74c481307206082b"
                    + "0601050507010104663064303c06082b060105050730028630687474703a2f2f"
                    + "7777772e65706172616b7374732e6c762f636572742f4c565f6549445f494341"
                    + "5f323032352e637274302406082b060105050730018618687474703a2f2f6f63"
                    + "73702e65706172",
            "616b7374732e6c7630430603551d1f043c303a3038a036a0348632687474703a"
                    + "2f2f7777772e65706172616b7374732e6c762f63726c2f4c565f6549445f4943"
                    + "415f323032355f31392e63726c300a06082a8648ce3d04030303818c00308188"
                    + "024201056944d79b7958cee49f31a9154dfd51f30099cdf6557d585b81a4a07e"
                    + "d9fb679de1c162e56e31a79bba2fa1db5b8eaefe31a7f431702588ff3172c7e0"
                    + "454d29ae0242019334199aa11da0e6726c1d64d3efa890f0316c18aefa696896"
                    + "46bc73e5c8f3bdaf227185588f7f6b469204a66a7927663884678af850eff48e"
                    + "a8439410313065",
            "77",
    };

    /**
     * The signing certificate of the same card, from EF {@code 34 1E}: seven
     * chunks, 231 bytes each but the last, 1547 in total. Same issuer as the
     * auth certificate but KeyUsage {@code nonRepudiation}, which is what makes
     * it the signing one.
     */
    private static final String[] SEID_SIGN_CERT_CHUNKS = {
            "3082060730820568a00302010202101f9a4c30b916d6e9692e9a377a73647830"
                    + "0a06082a8648ce3d040303307e310b3009060355040613024c56313930370603"
                    + "55040a0c30564153204c617476696a61732056616c73747320726164696f2075"
                    + "6e2074656c6576c4ab7a696a61732063656e747273311a301806035504610c11"
                    + "4e54524c562d34303030333031313230333118301606035504030c0f4c562065"
                    + "4944204943412032303235301e170d3235313230323037353031345a170d3330"
                    + "313230323037353031345a3068310b3009060355040613024c56311830160603"
                    + "5504030c0f4a41",
            "4e412041525345c5854a4556413113301106035504040c0a41525345c5854a45"
                    + "5641310d300b060355042a0c044a414e41311b301906035504051312504e4f4c"
                    + "562d3033303838372d31313036323076301006072a8648ce3d020106052b8104"
                    + "002203620004faed222d480a28b0919a8b7838c8684c63a7132f24a4f5021067"
                    + "006ce840d76407c666b1d2ab9a85896627e8a1ac0e9075a804971554dc76d0ff"
                    + "1dae9322330350f9e70b33312dafc8b2da3ad6a02ac4ef200a641430e59d823b"
                    + "5a0a838e8edba38203bf308203bb300c0603551d130101ff04023000300e0603"
                    + "551d0f0101ff04",
            "0403020640301d0603551d0e041604146fa2f1ee9ac0e8b4595a5dfee81fb6cc"
                    + "b87729be301f0603551d23041830168014db25331c60789730d629bde1f08ec6"
                    + "abfc015ed1301f0603551d2504183016060a2b0601040182370a030c06082b06"
                    + "010505070304308201d20603551d20048201c9308201c5303c060704008bec40"
                    + "01023031302f06082b06010505070201162368747470733a2f2f7777772e6570"
                    + "6172616b7374732e6c762f7265706f7369746f727930820183060c2b06010401"
                    + "81fa3d0201020230820171302f06082b06010505070201162368747470733a2f"
                    + "2f7777772e6570",
            "6172616b7374732e6c762f7265706f7369746f72793082013c06082b06010505"
                    + "0702023082012e0c82012ac5a0697320736572746966696bc481747320697220"
                    + "69656bc4bc61757473204c617476696a61732052657075626c696b617320697a"
                    + "736e69656774c48120706572736f6e752061706c696563696e6fc5a1c4812064"
                    + "6f6b756d656e74c4812e20536572746966696bc481747520697a646576697320"
                    + "564153204c617476696a61732056616c73747320726164696f20756e2074656c"
                    + "6576c4ab7a696a61732063656e74727320287265c4a32e4e722e203430303033"
                    + "30313132303329",
            "2c206e6f64726fc5a1696e6f7420617462696c7374c4ab627520456c656b7472"
                    + "6f6e69736b6f20646f6b756d656e7475206c696b756d616d20756e204569726f"
                    + "706173205061726c616d656e746120756e205061646f6d657320726567756c61"
                    + "69204e722e203931302f32303134307206082b0601050507010104663064303c"
                    + "06082b060105050730028630687474703a2f2f7777772e65706172616b737473"
                    + "2e6c762f636572742f4c565f6549445f4943415f323032352e63727430240608"
                    + "2b060105050730018618687474703a2f2f6f6373702e65706172616b7374732e"
                    + "6c763081aa0608",
            "2b0601050507010304819d30819a3008060604008e4601013008060604008e46"
                    + "01043013060604008e4601063009060704008e46010601301506082b06010505"
                    + "070b023009060704008bec4901013058060604008e460105304e3025161f6874"
                    + "7470733a2f2f7777772e65706172616b7374732e6c762f656e2f706473130265"
                    + "6e3025161f68747470733a2f2f7777772e65706172616b7374732e6c762f6c76"
                    + "2f70647313026c7630430603551d1f043c303a3038a036a0348632687474703a"
                    + "2f2f7777772e65706172616b7374732e6c762f63726c2f4c565f6549445f4943"
                    + "415f323032355f",
            "31392e63726c300a06082a8648ce3d04030303818c00308188024201d456c7ab"
                    + "171946c7e43182be4348119e8593239b8c5d65c42ffff2594aa53615549757c7"
                    + "2bf5f34b4b71b3858c7ccc5f9f9d5a9f873e1f7e60327526c97d9bf9a1024201"
                    + "4e9a61ea29b72e7e7ec4af93351e76809acf885cdd0f10ab446ca12cfff3c773"
                    + "cbdfe66e99935a399100bfbe4218c6ad0223958a506b2ae9fe1e0fc4f8248705"
                    + "f6",
    };

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
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                // FCP declaring 0x0400 = 1024 bytes.
                .expect(SELECT_AUTH_CERT_FCI, okPadded(
                        "62248002040082010183023401"
                                + "8800a1128c077bffffffff43009c077bffffffff43008a0105"
                                + "80000000000000000000"))
                // Card delivers 4 non-DER bytes, then EOF — far short of 1024.
                .expect("00b00000e5", okPadded("00000000800000000000000000000000"))
                .expect("00b00004e5", err6B00())
                .with(LatviaIdemiaCertLookupReplayTest::loadCanonicalCertRead)
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.AUTHENTICATION);

        assertCapturedTeid2AuthCert(certificate);
        fixture.assertAllConsumed();
    }

    /**
     * The LV "SeID" tap of 2026-08-06: both read forms of {@code AD F1 34 01}
     * return one {@code 0x00} byte, and the certificate is found at the known
     * alternate EF {@code 34 02} under the Oberthur AWP applet.
     *
     * <p>Every response byte is that capture, including the certificate: 1156
     * bytes in 231-byte chunks — the most that fits an SM-wrapped response, and
     * notably not the 256 of {@link #loadCanonicalCertRead}, so this also
     * covers the read loop following a card-chosen block size.
     *
     * <p>The capture reached EF {@code 34 02} the long way, through the PKCS#15
     * directory, because that was the only route implemented at the time. The
     * seven-APDU walk is now skipped in favour of selecting the known file id
     * directly, so those APDUs are absent below — their absence is the
     * assertion, and {@link #certificate_whenAlternateEfIsNotACertificate_readsThePathNamedByPkcs15}
     * keeps the walk itself covered.
     */
    @Test
    public void authCertificate_whenHardcodedEfIsEmpty_readsKnownAlternateEf()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(LatviaIdemiaCertLookupReplayTest::loadSeidAuthCertRead)
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.AUTHENTICATION);

        assertSeidCert(certificate, SEID_AUTH_CERT_CHUNKS, 1156);
        fixture.assertAllConsumed();
    }

    /**
     * The whole SeID authentication-certificate read — four APDUs plus the
     * chunks, with {@code AD F1 34 01} never touched. Shared with
     * {@link LatviaIdemiaSeIdSessionReplayTest}, which continues the same tap
     * into an authentication.
     */
    static void loadSeidAuthCertRead(ApduReplayReader r) {
        r.expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""));
        r.expect(SELECT_ALTERNATE_AUTH_EF, okPadded(""));
        loadChunkedRead(r, SEID_AUTH_CERT_CHUNKS);
        // Card left on MAIN for the next Token call.
        r.expect(TestApdus.SEL_MAIN_AID, okPadded(""));
    }

    /**
     * The same card's signing certificate, from the 2026-08-06 sign tap: the
     * QSCD applet's {@code AD F2 34 1F} is the same 1-byte placeholder and the
     * certificate is at {@code 34 1E}. Worth its own test rather than a
     * parameter of the one above, because it is the other applet, the other
     * file id, and a 1547-byte certificate whose final chunk is a partial 161
     * rather than the auth certificate's single byte.
     */
    @Test
    public void signCertificate_whenHardcodedEfIsEmpty_readsKnownAlternateEf()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .expect(TestApdus.SEL_QSCD_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_SIGN_EF, okPadded(""))
                .with(r -> loadChunkedRead(r, SEID_SIGN_CERT_CHUNKS))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.SIGNING);

        assertSeidCert(certificate, SEID_SIGN_CERT_CHUNKS, 1547);
        fixture.assertAllConsumed();
        // KeyUsage nonRepudiation is what distinguishes this from the auth
        // certificate — same card, same issuer, same subject.
        X509Certificate x509 = parse(certificate);
        assertThat(x509.getKeyUsage()[1]).isTrue();
        assertThat(x509.getKeyUsage()[0]).isFalse();
    }

    /**
     * The card is the authority on where its certificates are, so the known
     * file id is a shortcut and not a rule: when {@code 34 02} holds no
     * certificate either, the PKCS#15 directory still gets the last word.
     *
     * <p>No card is known to be personalised this way — every SeID capture has
     * its certificate at {@code 34 02}, exactly where the CDF says. So the
     * arrangement here is synthetic even though the bytes are not: the EF.OD
     * and CDF are the real captures with the CDF's Path changed to
     * {@code 34 03}, which is the only way to tell "we followed the card" apart
     * from "we guessed and got lucky".
     */
    @Test
    public void certificate_whenAlternateEfIsNotACertificate_readsThePathNamedByPkcs15()
            throws Exception {
        // Same CDF entry, Path 34 02 → 34 03. The trailing byte of the entry's
        // [1] typeAttributes is the only difference.
        String cdfNaming3403 = OBERTHUR_CDF.replace("300630040402340280", "300630040402340380");
        assertThat(cdfNaming3403).isNotEqualTo(OBERTHUR_CDF);

        var fixture = ReplayFixture.lvSeid()
                // First choice for this card: present, but a placeholder here.
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_AUTH_EF, okPadded(""))
                .expect("00b0000000", okPadded(ONE_PLACEHOLDER_BYTE))
                .expect("00b0000100", err6B00())
                // Second choice, the model's own EF. Its FCP declares one byte,
                // which is conclusive: no canonical read is attempted.
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .expect(SELECT_AUTH_CERT_FCI, okPadded(EMPTY_AUTH_CERT_FCI))
                // …so fall through to the EF.OD → CDF walk.
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_EF_OD, okPadded(""))
                .expect("00b0000000", okPadded(OBERTHUR_EF_OD))
                .expect("00b0002800", err6B00())
                .expect("00a4020c027005", okPadded(""))
                .expect("00b0000000", okPadded(cdfNaming3403))
                .expect("00b0004f00", err6B00())
                // The EF the CDF named, not the one we guessed. No re-SELECT of
                // the AID: selecting EFs by FID leaves the current DF alone.
                .expect("00a4020c023403", okPadded(""))
                .with(r -> loadChunkedRead(r, SEID_AUTH_CERT_CHUNKS))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.AUTHENTICATION);

        assertSeidCert(certificate, SEID_AUTH_CERT_CHUNKS, 1156);
        fixture.assertAllConsumed();
    }

    /**
     * The same fallback on the signing side, which is worth covering separately
     * because the walk runs in the QSCD applet against a different object
     * directory: its entries are {@code 70 11}…{@code 70 16}, so picking the
     * {@code [4]} tag rather than a neighbouring one is what makes it land on
     * CDF {@code 70 15}.
     *
     * <p>Synthetic in the same single respect as the authentication case: the
     * captured CDF's Path is {@code 34 1E}, the file the shortcut already
     * tries, so it is changed to {@code 34 1D} to tell following the card apart
     * from guessing.
     */
    @Test
    public void signCertificate_whenAlternateEfIsNotACertificate_readsThePathNamedByPkcs15()
            throws Exception {
        String cdfNaming341d = QSCD_CDF.replace("30040402341e80", "30040402341d80");
        assertThat(cdfNaming341d).isNotEqualTo(QSCD_CDF);

        var fixture = ReplayFixture.lvSeid()
                .expect(TestApdus.SEL_QSCD_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_SIGN_EF, okPadded(""))
                .expect("00b0000000", okPadded(ONE_PLACEHOLDER_BYTE))
                .expect("00b0000100", err6B00())
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .expect(SELECT_SIGN_CERT_FCI, okPadded(EMPTY_SIGN_CERT_FCI))
                // EF.OD → CDF walk in the QSCD applet.
                .expect(TestApdus.SEL_QSCD_AID, okPadded(""))
                .expect(SELECT_EF_OD, okPadded(""))
                .expect("00b0000000", okPadded(QSCD_EF_OD))
                .expect("00b0002800", err6B00())
                .expect("00a4020c027015", okPadded(""))
                .expect("00b0000000", okPadded(cdfNaming341d))
                .expect("00b0004a00", err6B00())
                .expect("00a4020c02341d", okPadded(""))
                .with(r -> loadChunkedRead(r, SEID_SIGN_CERT_CHUNKS))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .tunnel();

        byte[] certificate = fixture.token.certificate(CertificateType.SIGNING);

        assertSeidCert(certificate, SEID_SIGN_CERT_CHUNKS, 1547);
        fixture.assertAllConsumed();
    }

    /**
     * Nothing anywhere: the hardcoded EF is a placeholder, the known alternate
     * EF does not exist, and the applet exposes no PKCS#15 directory. That is a
     * card without an authentication certificate, and saying so is the whole
     * point of {@link CertificateNotFoundException} — the alternative was one
     * placeholder byte reaching {@code CertificateFactory}.
     *
     * <p>Both fallbacks fail with {@code 6A 82} here, which also pins that they
     * stay silent about their own failures rather than replacing the caller's
     * exception with an unrelated one.
     */
    @Test
    public void certificate_whenNothingHoldsACertificate_throwsCertificateNotFound()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_AUTH_EF, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .expect(SELECT_AUTH_CERT_FCI, okPadded(EMPTY_AUTH_CERT_FCI))
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_EF_OD, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .tunnel();

        var thrown = org.junit.jupiter.api.Assertions.assertThrows(
                CertificateNotFoundException.class,
                () -> fixture.token.certificate(CertificateType.AUTHENTICATION));

        assertThat(thrown.certificateType()).isEqualTo(CertificateType.AUTHENTICATION);
        // The message names every place looked in, and how each one answered.
        assertThat(thrown).hasMessageThat()
                .isEqualTo("No AUTHENTICATION certificate on card. Searched:"
                        + " EF 3402 in OBERTHUR (no such file);"
                        + " EF adf13401 (declared empty by its FCI);"
                        + " the PKCS#15 certificate directory (named none)");
        fixture.assertAllConsumed();
    }

    /**
     * A card that answers the FCI precisely keeps the fast path for the rest of the
     * session.
     *
     * <p>A declared size of one byte is the FCI <em>working</em>: it saved a SELECT
     * and two READs by saying outright that nothing is there. Treating that as
     * evidence the FCI is unusable would give the saving back on every later
     * certificate read — which is what happened while the flag was cleared one
     * statement too early.
     *
     * <p>Pinned by which SELECT the second read uses: {@code P2 = 0x04} is the FCI
     * form, {@code P2 = 0x0C} the canonical one. The fixture scripts only the former,
     * so a regression fails here as an unexpected APDU rather than as a slower tap
     * nobody measures.
     */
    @Test
    public void aPreciseFciAnswerKeepsTheFastPathForTheNextRead() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                // Authentication: the applet EF has nothing, the model EF declares one
                // byte, and the PKCS#15 walk finds nothing either.
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_AUTH_EF, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .expect(SELECT_AUTH_CERT_FCI, okPadded(EMPTY_AUTH_CERT_FCI))
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_EF_OD, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                // Signing, in the same session: still the FCI form. The canonical
                // SELECT is deliberately not scripted.
                .expect(TestApdus.SEL_QSCD_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_SIGN_EF, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .expect(SELECT_SIGN_CERT_FCI, okPadded(EMPTY_SIGN_CERT_FCI))
                .expect(TestApdus.SEL_QSCD_AID, okPadded(""))
                .expect(SELECT_EF_OD, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .tunnel();

        org.junit.jupiter.api.Assertions.assertThrows(CertificateNotFoundException.class,
                () -> fixture.token.certificate(CertificateType.AUTHENTICATION));
        org.junit.jupiter.api.Assertions.assertThrows(CertificateNotFoundException.class,
                () -> fixture.token.certificate(CertificateType.SIGNING));

        fixture.assertAllConsumed();
    }

    /**
     * The same journey as above right up to the last step, where the card
     * leaves the field instead of answering. That must not be reported as
     * {@link CertificateNotFoundException}: "this card has no certificate"
     * tells the user to give up on something a re-tap would fix.
     *
     * <p>The two misses before it are deliberately benign — {@code 6A 82} and a
     * declared-empty FCI — because a card-level failure earlier on is
     * remembered and rethrown in preference, which would mask the bug. This
     * arrangement is the one case where nothing else stands in the way.
     */
    @Test
    public void certificate_whenTheTagIsLostDuringThePkcs15Walk_reportsTheTransportFailure()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_ALTERNATE_AUTH_EF, err(0x6A, 0x82))
                .expect(TestApdus.SEL_MAIN_AID, okPadded(""))
                .expect(SELECT_AUTH_CERT_FCI, okPadded(EMPTY_AUTH_CERT_FCI))
                .expect(TestApdus.SEL_OBERTHUR_AID, okPadded(""))
                .expect(SELECT_EF_OD, tagLost())
                // Re-selecting MAIN is attempted regardless and fails the same
                // way; it stays silent so as not to replace what the caller is
                // about to be told.
                .expect(TestApdus.SEL_MAIN_AID, tagLost())
                .tunnel();

        var thrown = org.junit.jupiter.api.Assertions.assertThrows(
                SmartCardReaderException.class,
                () -> fixture.token.certificate(CertificateType.AUTHENTICATION));

        assertThat(thrown).isNotInstanceOf(CertificateNotFoundException.class);
        assertThat(thrown).hasCauseThat().isInstanceOf(IOException.class);
        fixture.assertAllConsumed();
    }

    /**
     * {@code Le = 0x00} reads at the offsets these chunks imply, then
     * {@code 6B 00} one byte past the end — the SeID card's own block size of
     * 231 bytes, taken from where each captured chunk started.
     */
    private static void loadChunkedRead(ApduReplayReader r, String[] chunks) {
        int offset = 0;
        for (String chunk : chunks) {
            r.expect(readAt(offset), okPadded(smPadded(chunk)));
            offset += chunk.length() / 2;
        }
        r.expect(readAt(offset), err6B00());
    }

    private static String readAt(int offset) {
        return String.format("00b0%02x%02x00", offset >> 8, offset & 0xFF);
    }

    /**
     * Append the padding the card's secure messaging adds: {@code 0x80}, then
     * zeros up to the AES block size. Reproduced here so the chunks above stay
     * readable as certificate content; the padded results are byte-identical to
     * the "Decrypted data" lines of the capture.
     */
    private static String smPadded(String hex) {
        StringBuilder padded = new StringBuilder(hex).append("80");
        while ((padded.length() / 2) % 16 != 0) {
            padded.append("00");
        }
        return padded.toString();
    }

    private static void assertSeidCert(byte[] certificate, String[] chunks, int length)
            throws Exception {
        assertThat(certificate).hasLength(length);
        assertThat(Hex.toHexString(certificate)).isEqualTo(String.join("", chunks));

        // Assert on the issuer and validity rather than the holder: this is a
        // real test card, and its subject carries a name and personal code.
        X509Certificate x509 = parse(certificate);
        assertThat(x509.getIssuerX500Principal().getName()).contains("CN=LV eID ICA 2025");
        assertThat(x509.getNotAfter().toInstant())
                .isEqualTo(Instant.parse("2030-12-02T07:50:14Z"));
    }

    private static X509Certificate parse(byte[] certificate) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
    }

    private static void assertCapturedTeid2AuthCert(byte[] certificate) throws Exception {
        assertThat(certificate).hasLength(1182);
        assertThat(Hex.toHexString(certificate, 0, 4)).isEqualTo("3082049a");

        // Same synthetic test identity as LatviaIdemiaPersonalDataReplayTest.
        assertThat(parse(certificate).getSubjectX500Principal().getName())
                .contains("CN=MĀRA PARAUDZIŅA");
    }

    /**
     * The pre-FCI APDU sequence: SELECT MAIN AID, SELECT cert with
     * {@code P2 = 0x0C} (no FCP requested), then {@code Le = 0x00} reads at
     * 256-byte offsets until {@code 6B 00}. The TeID2 card's 1182 certificate
     * bytes, the same ones as {@link LatviaIdemiaPersonalDataReplayTest},
     * re-chunked for this form.
     */
    static void loadCanonicalCertRead(ApduReplayReader r) {
        r.expect(TestApdus.SEL_MAIN_AID, okPadded(""));
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
