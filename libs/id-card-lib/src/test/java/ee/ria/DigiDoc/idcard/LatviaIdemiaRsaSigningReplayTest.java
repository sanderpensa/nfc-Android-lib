package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Signing with the 2020 Latvian RSA card, driven entirely by what the card says
 * about its own keys. The PKCS#15 bytes are its own, captured 2026-08-18.
 *
 * <p>Every expectation here would be wrong under the hardcoded profile, which is
 * the point. That profile would send algorithm {@code 80 01 04} with key
 * {@code 0x82}; this card wants {@code 80 01 02} with key {@code 0x81} to
 * authenticate and {@code 80 01 42} with {@code 0x9F} to sign. It shares its ATS
 * with the EC card, so nothing short of asking it could tell.
 *
 * <p>The authentication input is the other half. That key offers only plain
 * {@code rsaEncryption}, so the card signs whatever arrives and the PKCS#1
 * {@code DigestInfo} has to be built here — the difference between an RS256
 * signature and a well-formed signature over the wrong value. The signing key
 * names SHA-256, so there the bare digest goes as-is.
 *
 * <p>The replay reader fails on any APDU it was not given, so these expectations
 * are assertions about what leaves the phone, not just a script.
 */
public final class LatviaIdemiaRsaSigningReplayTest {

    /** An arbitrary SHA-256 digest — the value does not matter, its length does. */
    private static final String HASH_32 = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    /** RFC 8017 DigestInfo prefix for SHA-256. */
    private static final String DIGEST_INFO_SHA256 = "3031300d060960864801650304020105000420";
    private static final String RSA_SIGNATURE_256 = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

    @Test
    public void authenticate_usesRawRsaWithTheCardsKeyAndAHostBuiltDigestInfo()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    readAuthMetadata(r);
                    // The walk left an EF selected, so the applet is re-selected.
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    // Raw RSA, key 0x81 — neither is what the profile hardcodes.
                    r.expect("002241a4" + "06" + "800102" + "840181", ok());
                    // 51 bytes: the DigestInfo this side had to build.
                    r.expect("00880000" + "33" + DIGEST_INFO_SHA256 + HASH_32 + "00",
                            bytes(RSA_SIGNATURE_256));
                })
                .tunnel();

        byte[] signature = fixture.token.authenticate(TestPins.PIN1, Hex.decode(HASH_32));

        assertThat(signature).hasLength(256);
        fixture.assertAllConsumed();
    }

    @Test
    public void calculateSignature_usesSha256WithRsaAndSendsTheBareDigest() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    readSignMetadata(r);
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expect("00200085" + "0c" + TestPins.PIN2_PADDED_FF, ok());
                    // sha256WithRSAEncryption, key 0x9F.
                    r.expect("002241b6" + "06" + "800142" + "84019f", ok());
                    // 32 bytes, unwrapped and unpadded: the card encodes this one.
                    r.expect("002a9e9a" + "20" + HASH_32 + "00", bytes(RSA_SIGNATURE_256));
                })
                .tunnel();

        byte[] signature = fixture.token.calculateSignature(
                TestPins.PIN2, Hex.decode(HASH_32), false);

        assertThat(signature).hasLength(256);
        fixture.assertAllConsumed();
    }

    /**
     * Each applet's algorithm table is read under that applet, not shared from
     * whichever one was asked first.
     *
     * <p>They are not the same file — this card's Oberthur EF.TokenInfo is 563
     * bytes and its QSCD one 581 — and it is the applet's own key directory that
     * references the rows. The two happen to describe identical rows here, so the
     * signature is the same either way; what this pins is that the reference used
     * to produce it came from the table belonging to the key that signed. Sharing
     * would stage a reference from the wrong table on any card whose applets
     * numbered their rows differently, and the card would answer 90 00 to it.
     *
     * <p>The cost is the second {@code 50 32} read below, which is the price of
     * not assuming.
     */
    @Test
    public void eachAppletsAlgorithmTableIsReadUnderThatApplet() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    readAuthMetadata(r);
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800102" + "840181", ok());
                    r.expect("00880000" + "33" + DIGEST_INFO_SHA256 + HASH_32 + "00",
                            bytes(RSA_SIGNATURE_256));

                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    // The QSCD applet's own table, read under QSCD — that is the
                    // assertion. A shared cache would skip this read.
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_QSCD);
                    r.expectFileRead("5031", RsaCardMetadata.QSCD_EF_OD);
                    r.expectFileRead("7012", RsaCardMetadata.SIGN_PRKD);
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expect("00200085" + "0c" + TestPins.PIN2_PADDED_FF, ok());
                    r.expect("002241b6" + "06" + "800142" + "84019f", ok());
                    r.expect("002a9e9a" + "20" + HASH_32 + "00", bytes(RSA_SIGNATURE_256));
                })
                .tunnel();

        fixture.token.authenticate(TestPins.PIN1, Hex.decode(HASH_32));
        fixture.token.calculateSignature(TestPins.PIN2, Hex.decode(HASH_32), false);

        fixture.assertAllConsumed();
    }

    private static void readAuthMetadata(ApduReplayReader r) {
        r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_OBERTHUR);
        r.expectFileRead("5031", RsaCardMetadata.AUTH_EF_OD);
        r.expectFileRead("7002", RsaCardMetadata.AUTH_PRKD);
    }

    private static void readSignMetadata(ApduReplayReader r) {
        r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_QSCD);
        r.expectFileRead("5031", RsaCardMetadata.QSCD_EF_OD);
        r.expectFileRead("7012", RsaCardMetadata.SIGN_PRKD);
    }

}
