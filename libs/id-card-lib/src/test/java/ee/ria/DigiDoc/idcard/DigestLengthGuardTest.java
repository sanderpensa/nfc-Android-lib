package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * The digest a caller hands in has to match the algorithm this library reported for
 * that key. Both halves of that, because they fail differently.
 *
 * <p>Where the card names a hash, a wrong length is corrupted by the card: it builds
 * the PKCS#1 encoding around the digest as if it were the hash it expected.
 *
 * <p>Where the card names <em>no</em> hash — the 2020 Latvian card's authentication
 * key — the failure is subtler and was the reason for this test's existence. The
 * DigestInfo is built here from whatever arrives, so a 48-byte digest becomes a
 * valid RS384 signature while RS256 was reported. Nothing catches that downstream:
 * the signature verifies against its own encoding, and only the name in the token is
 * wrong, so the relying party rejects it with no local symptom. The length is
 * therefore pinned to the algorithm that was reported.
 */
public final class DigestLengthGuardTest {


    /** Hashless row, wrong length: refused before anything is signed. */
    @Test
    public void aHashlessRowRefusesADigestOfTheWrongLength() throws Exception {
        var fixture = rsaAuthFixture();

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> fixture.token.authenticate(TestPins.PIN1, new byte[48]));

        assertThat(thrown).hasMessageThat().contains("names no hash");
        assertThat(thrown).hasMessageThat().contains("RS256");
        assertThat(thrown).hasMessageThat().contains("48 bytes");
        // Says what to do about it, since the caller is the one who can fix it.
        assertThat(thrown).hasMessageThat().contains("Token.signatureAlgorithm");
        fixture.assertAllConsumed();
    }

    /** Hashless row, right length: the digest is wrapped and sent. */
    @Test
    public void aHashlessRowAcceptsTheDigestItReported() throws Exception {
        String digest = "ab".repeat(32);
        String signature = "cd".repeat(256);
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_OBERTHUR);
                    r.expectFileRead("5031", RsaCardMetadata.AUTH_EF_OD);
                    r.expectFileRead("7002", RsaCardMetadata.AUTH_PRKD);
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800102" + "840181", ok());
                    r.expect("00880000" + "33"
                            + "3031300d060960864801650304020105000420" + digest + "00",
                            bytes(signature));
                })
                .tunnel();

        assertThat(fixture.token.authenticate(TestPins.PIN1, Hex.decode(digest)))
                .hasLength(256);
        fixture.assertAllConsumed();
    }

    /** Named row, wrong length: refused, and the message names the algorithm. */
    @Test
    public void aNamedRowRefusesADigestOfTheWrongLength() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_QSCD);
                    r.expectFileRead("5031", RsaCardMetadata.QSCD_EF_OD);
                    r.expectFileRead("7012", RsaCardMetadata.SIGN_PRKD);
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expect("00200085" + "0c" + TestPins.PIN2_PADDED_FF, ok());
                    r.expect("002241b6" + "06" + "800142" + "84019f", ok());
                })
                .tunnel();

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> fixture.token.calculateSignature(TestPins.PIN2, new byte[48], false));

        assertThat(thrown).hasMessageThat().contains("signs with RS256");
        assertThat(thrown).hasMessageThat().contains("32-byte hash");
        fixture.assertAllConsumed();
    }

    /** EC is unaffected: nothing encodes a hash identifier, so length is the caller's. */
    @Test
    public void anEcKeyIsNotLengthChecked() throws Exception {
        String shortHash = "aa".repeat(32);
        var fixture = ReplayFixture.lv()
                .with(LvCardMetadata::scriptOberthur)
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800104" + "840182", ok());
                    r.expect("00880000" + "20" + shortHash + "00", bytes("ee".repeat(96)));
                })
                .tunnel();

        assertThat(fixture.token.authenticate(TestPins.PIN1, Hex.decode(shortHash)))
                .hasLength(96);
        fixture.assertAllConsumed();
    }

    private static ReplayFixture.Tunneled<LatviaIdemiaSeIdWithPace> rsaAuthFixture()
            throws Exception {
        return ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_OBERTHUR);
                    r.expectFileRead("5031", RsaCardMetadata.AUTH_EF_OD);
                    r.expectFileRead("7002", RsaCardMetadata.AUTH_PRKD);
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800102" + "840181", ok());
                })
                .tunnel();
    }

}
