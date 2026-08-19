package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.bouncycastle.util.encoders.Hex;

/**
 * The one line that says which card a log came from.
 *
 * <p>It exists because identifying a card from its APDUs means comparing
 * certificate sizes against notes, which is slow and was got wrong: a TeID2
 * capture was read as a SeID one on 2026-08-18 because both walk PKCS#15 and the
 * distinguishing detail was a declared file size buried in an FCP.
 *
 * <p>What it deliberately does not claim is the personalisation. The Latvian
 * "SeID" ATS covers two very different cards, so the marking narrows the field
 * and the certificate and security-environment lines finish the job.
 */
public final class TokenWithPaceMarkingTest {

    @ParameterizedTest(name = "{1}")
    @CsvSource({
            "0012233f536549440f9000,        'EE IDEMIA \"SeID\"'",
            "0012233f54654944320f9000,      'EE IDEMIA \"TeID2\"'",
            "8031d85365494464b085051012233f, 'EE Thales'",
            "0012428f536549440f9000,        'LV IDEMIA \"SeID\"'",
            "0012428f54654944320f9000,      'LV IDEMIA \"TeID2\"'",
    })
    public void marking_namesEachKnownCard(String ats, String expectedName) {
        String marking = TokenWithPace.marking(Hex.decode(ats.trim()));

        assertThat(marking).startsWith(expectedName);
        // The ATS goes in too, so an unfamiliar card is still identifiable.
        assertThat(marking).contains(ats.trim());
    }

    @Test
    public void marking_anUnknownAtsStillReportsItsBytes() {
        String marking = TokenWithPace.marking(Hex.decode("00aabbccdd"));

        assertThat(marking).contains("unrecognised marking");
        assertThat(marking).contains("00aabbccdd");
    }

    @Test
    public void marking_noAtsIsNotAnException() {
        assertThat(TokenWithPace.marking(null)).contains("no ATS");
    }

    /**
     * The two Latvian markings must not be confused with each other, since the
     * implementation chosen from them differs in where it looks for certificates.
     */
    @Test
    public void marking_separatesTheTwoLatvianCards() {
        String seId = TokenWithPace.marking(TokenWithPace.ATS_LV_IDEMIA_SEID);
        String teId2 = TokenWithPace.marking(TokenWithPace.ATS_LV_IDEMIA_TEID2);

        assertThat(seId).isNotEqualTo(teId2);
        assertThat(seId).contains("SeID");
        assertThat(teId2).contains("TeID2");
    }
}
