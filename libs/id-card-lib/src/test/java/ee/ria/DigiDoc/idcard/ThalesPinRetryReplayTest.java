package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import ee.ria.DigiDoc.smartcardreader.ApduResponseException;
import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Thales PIN retry + PUK unblock replay.
 *
 * <p>Thales differs from IDEMIA on three retry-related details that
 * this test pins:
 * <ul>
 *   <li>PIN padding is 0x00, not 0xFF (see {@code Thales.code}).</li>
 *   <li>{@code handleApduResponseException} also maps SW {@code 69 84}
 *       (selected PIN reference already locked) to "0 retries" — the
 *       4th row of the parametrized test below.</li>
 *   <li>{@code unblockAndChangeCode} is a <em>single</em> APDU carrying
 *       (PUK || newPIN) instead of IDEMIA's 3-step flow.</li>
 * </ul>
 */
public final class ThalesPinRetryReplayTest {

    @ParameterizedTest(name = "SW {0} {1} → {2} retries left")
    @CsvSource({
            "0x63, 0xC2, 2",
            "0x63, 0xC1, 1",
            "0x69, 0x83, 0",
            "0x69, 0x84, 0",
    })
    public void verifyPin1_failure_translatesToCodeVerificationException(
            int sw1, int sw2, int expectedRetries) throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> r.expect(
                        "00200081" + "0c" + TestPins.WRONG_PIN1_PADDED_00,
                        err(sw1, sw2)))
                .tunnel();

        CodeVerificationException ex = assertThrows(CodeVerificationException.class,
                () -> fixture.token.authenticate(TestPins.WRONG_PIN1, new byte[48]));
        assertThat(ex.getType()).isEqualTo(CodeType.PIN1);
        assertThat(ex.getRetries()).isEqualTo(expectedRetries);
        fixture.assertAllConsumed();
    }

    @Test
    public void unblockAndChangeCode_pin1_replaysSingleApduUnblock() throws Exception {
        // Single transmit: INS 0x2C, P1=0x00 (PUK provided), P2=0x81 (PIN1).
        // Data = code(puk) || code(newPin) = 24 bytes 0x00-padded.
        var fixture = ReplayFixture.thales()
                .with(r -> r.expect(
                        "002c0081" + "18" + TestPins.PUK_PADDED_00 + TestPins.NEW_PIN1_PADDED_00,
                        ok()))
                .tunnel();

        fixture.token.unblockAndChangeCode(TestPins.PUK, CodeType.PIN1, TestPins.NEW_PIN1);

        fixture.assertAllConsumed();
    }

    // GET DATA answers, A0 { 83 01 <ref>, DF21 04 <retries> ff a5 03, DF2F 01 <changed> }
    // — the captured shape, with the two values under test chosen.
    private static String pinStatus(int ref, int retries, int changed) {
        return String.format("a00e8301%02xdf2104%02xffa503df2f01%02x", ref, retries, changed);
    }

    /**
     * Retry counter and changed flag share one GET DATA, so asking for both costs one
     * read. The transcript holds a single PIN2 GET DATA; a second would arrive as an
     * unexpected APDU.
     */
    @Test
    public void pinChangedFlagAndRetryCounter_shareOneGetData() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> r.expect("00cb00ff" + "05" + "a0038301" + "82" + "00",
                        bytes(pinStatus(0x82, 3, 0))))
                .tunnel();

        assertThat(fixture.token.pinChangedFlag(CodeType.PIN2)).isEqualTo(0);
        assertThat(fixture.token.codeRetryCounter(CodeType.PIN2)).isEqualTo(3);
        fixture.assertAllConsumed();
    }

    /** Each code has its own answer; PIN1's is not PIN2's. */
    @Test
    public void retryCounter_isCachedPerCode() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> {
                    r.expect("00cb00ff" + "05" + "a0038301" + "81" + "00", bytes(pinStatus(0x81, 3, 1)));
                    r.expect("00cb00ff" + "05" + "a0038301" + "82" + "00", bytes(pinStatus(0x82, 1, 1)));
                })
                .tunnel();

        assertThat(fixture.token.codeRetryCounter(CodeType.PIN1)).isEqualTo(3);
        assertThat(fixture.token.codeRetryCounter(CodeType.PIN2)).isEqualTo(1);
        fixture.assertAllConsumed();
    }

    /**
     * A VERIFY changes the counter whether it succeeds or not, so the answer is
     * forgotten before it is sent and the next question goes back to the card.
     */
    @Test
    public void retryCounter_isReadAgainAfterAVerify() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> {
                    r.expect("00cb00ff" + "05" + "a0038301" + "81" + "00", bytes(pinStatus(0x81, 3, 1)));
                    r.expect("00200081" + "0c" + TestPins.WRONG_PIN1_PADDED_00, err(0x63, 0xC2));
                    r.expect("00cb00ff" + "05" + "a0038301" + "81" + "00", bytes(pinStatus(0x81, 2, 1)));
                })
                .tunnel();

        assertThat(fixture.token.codeRetryCounter(CodeType.PIN1)).isEqualTo(3);
        assertThrows(CodeVerificationException.class,
                () -> fixture.token.authenticate(TestPins.WRONG_PIN1, new byte[48]));
        assertThat(fixture.token.codeRetryCounter(CodeType.PIN1)).isEqualTo(2);
        fixture.assertAllConsumed();
    }

    /**
     * The captured answer of a blocked PIN: DF21 is present and reads 00
     * ({@code research/logs/thales-ee/pin1-block-and-unblock.log}). A real block is
     * still reported as 0.
     */
    @Test
    public void retryCounter_blockedPinAnswersZeroWithTheTagPresent() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> r.expect("00cb00ff" + "05" + "a0038301" + "81" + "00",
                        bytes("a0348301818c04f0000000df210400ffa503df2702ffffdf28010cdf2f0101"
                                + "df3f1403040c01aa01ffff550055ffffaaff55aa000000")))
                .tunnel();

        assertThat(fixture.token.codeRetryCounter(CodeType.PIN1)).isEqualTo(0);
        fixture.assertAllConsumed();
    }

    /**
     * An answer with no DF21 at all is not a blocked PIN — no card has been seen to
     * signal a block that way — so it is reported as unreadable rather than as 0.
     * SmartCardReaderException, not ApduResponseException: the card said 90 00.
     */
    @Test
    public void retryCounter_answerWithoutDf21_isReportedNotReadAsBlocked() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> r.expect("00cb00ff" + "05" + "a0038301" + "81" + "00",
                        bytes("a007830181df2f0101")))
                .tunnel();

        SmartCardReaderException thrown = assertThrows(SmartCardReaderException.class,
                () -> fixture.token.codeRetryCounter(CodeType.PIN1));

        assertThat(thrown).isNotInstanceOf(ApduResponseException.class);
        assertThat(thrown).hasMessageThat().contains("DF21");
        fixture.assertAllConsumed();
    }

    /** The changed flag keeps its conservative default: absent reads as not changed. */
    @Test
    public void pinChangedFlag_answerWithoutDf2f_readsAsNotChanged() throws Exception {
        var fixture = ReplayFixture.thales()
                .with(r -> r.expect("00cb00ff" + "05" + "a0038301" + "82" + "00",
                        bytes("a007830182df21040300")))
                .tunnel();

        assertThat(fixture.token.pinChangedFlag(CodeType.PIN2)).isEqualTo(0);
        fixture.assertAllConsumed();
    }
}
