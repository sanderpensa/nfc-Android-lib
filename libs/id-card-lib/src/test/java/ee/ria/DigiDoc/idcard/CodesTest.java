package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * The twelve-byte code field, and the two lengths that must never be squeezed
 * into it.
 *
 * <p>An empty code pads to twelve filler bytes, which is a structurally
 * perfect command: the card compares it, fails, and spends one of the user's
 * retries on a value nobody typed. On a change or unblock the card instead
 * <em>stores</em> those twelve bytes, leaving a code no keypad can reproduce —
 * which is what an empty "new PIN" field did to a test card on 2026-08-06,
 * and why unblocking it again appeared not to help.
 *
 * <p>An over-long code cannot go in the field at all, and on a change the
 * field holds two of them end to end, so letting one through would shift the
 * second past a boundary the card still expects.
 */
public final class CodesTest {

    @Test
    public void padded_idemiaFillsWith0xFF() throws Exception {
        assertThat(Hex.toHexString(Codes.padded("1234".getBytes(), (byte) 0xFF)))
                .isEqualTo("31323334ffffffffffffffff");
    }

    @Test
    public void padded_thalesFillsWith0x00() throws Exception {
        assertThat(Hex.toHexString(Codes.padded("12345".getBytes(), (byte) 0x00)))
                .isEqualTo("313233343500000000000000");
    }

    @Test
    public void padded_exactlyTwelveBytes_addsNoFiller() throws Exception {
        assertThat(Hex.toHexString(Codes.padded("123456789012".getBytes(), (byte) 0xFF)))
                .isEqualTo("313233343536373839303132");
    }

    @Test
    public void padded_empty_isRefusedRatherThanSentAsFiller() {
        CodeFormatException thrown = assertThrows(CodeFormatException.class,
                () -> Codes.padded(new byte[0], (byte) 0xFF));

        // The length is in the message because the symptom the caller sees on
        // the card ("wrong PIN") points nowhere near an empty input field.
        assertThat(thrown).hasMessageThat().contains("was 0");
    }

    @Test
    public void padded_longerThanTheField_isRefusedAsACodeProblem() {
        // Used to surface as IllegalArgumentException thrown from inside
        // Arrays.fill, after Arrays.copyOf had already truncated the code.
        CodeFormatException thrown = assertThrows(CodeFormatException.class,
                () -> Codes.padded("1234567890123".getBytes(), (byte) 0xFF));

        assertThat(thrown).hasMessageThat().contains("was 13");
    }

    @Test
    public void padded_null_isRefused() {
        assertThrows(CodeFormatException.class, () -> Codes.padded(null, (byte) 0x00));
    }
}
