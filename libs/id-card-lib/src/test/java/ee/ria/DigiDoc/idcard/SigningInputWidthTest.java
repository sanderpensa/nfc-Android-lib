package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;

/**
 * How wide the value sent to an EC key is, which is not a constant.
 *
 * <p>ECDSA signs an integer and the card truncates what it is given to its own field
 * size, so a digest padded to the wrong width is signed over a value nobody chose:
 * pad a 32-byte SHA-256 digest to 48 for a P-256 card and it truncates back to 32,
 * keeping sixteen zero bytes and half the digest. Nothing downstream catches that —
 * this is the signing path, which {@link SignatureVerifier} deliberately does not
 * cover — so the width has to be right rather than merely usual.
 *
 * <p>The library learned to answer ES256 and ES512 before it learned to send them a
 * digest of the right width. No such card is on record, which is why this is pinned
 * by construction rather than by a capture.
 */
public final class SigningInputWidthTest {

    /** An EC environment naming an algorithm, as a card-resolved row does. */
    private static SecurityEnvironment naming(SignatureAlgorithm algorithm) {
        return new SecurityEnvironment(new byte[] {(byte) 0x80, 0x01, 0x54}, (byte) 0x9e,
                false, false, algorithm, SecurityEnvironment.Source.CARD);
    }

    @ParameterizedTest
    @CsvSource({
            "ES256, 32, 32",
            "ES384, 32, 48",
            "ES384, 48, 48",
            "ES512, 48, 64",
            "ES512, 64, 64",
    })
    public void theInputIsWidenedToTheAlgorithmTheCardNamed(
            String algorithm, int digestLength, int expectedWidth) throws Exception {
        var fixture = ReplayFixture.lv().tunnel();

        byte[] input = fixture.token.signingInput(new byte[digestLength],
                naming(SignatureAlgorithm.valueOf(algorithm)));

        assertThat(input).hasLength(expectedWidth);
    }

    /**
     * A card that names no algorithm keeps the historical 48. That is every Estonian
     * card — its width is measured rather than inferred — and it is why this change
     * moves nothing for any card on record.
     */
    @Test
    public void anEnvironmentThatNamesNothingKeepsTheMeasuredWidth() throws Exception {
        var fixture = ReplayFixture.lv().tunnel();
        SecurityEnvironment measured = new SecurityEnvironment(
                new byte[] {(byte) 0x80, 0x04, (byte) 0xFF, 0x20, 0x08, 0x00}, (byte) 0x81,
                false, false, null, SecurityEnvironment.Source.MEASURED);

        assertThat(fixture.token.signingInput(new byte[32], measured)).hasLength(48);
        assertThat(fixture.token.signingInput(new byte[48], measured)).hasLength(48);
        // Longer than the pad width passes through: a P-521 digest is not truncated.
        assertThat(fixture.token.signingInput(new byte[64], measured)).hasLength(64);
    }

    /** The value survives the widening — left-padding an integer does not change it. */
    @Test
    public void wideningPreservesTheDigest() throws Exception {
        var fixture = ReplayFixture.lv().tunnel();
        byte[] digest = new byte[32];
        digest[0] = 0x11;
        digest[31] = (byte) 0xFF;

        byte[] input = fixture.token.signingInput(digest, naming(SignatureAlgorithm.ES384));

        assertThat(input).hasLength(48);
        for (int i = 0; i < 16; i++) {
            assertThat(input[i]).isEqualTo((byte) 0x00);
        }
        assertThat(Arrays.copyOfRange(input, 16, 48)).isEqualTo(digest);
    }
}
