package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * {@code decrypt()} on both IDEMIA families.
 *
 * <p>Covered because it is the third operation resolving a security environment and
 * the only one no test drove: nothing in the app calls it, so a break here would go
 * unnoticed until an integrator hit it.
 *
 * <p>What the assertions pin is that the cryptogram is passed through
 * <em>untouched</em> — prefixed with the {@code 0x00} padding indicator and nothing
 * else. Decipher takes a key agreement input, not a hash, so neither the
 * DigestInfo wrapping nor the EC field widening that {@code operationInput} applies
 * to signing may be applied here. Routing decrypt through that method would corrupt
 * the input while still producing a well-formed APDU, which is the kind of mistake
 * a test has to catch.
 */
public final class IdemiaDecryptReplayTest {

    /** An uncompressed P-384 point, the shape an ECDH caller passes in. */
    private static final String EPHEMERAL_POINT = "04a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    private static final String SHARED_SECRET = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    /** {@code Lc} = the point plus the one-byte padding indicator decrypt() prepends. */
    private static final String DECIPHER_LC = "62";

    /**
     * Latvian EC: the environment is read from the card, and the row staged is the
     * key-agreement one.
     *
     * <p>{@code 80 01 0b} is entry 13, which advertises {@code derive-key} alone.
     * The obvious-looking {@code 80 01 04} is entry 7 — the ECDSA row that
     * <em>authentication</em> uses, and what this path staged while the mask alone
     * chose the row: every signing row also advertises derive-key, so the mask
     * matched all thirteen and the key's first entry won. The key reference is the
     * authentication key either way, since decipher borrows it.
     *
     * <p>Nothing on the card would have reported the difference — it answers
     * {@code 90 00} to any reference and a shared secret cannot be checked locally
     * — so this assertion is the only thing standing between a wrong reference and
     * a garbage secret.
     */
    @Test
    public void decrypt_onLatvianCard_stagesTheKeyAgreementRowNotTheSigningOne()
            throws Exception {
        var fixture = ReplayFixture.lv()
                .with(LvCardMetadata::scriptOberthur)
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    // MSE:SET CT — P2 = 0xB8, not the 0xA4/0xB6 of the signing paths.
                    r.expect("002241b8" + "06" + "80010b" + "840182", ok());
                    // PSO DECIPHER, cryptogram behind its 0x00 indicator, unmodified.
                    r.expect("002a8086" + DECIPHER_LC + "00" + EPHEMERAL_POINT + "00",
                            bytes(SHARED_SECRET));
                })
                .tunnel();

        byte[] secret = fixture.token.decrypt(
                TestPins.PIN1, Hex.decode(EPHEMERAL_POINT), true);

        assertThat(Hex.toHexString(secret)).isEqualTo(SHARED_SECRET);
        fixture.assertAllConsumed();
    }

    /**
     * Estonian: no walk at all, so the four-byte decrypt template goes out
     * directly. {@code FF 30 04 00} is its own algorithm, not the authentication
     * one — a copy-paste there would be invisible without this.
     *
     * <p>This constant is also the evidence for what the Latvian path above should
     * send: {@code FF 30 04 00} is the IDEMIA table's derive-key-only row, and it
     * is what Estonian cards have used in production. Latvian resolution now picks
     * the same kind of row rather than a signing one.
     */
    @Test
    public void decrypt_onEstonianCard_usesItsOwnFourByteTemplate() throws Exception {
        var fixture = ReplayFixture.ee()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241b8" + "09" + "8004ff300400" + "840181", ok());
                    r.expect("002a8086" + DECIPHER_LC + "00" + EPHEMERAL_POINT + "00",
                            bytes(SHARED_SECRET));
                })
                .tunnel();

        byte[] secret = fixture.token.decrypt(
                TestPins.PIN1, Hex.decode(EPHEMERAL_POINT), true);

        assertThat(Hex.toHexString(secret)).isEqualTo(SHARED_SECRET);
        fixture.assertAllConsumed();
    }

    /**
     * A wrong PIN1 must surface as {@link CodeVerificationException} with its retry
     * count, before any MSE:SET — decrypt verifies first, like the other two.
     */
    @Test
    public void decrypt_wrongPin1_failsBeforeStagingAnything() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(LvCardMetadata::scriptOberthur)
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.WRONG_PIN1_PADDED_FF,
                            ApduReplayReader.err(0x63, 0xC2));
                })
                .tunnel();

        CodeVerificationException thrown = org.junit.jupiter.api.Assertions.assertThrows(
                CodeVerificationException.class,
                () -> fixture.token.decrypt(
                        TestPins.WRONG_PIN1, Hex.decode(EPHEMERAL_POINT), true));

        assertThat(thrown.getType()).isEqualTo(CodeType.PIN1);
        assertThat(thrown.getRetries()).isEqualTo(2);
        fixture.assertAllConsumed();
    }

    /**
     * A short EC hash reaches INTERNAL AUTHENTICATE untouched, and PSO:CDS widened.
     *
     * <p>The asymmetry is deliberate and predates the security-environment work:
     * signing has always widened a short digest to the P-384 field, authentication
     * has always passed the caller's bytes through. Unifying the two would have
     * changed the wire format of a working operation for no benefit, so these pin
     * both halves.
     */
    @Test
    public void aShortEcHashIsWidenedForSigningButNotForAuthentication() throws Exception {
        String shortHash = "aa".repeat(32);
        String widened = "00".repeat(16) + shortHash;
        String signature = "cc".repeat(96);

        var auth = ReplayFixture.lv()
                .with(LvCardMetadata::scriptOberthur)
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800104" + "840182", ok());
                    // 32 bytes, exactly as handed in.
                    r.expect("00880000" + "20" + shortHash + "00", bytes(signature));
                })
                .tunnel();
        auth.token.authenticate(TestPins.PIN1, Hex.decode(shortHash));
        auth.assertAllConsumed();

        var sign = ReplayFixture.lv()
                .with(r -> LvCardMetadata.scriptQscd(r))
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expect("00200085" + "0c" + TestPins.PIN2_PADDED_FF, ok());
                    r.expect("002241b6" + "06" + "800154" + "84019e", ok());
                    // 48 bytes: zero-widened to the field.
                    r.expect("002a9e9a" + "30" + widened + "00", bytes(signature));
                })
                .tunnel();
        sign.token.calculateSignature(TestPins.PIN2, Hex.decode(shortHash), true);
        sign.assertAllConsumed();
    }
}
