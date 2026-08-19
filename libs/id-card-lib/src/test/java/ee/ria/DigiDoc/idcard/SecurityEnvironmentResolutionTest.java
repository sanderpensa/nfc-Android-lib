package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Where each card model's algorithm and key references come from.
 *
 * <p>Two rules, and they are opposites:
 *
 * <ul>
 *   <li><b>Estonian cards are never asked.</b> Their layout is documented and one
 *       pair of key references has served every marking in the field, so the
 *       constants are used and no metadata is read at all.</li>
 *   <li><b>Latvian cards are always asked, and never guessed for.</b> Two cards
 *       sharing the "SeID" ATS use one-byte and four-byte algorithm references, so
 *       no constant is right for all of them. A card that will not describe itself
 *       raises {@link SecurityEnvironmentException} rather than being signed for on
 *       an assumption — the card accepts any algorithm reference with {@code 90 00},
 *       so a wrong guess produces a signature that verifies nowhere and says
 *       nothing.</li>
 * </ul>
 */
public final class SecurityEnvironmentResolutionTest {

    private static final String SELECT_TOKEN_INFO = "00a4020c025032";

    /**
     * There are no Latvian measured constants to fall back to, and asking for them
     * fails rather than returning Estonian ones.
     *
     * <p>Unreachable through the public API: Latvian cards always resolve from the
     * card, so nothing calls this. It is asserted directly because the alternative
     * is an invariant held only by a boolean in another class — the inherited key
     * references really are Estonian ({@code 0x81} / {@code 0x9F}), and a subclass
     * that stopped asking the card would sign a Latvian card with them and get a
     * plausible-looking signature that verifies nowhere.
     */
    @Test
    public void latvianCardsHaveNoMeasuredConstantsToFallBackOn() throws Exception {
        LatviaIdemiaWithPace token =
                new LatviaIdemiaWithPace(new ApduReplayReader().build());

        for (SigningOperation operation : SigningOperation.values()) {
            SecurityEnvironmentException thrown = assertThrows(SecurityEnvironmentException.class,
                    () -> token.measuredSecurityEnvironment(operation));
            assertThat(thrown).hasMessageThat().contains("no measured constants");
        }
    }

    /** The 2020 RSA card's signing key: RSA, key 0x9f, referencing entry 2 only. */

    /** Estonian: no metadata read, straight to the constants. */
    @Test
    public void estonianCardsAreNotAskedAndPayNothingForIt() throws Exception {
        var fixture = ReplayFixture.ee().tunnel();

        SecurityEnvironment authentication =
                fixture.token.securityEnvironment(SigningOperation.AUTHENTICATE);
        SecurityEnvironment signing =
                fixture.token.securityEnvironment(SigningOperation.SIGN);

        assertThat(authentication.source()).isEqualTo(SecurityEnvironment.Source.MEASURED);
        assertThat(signing.source()).isEqualTo(SecurityEnvironment.Source.MEASURED);
        // The replay reader fails on any APDU it was not given, so the absence of a
        // metadata read above is the assertion.
        assertThat(Hex.toHexString(authentication.mseSetBody()))
                .isEqualTo("8004ff200800" + "840181");
        assertThat(Hex.toHexString(signing.mseSetBody()))
                .isEqualTo("8004ff150800" + "84019f");
        fixture.assertAllConsumed();
    }

    /** Latvian: read from the card, and reported as such. */
    @Test
    public void latvianCardsAreAskedAndTheAnswerComesFromTheCard() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(r -> LvCardMetadata.scriptQscd(r, false))
                .tunnel();

        SecurityEnvironment signing =
                fixture.token.securityEnvironment(SigningOperation.SIGN);

        assertThat(signing.source()).isEqualTo(SecurityEnvironment.Source.CARD);
        assertThat(signing.isRsa()).isFalse();
        assertThat(signing.namedAlgorithm()).isEqualTo(SignatureAlgorithm.ES384);
        assertThat(Hex.toHexString(signing.mseSetBody())).isEqualTo("800154" + "84019e");
        fixture.assertAllConsumed();
    }

    /**
     * No EF.TokenInfo: refused, not guessed. And refused before the PIN, so it
     * costs the user no retry — the fixture scripts no VERIFY, and an attempt to
     * send one would fail as an unexpected APDU.
     */
    @Test
    public void aLatvianCardThatWillNotDescribeItselfIsRefusedBeforeThePin() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(r -> {
                    // calculateSignature selects the applet before resolving.
                    r.expect(TestApdus.SEL_QSCD_AID, ApduReplayReader.ok());
                    r.expect(SELECT_TOKEN_INFO, err(0x6A, 0x82));
                })
                .tunnel();

        SecurityEnvironmentException thrown = assertThrows(SecurityEnvironmentException.class,
                () -> fixture.token.calculateSignature(
                        TestPins.PIN2, Hex.decode(TestApdus.SIGN_INPUT_HASH_48), true));

        assertThat(thrown).hasMessageThat().contains("SIGN");
        assertThat(thrown).hasMessageThat().contains("did not describe its keys");
        fixture.assertAllConsumed();
    }

    /**
     * A tag that leaves the field mid-walk is reported as what it is, not as a card
     * that would not describe itself.
     *
     * <p>The distinction matters because the two call for opposite responses. "This
     * card did not describe its keys" tells the user the card cannot be used and
     * there is no point retrying; a lost tag means hold it still and try again. With
     * no fallback behind Latvian resolution, swallowing the transport failure turns
     * every fumbled tap into a condemned card.
     *
     * <p>Asserted by exception type: a {@code SmartCardReaderException} that is not a
     * {@link SecurityEnvironmentException}, carrying the transport cause.
     *
     * <p>The applet re-select is scripted because the walk restores it on the way to
     * the throw as well as on the way out — the same shape {@code certificate()} uses,
     * and it matters for an SM desync rather than a genuinely lost tag: a caller that
     * catches and retries must not inherit a card with an EF still selected. Here it
     * fails too, since the tag really is gone, and that failure must not replace the
     * error being reported.
     */
    @Test
    public void aTagLostWhileWalkingIsReportedAsATagLoss() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ApduReplayReader.ok());
                    r.expect(SELECT_TOKEN_INFO, ApduReplayReader.ok());
                    // The table read starts, and the tag goes.
                    r.expect("00b0000000", ApduReplayReader.tagLost());
                    // The restore is attempted, and fails the same way.
                    r.expect(TestApdus.SEL_QSCD_AID, ApduReplayReader.tagLost());
                })
                .tunnel();

        SmartCardReaderException thrown = assertThrows(SmartCardReaderException.class,
                () -> fixture.token.calculateSignature(
                        TestPins.PIN2, Hex.decode(TestApdus.SIGN_INPUT_HASH_48), true));

        assertThat(thrown).isNotInstanceOf(SecurityEnvironmentException.class);
        assertThat(thrown).hasCauseThat().hasMessageThat().contains("Tag was lost");
        // Every APDU the fixture holds was sent, the restore attempt included.
        fixture.assertAllConsumed();
    }

    /**
     * An EF.OD naming no private key directory is the same refusal: the table alone
     * cannot say which key or which of its rows to use.
     */
    @Test
    public void aLatvianCardWithNoKeyDirectoryIsAlsoRefused() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(r -> {
                    LvCardMetadata.scriptTokenInfoOnly(r);
                    // An EF.OD carrying only a certificate directory, no [0].
                    LvCardMetadata.scriptObjectDirectory(r, "a406300404027005");
                    r.expect(TestApdus.SEL_QSCD_AID, ApduReplayReader.ok());
                })
                .tunnel();

        assertThrows(SecurityEnvironmentException.class,
                () -> fixture.token.securityEnvironment(SigningOperation.SIGN));
        fixture.assertAllConsumed();
    }

    /**
     * An RSA key whose only algorithm row names a hash this library cannot encode
     * for is refused, not used. The card would build a SHA-1 {@code DigestInfo}
     * around whatever digest it was handed, and no other guard would notice.
     */
    @Test
    public void anRsaRowNamingAnUnknownHashIsRefused() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    // Row 2 is sha1WithRSAEncryption here, and the signing key
                    // references entry 2 and nothing else.
                    LvCardMetadata.scriptTokenInfo(r, "301ea21c301a02010202014005000302005106092a864886f70d010105020112");
                    LvCardMetadata.scriptObjectDirectory(r, LvCardMetadata.QSCD_EF_OD);
                    LvCardMetadata.scriptPrivateKeyDirectory(r, "7012", RsaCardMetadata.SIGN_PRKD);
                    r.expect(TestApdus.SEL_QSCD_AID, ApduReplayReader.ok());
                })
                .tunnel();

        assertThrows(SecurityEnvironmentException.class,
                () -> fixture.token.securityEnvironment(SigningOperation.SIGN));
        fixture.assertAllConsumed();
    }

    /** Resolving twice costs one walk: the answer is kept for the session. */
    @Test
    public void theAnswerIsResolvedOncePerOperation() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(r -> LvCardMetadata.scriptQscd(r, false))
                .tunnel();

        SecurityEnvironment first = fixture.token.securityEnvironment(SigningOperation.SIGN);
        SecurityEnvironment second = fixture.token.securityEnvironment(SigningOperation.SIGN);

        assertThat(second).isSameInstanceAs(first);
        fixture.assertAllConsumed();
    }

    /**
     * Decrypt resolves through the same path. On an EC card the row it needs
     * advertises {@code derive-key} rather than {@code decipher}, since the
     * primitive is ECDH key agreement — requiring only {@code decipher} made this
     * unresolvable.
     */
    @Test
    public void decryptResolvesOnAnEcCardWhereTheRowSaysDeriveKey() throws Exception {
        var fixture = ReplayFixture.lv()
                .with(LvCardMetadata::scriptOberthur)
                .tunnel();

        SecurityEnvironment decrypt =
                fixture.token.securityEnvironment(SigningOperation.DECRYPT);

        assertThat(decrypt.source()).isEqualTo(SecurityEnvironment.Source.CARD);
        assertThat(Hex.toHexString(decrypt.mseSetBody())).isEqualTo("800104" + "840182");
        fixture.assertAllConsumed();
    }
}
