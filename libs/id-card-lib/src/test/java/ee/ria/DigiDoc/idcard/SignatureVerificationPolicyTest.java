package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * What the library does about a signature that does not verify — which depends on
 * where the security environment came from, and not on the card model.
 *
 * <p>{@link SignatureVerifierTest} covers whether a signature verifies. This covers
 * the consequence, because the two are separate decisions and only one of them is
 * safe to get wrong: refusing a signature that was actually fine turns a working tap
 * into a failed one.
 *
 * <p>Both tests drive a real tap end to end — read the certificate, then authenticate
 * — because that is the only arrangement in which the check runs at all: nothing is
 * verified when no certificate was read this session.
 *
 * <p>The mismatch is produced by authenticating over a different digest than the
 * captured signature was made over. That is the same thing the guard exists to catch
 * — a signature that is not over what the library thinks it is — reached without
 * fabricating card bytes.
 */
public final class SignatureVerificationPolicyTest {

    /**
     * A 48-byte value that is not what either captured signature was made over, so
     * verification against the captured certificate cannot succeed.
     */
    private static final String UNRELATED_HASH =
            "1111111111111111111111111111111111111111111111111111111111111111"
                    + "11111111111111111111111111111111";

    /**
     * Estonian cards sign under constants this library measured, not under anything
     * the card said. A mismatch there is far likelier to be the local check than the
     * card, so it is logged and the signature is returned — the tap still works.
     *
     * <p>This is the case with no card capture behind it: no Estonian log yet shows a
     * certificate read followed by an authentication. Until one does, the check must
     * not be able to fail such a tap.
     */
    @Test
    public void onMeasuredConstantsAMismatchIsReportedAndTheSignatureIsStillReturned()
            throws Exception {
        var fixture = ReplayFixture.ee()
                .with(EstoniaIdemiaPersonalDataReplayTest::loadAuthCertTranscript)
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "09" + "8004ff200800" + "840181", ok());
                    // The card's answer is a real captured signature, but over the
                    // demo hash rather than the one asked for here.
                    r.expect("00880000" + "30" + UNRELATED_HASH + "00",
                            bytes(EstoniaIdemiaSignFlowReplayTest.CAPTURED_AUTH_SIGNATURE));
                })
                .tunnel();

        fixture.token.certificate(CertificateType.AUTHENTICATION);
        byte[] signature = fixture.token.authenticate(TestPins.PIN1, Hex.decode(UNRELATED_HASH));

        assertThat(Hex.toHexString(signature))
                .isEqualTo(EstoniaIdemiaSignFlowReplayTest.CAPTURED_AUTH_SIGNATURE);
        fixture.assertAllConsumed();
    }

    /**
     * Latvian cards sign under an environment the card described, and a card has been
     * observed describing itself in a way that cannot be acted on correctly — the 2020
     * card gives three hash rows the same algorithm reference. A signature made under
     * a wrong description verifies nowhere, so it is refused here rather than sent to
     * a relying party that can only reject it without saying why.
     */
    @Test
    public void onWhatTheCardDescribedAMismatchRefusesTheSignature() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(LatviaIdemiaCertLookupReplayTest::loadSeidAuthCertRead)
                .with(LvCardMetadata::scriptOberthur)
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    r.expect("002241a4" + "06" + "800104" + "840182", ok());
                    r.expect("00880000" + "30" + UNRELATED_HASH + "00",
                            bytes(LatviaIdemiaSeIdSessionReplayTest.CAPTURED_AUTH_SIGNATURE));
                })
                .tunnel();

        fixture.token.certificate(CertificateType.AUTHENTICATION);

        SignatureAlgorithmException thrown = assertThrows(SignatureAlgorithmException.class,
                () -> fixture.token.authenticate(TestPins.PIN1, Hex.decode(UNRELATED_HASH)));

        assertThat(thrown).hasMessageThat().contains("does not verify under its own certificate");
        // Everything the card was asked for was asked: the refusal happens after the
        // PIN has been spent, which is the cost of catching it at all.
        fixture.assertAllConsumed();
    }
}
