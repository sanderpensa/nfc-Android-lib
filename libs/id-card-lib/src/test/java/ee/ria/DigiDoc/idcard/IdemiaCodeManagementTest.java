package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ee.ria.DigiDoc.smartcardreader.ApduResponseException;
import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * Drives the post-PACE Token surface on {@link IdemiaWithPace} —
 * {@code codeRetryCounter}, {@code changeCode}, {@code unblockAndChangeCode},
 * {@code certificate(AUTH/SIGN)}, {@code pinChangedFlag} — against a mocked
 * reader. These methods are pure APDU plumbing inherited from {@link Idemia};
 * the tests verify the exact CLA/INS/P1/P2 (and, for the data-carrying
 * commands, body bytes) emitted on the wire.
 */
public final class IdemiaCodeManagementTest {

    @Test
    public void pinChangedFlag_returnsConstantRegardlessOfCodeType() {
        IdemiaWithPace token = new IdemiaWithPace(new CommandStubReader().build());
        // IDEMIA ignores the CodeType param and always returns 1 — verify for both.
        assertThat(token.pinChangedFlag(CodeType.PIN1)).isEqualTo(1);
        assertThat(token.pinChangedFlag(CodeType.PIN2)).isEqualTo(1);
    }

    // -------- codeRetryCounter --------

    @Test
    public void codeRetryCounter_pin1_selectsMainAidAndReturnsRetryByte() throws Exception {
        // The retry counter is at index 13 of the GET DATA response.
        CommandStubReader stub = new CommandStubReader().respondTo(0x00, 0xCB, 0x3F, 0xFF, padded(14, 5));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        int retries = token.codeRetryCounter(CodeType.PIN1);

        assertThat(retries).isEqualTo(5);
        // First APDU: SELECT MAIN AID (PIN1 lives there)
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C);
        // Second APDU: GET DATA with the PIN1 status tag
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0xCB, 0x3F, 0xFF);
    }

    @Test
    public void codeRetryCounter_pin2_selectsQscdAid() throws Exception {
        CommandStubReader stub = new CommandStubReader().respondTo(0x00, 0xCB, 0x3F, 0xFF, padded(14, 3));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        int retries = token.codeRetryCounter(CodeType.PIN2);

        assertThat(retries).isEqualTo(3);
        // First APDU: SELECT QSCD AID (PIN2 lives there, not under MAIN)
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C);
        // The data payload encodes the QSCD AID, distinct from MAIN AID
        byte[] qscdAid = Hex.decode("515343442041" + "70706c69636174696f6e"); // "QSCD Application"
        assertThat(stub.captured.get(0).data).isEqualTo(qscdAid);
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0xCB, 0x3F, 0xFF);
    }

    @Test
    public void codeRetryCounter_puk_selectsMainAid() throws Exception {
        CommandStubReader stub = new CommandStubReader().respondTo(0x00, 0xCB, 0x3F, 0xFF, padded(14, 0));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        assertThat(token.codeRetryCounter(CodeType.PUK)).isEqualTo(0);
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C); // MAIN AID
    }

    // -------- changeCode --------

    @Test
    public void changeCode_pin1_emitsChangeReferenceData() throws Exception {
        CommandStubReader stub = new CommandStubReader();
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        token.changeCode(CodeType.PIN1, "1234".getBytes(), "5678".getBytes());

        // Sequence: SELECT MAIN AID, then CHANGE REFERENCE DATA (INS=0x24)
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C);
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0x24, 0x00, 0x01); // P2 = 0x01 for PIN1
        // Data: code("1234") || code("5678") — each padded to 12 bytes with 0xFF.
        assertThat(stub.captured.get(1).data).isEqualTo(Hex.decode(
                "31323334ffffffffffffffff" + "35363738ffffffffffffffff"));
    }

    @Test
    public void changeCode_pin2_selectsQscdAndUsesPin2P2() throws Exception {
        CommandStubReader stub = new CommandStubReader();
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        token.changeCode(CodeType.PIN2, "12345".getBytes(), "98765".getBytes());

        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C); // QSCD AID
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0x24, 0x00, 0x85); // P2 = 0x85 for PIN2
        // Data: code("12345") || code("98765").
        assertThat(stub.captured.get(1).data).isEqualTo(Hex.decode(
                "3132333435ffffffffffffff" + "3938373635ffffffffffffff"));
    }

    @Test
    public void changeCode_wrongCurrentCode_throwsCodeVerificationException() throws Exception {
        // Chip returns 63 C2 = "wrong code, 2 retries left".
        CommandStubReader stub = new CommandStubReader()
                .throwOn(0x00, 0x24, new ApduResponseException((byte) 0x63, (byte) 0xC2));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        CodeVerificationException ex = assertThrows(CodeVerificationException.class,
                () -> token.changeCode(CodeType.PIN1, "0000".getBytes(), "1234".getBytes()));
        assertThat(ex.getType()).isEqualTo(CodeType.PIN1);
        assertThat(ex.getRetries()).isEqualTo(2);
    }

    @Test
    public void changeCode_unexpectedSw_rethrowsAsApduResponseException() throws Exception {
        // SW != 63xx / 6983 — exception should propagate untranslated.
        CommandStubReader stub = new CommandStubReader()
                .throwOn(0x00, 0x24, new ApduResponseException((byte) 0x6A, (byte) 0x82));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        assertThrows(ApduResponseException.class,
                () -> token.changeCode(CodeType.PIN1, "0000".getBytes(), "1234".getBytes()));
    }

    // -------- unblockAndChangeCode --------

    @Test
    public void unblockAndChangeCode_pin1_selectsMainAidThenVerifyPukThenReset() throws Exception {
        CommandStubReader stub = new CommandStubReader();
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        token.unblockAndChangeCode("12345678".getBytes(), CodeType.PIN1, "1234".getBytes());

        // Sequence: SELECT MAIN AID, VERIFY PUK, RESET RETRY COUNTER (INS=2C)
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C);  // MAIN AID
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0x20, 0x00, 0x02);  // VERIFY PUK (P2=0x02)
        CommandStubReader.assertHeader(stub.captured.get(2), 0x00, 0x2C, 0x02, 0x01);  // RESET PIN1 (P1=2, P2=PIN1)
        // VERIFY PUK data: code("12345678").
        assertThat(stub.captured.get(1).data).isEqualTo(Hex.decode("3132333435363738ffffffff"));
        // RESET RETRY COUNTER data: code("1234") — new PIN1.
        assertThat(stub.captured.get(2).data).isEqualTo(Hex.decode("31323334ffffffffffffffff"));
    }

    @Test
    public void unblockAndChangeCode_pin2_switchesToQscdAfterPuk() throws Exception {
        CommandStubReader stub = new CommandStubReader();
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        token.unblockAndChangeCode("12345678".getBytes(), CodeType.PIN2, "12345".getBytes());

        // Sequence: SELECT MAIN AID, VERIFY PUK, SELECT QSCD AID, RESET PIN2
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C);  // MAIN AID
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0x20, 0x00, 0x02);  // VERIFY PUK
        CommandStubReader.assertHeader(stub.captured.get(2), 0x00, 0xA4, 0x04, 0x0C);  // QSCD AID
        CommandStubReader.assertHeader(stub.captured.get(3), 0x00, 0x2C, 0x02, 0x85);  // RESET PIN2 (P2=0x85)
        // VERIFY PUK data: code("12345678").
        assertThat(stub.captured.get(1).data).isEqualTo(Hex.decode("3132333435363738ffffffff"));
        // RESET RETRY COUNTER data: code("12345") — new PIN2.
        assertThat(stub.captured.get(3).data).isEqualTo(Hex.decode("3132333435ffffffffffffff"));
    }

    @Test
    public void unblockAndChangeCode_wrongPuk_throwsCodeVerificationExceptionForPuk() throws Exception {
        // VERIFY PUK fails — the translated error type must be PUK, regardless of which
        // PIN was being unblocked. (Tested separately for PIN1 and PIN2 in case the
        // code-translation logic ever differentiates.)
        CommandStubReader stub = new CommandStubReader()
                .throwOn(0x00, 0x20, new ApduResponseException((byte) 0x63, (byte) 0xC1));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        CodeVerificationException ex = assertThrows(CodeVerificationException.class,
                () -> token.unblockAndChangeCode("BADPUK".getBytes(), CodeType.PIN1, "1234".getBytes()));
        assertThat(ex.getType()).isEqualTo(CodeType.PUK);
        assertThat(ex.getRetries()).isEqualTo(1);
    }

    // -------- certificate --------

    // Cert read uses the FCI shape: SELECT with P2 = 0x04, parse file size
    // from FCI tag 80/81, then READ BINARY exactly that many bytes. The fast
    // path is only kept when the declared size is plausible for a certificate
    // AND the bytes read parse as a DER SEQUENCE; otherwise the canonical
    // P2 = 0x0C + 6B 00 read runs instead. Two responses are queued on the
    // 0xA4 queue: the first is consumed by SELECT MAIN AID (empty/9000), the
    // second by SELECT cert (returns the FCI bytes).

    @Test
    public void certificate_authentication_selectsAuthCertEfViaFciAndReadsDeclaredSize() throws Exception {
        // FCI: tag 80 declaring file size = 0x0104 = 260 bytes.
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = fciCertReadStub("80020104", certContent);
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(certContent);
        // SELECT MAIN AID (P2 = 0x0C — AID select is unchanged)
        CommandStubReader.assertHeader(stub.captured.get(0), 0x00, 0xA4, 0x04, 0x0C);
        // SELECT cert: P2 = 0x04 (request FCI), AUTH path AD F1 34 01
        CommandStubReader.Apdu certSelect = stub.captured.get(1);
        CommandStubReader.assertHeader(certSelect, 0x00, 0xA4, 0x09, 0x04);
        assertThat(certSelect.data).isEqualTo(Hex.decode("ADF13401"));
        // Two READ BINARYs: 0xE5 bytes at offset 0, remainder at offset 0x00E5.
        CommandStubReader.assertHeader(stub.captured.get(2), 0x00, 0xB0, 0x00, 0x00);
        CommandStubReader.assertHeader(stub.captured.get(3), 0x00, 0xB0, 0x00, 0xE5);
        assertThat(stub.captured).hasSize(4);
    }

    @Test
    public void certificate_signing_routesToSigningCertEfViaFci() throws Exception {
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = fciCertReadStub("80020104", certContent);
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.SIGNING);

        assertThat(cert).isEqualTo(certContent);
        CommandStubReader.Apdu certSelect = stub.captured.get(1);
        CommandStubReader.assertHeader(certSelect, 0x00, 0xA4, 0x09, 0x04);
        // SIGN cert path: AD F2 34 1F
        assertThat(certSelect.data).isEqualTo(Hex.decode("ADF2341F"));
    }

    @Test
    public void certificate_fciSizeFromTag81_alternativeFormAccepted() throws Exception {
        // Tag 81 is the "transparent EF data length" variant accepted by the
        // FCI parser alongside tag 80. iOS treats them equivalently.
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = fciCertReadStub("81020104", certContent);
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(certContent);
    }

    @Test
    public void certificate_fciDeclaresImplausiblySmallSize_fallsBackToEofLoop() throws Exception {
        // Older LV cards answer P2 = 0x04 with a well-formed FCP declaring
        // tag 80 = 0x0001 for the cert EF (see
        // LatviaIdemiaCertFciFallbackReplayTest). Reading that one byte and
        // handing it upstream surfaced as "No certificate found", so an
        // implausible size is treated as no size at all.
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT MAIN AID
                .respondTo(0x00, 0xA4, Hex.decode("62088002000183023401"))  // FCP, size = 1
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT MAIN AID (retry)
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT cert, P2 = 0x0C
                .respondTo(0x00, 0xB0, certContent)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(certContent);
        // No READ BINARY is issued against the bogus size — the third APDU is
        // already the re-SELECT of the canonical (pre-FCI) sequence.
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0xA4, 0x09, 0x04);
        CommandStubReader.assertHeader(stub.captured.get(2), 0x00, 0xA4, 0x04, 0x0C);
        CommandStubReader.Apdu canonicalSelect = stub.captured.get(3);
        CommandStubReader.assertHeader(canonicalSelect, 0x00, 0xA4, 0x09, 0x0C);
        assertThat(canonicalSelect.data).isEqualTo(Hex.decode("ADF13401"));
        CommandStubReader.assertHeader(stub.captured.get(4), 0x00, 0xB0, 0x00, 0x00);
    }

    @Test
    public void certificate_fciBoundedReadReturnsNonDer_fallsBackToEofLoop() throws Exception {
        // Plausible declared size, but the card delivers something that isn't
        // a certificate. The bounded read is discarded rather than returned.
        byte[] notDer = new byte[260];
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, Hex.decode("80020104"))
                .respondTo(0x00, 0xB0, notDer)               // bounded read, 260 zero bytes
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xB0, certContent)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(certContent);
    }

    @Test
    public void certificate_cardRejectsFciSelect_fallsBackToEofLoop() throws Exception {
        // A card that answers P2 = 0x04 with an error SW (6A 86 = wrong P1/P2)
        // must not fail the read: the probe is surface the pre-FCI code never
        // touched, so a card-level "no" falls back instead of propagating.
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT MAIN AID
                .throwOn(0x00, 0xA4, new ApduResponseException((byte) 0x6A, (byte) 0x86))
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT MAIN AID (retry)
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT cert, P2 = 0x0C
                .respondTo(0x00, 0xB0, certContent)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(certContent);
        CommandStubReader.assertHeader(stub.captured.get(1), 0x00, 0xA4, 0x09, 0x04);
        CommandStubReader.assertHeader(stub.captured.get(3), 0x00, 0xA4, 0x09, 0x0C);
    }

    @Test
    public void certificate_cardRejectsFciBoundedRead_fallsBackToEofLoop() throws Exception {
        // Probe accepted and the size looks fine, but READ BINARY is refused
        // (69 86 = no current EF — a card that returned the FCP without
        // actually selecting the EF). Same treatment: retry canonically.
        byte[] certContent = derCertificate(256);
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, Hex.decode("80020104"))
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x69, (byte) 0x86))
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xB0, certContent)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(certContent);
        CommandStubReader.assertHeader(stub.captured.get(2), 0x00, 0xB0, 0x00, 0x00);
        CommandStubReader.assertHeader(stub.captured.get(4), 0x00, 0xA4, 0x09, 0x0C);
    }

    @Test
    public void certificate_transportFailure_propagatesWithoutFallback() throws Exception {
        // Not a card-level rejection: an SM/transport failure would fail on the
        // canonical path too, so it must surface instead of being swallowed
        // into a retry that hides the cause.
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])
                .throwOn(0x00, 0xA4, new SmartCardReaderException("SM failure"));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        SmartCardReaderException ex = assertThrows(SmartCardReaderException.class,
                () -> token.certificate(CertificateType.AUTHENTICATION));
        assertThat(ex).isNotInstanceOf(ApduResponseException.class);
        assertThat(ex).hasMessageThat().isEqualTo("SM failure");
        // Only SELECT MAIN AID + the failed probe — no canonical retry.
        assertThat(stub.captured).hasSize(2);
    }

    @Test
    public void certificate_afterFciFallback_skipsFciProbeForRestOfSession() throws Exception {
        // The FCI verdict is remembered per token instance (= per card
        // session): having learned that this card's FCI is unusable, the
        // second cert read emits the pre-FCI sequence only — no P2 = 0x04
        // SELECT, so no wasted round-trip.
        byte[] authCert = derCertificate(256);
        byte[] signCert = derCertificate(300);
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT MAIN AID
                .respondTo(0x00, 0xA4, Hex.decode("62088002000183023401"))  // FCP, size = 1
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT MAIN AID (retry)
                .respondTo(0x00, 0xA4, new byte[0])                     // SELECT cert, P2 = 0x0C
                .respondTo(0x00, 0xB0, authCert)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00))
                .respondTo(0x00, 0xA4, new byte[0])                     // 2nd read: SELECT MAIN AID
                .respondTo(0x00, 0xA4, new byte[0])                     // 2nd read: SELECT cert, P2 = 0x0C
                .respondTo(0x00, 0xB0, signCert)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        assertThat(token.certificate(CertificateType.AUTHENTICATION)).isEqualTo(authCert);
        int afterFirstRead = stub.captured.size();
        assertThat(token.certificate(CertificateType.SIGNING)).isEqualTo(signCert);

        // Second read: SELECT MAIN AID, SELECT cert (P2 = 0x0C), READ, READ(6B00).
        CommandStubReader.assertHeader(stub.captured.get(afterFirstRead), 0x00, 0xA4, 0x04, 0x0C);
        CommandStubReader.Apdu certSelect = stub.captured.get(afterFirstRead + 1);
        CommandStubReader.assertHeader(certSelect, 0x00, 0xA4, 0x09, 0x0C);
        assertThat(certSelect.data).isEqualTo(Hex.decode("ADF2341F"));
        CommandStubReader.assertHeader(stub.captured.get(afterFirstRead + 2), 0x00, 0xB0, 0x00, 0x00);
        assertThat(stub.captured).hasSize(afterFirstRead + 4);
    }

    @Test
    public void certificate_fciAbsent_fallsBackToEofLoop() throws Exception {
        // No tag 80/81 in FCI → switch to canonical READ BINARY loop until
        // 6B 00. Single-chunk payload here; multi-chunk variant below proves
        // the loop doesn't silently truncate past a fixed size.
        byte[] payloadChunk = new byte[] {0x01, 0x02, 0x03};
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, Hex.decode("AA0511223344"))   // unrelated tag
                .respondTo(0x00, 0xB0, payloadChunk)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        assertThat(cert).isEqualTo(payloadChunk);
    }

    @Test
    public void certificate_fciAbsent_eofLoopReadsBeyondFciFallbackSize() throws Exception {
        // Regression: with the old "size defaults to 0xE5" form, this would
        // have silently truncated to 229 bytes. The EOF loop reads all chunks
        // until 6B 00 terminates — proves there's no hidden truncation cap.
        byte[] firstChunk = new byte[300];   // bigger than the old 0xE5 cap
        for (int i = 0; i < firstChunk.length; i++) {
            firstChunk[i] = (byte) (i & 0xFF);
        }
        byte[] secondChunk = new byte[]{(byte) 0xAA, (byte) 0xBB};
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, Hex.decode("AA0511223344"))   // unrelated tag, no size
                .respondTo(0x00, 0xB0, firstChunk)
                .respondTo(0x00, 0xB0, secondChunk)
                .throwOn(0x00, 0xB0, new ApduResponseException((byte) 0x6B, (byte) 0x00));
        IdemiaWithPace token = new IdemiaWithPace(stub.build());

        byte[] cert = token.certificate(CertificateType.AUTHENTICATION);

        // Both chunks delivered, then 6B 00 terminated cleanly. 302 > 229
        // proves we're past the old fallback size.
        assertThat(cert).hasLength(302);
        assertThat(cert[0]).isEqualTo((byte) 0x00);
        assertThat(cert[299]).isEqualTo((byte) (299 & 0xFF));
        assertThat(cert[300]).isEqualTo((byte) 0xAA);
        assertThat(cert[301]).isEqualTo((byte) 0xBB);
    }

    /** Stub for the FCI fast path: SELECT MAIN AID, SELECT cert (FCI), reads. */
    private static CommandStubReader fciCertReadStub(String fciHex, byte[] cert) {
        CommandStubReader stub = new CommandStubReader()
                .respondTo(0x00, 0xA4, new byte[0])
                .respondTo(0x00, 0xA4, Hex.decode(fciHex));
        for (int offset = 0; offset < cert.length; offset += 0xE5) {
            int end = Math.min(cert.length, offset + 0xE5);
            stub.respondTo(0x00, 0xB0, Arrays.copyOfRange(cert, offset, end));
        }
        return stub;
    }

    /**
     * DER-shaped certificate stand-in: SEQUENCE header with a 2-byte length
     * followed by {@code contentLength} filler bytes. Only the outer framing
     * matters — {@code Idemia} checks the DER envelope, not the content.
     */
    private static byte[] derCertificate(int contentLength) {
        byte[] cert = new byte[4 + contentLength];
        cert[0] = 0x30;
        cert[1] = (byte) 0x82;
        cert[2] = (byte) (contentLength >> 8);
        cert[3] = (byte) contentLength;
        Arrays.fill(cert, 4, cert.length, (byte) 0x41);
        return cert;
    }

    /** GET DATA stub payload: {@code totalLen} bytes, retry byte at index 13. */
    private static byte[] padded(int totalLen, int retryByteAtIndex13) {
        byte[] out = new byte[totalLen];
        out[13] = (byte) retryByteAtIndex13;
        return out;
    }
}
