package ee.ria.DigiDoc.idcard;

import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

/**
 * What the 2020 Latvian RSA card answers when asked to describe its keys, captured
 * 2026-08-19 — the card behind "LV eID ICA 2021", RSA-2048.
 *
 * <p>One home for these bytes because four test classes had grown their own copy,
 * and two copies of a card's answer can disagree. What this card says is the basis
 * for most of the RSA behaviour in the library, so it should say it once:
 *
 * <ul>
 *   <li>its <b>authentication key</b> is {@code 0x81} and offers only raw
 *       {@code rsaEncryption}, so it names no hash and the caller must build the
 *       {@code DigestInfo};</li>
 *   <li>its <b>signing key</b> is {@code 0x9F} and names
 *       {@code sha256WithRSAEncryption}, so RS256 there is the card's own statement
 *       and it builds the encoding itself.</li>
 * </ul>
 *
 * <p>The two EF.OD constants happen to be byte-identical to the EC card's in
 * {@link LvCardMetadata} — the object directory is a fixed structure that does not
 * vary by personalisation — but they are kept separately on purpose. Sharing them
 * would tie two physical cards' captures together, so a future card that did differ
 * would read as a bug in whichever test broke first.
 *
 * <p>Only the PKCS#15 files are here. Certificates are not: they carry a
 * cardholder's name and personal code, and no test needs more than the public
 * modulus, which {@code LatviaIdemiaRsaSessionReplayTest} embeds directly.
 */
final class RsaCardMetadata {

    private RsaCardMetadata() {}

    static final String TOKEN_INFO_OBERTHUR =
            "3082022f0201010c064944454d4941800a4c617476696120654944030205e030"
                    + "7e30150201020410a000000077010800070000fe0000010030150201030410a0"
                    + "00000077010800070000fe000001003012020102040de828bd080ff2504f5420"
                    + "4157503012020103040de828bd080ff2504f54204157503012020104040de828"
                    + "bd080ff2504f54204157503012020105040de828bd080ff2504f5420415750a2"
                    + "82017d301a02010102010605000302005106092a864886f70d01010502011230"
                    + "1a02010202014005000302005106092a864886f70d01010b020142301a020103"
                    + "02014105000302005106092a864886f70d01010c020142301a02010402014205"
                    + "000302004106092a864886f70d01010d020142301a0201050201010500030200"
                    + "5106092a864886f70d010101020102301a02010602010105000302000d06092a"
                    + "864886f70d01010102011a301c0201070202104105000302005106072a8648ce"
                    + "3d02010204ff200800301c0201080202104205000302005106072a8648ce3d04"
                    + "010204ff110800301d0201090202104305000302005106082a8648ce3d040301"
                    + "0204ff130800301d02010a0202104405000302005106082a8648ce3d04030202"
                    + "04ff140800301d02010b0202104505000302005106082a8648ce3d0403030204"
                    + "ff150800301d02010c0202104605000302005106082a8648ce3d0403040204ff"
                    + "160800301b02010d020210500500030307018006052b8104010c0204ff300400"
                    + "a511180f32303230303930313138333433395a";
    static final String AUTH_EF_OD =
            "a806300404027001a006300404027002a106300404027004a406300404027005"
                    + "a706300404027006";
    static final String AUTH_PRKD =
            "307430370c1141757468656e7469636174696f6e20303103020780040101301b"
                    + "300603020780050030080303060040040101300703020001040101302d041455"
                    + "4dd0b709089a9183650b73d446ee42521e1b3a030202740101ff030203b80202"
                    + "0081a106020105020106a10a30083002040002020800";
    static final String TOKEN_INFO_QSCD =
            "308202410201010c064944454d4941800f4c6174766961206549442051534344"
                    + "030205e030818a30150201020410a000000077010800070000fe000001003015"
                    + "0201030410a000000077010800070000fe000001003015020102041051534344"
                    + "204170706c69636174696f6e3015020103041051534344204170706c69636174"
                    + "696f6e3015020104041051534344204170706c69636174696f6e301502010504"
                    + "1051534344204170706c69636174696f6ea282017d301a020101020106050003"
                    + "02005106092a864886f70d010105020112301a02010202014005000302005106"
                    + "092a864886f70d01010b020142301a02010302014105000302005106092a8648"
                    + "86f70d01010c020142301a02010402014205000302004106092a864886f70d01"
                    + "010d020142301a02010502010105000302005106092a864886f70d0101010201"
                    + "02301a02010602010105000302000d06092a864886f70d01010102011a301c02"
                    + "01070202104105000302005106072a8648ce3d02010204ff200800301c020108"
                    + "0202104205000302005106072a8648ce3d04010204ff110800301d0201090202"
                    + "104305000302005106082a8648ce3d0403010204ff130800301d02010a020210"
                    + "4405000302005106082a8648ce3d0403020204ff140800301d02010b02021045"
                    + "05000302005106082a8648ce3d0403030204ff150800301d02010c0202104605"
                    + "000302005106082a8648ce3d0403040204ff160800301b02010d020210500500"
                    + "030307018006052b8104010c0204ff300400a511180f32303230303930313138"
                    + "333434305a";
    static final String QSCD_EF_OD =
            "a806300404027011a006300404027012a106300404027014a406300404027015"
                    + "a706300404027016";
    static final String SIGN_PRKD =
            "305e30230c0c5369676e61747572652031460302078004010502010130093007"
                    + "03020204040105302b0414681370c2952b62b6efbea087f4e148d7690ae51403"
                    + "030630400101ff030203b80202009fa103020102a10a30083002040002020800";

    /**
     * The reads that resolve the authentication key, under the Oberthur applet,
     * ending with the re-select the walk does to put the applet back.
     */
    static void scriptAuthenticationKey(ApduReplayReader r) {
        r.expectFileRead("5032", TOKEN_INFO_OBERTHUR);
        r.expectFileRead("5031", AUTH_EF_OD);
        r.expectFileRead("7002", AUTH_PRKD);
        r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
    }

    /** The same for the signing key, under QSCD. */
    static void scriptSigningKey(ApduReplayReader r) {
        r.expectFileRead("5032", TOKEN_INFO_QSCD);
        r.expectFileRead("5031", QSCD_EF_OD);
        r.expectFileRead("7012", SIGN_PRKD);
        r.expect(TestApdus.SEL_QSCD_AID, ok());
    }
}
