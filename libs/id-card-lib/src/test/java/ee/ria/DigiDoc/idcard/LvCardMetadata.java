package ee.ria.DigiDoc.idcard;

import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

/**
 * The PKCS#15 metadata a Latvian card answers with, for fixtures that need to get
 * past resolution to reach the operation they are actually testing.
 *
 * <p>Latvian cards read their algorithm and key references from the card, so any
 * replay of a Latvian signing flow has to include that read. These bytes are from a
 * TeID2 capture on 2026-08-18 and resolve to {@code 80 01 04} with key {@code 0x82}
 * for authentication and {@code 80 01 54} with {@code 0x9e} for signing — the values
 * the older captures were taken with, which is what makes splicing them in sound.
 *
 * <p>That splice is worth naming: the session bytes in those tests come from
 * captures made before the library asked, so the metadata here is from a later
 * capture of the same card model rather than from the same tap. It is real, and it
 * is consistent with what those sessions sent, but it is not from the same session.
 */
final class LvCardMetadata {

    private LvCardMetadata() {}

    static final String TOKEN_INFO =
            "3082021a0201010c064944454d4941800a4c617476696120654944030205e030"
                    + "7e30150201020410a000000077010800070000fe0000010030150201030410a0"
                    + "00000077010800070000fe000001003012020102040de828bd080ff2504f5420"
                    + "4157503012020103040de828bd080ff2504f54204157503012020104040de828"
                    + "bd080ff2504f54204157503012020105040de828bd080ff2504f5420415750a2"
                    + "820168301a02010102010605000302005106092a864886f70d01010502011230"
                    + "1a02010202014005000302005106092a864886f70d01010b020142301a020103"
                    + "02014105000302005106092a864886f70d01010c020152301a02010402014205"
                    + "000302005106092a864886f70d01010d020162301a0201050201010500030200"
                    + "5106092a864886f70d010101020102301a02010602010105000302000d06092a"
                    + "864886f70d01010102011a301a0201070202104105000302005106082a8648ce"
                    + "3d01020102010430190201080202104205000302005106072a8648ce3d040102"
                    + "0114301a0201090202104305000302005106082a8648ce3d040301020134301a"
                    + "0201100202104405000302005106082a8648ce3d040302020144301a02011102"
                    + "02104505000302005106082a8648ce3d040303020154301a0201120202104605"
                    + "000302005106082a8648ce3d0403040201643017020113020210500500030200"
                    + "0106052b8104010c02010ba511180f32303236303231363134313734345a";
    static final String OBERTHUR_EF_OD =
            "a806300404027001a006300404027002a106300404027004a406300404027005"
                    + "a706300404027006";
    static final String AUTH_PRKD =
            "a0818c30370c1141757468656e7469636174696f6e2030320302078004010130"
                    + "1b30060302078005003008030306004004010130070302000104010130450420"
                    + "7fa0d77dd8d3ca85d1a9429f77494e781680c1a0fde27100b041e9b377b9f5aa"
                    + "03020274030203b802020082a11502010702010802010902010a02010b02010c"
                    + "02010da10a30083002040002020180";
    static final String QSCD_EF_OD =
            "a806300404027011a006300404027012a106300404027014a406300404027015"
                    + "a706300404027016";
    static final String SIGN_PRKD =
            "a06730230c0c5369676e61747572652031450302078004010502010130093007"
                    + "030202040401053034042096d928a12b1db6b41222ba2a92b8efc1883b284f0a"
                    + "861943aa6593f9cc8cc38c0303062040030203b80202009ea10302010ba10a30"
                    + "083002040002020180";

    /** The reads resolution makes under the Oberthur applet, plus its re-select. */
    static void scriptOberthur(ApduReplayReader r) {
        r.expectFileRead("5032", TOKEN_INFO);
        r.expectFileRead("5031", OBERTHUR_EF_OD);
        r.expectFileRead("7002", AUTH_PRKD);
        // The walk left an EF selected, so the applet is selected again.
        r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
    }

    /**
     * The same under QSCD. EF.TokenInfo is only read once per session — it
     * describes the platform, not the applet — so a fixture doing both operations
     * calls {@link #scriptOberthur} first and this one needs no table read.
     */
    static void scriptQscd(ApduReplayReader r, boolean tableAlreadyRead) {
        if (!tableAlreadyRead) {
            r.expectFileRead("5032", TOKEN_INFO);
        }
        r.expectFileRead("5031", QSCD_EF_OD);
        r.expectFileRead("7012", SIGN_PRKD);
        r.expect(TestApdus.SEL_QSCD_AID, ok());
    }

    /** Just the algorithm table, for fixtures that stop before the key directory. */
    static void scriptTokenInfoOnly(ApduReplayReader r) {
        r.expectFileRead("5032", TOKEN_INFO);
    }

    /** An EF.OD of the caller's choosing, for testing what a short one does. */
    static void scriptObjectDirectory(ApduReplayReader r, String content) {
        r.expectFileRead("5031", content);
    }

    /** An EF.TokenInfo of the caller's choosing. */
    static void scriptTokenInfo(ApduReplayReader r, String content) {
        r.expectFileRead("5032", content);
    }

    /** A private key directory of the caller's choosing. */
    static void scriptPrivateKeyDirectory(ApduReplayReader r, String fileId, String content) {
        r.expectFileRead(fileId, content);
    }

}
