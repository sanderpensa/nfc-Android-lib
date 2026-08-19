package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

/**
 * The two Latvian personalisations describing their own keys, replayed from
 * device captures — the 2026 EC card and the 2020 RSA one.
 *
 * <p>These are the bytes the whole dynamic-resolution design rests on, so they
 * are pinned here rather than only exercised through a card session. Between them
 * they cover every difference that a hardcoded profile gets wrong: key
 * references, key type, which algorithm a key may use, the width of an algorithm
 * reference, and whether the card will build the PKCS#1 encoding or expects the
 * caller to.
 */
public final class Pkcs15SecurityEnvironmentTest {

    // ---- the EC card: its answers must match the constants that already work ----

    @Test
    public void ecCard_signingKeyNamesOneAlgorithm_theOneTheProfileSends() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(LvCardMetadata.TOKEN_INFO));
        Pkcs15SecurityEnvironment.Key key = onlyKey(LvCardMetadata.SIGN_PRKD);

        assertThat(key.rsa).isFalse();
        assertThat(key.keyReference).isEqualTo((byte) 0x9E);
        assertThat(key.sizeBits).isEqualTo(384);
        assertThat(key.algorithmEntries).containsExactly(11);

        Pkcs15SecurityEnvironment.Algorithm signing = table.get(11);
        assertThat(Hex.toHexString(signing.algorithmReference)).isEqualTo("54");
        assertThat(Hex.toHexString(signing.mseSetObject())).isEqualTo("800154");
        assertThat(signing.supports(Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE))
                .isTrue();
        // ecdsa-with-SHA384 names its hash, so the card encodes; we send the digest.
        assertThat(signing.needsHostDigestInfo()).isFalse();
    }

    @Test
    public void ecCard_authenticationKeyOffersTheHashlessRow() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(LvCardMetadata.TOKEN_INFO));
        Pkcs15SecurityEnvironment.Key key = onlyKey(LvCardMetadata.AUTH_PRKD);

        assertThat(key.keyReference).isEqualTo((byte) 0x82);
        assertThat(key.algorithmEntries).containsExactly(7, 8, 9, 10, 11, 12, 13).inOrder();
        assertThat(Hex.toHexString(table.get(7).mseSetObject())).isEqualTo("800104");
        // The last row is key agreement and must never be picked for signing.
        assertThat(table.get(13).supports(
                Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE)).isFalse();
    }

    /**
     * The rows are numbered in BCD while the key directory references them in
     * binary, so entry ten is written {@code 0x10} in one file and {@code 0x0a} in
     * the other. Both readings have to reach the same row.
     */
    @Test
    public void ecCard_rowsAreReachableUnderBothNumberings() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(LvCardMetadata.TOKEN_INFO));

        assertThat(table.get(10)).isNotNull();
        assertThat(Hex.toHexString(table.get(10).algorithmReference)).isEqualTo("44");
        assertThat(table.get(0x10)).isSameInstanceAs(table.get(10));
    }

    // ---- the RSA card: every one of these differs from the EC card ----

    @Test
    public void rsaCard_signingKeyResolvesToSha256WithRsa() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(RsaCardMetadata.TOKEN_INFO_OBERTHUR));
        Pkcs15SecurityEnvironment.Key key = onlyKey(RsaCardMetadata.SIGN_PRKD);

        assertThat(key.rsa).isTrue();
        assertThat(key.keyReference).isEqualTo((byte) 0x9F);
        assertThat(key.sizeBits).isEqualTo(2048);
        assertThat(key.algorithmEntries).containsExactly(2);

        Pkcs15SecurityEnvironment.Algorithm signing = table.get(2);
        assertThat(Hex.toHexString(signing.mseSetObject())).isEqualTo("800142");
        // The row names SHA-256, so RS256 is the card's own choice, not a guess.
        assertThat(signing.oid).isEqualTo("1.2.840.113549.1.1.11");
        assertThat(signing.needsHostDigestInfo()).isFalse();
    }

    /**
     * The authentication key can only do raw RSA. That is the load-bearing
     * difference: the card will not build the DigestInfo, so the caller must, or
     * the signature will not verify as RS256.
     */
    @Test
    public void rsaCard_authenticationKeyIsRawRsaAndNeedsAHostDigestInfo() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(RsaCardMetadata.TOKEN_INFO_OBERTHUR));
        Pkcs15SecurityEnvironment.Key key = onlyKey(RsaCardMetadata.AUTH_PRKD);

        assertThat(key.rsa).isTrue();
        assertThat(key.keyReference).isEqualTo((byte) 0x81);
        assertThat(key.algorithmEntries).containsExactly(5, 6).inOrder();

        Pkcs15SecurityEnvironment.Algorithm raw = table.get(5);
        assertThat(Hex.toHexString(raw.mseSetObject())).isEqualTo("800102");
        assertThat(raw.oid).isEqualTo("1.2.840.113549.1.1.1");
        assertThat(raw.needsHostDigestInfo()).isTrue();
        assertThat(raw.supports(Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE)).isTrue();

        // The other row it offers is for decipher only.
        Pkcs15SecurityEnvironment.Algorithm decipher = table.get(6);
        assertThat(decipher.supports(
                Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE)).isFalse();
        assertThat(decipher.supports(Pkcs15SecurityEnvironment.OPERATION_DECIPHER)).isTrue();
    }

    /** The 2020 card uses the four-byte reference form for its EC rows. */
    @Test
    public void rsaCard_carriesFourByteAlgorithmReferences() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(RsaCardMetadata.TOKEN_INFO_OBERTHUR));

        assertThat(Hex.toHexString(table.get(7).algorithmReference)).isEqualTo("ff200800");
        assertThat(Hex.toHexString(table.get(7).mseSetObject())).isEqualTo("8004ff200800");
    }

    // ---- robustness: nothing here may throw on a card that answers oddly ----

    @Test
    public void malformedOrEmptyInputYieldsNothingRatherThanThrowing() {
        assertThat(Pkcs15SecurityEnvironment.algorithms(new byte[0])).isEmpty();
        assertThat(Pkcs15SecurityEnvironment.algorithms(new byte[] {0x30, 0x7F})).isEmpty();
        assertThat(Pkcs15SecurityEnvironment.keys(new byte[] {(byte) 0xA0, 0x7F})).hasSize(1);
        assertThat(Pkcs15SecurityEnvironment.privateKeyDirectoryId(new byte[] {0x30})).isNull();
    }

    /** A read cut short still yields every row in front of the cut. */
    @Test
    public void aTruncatedTokenInfoStillYieldsTheRowsItGotTo() {
        byte[] full = bytes(LvCardMetadata.TOKEN_INFO);
        byte[] cut = java.util.Arrays.copyOf(full, 400);

        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(cut);

        assertThat(table).isNotEmpty();
        assertThat(Hex.toHexString(table.get(2).algorithmReference)).isEqualTo("42");
        assertThat(table.get(13)).isNull();
    }

    @Test
    public void objectDirectoryNamesThePrivateKeyDirectory() {
        assertThat(Hex.toHexString(
                Pkcs15SecurityEnvironment.privateKeyDirectoryId(bytes(LvCardMetadata.OBERTHUR_EF_OD))))
                .isEqualTo("7002");
    }

    /**
     * A row's own reference number wins over another row's BCD alias for the same
     * number. Contrived — no observed table mixes the two numberings — but the
     * indexing must not depend on which row came first.
     */
    @Test
    public void aDirectReferenceIsNotShadowedByAnEarlierRowsBcdAlias() {
        // Row 0x13 (alias 13) declared first, then a row whose own number is 0x0d.
        String rowThirteen = row("13", "1050", "0b");
        String rowZeroD = row("0d", "1044", "44");
        String table = wrap(rowThirteen + rowZeroD);

        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> parsed =
                Pkcs15SecurityEnvironment.algorithms(bytes(table));

        // 13 is 0x0d's own number, so it must resolve to that row, not the alias.
        assertThat(Hex.toHexString(parsed.get(0x0d).algorithmReference)).isEqualTo("44");
        assertThat(Hex.toHexString(parsed.get(13).algorithmReference)).isEqualTo("44");
        // 0x13 keeps its own direct entry.
        assertThat(Hex.toHexString(parsed.get(0x13).algorithmReference)).isEqualTo("0b");
    }

    /** {@code AlgorithmInfo} with the fields the parser reads, as hex. */
    private static String row(String reference, String algorithm, String algRef) {
        String body = "02" + len(reference) + reference
                + "02" + len(algorithm) + algorithm
                + "0500" + "03020051" + "06092a864886f70d01010b"
                + "02" + len(algRef) + algRef;
        return "30" + len(body) + body;
    }

    private static String wrap(String rows) {
        String a2 = "a2" + len(rows) + rows;
        return "30" + len(a2) + a2;
    }

    private static String len(String hex) {
        return String.format("%02x", hex.length() / 2);
    }

    /**
     * An RSA row is only usable if we know what the card will encode. Plain
     * {@code rsaEncryption} and the SHA-2 rows qualify; {@code sha1WithRSAEncryption}
     * does not, and it is on the Latvian table at row 1.
     */
    @Test
    public void onlyRsaRowsWhoseEncodingIsKnownAreUsable() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(RsaCardMetadata.TOKEN_INFO_OBERTHUR));

        // Row 5: plain rsaEncryption — the caller encodes.
        assertThat(table.get(5).rsaEncodingIsUnderstood()).isTrue();
        // Row 2: sha256WithRSAEncryption — the card encodes, and we know the digest.
        assertThat(table.get(2).rsaEncodingIsUnderstood()).isTrue();
        // Row 1: sha1WithRSAEncryption — the card would encode a hash we do not map.
        assertThat(table.get(1).oid).isEqualTo("1.2.840.113549.1.1.5");
        assertThat(table.get(1).rsaEncodingIsUnderstood()).isFalse();
    }

    /**
     * The same predicate must not be applied to EC rows. Latvian EC keys resolve
     * through {@code ecPublicKey}, whose OID names no hash and is not mapped — ECDSA
     * encodes no hash identifier, so there is nothing to get wrong.
     */
    @Test
    public void theEcRowLatvianKeysActuallyUseWouldFailTheRsaPredicate() {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(bytes(LvCardMetadata.TOKEN_INFO));

        assertThat(table.get(7).oid).isEqualTo("1.2.840.10045.1.2.1");
        assertThat(table.get(7).rsaEncodingIsUnderstood()).isFalse();
        // …and it is nonetheless the row the working profile sends.
        assertThat(Hex.toHexString(table.get(7).mseSetObject())).isEqualTo("800104");
    }

    // ---- what a row says about the operations it allows ----

    /**
     * A row carrying {@code supportedOperations} with no bits set has said it
     * supports nothing, and must not be selected for anything.
     *
     * <p>Distinct from the row below, which omits the field: {@code 03 01 00} is an
     * answer and an absent field is not, so they cannot both be read permissively.
     * No captured card has an empty one — this pins the reading, not a behaviour
     * anyone has seen.
     */
    @Test
    public void aRowThatSupportsNothingIsSelectedForNothing() {
        Pkcs15SecurityEnvironment.Algorithm row = Pkcs15SecurityEnvironment
                .algorithms(bytes("301da21b3019020102020140050003010006092a864886f70d01010b020142"))
                .get(2);

        assertThat(row.supports(Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE)).isFalse();
        assertThat(row.supports(Pkcs15SecurityEnvironment.OPERATION_DECIPHER)).isFalse();
        assertThat(row.supports(Pkcs15SecurityEnvironment.OPERATION_DERIVE_KEY)).isFalse();
    }

    /**
     * A row that omits the field entirely stays usable — refusing it would reject a
     * card for leaving out something optional.
     */
    @Test
    public void aRowThatSaysNothingAboutOperationsStaysUsable() {
        Pkcs15SecurityEnvironment.Algorithm row = Pkcs15SecurityEnvironment
                .algorithms(bytes("301aa2183016020102020140050006092a864886f70d01010b020142"))
                .get(2);

        assertThat(row.supports(Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE)).isTrue();
        assertThat(row.supports(Pkcs15SecurityEnvironment.OPERATION_DECIPHER)).isTrue();
    }

    private static Pkcs15SecurityEnvironment.Key onlyKey(String privateKeyDirectory) {
        List<Pkcs15SecurityEnvironment.Key> keys =
                Pkcs15SecurityEnvironment.keys(bytes(privateKeyDirectory));
        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).isUsable()).isTrue();
        return keys.get(0);
    }

    // ---- a file that nests further than any card has ----

    /**
     * A pathologically nested file is walked to a fixed depth and no further.
     *
     * <p>The walk is otherwise bounded only by how much was read, and nothing
     * bounds that: about twelve kilobytes of nested containers overflows the stack
     * on a thread with a 512 KB one. That matters because {@code
     * StackOverflowError} is an {@link Error}, so it would pass the {@code catch
     * (Exception)} that turns an unreadable file into a card that cannot sign —
     * and pass the consumer's, and the demo application's, and take the NFC
     * callback thread with it.
     *
     * <p>Nothing on record comes close: every captured file is three to six deep.
     * The depth this pins is a ceiling, not a shape any card has.
     */
    @Test
    public void aFileNestedFurtherThanAnyCardIsWalkedToTheCapAndNoFurther() {
        byte[] deep = nested(4000);

        List<Pkcs15SecurityEnvironment.Field> fields =
                Pkcs15SecurityEnvironment.allFields(deep);

        // One field per level followed, and the walk stops rather than dying.
        assertThat(fields).hasSize(32);
    }

    /** Real files stay well inside the cap, so the walk still sees all of them. */
    @Test
    public void everyCapturedFileIsNowhereNearTheCap() {
        for (String file : new String[] {
                LvCardMetadata.TOKEN_INFO, LvCardMetadata.OBERTHUR_EF_OD,
                LvCardMetadata.AUTH_PRKD, LvCardMetadata.QSCD_EF_OD, LvCardMetadata.SIGN_PRKD,
                RsaCardMetadata.TOKEN_INFO_OBERTHUR, RsaCardMetadata.TOKEN_INFO_QSCD,
                RsaCardMetadata.AUTH_EF_OD, RsaCardMetadata.AUTH_PRKD,
                RsaCardMetadata.QSCD_EF_OD, RsaCardMetadata.SIGN_PRKD}) {
            assertThat(depthOf(bytes(file))).isAtMost(8);
        }
    }

    /**
     * The key-size walk stops at the same depth, and a card is still read.
     *
     * <p>Capping {@link Pkcs15SecurityEnvironment#allFields} alone left this
     * reachable: {@code keys()} descends into a {@code [1]} whose children are not
     * all integers, and that walk had no cap. The guard in front of it inspects
     * only immediate children, so a {@code [1]} holding one nested SEQUENCE goes
     * straight past. Measured before the cap: 3,000 levels overflowed a 512 KB
     * stack through this path, with {@code allFields} already bounded.
     *
     * <p>What the card gets is a key it can still use — only the size, which is
     * read by nothing but the debug line, goes unresolved.
     */
    @Test
    public void aKeyNestedFurtherThanTheCapIsStillReadButItsSizeIsNot() {
        List<Pkcs15SecurityEnvironment.Key> keys =
                Pkcs15SecurityEnvironment.keys(privateKeyDirectoryNested(4000));

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).sizeBits).isNull();
    }

    /** The same shape within the cap still resolves the size, so the cap is the only difference. */
    @Test
    public void aKeyNestedWithinTheCapStillResolvesItsSize() {
        List<Pkcs15SecurityEnvironment.Key> keys =
                Pkcs15SecurityEnvironment.keys(privateKeyDirectoryNested(4));

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).sizeBits).isEqualTo(2048);
    }

    /**
     * One PrKD entry whose {@code [1]} holds an INTEGER {@code depth} SEQUENCEs
     * down — the shape the key-size walk follows.
     */
    private static byte[] privateKeyDirectoryNested(int depth) {
        byte[] inner = tlv(0x02, new byte[] {0x08, 0x00});
        for (int i = 0; i < depth; i++) {
            inner = tlv(0x30, inner);
        }
        return tlv(0x30, tlv(0xA1, inner));
    }

    private static byte[] tlv(int tag, byte[] value) {
        byte[] header;
        int length = value.length;
        if (length <= 0x7F) {
            header = new byte[] {(byte) tag, (byte) length};
        } else if (length <= 0xFF) {
            header = new byte[] {(byte) tag, (byte) 0x81, (byte) length};
        } else {
            header = new byte[] {(byte) tag, (byte) 0x82, (byte) (length >> 8), (byte) length};
        }
        byte[] out = new byte[header.length + length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(value, 0, out, header.length, length);
        return out;
    }

    /** {@code depth} nested constructed tags, correctly length-encoded. */
    private static byte[] nested(int depth) {
        byte[] inner = new byte[0];
        for (int i = 0; i < depth; i++) {
            byte[] header;
            int length = inner.length;
            if (length <= 0x7F) {
                header = new byte[] {(byte) 0xA0, (byte) length};
            } else if (length <= 0xFF) {
                header = new byte[] {(byte) 0xA0, (byte) 0x81, (byte) length};
            } else {
                header = new byte[] {(byte) 0xA0, (byte) 0x82,
                        (byte) (length >> 8), (byte) length};
            }
            byte[] next = new byte[header.length + length];
            System.arraycopy(header, 0, next, 0, header.length);
            System.arraycopy(inner, 0, next, header.length, length);
            inner = next;
        }
        return inner;
    }

    private static int depthOf(byte[] data) {
        int deepest = 0;
        for (Pkcs15SecurityEnvironment.Field field : Pkcs15SecurityEnvironment.fieldsOf(data)) {
            int here = 1 + ((field.tag & 0x20) != 0 ? depthOf(field.value) : 0);
            deepest = Math.max(deepest, here);
        }
        return deepest;
    }

    private static byte[] bytes(String hex) {
        return Hex.decode(hex);
    }
}
