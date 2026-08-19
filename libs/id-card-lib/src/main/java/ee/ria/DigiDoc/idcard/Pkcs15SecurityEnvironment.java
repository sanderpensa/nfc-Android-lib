/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package ee.ria.DigiDoc.idcard;

import org.bouncycastle.util.encoders.Hex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What a card says about its own keys and the algorithms they may be used with,
 * read out of its PKCS#15 files.
 *
 * <p>This exists because two of the three things a {@code MSE:SET} needs cannot
 * be derived from anywhere else. The certificate fixes the hash for an EC key —
 * the curve implies it — but for RSA it fixes nothing: the same 2048-bit key is
 * equally valid with SHA-256, SHA-384 or SHA-512. And the <em>key reference</em>
 * has never been derivable from a certificate for either. Both Latvian
 * personalisations carry the same ATS while using different key references
 * ({@code 0x82}/{@code 0x9E} against {@code 0x81}/{@code 0x9F}), so not even the
 * card's answer to {@code SELECT} distinguishes them. The card's own metadata is
 * the only source that does.
 *
 * <p>Two files answer between them:
 *
 * <ul>
 *   <li><b>EF.TokenInfo</b> ({@code 50 32}) holds {@code supportedAlgorithms}, a
 *       table of {@code AlgorithmInfo}. Each row ends with {@code algRef} — the
 *       payload of the {@code 80 xx} object in {@code MSE:SET} — and says by OID
 *       which algorithm it selects and by bit string which operations it may be
 *       used for.</li>
 *   <li><b>EF.OD</b> ({@code 50 31}) names the private key directory under
 *       {@code [0]}, whose entry per key gives the key reference, the key type,
 *       and the table rows that key is allowed to use.</li>
 * </ul>
 *
 * <p>Parsing only — no card I/O, so it can be tested against captured bytes.
 * Nothing here throws on malformed input: a card that answers something
 * unexpected yields an empty table or no keys, and the caller falls back to the
 * constants measured from real cards.
 *
 * <p>Two encodings have to be tolerated, both observed:
 *
 * <ul>
 *   <li>{@code algRef} is one byte on the 2026 Latvian cards ({@code 0x54}) and
 *       four on the 2020 one ({@code FF 15 08 00}), the form documented for
 *       Estonian IDEMIA — so it is kept as bytes, never an int.</li>
 *   <li>Table rows are numbered in BCD ({@code 01}…{@code 09}, {@code 10}…) while
 *       the key directory references them in binary ({@code 07}…{@code 0d}), so
 *       rows are indexed under both readings.</li>
 * </ul>
 */
final class Pkcs15SecurityEnvironment {

    /** {@code supportedOperations} bit 1, most significant bit first. */
    static final int OPERATION_COMPUTE_SIGNATURE = 0x40;
    /** {@code supportedOperations} bit 5. */
    static final int OPERATION_DECIPHER = 0x04;
    /** {@code supportedOperations} bit 7 — how ECDH key agreement advertises itself. */
    static final int OPERATION_DERIVE_KEY = 0x01;

    /** {@code rsaEncryption} — no hash, so the caller must supply a DigestInfo. */
    private static final String OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

    /** ODF {@code [0]}: the private key directory. */
    private static final int TAG_PRIVATE_KEYS = 0xA0;
    /** TokenInfo {@code [2]}: {@code SEQUENCE OF AlgorithmInfo}. */
    private static final int TAG_SUPPORTED_ALGORITHMS = 0xA2;

    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_INTEGER = 0x02;
    private static final int TAG_BIT_STRING = 0x03;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_OID = 0x06;
    private static final int TAG_UTF8_STRING = 0x0C;
    private static final int TAG_CONTEXT_1 = 0xA1;
    /** A PrKD entry: an untagged SEQUENCE is an RSA key, {@code [0]} is EC. */
    private static final int TAG_PRIVATE_EC_KEY = 0xA0;

    private Pkcs15SecurityEnvironment() {}

    /** One row of {@code supportedAlgorithms}. */
    static final class Algorithm {
        /** {@code AlgorithmInfo.reference}, as written — see the BCD note. */
        final int entry;
        /** {@code algRef}: the payload of the {@code 80 xx} object in MSE:SET. */
        final byte[] algorithmReference;
        final Integer operations;
        final String oid;

        Algorithm(int entry, byte[] algorithmReference, Integer operations, String oid) {
            this.entry = entry;
            this.algorithmReference = algorithmReference;
            this.operations = operations;
            this.oid = oid;
        }

        /**
         * Whether this row may be used for an operation. A row with no
         * {@code supportedOperations} field at all is treated as usable: refusing it
         * would reject a card for omitting an optional field. A row that carries the
         * field but sets no bits has said it supports nothing, and is refused.
         */
        boolean supports(int operationMask) {
            return operations == null || (operations & operationMask) != 0;
        }

        /**
         * Whether the caller has to wrap the digest in a DigestInfo before
         * handing it over.
         *
         * <p>A row naming a hash — {@code sha256WithRSAEncryption} — means the
         * card builds the PKCS#1 encoding itself, so it wants the bare digest.
         * Plain {@code rsaEncryption} means it will sign whatever it is given, so
         * the DigestInfo has to come from here or the signature will not verify
         * as RS256. The 2020 Latvian card's authentication key offers only the
         * plain row, which is why this distinction is load-bearing.
         */
        boolean needsHostDigestInfo() {
            return OID_RSA_ENCRYPTION.equals(oid);
        }

        /**
         * Whether this library knows what an RSA card will do to the input under
         * this row.
         *
         * <p>Two rows are safe: plain {@code rsaEncryption}, where the card adds
         * nothing and the caller builds the {@code DigestInfo}; and a row naming a
         * hash {@link SignatureAlgorithm#forOid} recognises, where the card builds
         * it and we know from which digest. A row naming any other hash — the
         * Latvian table carries {@code sha1WithRSAEncryption} at row 1 — is neither:
         * it would encode a digest we sent as a hash we did not intend, and nothing
         * on the card would say so.
         *
         * <p>Only consulted for RSA keys. ECDSA signs the value it is given without
         * encoding a hash identifier into it, so an unrecognised hash name on an EC
         * row cannot corrupt the input the same way — which matters, because the
         * Latvian EC keys legitimately use {@code ecPublicKey} rows.
         */
        boolean rsaEncodingIsUnderstood() {
            return OID_RSA_ENCRYPTION.equals(oid) || SignatureAlgorithm.forOid(oid) != null;
        }

        /** The complete {@code 80 xx ...} object, ready to concatenate. */
        byte[] mseSetObject() {
            byte[] object = new byte[2 + algorithmReference.length];
            object[0] = (byte) 0x80;
            object[1] = (byte) algorithmReference.length;
            System.arraycopy(algorithmReference, 0, object, 2, algorithmReference.length);
            return object;
        }

        @Override
        public String toString() {
            return String.format("entry 0x%02x, MSE:SET 80 %02x %s, oid %s", entry,
                    algorithmReference.length, Hex.toHexString(algorithmReference), oid);
        }
    }

    /** One entry of the private key directory. */
    static final class Key {
        final boolean rsa;
        final Byte keyReference;
        final Integer sizeBits;
        final List<Integer> algorithmEntries;
        final String label;

        Key(boolean rsa, Byte keyReference, Integer sizeBits,
            List<Integer> algorithmEntries, String label) {
            this.rsa = rsa;
            this.keyReference = keyReference;
            this.sizeBits = sizeBits;
            this.algorithmEntries = algorithmEntries;
            this.label = label;
        }

        boolean isUsable() {
            return keyReference != null && !algorithmEntries.isEmpty();
        }

        @Override
        public String toString() {
            return String.format("%s key%s, keyReference=%s, %s bits, entries=%s",
                    rsa ? "RSA" : "EC", label == null ? "" : " \"" + label + "\"",
                    keyReference == null ? "?" : String.format("0x%02x", keyReference),
                    sizeBits == null ? "?" : sizeBits, algorithmEntries);
        }
    }

    /**
     * The file id of the private key directory, from EF.OD, or {@code null} if it
     * names none.
     */
    static byte[] privateKeyDirectoryId(byte[] objectDirectory) {
        Field container = findField(objectDirectory, TAG_PRIVATE_KEYS);
        if (container == null) {
            return null;
        }
        Field path = findField(container.value, TAG_OCTET_STRING);
        byte[] value = path != null ? path.value : container.value;
        if (value == null || value.length < 2) {
            return null;
        }
        // Paths may be absolute; the file id is the trailing two bytes either way.
        return Arrays.copyOfRange(value, value.length - 2, value.length);
    }

    /**
     * {@code supportedAlgorithms} from EF.TokenInfo, indexed by row number under
     * both the BCD and the binary reading so a key directory can find them either
     * way. Empty when the file carries no table — it is an OPTIONAL field.
     */
    static Map<Integer, Algorithm> algorithms(byte[] tokenInfo) {
        Map<Integer, Algorithm> table = new LinkedHashMap<>();
        List<Algorithm> parsed = new ArrayList<>();
        Field supported = findField(tokenInfo, TAG_SUPPORTED_ALGORITHMS);
        if (supported == null) {
            return table;
        }
        for (Field row : fieldsOf(supported.value)) {
            if (row.tag != TAG_SEQUENCE) {
                continue;
            }
            List<byte[]> integers = new ArrayList<>();
            Integer operations = null;
            String oid = null;
            for (Field field : fieldsOf(row.value)) {
                switch (field.tag) {
                    case TAG_INTEGER -> integers.add(field.value);
                    // A BIT STRING carrying no data bits says the row supports
                    // nothing, which is different from the field being absent: null
                    // means "did not say" and is read permissively below, so an
                    // explicit 03 01 00 must not land there.
                    case TAG_BIT_STRING -> operations =
                            field.value.length > 1 ? field.value[1] & 0xFF : 0;
                    case TAG_OID -> oid = oid(field.value);
                    default -> { }
                }
            }
            // {reference, algorithm, parameters, supportedOperations, objId, algRef}
            // — it is the last integer that goes on the wire, not the first.
            if (integers.size() < 3) {
                continue;
            }
            int entry = unsigned(integers.get(0));
            parsed.add(new Algorithm(
                    entry, integers.get(integers.size() - 1), operations, oid));
        }

        // Two passes, and the order matters. Every row is indexed under its
        // reference byte as written, and again under that byte's BCD reading —
        // this card numbers its table 01..09,10,11,12,13 while the key directory
        // references the same rows in binary, 07..0d, so both readings have to
        // reach the row. Doing it in one pass would let an earlier row's alias
        // occupy a number a later row owns outright: row 0x13's alias is 13, which
        // is also a direct 0x0d. No observed table mixes the two numberings, but if
        // one ever does, the direct reading is the one that should win.
        for (Algorithm row : parsed) {
            table.put(row.entry, row);
        }
        for (Algorithm row : parsed) {
            int decoded = fromBcd(row.entry);
            if (decoded != row.entry) {
                table.putIfAbsent(decoded, row);
            }
        }
        return table;
    }

    /** The keys a private key directory describes, in order. */
    static List<Key> keys(byte[] privateKeyDirectory) {
        List<Key> keys = new ArrayList<>();
        for (Field entry : fieldsOf(privateKeyDirectory)) {
            if (entry.tag != TAG_SEQUENCE && entry.tag != TAG_PRIVATE_EC_KEY) {
                continue;
            }
            keys.add(key(entry.tag == TAG_SEQUENCE, entry.value));
        }
        return keys;
    }

    /**
     * The algorithm references live in a {@code [1]} whose children are all
     * integers, inside {@code CommonKeyAttributes} — a sibling of
     * {@code keyReference} rather than a field of the key itself. The field size
     * is the last integer under the type attributes.
     */
    private static Key key(boolean rsa, byte[] body) {
        List<Integer> entries = new ArrayList<>();
        Byte keyReference = null;

        for (Field container : allFields(body)) {
            if (container.tag != TAG_SEQUENCE) {
                continue;
            }
            Integer lastInteger = null;
            for (Field child : fieldsOf(container.value)) {
                if (child.tag == TAG_INTEGER) {
                    lastInteger = unsigned(child.value);
                } else if (child.tag == TAG_CONTEXT_1 && entries.isEmpty()
                        && onlyIntegers(child.value)) {
                    for (Field reference : fieldsOf(child.value)) {
                        entries.add(unsigned(reference.value));
                    }
                    if (lastInteger != null) {
                        keyReference = (byte) (int) lastInteger;
                    }
                }
            }
        }

        Integer sizeBits = null;
        for (Field field : fieldsOf(body)) {
            if (field.tag == TAG_CONTEXT_1 && !onlyIntegers(field.value)) {
                List<Integer> integers = integersIn(field.value);
                if (!integers.isEmpty()) {
                    sizeBits = integers.get(integers.size() - 1);
                }
            }
        }
        return new Key(rsa, keyReference, sizeBits, entries, firstString(body));
    }

    // ---- DER walking, tolerant of a truncated read ----

    /** One field of a DER value. */
    static final class Field {
        final int tag;
        final byte[] value;

        Field(int tag, byte[] value) {
            this.tag = tag;
            this.value = value;
        }
    }

    /** The immediate children of a DER value, in order. Never throws. */
    static List<Field> fieldsOf(byte[] data) {
        List<Field> fields = new ArrayList<>();
        int i = 0;
        while (data != null && i + 1 < data.length) {
            int tag = data[i++] & 0xFF;
            int length = data[i++] & 0xFF;
            if (length > 0x80) {
                int lengthBytes = length - 0x80;
                if (lengthBytes > 3 || i + lengthBytes > data.length) {
                    break;
                }
                length = 0;
                for (int b = 0; b < lengthBytes; b++) {
                    length = (length << 8) | (data[i++] & 0xFF);
                }
            }
            if (length < 0) {
                break;
            }
            // Clamp rather than give up: a short read still has usable fields in
            // front of the cut, and returning nothing would hide all of them.
            length = Math.min(length, data.length - i);
            fields.add(new Field(tag, Arrays.copyOfRange(data, i, i + length)));
            i += length;
        }
        return fields;
    }

    /** Every field at any depth, outermost first. */
    static List<Field> allFields(byte[] data) {
        List<Field> all = new ArrayList<>();
        for (Field field : fieldsOf(data)) {
            all.add(field);
            // Bit 6 is DER's constructed flag, so this covers SEQUENCE, SET and
            // every [n] container without enumerating them. The previous test
            // (tag & 0xA0) == 0xA0 also matched private-class tags and missed the
            // application-class range; no captured card exercised the difference.
            if ((field.tag & 0x20) != 0) {
                all.addAll(allFields(field.value));
            }
        }
        return all;
    }

    static Field findField(byte[] data, int tag) {
        for (Field field : allFields(data)) {
            if (field.tag == tag) {
                return field;
            }
        }
        return null;
    }

    private static List<Integer> integersIn(byte[] data) {
        List<Integer> integers = new ArrayList<>();
        for (Field field : fieldsOf(data)) {
            if (field.tag == TAG_INTEGER) {
                integers.add(unsigned(field.value));
            } else if (field.tag == TAG_SEQUENCE || field.tag == TAG_CONTEXT_1) {
                integers.addAll(integersIn(field.value));
            }
        }
        return integers;
    }

    private static boolean onlyIntegers(byte[] data) {
        List<Field> fields = fieldsOf(data);
        if (fields.isEmpty()) {
            return false;
        }
        for (Field field : fields) {
            if (field.tag != TAG_INTEGER) {
                return false;
            }
        }
        return true;
    }

    private static String firstString(byte[] data) {
        for (Field field : allFields(data)) {
            if (field.tag == TAG_UTF8_STRING && field.value.length > 0) {
                return new String(field.value, java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    static int unsigned(byte[] value) {
        int result = 0;
        for (byte b : value) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }

    /**
     * A row number read as BCD, or unchanged when it cannot be BCD. {@code 0x13}
     * becomes 13; {@code 0x1a} stays as it is, a nibble above 9 being no decimal
     * digit.
     */
    static int fromBcd(int value) {
        int high = (value >> 4) & 0x0F;
        int low = value & 0x0F;
        if (high > 9 || low > 9) {
            return value;
        }
        return high * 10 + low;
    }

    static String oid(byte[] encoded) {
        if (encoded.length == 0) {
            return null;
        }
        StringBuilder out = new StringBuilder()
                .append((encoded[0] & 0xFF) / 40).append('.').append((encoded[0] & 0xFF) % 40);
        long node = 0;
        for (int i = 1; i < encoded.length; i++) {
            node = (node << 7) | (encoded[i] & 0x7F);
            if ((encoded[i] & 0x80) == 0) {
                out.append('.').append(node);
                node = 0;
            }
        }
        return out.toString();
    }
}
