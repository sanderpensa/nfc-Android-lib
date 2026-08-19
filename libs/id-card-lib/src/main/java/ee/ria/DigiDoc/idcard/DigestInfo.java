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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The PKCS#1 {@code DigestInfo} that has to sit in front of a hash before a card
 * raw-signs it.
 *
 * <p>Needed because an algorithm that names no hash — plain {@code rsaEncryption}
 * — signs exactly the bytes it is given. Hand it a bare digest and the result is
 * {@code RSA(pad(digest))}, which is a perfectly well-formed signature over the
 * wrong value: no RS256 verifier will accept it, and nothing on the card or in
 * the response says why. The 2020 Latvian card's authentication key offers only
 * that algorithm, so this is the difference between a token that validates and
 * one that is rejected with no diagnosis.
 *
 * <p>Where the card's algorithm does name a hash, it builds this itself and must
 * be given the bare digest instead — so this is applied on the strength of what
 * the card said, never by default.
 *
 * <p>The prefixes are the standard RFC 8017 encodings, indexed by digest length,
 * which is the only thing a caller holding an anonymous byte array can key on.
 */
final class DigestInfo {

    /** {@code DigestInfo} prefixes by digest length, RFC 8017 §9.2 note 1. */
    private static final Map<Integer, byte[]> PREFIXES = new LinkedHashMap<>();
    static {
        // SHA-1
        PREFIXES.put(20, new byte[] {
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A,
                0x05, 0x00, 0x04, 0x14});
        // SHA-224
        PREFIXES.put(28, new byte[] {
                0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C});
        // SHA-256
        PREFIXES.put(32, new byte[] {
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20});
        // SHA-384
        PREFIXES.put(48, new byte[] {
                0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30});
        // SHA-512
        PREFIXES.put(64, new byte[] {
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40});
    }

    private DigestInfo() {}

    /**
     * {@code hash} with its {@code DigestInfo} prefix.
     *
     * @throws SignatureAlgorithmException When the length is not one of the SHA-2
     *                                     family's, since guessing the digest
     *                                     algorithm from a wrong length would
     *                                     produce a signature over a structure
     *                                     the verifier does not expect.
     */
    static byte[] wrap(byte[] hash) throws SignatureAlgorithmException {
        byte[] prefix = hash == null ? null : PREFIXES.get(hash.length);
        if (prefix == null) {
            throw new SignatureAlgorithmException(String.format(
                    "Cannot build a DigestInfo for a %d-byte hash: expected 20, 28, 32, 48"
                            + " or 64 bytes (SHA-1 through SHA-512)",
                    hash == null ? 0 : hash.length));
        }
        byte[] wrapped = Arrays.copyOf(prefix, prefix.length + hash.length);
        System.arraycopy(hash, 0, wrapped, prefix.length, hash.length);
        return wrapped;
    }
}
