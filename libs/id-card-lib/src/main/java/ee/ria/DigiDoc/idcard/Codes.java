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

/** Turning a PIN or PUK into the fixed-width field the card expects. */
final class Codes {

    /**
     * Every code travels in a twelve-byte field, right-padded with a filler
     * byte the model chooses ({@code 0xFF} on IDEMIA, {@code 0x00} on Thales).
     */
    private static final int FIELD_LENGTH = 12;

    private Codes() {}

    /**
     * {@code code}, right-padded to twelve bytes with {@code pad}.
     *
     * <p>A code must be between one byte and the width of the field. Both ends
     * are refused rather than fudged, because both produce something the card
     * will read as a code that the caller never meant:
     *
     * <ul>
     *   <li><b>Empty</b> pads to twelve filler bytes — a structurally perfect
     *       command, so the card compares it, fails, and spends one of the
     *       user's retries. On a change or unblock it is stored as the new
     *       code, which no keypad can then reproduce.</li>
     *   <li><b>Longer than the field</b> cannot be represented at all, and on a
     *       change the field is a concatenation of two of these, so an
     *       over-long first code shifts the second one past a boundary the
     *       card still expects to be there.</li>
     * </ul>
     *
     * <p>Nothing between those ends is checked. Minimum lengths are card
     * policy and differ by model and code type, so guessing at them here would
     * reject codes some cards accept.
     */
    static byte[] padded(byte[] code, byte pad) throws CodeFormatException {
        int length = code == null ? 0 : code.length;
        if (length == 0 || length > FIELD_LENGTH) {
            throw new CodeFormatException("PIN/PUK must be 1-" + FIELD_LENGTH
                    + " bytes to fit the code field, but was " + length);
        }
        byte[] padded = Arrays.copyOf(code, FIELD_LENGTH);
        Arrays.fill(padded, length, FIELD_LENGTH, pad);
        return padded;
    }
}
