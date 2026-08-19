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

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

/**
 * A PIN or PUK was handed to the library in a shape that cannot go in the
 * card's twelve-byte code field — empty, or longer than the field.
 *
 * <p>Thrown before the code reaches the card, which is the point of it: no VERIFY,
 * CHANGE or UNBLOCK goes out, so no retry is spent and nothing is stored. The
 * operation may already have selected an applet or read metadata by then — what
 * matters is that the malformed code itself never leaves. Codes
 * are sent right-padded to twelve bytes, so an empty one would become twelve
 * padding bytes — a perfectly well-formed command that the card cannot tell
 * apart from a real attempt, because the padding is applied here rather than
 * on the card. On a VERIFY that costs the user a retry. On a change or unblock
 * it is worse: the card <em>stores</em> those twelve bytes, leaving a code no
 * keypad can reproduce and which only another unblock can clear.
 *
 * <p>This is a caller error rather than a card condition, but it is checked
 * (via {@link SmartCardReaderException}) deliberately: on Android these calls
 * run on the NFC callback thread, where an unchecked exception surfaces as an
 * opaque "uncaught remote exception" and leaves the UI waiting. Existing
 * {@code catch (SmartCardReaderException)} handlers report it instead.
 *
 * <p>Only the field's own limits are checked. Minimum lengths are card policy
 * and differ by model and code type, so the library does not guess at them — a
 * caller that knows its card should validate before calling.
 */
public class CodeFormatException extends SmartCardReaderException {

    CodeFormatException(String message) {
        super(message);
    }
}
