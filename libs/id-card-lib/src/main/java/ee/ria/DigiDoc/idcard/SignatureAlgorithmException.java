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
 * No signature algorithm could be settled on for a certificate — the key is of
 * a kind this library cannot yet drive, or the certificate did not parse.
 *
 * <p>When it is raised depends on which of three things went wrong, and only the
 * first two are free:
 *
 * <ul>
 *   <li><b>No algorithm could be settled on</b> — an unsupported key, or a
 *       certificate that will not parse. Nothing has reached the card.</li>
 *   <li><b>The digest does not fit the algorithm the key signs with.</b> Raised
 *       while the input is prepared, which happens before the PIN is verified — so
 *       no retry is spent, though the card may already have been read to find out
 *       what the key signs with.</li>
 *   <li><b>The signature did not verify under the card's own certificate</b>
 *       (authentication only, and only where the environment came from the card).
 *       That one costs a retry: it cannot be known until the card has signed.</li>
 * </ul>
 *
 * <p>The first two are the point of the type: the alternative is discovering the
 * mismatch at {@code MSE:SET} time, after a PIN has been spent on a signature that
 * was never going to verify.
 *
 * <p>Checked (via {@link SmartCardReaderException}) for the same reason as
 * {@link CodeFormatException}: on Android these calls run on the NFC callback
 * thread, where an unchecked exception surfaces as an opaque "uncaught remote
 * exception" and leaves the UI waiting.
 */
public class SignatureAlgorithmException extends SmartCardReaderException {

    SignatureAlgorithmException(String message) {
        super(message);
    }

    SignatureAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }
}
