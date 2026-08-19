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
 * <p>Thrown before anything reaches the card, which is the point of it: the
 * alternative is discovering the mismatch at {@code MSE:SET} time, after a PIN
 * has already been spent on a signature that was never going to verify.
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
