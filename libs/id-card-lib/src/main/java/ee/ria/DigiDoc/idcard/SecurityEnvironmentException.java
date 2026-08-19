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
 * A card whose keys have to be read from its own metadata would not describe them.
 *
 * <p>Thrown for Latvian cards only, and deliberately rather than falling back to
 * the constants measured for the model. Those constants are demonstrably wrong for
 * at least one Latvian card in circulation — two cards sharing the "SeID" ATS use
 * one-byte and four-byte algorithm references respectively — so there is no set of
 * assumptions that is right for all of them.
 *
 * <p>Guessing would not fail cleanly either. The card accepts <em>any</em>
 * algorithm reference in {@code MSE:SET} with {@code 90 00} — all 256 were tried
 * on one — so a wrong assumption produces a signature that verifies nowhere, with
 * nothing on the card or in the response to say so. Failing here is the only
 * outcome that can be diagnosed.
 *
 * <p>Raised before any PIN is verified, so it costs the user no retry.
 *
 * <p>Estonian cards never reach this: their layout is documented and one pair of
 * key references has served every marking in the field, so they use the measured
 * constants by design.
 */
public class SecurityEnvironmentException extends SmartCardReaderException {

    SecurityEnvironmentException(String message) {
        super(message);
    }
}
