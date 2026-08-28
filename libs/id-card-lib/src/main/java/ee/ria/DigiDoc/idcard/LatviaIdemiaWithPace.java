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
import ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReader;

/**
 * Latvian eID card NFC token.
 * <p>
 * Extends IdemiaWithPace since the Latvian eID uses the same IDEMIA ID-One Cosmo v8
 * platform (IAS-ECC Oberthur) as the Estonian card. PACE, SM, certificate, and PIN
 * operations are inherited.
 * <p>
 * Overrides personalData() for Latvian personal code parsing, provides AID selection
 * fallback, and reads key references from the card's PrKDF for authentication/signing
 * since the Latvian card uses different key slot assignments.
 */
class LatviaIdemiaWithPace extends IdemiaWithPace {

    LatviaIdemiaWithPace(NfcSmartCardReader reader) {
        super(reader);
        // No key references set here. They would only ever be read by
        // measuredSecurityEnvironment, which this class refuses outright — and
        // leaving them would contradict the note below, which is the point: a
        // Latvian value in code is a value someone can apply to the wrong card.
    }

    /**
     * Refused, because there is nothing measured to return.
     *
     * <p>The inherited key references are Estonian ({@code 0x81} / {@code 0x9F}) and
     * so are the inherited {@code MSE:SET} templates. Nothing sets Latvian ones,
     * deliberately — see the constructor — so the inherited implementation would
     * quietly describe an Estonian card and the card would accept it, producing a
     * signature that verifies nowhere.
     *
     * <p>Unreachable today: {@link #resolveSecurityEnvironmentFromCard} returns
     * {@code true}, so resolution never falls back here. That is exactly why this
     * override exists — the invariant should not rest on a boolean two classes away
     * that a later subclass could flip.
     */
    @Override
    protected SecurityEnvironment measuredSecurityEnvironment(SigningOperation operation)
            throws SecurityEnvironmentException {
        throw new SecurityEnvironmentException(String.format(
                "%s: there are no measured constants for Latvian cards — their algorithm"
                        + " and key references differ between personalisations, so they are"
                        + " read from the card or the operation is refused", operation));
    }

    @Override
    public CardType cardType() {
        return CardType.LATVIA_IDEMIA;
    }

    /**
     * Latvian cards are asked, always.
     *
     * <p>Five personalisations are on record and no static rule has survived them:
     * the "SeID" ATS alone covers an EC card with certificates at {@code 34 02}, an
     * EC card with them at the model's own EFs, and an RSA-2048 card with different
     * key references. One of the EC cards uses one-byte algorithm references and
     * another the four-byte form. No constant is right for all of them, so the card is
     * the only source and {@link #measuredSecurityEnvironment} refuses rather than
     * offering a fallback. Inherited by {@code LatviaIdemiaSeIdWithPace}.
     */
    @Override
    protected boolean resolveSecurityEnvironmentFromCard() {
        return true;
    }

    /**
     * True: on these cards {@code personalData()} reads the authentication
     * certificate itself, so a caller wanting both it and that certificate would
     * otherwise read the same ~1.2 KB EF twice under secure messaging in one tap.
     * Inherited by {@link LatviaIdemiaSeIdWithPace}, which keeps its certificates
     * elsewhere but reads them the same way.
     */
    @Override
    protected boolean reuseCertificateReadThisSession() {
        return true;
    }

    // The MSE:SET templates that used to live here are gone deliberately. They
    // were right for the TeID2-marked cards and wrong for at least one SeID-marked
    // one, which uses the four-byte FF xx 08 00 form with the same key references —
    // and no ATS tells the two apart. Latvian cards therefore read their algorithm
    // and key references from the card (resolveSecurityEnvironmentFromCard above)
    // and raise SecurityEnvironmentException rather than assume. The measured values
    // are absent from production code, which is the point — nowhere they could be
    // applied to a card they were not measured on. They are not secret: IDEMIA_LV.md
    // §9-§11 document them per capture, and the replay fixtures assert them as
    // literals, both places where a wrong value fails a test rather than a tap.

    /**
     * Reads the two things the card holds, and hands both to
     * {@link LatvianPersonalDataParser}, which states the contract.
     *
     * <p>EF 0x5001 under DF 0x5000, then the authentication certificate. Note the
     * file numbering does not carry across models: EF 0x5001 is the personal code
     * here and the surname on a card that states all eight records — see
     * {@link PersonalDataParser}.
     */
    @Override
    public PersonalData personalData() throws SmartCardReaderException {
        // Personal code from EF 0x5001; everything else is in the certificate.
        selectMainAid();
        reader.transmit(0x00, 0xA4, 0x01, 0x0C, new byte[]{0x50, 0x00}, null);
        reader.transmit(0x00, 0xA4, 0x02, 0x0C, new byte[]{0x50, 0x01}, null);
        byte[] record = reader.transmit(0x00, 0xB0, 0x00, 0x00, null, 0x00);

        return LatvianPersonalDataParser.parse(
                record, certificate(CertificateType.AUTHENTICATION));
    }
}
