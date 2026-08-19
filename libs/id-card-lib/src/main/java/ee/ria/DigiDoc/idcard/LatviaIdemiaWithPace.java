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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;
import ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReader;
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil;

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
    private static final String TAG = LatviaIdemiaWithPace.class.getName();

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
     * Read personal data from the auth certificate subject and EF 0x5001 (personal code).
     * Latvian eID cards store only the personal code in EF files (DF 0x5000 / EF 0x5001).
     * Name, issuing country, and document number are extracted from the auth certificate subject:
     *   - OID 2.5.4.4  (surname)
     *   - OID 2.5.4.42 (givenName)
     *   - OID 2.5.4.5  (serialNumber) — format "PNOLV-{personalCode}"
     *   - C (2.5.4.6)  — issuing country of the certificate authority. Mapped
     *     to {@link PersonalData#issuingCountry()}, NOT to citizenship: the
     *     value is the CA's country (always "LV" here), and a foreign resident
     *     could in principle hold an LV-issued card. Citizenship is left empty
     *     because the LV card does not expose it over NFC.
     * Cert expiry comes from the certificate's notAfter; document expiry is
     * not exposed by Latvian IDEMIA cards over NFC, so it is left null.
     */
    @Override
    public PersonalData personalData() throws SmartCardReaderException {
        // Read personal code from EF 0x5001
        selectMainAid();
        reader.transmit(0x00, 0xA4, 0x01, 0x0C, new byte[]{0x50, 0x00}, null);
        reader.transmit(0x00, 0xA4, 0x02, 0x0C, new byte[]{0x50, 0x01}, null);
        byte[] record = reader.transmit(0x00, 0xB0, 0x00, 0x00, null, 0x00);
        // Strip trailing 0xFF (CardOS unused-space marker on fixed-size EFs)
        // before UTF-8 decoding — String.trim() only strips ASCII whitespace.
        int len = record.length;
        while (len > 0 && record[len - 1] == (byte) 0xFF) {
            len--;
        }
        String personalCode = new String(record, 0, len, StandardCharsets.UTF_8).trim();

        // Parse auth certificate for remaining fields
        try {
            byte[] certBytes = certificate(CertificateType.AUTHENTICATION);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate)
                cf.generateCertificate(new ByteArrayInputStream(certBytes));

            X500Name subject = X500Name.getInstance(
                x509.getSubjectX500Principal().getEncoded());

            String surname = rdnString(subject, BCStyle.SURNAME);
            String givenName = rdnString(subject, BCStyle.GIVENNAME);
            String issuingCountryRaw = rdnString(subject, BCStyle.C);
            String issuingCountry = issuingCountryRaw.isEmpty() ? null : issuingCountryRaw;
            String serialNumber = rdnString(subject, BCStyle.SERIALNUMBER);

            // X.509 notAfter is a UTC instant — interpret in UTC so the displayed
            // date is the same regardless of device timezone, matching openssl
            // and other PKI-tooling conventions.
            LocalDate certExpiryDate = x509.getNotAfter().toInstant()
                .atZone(ZoneOffset.UTC).toLocalDate();

            LocalDate dateOfBirth = LatviaPersonalDataParser.parseDateOfBirth(personalCode);

            // No PII in logs — names / personal code / document number stay
            // out per project convention. Cert expiry isn't identifying on
            // its own and is useful for triaging "card expired" reports.
            LoggingUtil.Companion.debugLog(TAG,
                "LV personal data parsed, certExpiry=" + certExpiryDate, null);

            return PersonalData.create(surname, givenName, "", issuingCountry, dateOfBirth,
                personalCode, serialNumber, null, certExpiryDate, CardType.LATVIA_IDEMIA);
        } catch (SmartCardReaderException e) {
            // NFC / SM / card-status errors from certificate(): propagate with
            // their original message and stack so the cause is visible upstream.
            throw e;
        } catch (CertificateException e) {
            // Specific message when DER parsing actually fails — distinct from
            // every-other-failure case below.
            throw new SmartCardReaderException("Failed to parse auth certificate", e);
        } catch (Exception e) {
            // Catch-all for anything else (BC IllegalArgumentException, NPE, etc.)
            // so nothing escapes uncaught onto the NFC binder thread. The throwable
            // class name in the message keeps logs readable.
            throw new SmartCardReaderException(
                "Unexpected error reading personal data: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * Extract a single RDN value from an X.500 subject by OID, returning "" when absent.
     * Delegates to BouncyCastle so UTF-8 strings, multi-valued RDNs, escaped commas, and
     * tag/length variations of DirectoryString are handled correctly.
     */
    private static String rdnString(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0) {
            return "";
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

}
