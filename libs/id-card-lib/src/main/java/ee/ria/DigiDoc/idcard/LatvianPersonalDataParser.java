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
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil;

/**
 * Personal data as Latvian cards hold it: the personal code in EF 0x5001, and
 * everything else in the authentication certificate's subject.
 *
 * <p>The counterpart of {@link PersonalDataParser}, which serves the models that
 * state all eight fields in files. Nothing is shared between them — different
 * sources, different shapes — but the division is the same: the token reads the
 * bytes, this turns them into {@link PersonalData}.
 *
 * <p>Surname, given name and document number are certificate derivations standing in
 * for fields other card models read from a file. Anything the certificate says that
 * no card states belongs to the caller, which has the certificate; citizenship and
 * document expiry are null because this card states neither over NFC.
 */
final class LatvianPersonalDataParser {
    private static final String TAG = LatvianPersonalDataParser.class.getName();

    private LatvianPersonalDataParser() {
    }

    /**
     * @param personalCodeRecord EF 0x5001, as the card returned it.
     * @param certificate the authentication certificate, in DER.
     * @throws SmartCardReaderException when the certificate cannot be read as one.
     */
    static PersonalData parse(byte[] personalCodeRecord, byte[] certificate)
            throws SmartCardReaderException {
        String personalCode = personalCode(personalCodeRecord);

        try {
            X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificate));

            X500Name subject = X500Name.getInstance(
                    x509.getSubjectX500Principal().getEncoded());

            String surname = rdnString(subject, BCStyle.SURNAME);
            String givenName = rdnString(subject, BCStyle.GIVENNAME);
            String serialNumber = rdnString(subject, BCStyle.SERIALNUMBER);

            LocalDate dateOfBirth = LatvianPersonalCode.parseDateOfBirth(personalCode);

            // Logged, not returned: a certificate fact belongs to whoever holds the
            // certificate. It earns a log line because "is the card expired" is the
            // first question a support report has to answer, and reading the instant
            // in UTC keeps the logged date the same whatever the device's timezone.
            // No PII: names, personal code and document number stay out per project
            // convention, and an expiry date is not identifying on its own.
            LoggingUtil.Companion.debugLog(TAG, "LV personal data parsed, certExpiry="
                    + x509.getNotAfter().toInstant().atZone(ZoneOffset.UTC).toLocalDate(), null);

            return PersonalData.create(surname, givenName, null, dateOfBirth,
                    personalCode, serialNumber, null, CardType.LATVIA_IDEMIA);
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
     * EF 0x5001 as text.
     *
     * <p>Trailing {@code 0xFF} is CardOS's unused-space marker on a fixed-size EF, and
     * is stripped before decoding — {@code String.trim()} only strips ASCII whitespace,
     * so it would leave the marker in place.
     */
    private static String personalCode(byte[] record) {
        int len = record.length;
        while (len > 0 && record[len - 1] == (byte) 0xFF) {
            len--;
        }
        return new String(record, 0, len, StandardCharsets.UTF_8).trim();
    }

    /**
     * The first attribute value matching {@code oid} in the certificate subject, or
     * empty where the subject carries none. Handles UTF8String, PrintableString and
     * the other X.520 string types.
     */
    private static String rdnString(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0) {
            return "";
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }
}
