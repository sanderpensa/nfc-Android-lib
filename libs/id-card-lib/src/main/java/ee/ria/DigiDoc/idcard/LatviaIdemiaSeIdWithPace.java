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

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReader;

/**
 * The "SeID"-marked Latvian eID card (ATS
 * {@code 00 12 42 8F 53 65 49 44 0F 90 00}).
 *
 * <p>Identical to {@link LatviaIdemiaWithPace} in every respect but one: it
 * keeps its certificates one file id over from where the model's other
 * personalisation does. {@code AD F1 34 01} and {@code AD F2 34 1F} are
 * present but empty — the FCI declares a 1-byte file and a read returns a
 * single {@code 0x00} — while the real certificates are at {@code 34 02}
 * under the Oberthur AWP applet and {@code 34 1E} under QSCD. Both the card's
 * own PKCS#15 directories name exactly those files, labelled "Authentication
 * 02" and "Signature 1E" (captured 2026-08-06).
 *
 * <p>This class exists so that knowledge is applied up front rather than
 * discovered per tap: without it, every certificate read on this card spends
 * six APDUs (~260 ms) proving the empty EF is empty. It is deliberately not a
 * separate {@link CardType} — as far as an integrator's allow-list is
 * concerned this is a Latvian IDEMIA card like any other, and splitting the
 * type would silently stop apps that opted into {@code LATVIA_IDEMIA} from
 * accepting it.
 *
 * <p>The reordering is only a hint. The inherited chain still falls back to
 * the other EF and then to the card's PKCS#15 directory, so a SeID-marked
 * card personalised the usual way is read correctly too — just a few APDUs
 * slower than it would have been.
 */
class LatviaIdemiaSeIdWithPace extends LatviaIdemiaWithPace {

    /**
     * Where this card actually keeps its certificates: file ids under the
     * applet owning the key of that type, as both of its PKCS#15 certificate
     * directories name them.
     *
     * <p>These ids live here rather than in {@link Idemia} because this is the
     * only card they have been observed on. Sharing them would have every
     * other model spend two APDUs guessing at them whenever its own EF came
     * back empty, for no evidence — the PKCS#15 walk already covers those
     * cards correctly.
     */
    private static final Map<CertificateType, byte[]> CERT_FILE_IDS =
            new EnumMap<>(CertificateType.class);
    static {
        CERT_FILE_IDS.put(CertificateType.AUTHENTICATION, new byte[] {0x34, 0x02});
        CERT_FILE_IDS.put(CertificateType.SIGNING, new byte[] {0x34, 0x1E});
    }

    LatviaIdemiaSeIdWithPace(NfcSmartCardReader reader) {
        super(reader);
    }

    @Override
    List<CertLocation> certificateLocations(CertificateType type) {
        // This card's own file id first; the model's EF stays behind it, since
        // an unexpected personalisation is likelier than this card's applet EF
        // being unreadable, and it costs nothing until the first one misses.
        List<CertLocation> byModel = super.certificateLocations(type);
        CertLocation here = new CertLocation(appletContextFor(type), CERT_FILE_IDS.get(type));
        return Stream.concat(Stream.of(here), byModel.stream()).toList();
    }
}
