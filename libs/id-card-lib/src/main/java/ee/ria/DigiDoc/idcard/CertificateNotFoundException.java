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

import java.util.List;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

/**
 * The card carries no certificate of the requested type.
 *
 * <p>Thrown only once every way of finding one has been tried and come back
 * empty: each EF this card model is known to keep certificates in, and then
 * the card's own PKCS#15 certificate directory. It therefore means "this card
 * has no such certificate", not "the read failed" — transport, secure
 * messaging and card errors keep propagating as themselves, so a caller can
 * tell a card that cannot do the job from a tap that went wrong.
 *
 * <p>The message lists every location searched and what each one held, which
 * is what a support log needs to tell a card personalised without this
 * certificate from one whose layout the library does not yet know.
 *
 * <p>Before this existed, an empty EF's bytes were handed to
 * {@code CertificateFactory}, which failed with the opaque
 * {@code No certificate found} on the NFC binder thread.
 */
public class CertificateNotFoundException extends SmartCardReaderException {

    /**
     * The certificate that was asked for.
     *
     * <p>Not {@code transient}: an enum constant serializes as its name and comes
     * back as the same constant, so marking it would cost {@link #certificateType()}
     * its answer after a round trip and buy nothing.
     */
    private final CertificateType type;

    CertificateNotFoundException(CertificateType type, List<String> searched) {
        super(String.format("No %s certificate on card. Searched: %s",
                type, String.join("; ", searched)));
        this.type = type;
    }

    public CertificateType certificateType() {
        return type;
    }
}
