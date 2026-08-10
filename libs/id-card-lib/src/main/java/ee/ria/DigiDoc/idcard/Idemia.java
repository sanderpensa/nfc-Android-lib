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

import android.util.SparseArray;

import com.google.common.primitives.Bytes;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ee.ria.DigiDoc.smartcardreader.ApduResponseException;
import ee.ria.DigiDoc.smartcardreader.SmartCardReader;
import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil;

abstract class Idemia implements Token {

    private static final String TAG = Idemia.class.getName();

    private static final int READ_BINARY_CHUNK_LE = 0xE5;

    /**
     * Smallest FCI-declared size we are willing to trust for a certificate
     * file. Real EE/LV auth and sign certificates are ~1000-1600 bytes
     * (ECC P-384 keys, full DER); anything below this means the card's
     * {@code P2 = 0x04} FCI is not describing the certificate content —
     * observed on older LV cards, which report {@code 80 02 00 01}. Treated
     * as "no usable size" so we fall back to the canonical read.
     */
    private static final int MIN_PLAUSIBLE_CERT_SIZE = 0x100;

    /** DER tag every X.509 certificate starts with. */
    private static final byte DER_SEQUENCE_TAG = 0x30;

    /**
     * PKCS#15 EF.OD (ObjectDirectory) file id. Present per applet context on
     * IAS-ECC cards; the entry point of {@link #findCertificateFileId}'s walk.
     */
    private static final byte[] EF_OD = new byte[] {0x50, 0x31};

    /** ODF context-specific tag for the certificate directory ({@code [4]}). */
    private static final int PKCS15_TAG_CERTIFICATES = 0xA4;

    /**
     * PKCS#15 CDF entry tag holding the X.509 typeAttributes ({@code [1]}),
     * whose Path names the EF the certificate really lives in.
     */
    private static final int PKCS15_TAG_TYPE_ATTRIBUTES = 0xA1;

    private static final Map<CertificateType, byte[]> CERT_MAP = new HashMap<>();
    static {
        CERT_MAP.put(CertificateType.AUTHENTICATION, new byte[] {(byte) 0xAD, (byte) 0xF1, 0x34, 0x01});
        CERT_MAP.put(CertificateType.SIGNING, new byte[] {(byte) 0xAD, (byte) 0xF2, 0x34, (byte) 0x1F});
    }

    private static final Map<CodeType, Byte> PIN_MAP = new HashMap<>();
    static {
        PIN_MAP.put(CodeType.PIN1, (byte) 0x01);
        PIN_MAP.put(CodeType.PIN2, (byte) 0x05);
        PIN_MAP.put(CodeType.PUK, (byte) 0x02);
    }

    protected static final Map<CodeType, Byte> VERIFY_PIN_MAP = new HashMap<>();
    static {
        VERIFY_PIN_MAP.put(CodeType.PIN1, (byte) 0x01);
        VERIFY_PIN_MAP.put(CodeType.PIN2, (byte) 0x85);
        VERIFY_PIN_MAP.put(CodeType.PUK, (byte) 0x02);
    }

    protected final SmartCardReader reader;

    /**
     * Whether the FCI form of the certificate read is still worth attempting
     * on this card. Cleared the first time the card's FCI turns out to be
     * unusable, so the second certificate read goes straight to the canonical
     * form instead of paying for the {@code P2 = 0x04} SELECT again. One
     * token instance is created per card session, so this never outlives the
     * card it was learned from.
     */
    private boolean fciCertReadSupported = true;

    /**
     * Certificate EFs discovered through PKCS#15 for this card, keyed by type.
     * Only populated on cards whose {@link #CERT_MAP} EF turned out to be
     * empty, so the CDF walk is paid for at most once per certificate type
     * per card session.
     */
    private final Map<CertificateType, byte[]> pkcs15CertificateFiles =
            new EnumMap<>(CertificateType.class);

    Idemia(SmartCardReader reader) {
        this.reader = reader;
    }

    @Override
    public CardType cardType() {
        return CardType.ID1;
    }

    @Override
    public PersonalData personalData() throws SmartCardReaderException {
        selectMainAid();
        reader.transmit(0x00, 0xA4, 0x01, 0x0C, new byte[] {0x50, 0x00}, null);
        SparseArray<String> data = new SparseArray<>();
        for (int i = 1; i <= 8; i++) {
            reader.transmit(0x00, 0xA4, 0x02, 0x0C, new byte[] {0x50, (byte) i}, null);
            byte[] record = reader.transmit(0x00, 0xB0, 0x00, 0x00, null, 0x00);
            data.put(i, new String(record, StandardCharsets.UTF_8).trim());
        }
        return IdemiaPersonalDataParser.parse(data);
    }

    /**
     * A place a certificate is known to live. Either a full path under the
     * MAIN AID, selected with {@code 00 A4 09 xx} — the only form the FCI fast
     * path applies to — or a file id under one of the PKCS#15 applets,
     * selected with {@code 00 A4 02 0C} once its AID is current.
     */
    static final class CertLocation {
        private final AppletContext context;
        private final byte[] path;

        CertLocation(AppletContext context, byte[] path) {
            this.context = context;
            this.path = path;
        }

        AppletContext context() {
            return context;
        }

        byte[] path() {
            return path;
        }

        @Override
        public String toString() {
            return context == AppletContext.MAIN
                    ? "EF " + Hex.toHexString(path)
                    : "EF " + Hex.toHexString(path) + " in " + context;
        }
    }

    /**
     * Where this card model is known to keep this certificate, most likely
     * first, before falling back to asking the card itself. The default is the
     * only layout there is evidence for on most models: the model's own EF
     * under MAIN.
     *
     * <p>A variant that keeps them somewhere else overrides this and names
     * that place — see {@code LatviaIdemiaSeIdWithPace}. Only add a location
     * here for a card it has actually been observed on: a guess costs APDUs on
     * every card that does not need it, and the PKCS#15 walk behind this list
     * already handles unknown layouts correctly.
     *
     * <p>The order is a hint and never a rule. Every location is DER-validated
     * before it is accepted, and anything not found in this list is looked up
     * in the card's own PKCS#15 certificate directory, so a card matching no
     * known layout is still read correctly — just a few APDUs slower.
     */
    List<CertLocation> certificateLocations(CertificateType type) {
        return List.of(new CertLocation(AppletContext.MAIN, CERT_MAP.get(type)));
    }

    /**
     * Read the certificate from the first location that holds one, asking the
     * card's PKCS#15 directory if none of them does.
     *
     * <p>Locations come from {@link #certificateLocations}, best guess first,
     * so a card whose layout is known costs nothing extra. Each is accepted
     * only if its bytes are a DER certificate: that is what stops a guess from
     * becoming the wrong certificate, and what makes falling through to the
     * next location safe.
     *
     * <p>A location that fails outright does not end the search — the card may
     * simply not have that file — but the first such failure is remembered and
     * rethrown if nothing is found anywhere, so a broken tap still reports the
     * transport or card error that caused it rather than a misleading
     * "this card has no certificate".
     */
    @Override
    public byte[] certificate(CertificateType type) throws SmartCardReaderException {
        List<CertLocation> locations = certificateLocations(type);
        List<String> tried = new ArrayList<>(locations.size() + 1);
        SmartCardReaderException firstFailure = null;
        boolean leftMainAid = false;
        try {
            for (int i = 0; i < locations.size(); i++) {
                CertLocation location = locations.get(i);
                if (location.context() != AppletContext.MAIN) {
                    leftMainAid = true;
                }
                try {
                    byte[] certificate = readCertificateAt(location, type);
                    if (certificate != null && looksLikeDerCertificate(certificate)) {
                        if (i > 0) {
                            LoggingUtil.Companion.debugLog(TAG, String.format(
                                    "certificate(%s): %s holds no certificate; read"
                                            + " %d bytes from %s instead",
                                    type, locations.get(0), certificate.length,
                                    location), null);
                        }
                        return certificate;
                    }
                    tried.add(location + (certificate == null
                            ? " (declared empty by its FCI)"
                            : " (" + certificate.length + " byte(s))"));
                } catch (SmartCardReaderException e) {
                    if (cardResponse(e) == null) {
                        // Not the card declining: an SM or transport failure
                        // would fail at every other location too, so report it
                        // now instead of spending APDUs on a dead connection.
                        throw e;
                    }
                    if (isFileNotFound(e)) {
                        // The card says there is no such file. That is an answer,
                        // not a failure: this personalisation simply does not use
                        // this location.
                        tried.add(location + " (no such file)");
                    } else {
                        if (firstFailure == null) {
                            firstFailure = e;
                        }
                        tried.add(location + " (unreadable: " + e + ")");
                    }
                    LoggingUtil.Companion.debugLog(TAG, String.format(
                            "certificate(%s): %s not readable (%s) — trying the next"
                                    + " known location", type, location, e), null);
                }
            }

            leftMainAid = true;
            byte[] discovered = readCertificateViaPkcs15(type);
            if (discovered != null) {
                return discovered;
            }
            tried.add("the PKCS#15 certificate directory (named none)");
        } finally {
            if (leftMainAid) {
                restoreMainAid(type);
            }
        }

        if (firstFailure != null) {
            // Nothing found, but a read had failed on the way: that failure is
            // a better explanation than "this card has no certificate".
            throw firstFailure;
        }
        // Returning the placeholder bytes made CertificateFactory fail with the
        // opaque "No certificate found", which surfaced as an uncaught
        // exception on the NFC binder thread.
        throw new CertificateNotFoundException(type, tried);
    }

    /**
     * The card's own answer behind a failure, or {@code null} if the failure
     * was not the card declining — a lost tag or an SM error, say. SELECT
     * failures arrive raw; read failures come wrapped by
     * {@link #readUntilEof}, hence the cause check.
     */
    private static ApduResponseException cardResponse(SmartCardReaderException e) {
        if (e instanceof ApduResponseException apdu) {
            return apdu;
        }
        return e.getCause() instanceof ApduResponseException apdu ? apdu : null;
    }

    /**
     * Whether the card answered "file not found" ({@code 6A 82}), which
     * {@link #readUntilEof} already treats as an empty file rather than an
     * error.
     */
    private static boolean isFileNotFound(SmartCardReaderException e) {
        ApduResponseException apdu = cardResponse(e);
        return apdu != null && apdu.sw1 == (byte) 0x6A && apdu.sw2 == (byte) 0x82;
    }

    /**
     * Read whatever is at one location, or {@code null} if the card declared
     * the file too small to be a certificate without us having to read it.
     *
     * <p>Under MAIN that means the FCI form first (see
     * {@link #readCertificateViaFci}) with the canonical {@code 6B 00} loop
     * behind it; under an applet, a plain SELECT by file id and read.
     */
    private byte[] readCertificateAt(CertLocation location, CertificateType type)
            throws SmartCardReaderException {
        if (location.context() != AppletContext.MAIN) {
            selectAppletContext(location.context());
            reader.transmit(0x00, 0xA4, 0x02, 0x0C, location.path(), null);
            return readUntilEof();
        }

        if (fciCertReadSupported) {
            FciRead fci = readCertificateViaFci(type, location.path());
            if (fci.certificate() != null) {
                return fci.certificate();
            }
            fciCertReadSupported = false;
            if (fci.declaredSize() != null) {
                // The card gave a straight answer about this file: it holds
                // fewer bytes than any certificate could. Believe it and move
                // on, rather than spending a SELECT and two READs confirming
                // it. Nothing has been seen to contradict a declared size this
                // small — on the LV "SeID" card both read forms agree on one
                // byte, for both certificates.
                return null;
            }
        }
        return readCertificateCanonically(location.path());
    }

    /**
     * Leave the card on the MAIN AID, because that is where every other Token
     * method expects to find it. Failure to do so is logged, never thrown: it
     * must not replace whatever the caller is about to be told.
     */
    private void restoreMainAid(CertificateType type) {
        try {
            selectMainAid();
        } catch (Exception e) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): could not re-select MAIN AID after the"
                            + " certificate lookup (%s)", type, e), null);
        }
    }

    /** The applet whose DF owns the key, and the certificate, of this type. */
    static AppletContext appletContextFor(CertificateType type) {
        return type == CertificateType.SIGNING
                ? AppletContext.QSCD : AppletContext.OBERTHUR;
    }

    /** Outcome of the FCI form of the cert read. */
    private static final class FciRead {
        private final byte[] certificate;
        private final Integer declaredSize;

        FciRead(byte[] certificate, Integer declaredSize) {
            this.certificate = certificate;
            this.declaredSize = declaredSize;
        }

        /** The bytes, when the FCI bounded a real certificate; {@code null} otherwise. */
        byte[] certificate() {
            return certificate;
        }

        /**
         * The size the card declared, when it declared one too small to be a
         * certificate. Non-null here is the card stating this file is empty,
         * which is grounds to stop rather than read it — see
         * {@link #readCertificateAt}. {@code null} means the FCI said nothing
         * conclusive and the canonical read still has to be tried.
         */
        Integer declaredSize() {
            return declaredSize;
        }
    }

    /**
     * SELECT the cert EF with {@code P2 = 0x04} to request the FCP template,
     * and read exactly the many bytes it declares.
     *
     * <p>The fast path is only taken when the FCI is trustworthy: a size tag
     * is present, the size is not absurdly small for a certificate, and the
     * bytes actually read start like a DER certificate. Older LV cards answer
     * with {@code 62 24 80 02 00 01 …} — file ID and life-cycle correct, but
     * size 1 and a first byte of {@code 0x00} — so trusting the FCI
     * unconditionally yields a 1-byte "certificate" and an opaque
     * {@code No certificate found} parse failure upstream.
     *
     * <p>Three outcomes, and the difference between the last two matters:
     * <ul>
     *   <li>bytes in hand;</li>
     *   <li>a declared size too small to be a certificate — conclusive, so the
     *       caller can skip this file entirely;</li>
     *   <li>anything else (no size tag, a rejected {@code P2 = 0x04}, or a
     *       bounded read that is not DER) — inconclusive, so the caller must
     *       still try the canonical form. That is the case §6 of
     *       {@code IDEMIA_LV.md} warns about: a card can misreport the size
     *       and still deliver the file under {@code 00 A4 09 0C}.</li>
     * </ul>
     *
     * <p>Once a card has answered inconclusively the fast path is not
     * attempted again for the session, so only the first read pays the probe.
     */
    private FciRead readCertificateViaFci(CertificateType type, byte[] path)
            throws SmartCardReaderException {
        try {
            selectMainAid();
            byte[] fci = reader.transmit(0x00, 0xA4, 0x09, 0x04, path, null);

            Integer size = parseFciSize(fci);
            if (size == null) {
                LoggingUtil.Companion.debugLog(TAG, String.format(
                        "certificate(%s): FCI declares no size (fci=%s) — falling"
                                + " back to the 6B 00 loop for this session",
                        type, Hex.toHexString(fci)), null);
                return new FciRead(null, null);
            }
            if (size < MIN_PLAUSIBLE_CERT_SIZE) {
                LoggingUtil.Companion.debugLog(TAG, String.format(
                        "certificate(%s): FCI declares %d byte(s) (fci=%s) — too few"
                                + " for a certificate, so this EF is empty; not"
                                + " reading it", type, size, Hex.toHexString(fci)), null);
                return new FciRead(null, size);
            }

            byte[] certificate = readBoundedByFciSize(size);
            if (looksLikeDerCertificate(certificate)) {
                return new FciRead(certificate, null);
            }
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): FCI-bounded read returned %d bytes that are"
                            + " not DER — falling back to 6B 00 loop for this session",
                    type, certificate.length), null);
            return new FciRead(null, null);
        } catch (ApduResponseException e) {
            // Card-level "no" to the FCI form, at the SELECT or during the
            // bounded read. Only ApduResponseException is caught: an SM or
            // transport failure would fail on the canonical path too and must
            // surface with its original cause. The probe is surface the pre-FCI
            // implementation never touched, so it must not be able to fail a
            // read that used to work.
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): card rejected the FCI form (%s) — falling"
                            + " back to 6B 00 loop for this session", type, e), null);
            return new FciRead(null, null);
        }
    }

    /**
     * Canonical cert read: SELECT without requesting the FCI, so the card is
     * left in exactly the state the pre-FCI implementation used, then read
     * until {@code 6B 00}.
     */
    private byte[] readCertificateCanonically(byte[] path) throws SmartCardReaderException {
        selectMainAid();
        reader.transmit(0x00, 0xA4, 0x09, 0x0C, path, null);
        return readUntilEof();
    }

    /**
     * Last resort when no known location holds one: ask the card's PKCS#15
     * metadata where the certificate actually is, then read it there.
     *
     * <p>The walk stays inside the applet that owns the key of this type —
     * Oberthur AWP for authentication, QSCD for signing, matching CERT_MAP's
     * {@code AD F1} / {@code AD F2} DFs — and is: SELECT AID, read EF.OD
     * ({@code 50 31}), follow its {@code [4]} entry to the CDF, take the Path
     * out of the CDF entry's {@code [1]} typeAttributes, then SELECT and read
     * that EF. Observed on the LV "SeID" card (2026-08-06), whose CDF labels
     * even spell the file id out: "Authentication 02" → {@code 34 02},
     * "Signature 1E" → {@code 34 1E}.
     *
     * <p>Returns {@code null} — leaving the caller to report that the card has
     * no such certificate — when any step fails or the bytes read are not a
     * certificate. Every failure is non-fatal by design: this runs only for
     * cards that were already about to error out, so it must never turn a
     * clear "no certificate" into an unrelated exception. Restoring the MAIN
     * AID afterwards is {@link #certificate}'s job, so that a failure here can
     * hand straight over without a wasted SELECT.
     */
    private byte[] readCertificateViaPkcs15(CertificateType type) {
        AppletContext context = appletContextFor(type);
        try {
            byte[] fileId = pkcs15CertificateFiles.get(type);
            if (fileId != null) {
                // Cached from an earlier call in this session. Nothing has kept
                // the applet selected since, so select it again.
                selectAppletContext(context);
            } else {
                fileId = findCertificateFileId(context);
                if (fileId == null) {
                    return null;
                }
                pkcs15CertificateFiles.put(type, fileId);
                // The walk left the applet selected, and selecting EFs by FID
                // under it does not change the current DF, so the certificate
                // EF can be selected straight away.
            }

            reader.transmit(0x00, 0xA4, 0x02, 0x0C, fileId, null);
            byte[] certificate = readUntilEof();
            if (!looksLikeDerCertificate(certificate)) {
                LoggingUtil.Companion.debugLog(TAG, String.format(
                        "certificate(%s): PKCS#15 pointed at EF %s in %s, but its"
                                + " %d byte(s) are not a certificate",
                        type, Hex.toHexString(fileId), context, certificate.length), null);
                return null;
            }
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): no known location held one; read %d bytes from"
                            + " EF %s in %s, as named by PKCS#15",
                    type, certificate.length, Hex.toHexString(fileId), context), null);
            return certificate;
        } catch (Exception e) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): PKCS#15 certificate lookup in %s failed (%s)",
                    type, context, e), null);
            return null;
        }
    }

    /**
     * EF.OD → CDF walk in one applet context, returning the 2-byte file id of
     * the first certificate the CDF lists, or {@code null} if this context
     * registers no certificates.
     */
    private byte[] findCertificateFileId(AppletContext context) throws SmartCardReaderException {
        selectAppletContext(context);
        reader.transmit(0x00, 0xA4, 0x02, 0x0C, EF_OD, null);
        byte[] objectDirectory = readUntilEof();

        byte[] certificateDirectory =
                pkcs15FileId(TLV.parseAll(objectDirectory), PKCS15_TAG_CERTIFICATES);
        if (certificateDirectory == null) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s EF.OD lists no certificate directory (%s)",
                    context, Hex.toHexString(objectDirectory)), null);
            return null;
        }

        reader.transmit(0x00, 0xA4, 0x02, 0x0C, certificateDirectory, null);
        byte[] cdf = readUntilEof();
        byte[] fileId = pkcs15FileId(TLV.parseAll(cdf), PKCS15_TAG_TYPE_ATTRIBUTES);
        if (fileId == null) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s CDF %s names no certificate path (%s)",
                    context, Hex.toHexString(certificateDirectory),
                    Hex.toHexString(cdf)), null);
        }
        return fileId;
    }

    /** SELECT the AID owning one applet context. */
    private void selectAppletContext(AppletContext context) throws SmartCardReaderException {
        switch (context) {
            case MAIN -> selectMainAid();
            case OBERTHUR -> selectOberthurAid();
            case QSCD -> selectQSCDAid();
        }
    }

    /**
     * Where a certificate, or the PKCS#15 metadata naming it, can live.
     * {@code MAIN} is the card's own application; the other two are the
     * PKCS#15 applets that own the authentication and signing keys.
     */
    enum AppletContext { MAIN, OBERTHUR, QSCD }

    /**
     * Pull the 2-byte file id out of a PKCS#15 record: the requested
     * context-specific tag wraps a {@code SEQUENCE} (Path) wrapping an
     * {@code OCTET STRING} carrying the file id. Used for both ODF entries
     * (tag {@code [4]}/{@code [0]} → directory file) and CDF entries (tag
     * {@code [1]} → the certificate's own EF). Same minimal-walker
     * assumptions as the PrKDF walk — first match at every level, no
     * validation beyond the length. Scoping the {@code OCTET STRING} search
     * to the tagged subtree matters: a CDF entry's commonObjectAttributes
     * carry a 20-byte id in an {@code OCTET STRING} of their own, which an
     * unscoped search would return instead of the path.
     */
    private static byte[] pkcs15FileId(List<TLV> records, int containerTag) {
        TLV container = findTagRecursive(records, containerTag);
        if (container == null) {
            return null;
        }
        TLV path = findTagRecursive(container.children, 0x04);
        byte[] value = path != null ? path.getValue() : container.getValue();
        if (value == null || value.length < 2) {
            return null;
        }
        // Paths may be absolute (3F 00 …) and, when the parser did not descend
        // into the entry, still carry the SEQUENCE/OCTET STRING headers. Either
        // way the file id is the trailing 2 bytes.
        return Arrays.copyOfRange(value, value.length - 2, value.length);
    }

    /**
     * True when {@code data} plausibly starts an X.509 certificate: DER
     * SEQUENCE (tag {@code 30}) with a multi-byte definite length, and at
     * least as many bytes present as that length announces. Guards against
     * accepting a truncated or empty FCI-bounded read as a certificate.
     */
    private static boolean looksLikeDerCertificate(byte[] data) {
        if (data.length < 4 || data[0] != DER_SEQUENCE_TAG) {
            return false;
        }
        int lengthOfLength = (data[1] & 0xFF) - 0x80;
        if (lengthOfLength < 1 || lengthOfLength > 3 || data.length < 2 + lengthOfLength) {
            return false;
        }
        int length = 0;
        for (int i = 0; i < lengthOfLength; i++) {
            length = (length << 8) | (data[2 + i] & 0xFF);
        }
        return data.length >= 2 + lengthOfLength + length;
    }

    /**
     * Walk the FCI (possibly wrapped in a {@code 6F}/{@code 62} template,
     * possibly bare) for the first tag {@code 80} or {@code 81} carrying a
     * 2-byte big-endian file size. Returns {@code null} if neither tag is
     * present with a usable value — caller falls back to a {@code 6B 00}-
     * terminated read.
     */
    private Integer parseFciSize(byte[] fci) {
        TLV r = findTagRecursive(TLV.parseAll(fci), 0x80);
        if (r == null) {
            r = findTagRecursive(TLV.parseAll(fci), 0x81);
        }
        if (r == null) {
            return null;
        }
        byte[] value = r.getValue();
        if (value == null || value.length < 2) {
            return null;
        }
        return ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
    }

    /**
     * FCI fast path: read exactly {@code size} bytes in chunks of up to
     * {@value #READ_BINARY_CHUNK_LE}. A 6B 00 mid-read or zero-length
     * response is treated as graceful EOF — the card decided to deliver
     * less than declared, which we tolerate rather than throw.
     * <p>
     * Any other error SW propagates as the original {@link
     * ApduResponseException} rather than being wrapped, so
     * {@link #certificate(CertificateType)} can recognise it as "this card
     * does not do the FCI form" and retry canonically.
     */
    private byte[] readBoundedByFciSize(int size) throws SmartCardReaderException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        while (stream.size() < size) {
            int offset = stream.size();
            int le = Math.min(READ_BINARY_CHUNK_LE, size - offset);
            try {
                byte[] response = reader.transmit(0x00, 0xB0,
                        offset >> 8, offset & 0xFF, null, le);
                stream.write(response);
                if (response.length == 0) {
                    break;
                }
            } catch (ApduResponseException e) {
                if (e.sw1 == (byte) 0x6B && e.sw2 == (byte) 0x00) {
                    break;
                }
                throw e;
            } catch (IOException e) {
                throw new SmartCardReaderException(e);
            }
        }
        return stream.toByteArray();
    }

    /**
     * Canonical fallback when FCI lacks a usable size: chunked
     * {@code READ BINARY} with {@code Le = 0x00} until the card returns
     * {@code 6B 00} (or {@code 6A 82} — file not found, treated as empty).
     */
    private byte[] readUntilEof() throws SmartCardReaderException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        while (true) {
            int offset = stream.size();
            try {
                byte[] response = reader.transmit(0x00, 0xB0,
                        offset >> 8, offset & 0xFF, null, 0x00);
                stream.write(response);
                if (response.length == 0) {
                    break;
                }
            } catch (ApduResponseException e) {
                if (e.sw1 == (byte) 0x6B && e.sw2 == (byte) 0x00) {
                    break;
                }
                if (e.sw1 == (byte) 0x6A && e.sw2 == (byte) 0x82) {
                    break;
                }
                throw new SmartCardReaderException(e);
            } catch (IOException e) {
                throw new SmartCardReaderException(e);
            }
        }
        return stream.toByteArray();
    }

    @Override
    public int codeRetryCounter(CodeType type) throws SmartCardReaderException {
        if (type.equals(CodeType.PIN2)) {
            selectQSCDAid();
        } else {
            selectMainAid();
        }
        return reader.transmit(0x00, 0xCB, 0x3F, 0xFF, new byte[] {0x4D, 0x08, 0x70, 0x06, (byte) 0xBF, (byte) 0x81, Objects.requireNonNull(PIN_MAP.get(type)), 0x02, (byte) 0xA0, (byte) 0x80}, 0x00)[13];
    }

    @Override
    public void changeCode(CodeType type, byte[] currentCode, byte[] newCode) throws SmartCardReaderException {
        if (type.equals(CodeType.PIN2)) {
            selectQSCDAid();
        } else {
            selectMainAid();
        }
        try {
            reader.transmit(0x00, 0x24, 0x00, Objects.requireNonNull(VERIFY_PIN_MAP.get(type)), Bytes.concat(code(currentCode), code(newCode)), null);
        } catch (ApduResponseException e) {
            handleApduResponseException(type, e);
        }
    }

    @Override
    public void unblockAndChangeCode(byte[] pukCode, CodeType type, byte[] newCode) throws SmartCardReaderException {
        // PUK is associated with the MAIN AID context, so VERIFY PUK must run there.
        // Make this self-contained (matching the rest of the Token API) instead of
        // relying on the caller leaving MAIN active — otherwise calls composed after
        // codeRetryCounter(PIN2)/calculateSignature/etc. would silently fail with a
        // "wrong PUK" error.
        selectMainAid();
        verifyCode(CodeType.PUK, pukCode);
        if (type.equals(CodeType.PIN2)) {
            selectQSCDAid();
        }
        try {
            reader.transmit(0x00, 0x2C, 0x02, Objects.requireNonNull(VERIFY_PIN_MAP.get(type)), code(newCode), null);
        } catch (ApduResponseException e) {
            handleApduResponseException(CodeType.PUK, e);
        }
    }

    @Override
    public int pinChangedFlag(CodeType type) {
        return 1;
    }

    @Override
    public abstract byte[] calculateSignature(byte[] pin2, byte[] hash, boolean ecc)
            throws SmartCardReaderException;

    @Override
    public abstract byte[] authenticate(byte[] pin1, byte[] token)
            throws SmartCardReaderException;

    @Override
    public abstract byte[] decrypt(byte[] pin1, byte[] data, boolean ecc)
            throws SmartCardReaderException;

    protected void verifyCode(CodeType type, byte[] code) throws SmartCardReaderException {
        try {
            reader.transmit(0x00, 0x20, 0x00, Objects.requireNonNull(VERIFY_PIN_MAP.get(type)), code(code), null);
        } catch (ApduResponseException e) {
            handleApduResponseException(type, e);
        }
    }

    private void handleApduResponseException(CodeType type, ApduResponseException e) throws SmartCardReaderException {
        if (e.sw1 == 0x63 || (e.sw1 == 0x69 && e.sw2 == (byte) 0x83)) {
            if (e.sw2 == (byte) 0xC2) {
                throw new CodeVerificationException(type, 2);
            } else if (e.sw2 == (byte) 0xC1) {
                throw new CodeVerificationException(type, 1);
            }
            throw new CodeVerificationException(type, 0);
        }
        throw e;
    }

    protected void selectMainAid() throws SmartCardReaderException {
        reader.transmit(0x00, 0xA4, 0x04, 0x00, new byte[] {(byte) 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, (byte) 0xFE, 0x00, 0x00, 0x01, 0x00}, null);
    }

    protected void selectQSCDAid() throws SmartCardReaderException {
        reader.transmit(0x00, 0xA4, 0x04, 0x0C, new byte[] {0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E}, null);
    }

    protected void selectOberthurAid() throws SmartCardReaderException {
        reader.transmit(0x00, 0xA4, 0x04, 0x0C, new byte[] {(byte) 0xE8, 0x28, (byte) 0xBD, 0x08, 0x0F, (byte) 0xF2, 0x50, 0x4F, 0x54, 0x20, 0x41, 0x57, 0x50}, null);
    }

    /** IDEMIA pads the twelve-byte code field with {@code 0xFF}. */
    private static byte[] code(byte[] code) throws CodeFormatException {
        return Codes.padded(code, (byte) 0xFF);
    }

    /**
     * Walk {@code records} (and constructed children) depth-first and return
     * the first TLV matching {@code targetTag}, or {@code null}. Lets us find
     * the FCI size tag whether the card wraps it in a {@code 6F}/{@code 62}
     * template or sends it bare.
     */
    private static TLV findTagRecursive(List<TLV> records, int targetTag) {
        if (records == null) {
            return null;
        }
        for (TLV record : records) {
            if (record.getTag() == targetTag) {
                return record;
            }
            TLV found = findTagRecursive(record.children, targetTag);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * ID1 only has ECC keys so we don't need to pad it as we do RSA hashes,
     * but we need to pad hashes that are smaller than the key size with zeroes in front to resize
     * them to 48bytes in length because of API restrictions on the chip
     *
     * @param hash that needs to be signed
     * @return zero padded hash with 48 byte length or same hash if it's longer than 48 bytes
     * @throws IdCardException when padding the hash fails
     */
    protected static byte[] padWithZeroes(byte[] hash) throws IdCardException {
        if (hash.length >= 48) {
            return hash;
        }
        try (ByteArrayOutputStream toSign = new ByteArrayOutputStream()) {
            toSign.write(new byte[48 - hash.length]);
            toSign.write(hash);
            return toSign.toByteArray();
        } catch (IOException e) {
            throw new IdCardException("Failed to Add padding to hash", e);
        }
    }
}
