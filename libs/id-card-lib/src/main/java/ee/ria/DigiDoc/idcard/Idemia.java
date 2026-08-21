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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
     * observed on older LV cards, which report {@code 80 02 00 01}.
     *
     * <p>A size below this is read as <em>this file is empty</em>, so the
     * location is skipped and the next one tried — deliberately <em>without</em>
     * the canonical re-read, which is the whole saving. Falling back is what
     * happens when the FCI declares no size at all; a precise answer this small
     * is treated as an answer. Raising this constant therefore makes the lookup
     * skip more locations, not read more of them.
     */
    private static final int MIN_PLAUSIBLE_CERT_SIZE = 0x100;

    /** DER tag every X.509 certificate starts with. */
    private static final byte DER_SEQUENCE_TAG = 0x30;

    /**
     * PKCS#15 EF.OD (ObjectDirectory) file id. Present per applet context on
     * IAS-ECC cards; the entry point of {@link #findCertificateFileId}'s walk.
     */
    private static final byte[] EF_OD = new byte[] {0x50, 0x31};

    /** PKCS#15 EF.TokenInfo, which carries {@code supportedAlgorithms}. */
    private static final byte[] EF_TOKEN_INFO = new byte[] {0x50, 0x32};

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

    /**
     * Security environments resolved for this card, one per operation. Resolving
     * costs a PKCS#15 walk, so it is done once per operation per session.
     */
    private final Map<SigningOperation, SecurityEnvironment> securityEnvironments =
            new EnumMap<>(SigningOperation.class);

    /**
     * The algorithm table each applet publishes, read once per applet per session.
     *
     * <p>Per applet rather than shared, because the table is what an applet's own
     * key directory references and nothing guarantees the two applets agree. They
     * are not even the same file: the 2020 Latvian card's Oberthur EF.TokenInfo is
     * 563 bytes and its QSCD one 581. Those two happen to describe identical rows,
     * so sharing produced the right answer on every card measured — but if a
     * personalisation ever numbered its rows differently per applet, sharing would
     * stage an algorithm reference from the wrong table and the card would accept
     * it, which is the failure this whole path exists to avoid.
     *
     * <p>The cost is one of those three files read a second time, under the other
     * applet: EF.TokenInfo is the largest of them, measured at 5 APDUs and 430 ms of
     * a 12-APDU, ~940 ms walk — and only in a session that both authenticates and
     * signs. An empty result is not kept, so a card that
     * exposes the table under only one applet still works.
     */
    private final Map<AppletContext, Map<Integer, Pkcs15SecurityEnvironment.Algorithm>>
            algorithmTables = new EnumMap<>(AppletContext.class);

    /**
     * Whether resolving the security environment got as far as selecting a file.
     * If it did not — a card with no EF.TokenInfo answers {@code 6A 82} to the
     * very first SELECT — the applet is still current and needs no restoring.
     */
    private boolean walkSelectedAnEf;

    /**
     * Certificates read this session, by type. Kept so an authentication signature
     * can be checked against the key that was supposed to produce it — see
     * {@link SignatureVerifier}. Only what a caller has already asked for is here;
     * nothing is read on its account.
     */
    private final Map<CertificateType, byte[]> certificates =
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
                        certificates.put(type, certificate);
                        // Always logged, not only on a fallback: the EF and the
                        // size are what identify a personalisation. 1182 bytes at
                        // AD F1 34 01 is one Latvian card, 1156 at 34 02 another,
                        // 1710 a third — and the ATS does not tell them apart.
                        LoggingUtil.Companion.debugLog(TAG, String.format(
                                "certificate(%s): read %d bytes from %s%s",
                                type, certificate.length, location,
                                i > 0 ? String.format(" (%s held none)",
                                        locations.get(0)) : ""), null);
                        // After the line above, not before it: the mismatch message
                        // sends a reader to "the KeyUsage line logged when it was
                        // read", and an anomaly is only legible under the line that
                        // says which EF and how many bytes it is about. The PKCS#15
                        // path already logs in this order.
                        noteKeyUsage(type, certificate);
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
                certificates.put(type, discovered);
                noteKeyUsage(type, discovered);
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
    static ApduResponseException cardResponse(SmartCardReaderException e) {
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
            if (fci.declaredSize() != null) {
                // The card gave a straight answer about this file: it holds
                // fewer bytes than any certificate could. Believe it and move
                // on, rather than spending a SELECT and two READs confirming
                // it. Nothing has been seen to contradict a declared size this
                // small — on the LV "SeID" card both read forms agree on one
                // byte, for both certificates.
                //
                // The fast path stays on: a card that answered this precisely is
                // one whose FCI works. Clearing the flag here would give up the
                // saving this branch just took, for every later read in the
                // session.
                return null;
            }
            // No certificate and no declared size: the FCI told us nothing usable,
            // so stop paying for it and read canonically from here on.
            fciCertReadSupported = false;
        }
        return readCertificateCanonically(location.path());
    }

    /**
     * Puts the applet back after a metadata walk, tolerating its own failure.
     *
     * <p>The counterpart of {@link #restoreMainAid} for the resolution walk, and
     * silent for the same reason: it runs on the way to a throw as well as on the
     * way out, and the exception worth reporting is the one already in flight.
     */
    private void restoreAppletContext(SigningOperation operation) {
        try {
            selectAppletContext(operation.context);
        } catch (Exception e) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s: could not re-select %s after reading the card's key description"
                            + " (%s)", operation, operation.context, e), null);
        }
    }

    /**
     * Logs when a certificate's {@code KeyUsage} is not the one the requested type
     * should carry. Reports only — nothing is reordered, refused or re-read.
     *
     * <p>Parsing a candidate as DER proves it is <em>a</em> certificate, which is
     * what the placeholder EFs on Latvian cards needed. It does not prove it is
     * <em>the</em> certificate: a personalisation that put the signing certificate
     * where the authentication one is expected would return something valid for the
     * wrong key, and the failure would surface at the end, as a signature that does
     * not verify. {@code KeyUsage} is what tells them apart.
     *
     * <p>The rule is eIDAS's, not a convention observed on a few cards:
     * {@code nonRepudiation} is what makes a qualified signature qualified, and
     * {@code digitalSignature} is what an authentication certificate carries.
     *
     * <p>Silent on every certificate {@code CertificateKeyUsageTest} pins — EE IDEMIA
     * authentication, EE Thales authentication, and both Latvian markings — across
     * two chip families, which is why a Thales sample matters more than another
     * IDEMIA one would. <b>EE IDEMIA's signing certificate is not among the
     * captures.</b> It was read from a device tap on 2026-08-19 and carries
     * {@code nonRepudiation}, so it is silent too, but that is an observation in a
     * log rather than something this repository checks — the one certificate in
     * production whose behaviour here is not pinned by a test.
     *
     * <p>Only the expected bit is tested, never the other one's absence. A
     * certificate carrying both passes for either type, deliberately: this reports
     * and does not decide, and a permissive certificate is not evidence that the
     * wrong one was read. Exclusivity does hold across every capture, but that is a
     * fact about those cards and is asserted where facts about cards belong — in
     * {@code CertificateKeyUsageTest}, not in a runtime check that would then be
     * flagging conformance rather than identity.
     *
     * <p>Log-only on purpose. Preferring a candidate by {@code KeyUsage} means
     * falling through to the next location on a miss, and on Estonian cards there is
     * exactly one location — so an EE card with unexpected bits would newly pay a
     * PKCS#15 discovery walk on a tap, which is the cost EE deliberately declines
     * elsewhere. Reporting costs nothing and no card can lose by it.
     */
    private void noteKeyUsage(CertificateType type, byte[] certificate) {
        boolean[] usage;
        try {
            usage = ((X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificate)))
                    .getKeyUsage();
        } catch (Exception e) {
            // Not this method's business: the caller already established that these
            // bytes parse, and anything else is reported where it is acted on.
            return;
        }
        if (usage == null || usage.length < 2) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): carries no KeyUsage, so it cannot be checked"
                            + " against the type that was asked for", type), null);
            return;
        }

        boolean digitalSignature = usage[0];
        boolean nonRepudiation = usage[1];
        boolean expected = type == CertificateType.SIGNING ? nonRepudiation : digitalSignature;
        if (expected) {
            return;
        }
        if (type == CertificateType.SIGNING ? digitalSignature : nonRepudiation) {
            // The other type's bit, and only it: this is very likely the other
            // certificate, read from a location that does not hold what was asked for.
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "certificate(%s): this certificate's KeyUsage is the other type's"
                            + " (%s) — it looks like the wrong certificate for the key"
                            + " that will be used, which would surface later as a"
                            + " signature that does not verify",
                    type, type == CertificateType.SIGNING
                            ? "digitalSignature" : "nonRepudiation"), null);
            return;
        }
        LoggingUtil.Companion.debugLog(TAG, String.format(
                "certificate(%s): KeyUsage carries neither digitalSignature nor"
                        + " nonRepudiation, so it says nothing about which key this is",
                type), null);
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

    /**
     * Everything the {@code MSE:SET} for an operation needs — the algorithm
     * reference and the key reference — preferring what the card says about
     * itself and falling back to the constants measured from real cards.
     *
     * <p>The card is asked first because it is the only source that can be right
     * for a personalisation nobody has seen. Two Latvian cards share an ATS while
     * using different key references, so no amount of model detection can pick
     * between them; the key directory can. That costs a PKCS#15 walk — twelve
     * APDUs, once per operation per session.
     *
     * <p>It falls back rather than failing, because a card that answers something
     * unexpected must not become a card that cannot sign. Whatever happens, the
     * caller is left on the applet the operation needs.
     */
    SecurityEnvironment securityEnvironment(SigningOperation operation)
            throws SmartCardReaderException {
        SecurityEnvironment cached = securityEnvironments.get(operation);
        if (cached != null) {
            return cached;
        }

        walkSelectedAnEf = false;
        SecurityEnvironment resolved;
        if (resolveSecurityEnvironmentFromCard()) {
            try {
                resolved = securityEnvironmentFromCard(operation);
            } finally {
                if (walkSelectedAnEf) {
                    // The walk left an EF selected; put the applet back the way the
                    // caller had it, on every exit — a caller that catches and
                    // carries on must not inherit a half-walked card, and that
                    // includes the caller that catches a transport failure and
                    // retries. In a finally for that reason: an SM desync throws
                    // from the middle of the walk, which is exactly the case where
                    // the next attempt needs the applet current.
                    //
                    // Its own failure is swallowed, as in certificate(): a restore
                    // that throws must not replace the error being reported, which
                    // is the one that says what actually went wrong.
                    restoreAppletContext(operation);
                }
            }
            if (resolved == null) {
                // No fallback here on purpose — see SecurityEnvironmentException.
                // Nothing has been staged and no PIN verified, so this costs the
                // user nothing but an error.
                throw new SecurityEnvironmentException(String.format(
                        "%s: this card did not describe its keys, and a card of this model"
                                + " cannot be signed for on assumptions — its algorithm and"
                                + " key references differ between personalisations",
                        operation));
            }
        } else {
            resolved = measuredSecurityEnvironment(operation);
        }
        LoggingUtil.Companion.debugLog(TAG, String.format("%s: %s", operation, resolved), null);
        securityEnvironments.put(operation, resolved);
        return resolved;
    }

    /**
     * Whether to read this card's own description of its keys rather than use the
     * constants measured for the model.
     *
     * <p>Off by default, which is the Estonian answer. Their layout is documented
     * and one pair of key references — {@code 0x81} / {@code 0x9F} — has served
     * every marking in the field, so a walk there protects against a variation
     * nobody has seen while costing ~940 ms per operation on a tap that can be lost
     * for being slow. Latvian cards turn it on, and have every reason to: five
     * personalisations, two of them behind one ATS, with key references, algorithm
     * reference widths and even key types varying between them.
     *
     * <p>The machinery is model-independent in design, and an EE capture on
     * 2026-08-18 resolved from metadata and reproduced the <em>authentication and
     * signing</em> constants exactly. Read that for exactly what it is: one manual
     * exercise, two of the three operations, and nothing in the test suite that
     * would notice if it stopped being true. There is no captured Estonian key
     * directory, so no test compares resolution against the measured constants —
     * {@code estonianCardsAreNotAskedAndPayNothingForIt} asserts the opposite
     * property, that no metadata is read at all.
     *
     * <p><b>So this is not one boolean.</b> Two things would have to be settled
     * first, and both need a captured Estonian EF.OD and PrKD:
     *
     * <ul>
     *   <li><b>Decrypt was never compared.</b> Its constant is the derive-key-only
     *       row ({@code FF 30 04 00}); resolution reached the row by the operation
     *       mask, which every row on the card satisfies. On Latvian cards that
     *       staged a signing reference for decryption until 2026-08-21 — see the
     *       preference in {@link #firstUsableEnvironment}. The Estonian equivalent
     *       has never been checked either way.</li>
     *   <li><b>The key's entry ordering is unpinned.</b> Resolution takes the first
     *       row in the key's list that can serve the operation. Estonian signing
     *       measures to a row that names a hash and authentication to one that does
     *       not, so if either key's list led with the other's row, flipping this
     *       would change what goes on the wire — quietly, since the card accepts
     *       any reference.</li>
     * </ul>
     *
     * <p>The algorithm table for this platform is already captured — the four-byte
     * references in the tests' RSA fixture are these same constants at rows
     * {@code 0x07}, {@code 0x0b} and {@code 0x0d}. Only the key directory is
     * missing.
     */
    protected boolean resolveSecurityEnvironmentFromCard() {
        return false;
    }

    /**
     * The card's own answer, or {@code null} when it does not give one.
     *
     * <p>A card that declines — no EF.TokenInfo, no key directory, nothing usable
     * in it — yields {@code null}, which the caller turns into a refusal. A failure
     * that is not the card declining is rethrown; see the comment on the catch
     * below for why the two must not be confused.
     */
    private SecurityEnvironment securityEnvironmentFromCard(SigningOperation operation)
            throws SmartCardReaderException {
        try {
            // The applet's own table: it is what this applet's key directory
            // references. See algorithmTables.
            Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                    algorithmTable(operation.context);
            if (table.isEmpty()) {
                return null;
            }
            byte[] objectDirectory = readEf(EF_OD);
            byte[] directoryId = Pkcs15SecurityEnvironment.privateKeyDirectoryId(objectDirectory);
            if (directoryId == null) {
                return null;
            }
            List<Pkcs15SecurityEnvironment.Key> keys =
                    Pkcs15SecurityEnvironment.keys(readEf(directoryId));
            return firstUsableEnvironment(operation, keys, table);
        } catch (Exception e) {
            if (e instanceof SmartCardReaderException card && cardResponse(card) == null) {
                // Not the card declining: the tag is gone, or SM has broken. There
                // is no fallback behind this on a Latvian card, so swallowing it
                // would report a transport failure as "this card did not describe
                // its keys" — a card the user is told to stop using, when all that
                // happened is that they moved the phone.
                throw card;
            }
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s: could not read the card's key description (%s)", operation, e), null);
            return null;
        }
    }

    /**
     * The first key that declares an algorithm able to perform this operation.
     * Both cards seen have exactly one key per applet; the loop is for the card
     * that does not.
     */
    private SecurityEnvironment firstUsableEnvironment(
            SigningOperation operation, List<Pkcs15SecurityEnvironment.Key> keys,
            Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table) {
        // Matching the mask is not enough for an operation that accepts more than
        // compute-signature. Every signing row on all three captured tables also
        // advertises derive-key (00 51), so DECRYPT's decipher|derive-key mask
        // matches every row on the card and the first entry in the key's list wins
        // — a signing row. On the LV EC card that stages the same ECDSA reference
        // authentication uses; the key-agreement row (derive-key alone) is never
        // reached. Estonian cards, which work in production on measured constants,
        // use the derive-key-only row for decrypt (80 04 FF 30 04 00) and the
        // signing row for authentication, which is the arrangement being restored
        // here.
        //
        // Selecting by the absent bit rather than by algorithm identity because
        // identity does not discriminate: on the 2020 RSA card the signing row and
        // the decipher row both carry rsaEncryption, so the operation bits are the
        // only thing that tells them apart.
        //
        // A no-op for AUTHENTICATE and SIGN by construction: their mask is
        // compute-signature alone, so nothing else is preferable and the single
        // pass below is the one that runs.
        boolean preferNonSigning = (operation.operationMask
                & ~Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE) != 0;
        for (Pkcs15SecurityEnvironment.Key key : keys) {
            if (!key.isUsable()) {
                continue;
            }
            if (preferNonSigning) {
                SecurityEnvironment preferred = environmentFor(operation, key, table, true);
                if (preferred != null) {
                    return preferred;
                }
            }
            SecurityEnvironment any = environmentFor(operation, key, table, false);
            if (any != null) {
                if (preferNonSigning) {
                    // Worth a line: this card offers nothing but signing rows for an
                    // operation that is not signing, so the reference staged is a
                    // compromise. Nothing verifies a decipher result locally, so if
                    // it turns out wrong this log is the only trace of why.
                    LoggingUtil.Companion.debugLog(TAG, String.format(
                            "%s: no row avoids compute-signature, using a signing row"
                                    + " for %s", operation, key), null);
                }
                return any;
            }
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s: %s declares no algorithm that can do it", operation, key), null);
        }
        return null;
    }

    /**
     * The first row of {@code key} that can serve {@code operation}, or {@code null}.
     *
     * @param avoidSigningRows skip rows that advertise compute-signature. A row that
     *                         did not say what it supports counts as one, since
     *                         {@code supports} reads silence permissively and this
     *                         pass is the one that should be strict.
     */
    private SecurityEnvironment environmentFor(
            SigningOperation operation, Pkcs15SecurityEnvironment.Key key,
            Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table,
            boolean avoidSigningRows) {
        for (Integer entry : key.algorithmEntries) {
            Pkcs15SecurityEnvironment.Algorithm algorithm = table.get(entry);
            if (algorithm == null || !algorithm.supports(operation.operationMask)) {
                continue;
            }
            if (avoidSigningRows && algorithm.supports(
                    Pkcs15SecurityEnvironment.OPERATION_COMPUTE_SIGNATURE)) {
                continue;
            }
            if (key.rsa && !algorithm.rsaEncodingIsUnderstood()) {
                // The row names a hash this library does not know, and for RSA
                // the card builds the PKCS#1 encoding from that hash. Using it
                // would mean sending a digest of one kind and having it encoded
                // as another — a signature that verifies nowhere. Skip the row;
                // another may serve.
                LoggingUtil.Companion.debugLog(TAG, String.format(
                        "%s: skipping entry 0x%02x, its algorithm (%s) is one this"
                                + " library cannot encode for",
                        operation, entry, algorithm.oid), null);
                continue;
            }
            // needsHostDigestInfo is gated on the key type for the same reason
            // rsaEncodingIsUnderstood is, above: it asks whether the caller must
            // build a PKCS#1 encoding, which is a question about RSA only. The row
            // and the key are read from different files, so an EC key citing an
            // rsaEncryption row would otherwise have a DigestInfo wrapped around an
            // EC digest — and nothing downstream would say so, since the length
            // guard returns early for EC and the signing path is not verified. No
            // card does this; the gate is here so that one could not.
            return new SecurityEnvironment(algorithm.mseSetObject(), key.keyReference,
                    key.rsa, key.rsa && algorithm.needsHostDigestInfo(),
                    SignatureAlgorithm.forOid(algorithm.oid),
                    SecurityEnvironment.Source.CARD);
        }
        return null;
    }

    /**
     * EF.TokenInfo's algorithm table, read once per session.
     *
     * <p><b>The caller must already have selected the applet {@code context}
     * names.</b> This method does not select it: the read is a bare SELECT by file
     * id under whatever DF is current, and {@code context} is used only as the
     * cache key. Passing a context that does not match what is selected files one
     * applet's table under the other's name — a wrong answer with nothing to
     * report it, rather than a failure. Every caller selects first; this says so
     * because the signature reads as though it would.
     */
    private Map<Integer, Pkcs15SecurityEnvironment.Algorithm> algorithmTable(
            AppletContext context) throws SmartCardReaderException {
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> cached = algorithmTables.get(context);
        if (cached != null) {
            // Only non-empty tables are ever put here — see below — so a hit is an
            // answer rather than a card that was asked and said nothing.
            return cached;
        }
        Map<Integer, Pkcs15SecurityEnvironment.Algorithm> table =
                Pkcs15SecurityEnvironment.algorithms(readEf(EF_TOKEN_INFO));
        if (!table.isEmpty()) {
            algorithmTables.put(context, table);
        }
        return table;
    }

    /**
     * Checks a signature against the certificate of the key that made it, when that
     * certificate has already been read.
     *
     * <p>Never fails a tap for being unable to look: no certificate read this
     * session, an unparseable one, or a platform lacking the algorithm all log and
     * carry on.
     *
     * <p>A genuine mismatch is fatal only when the environment came from the card
     * itself. That is where the risk is — the card described its own key and the
     * description can be wrong, as the 2020 Latvian algorithm table shows, and a
     * signature made under a wrong description verifies nowhere. Refusing it locally
     * turns a confusing rejection by the relying party into a clear error here.
     *
     * <p>Where the environment came from constants this library measured
     * ({@link SecurityEnvironment.Source#MEASURED}, i.e. Estonian cards), a mismatch
     * is reported at error level and the signature is returned. Those constants have
     * worked on every Estonian card for years, so a mismatch reported here is far
     * likelier to be this check than the card — an unavailable JCA algorithm, a
     * provider disagreeing about signature encoding — and this may not be the thing
     * that breaks a flow that works. No Estonian capture that reads a certificate and
     * then authenticates exists yet to prove otherwise; until one does, the check
     * earns its place there by reporting, not by refusing.
     *
     * <p><b>That report is only as good as the host's logging.</b> Every level in
     * {@code LoggingUtil}, error included, is suppressed unless the consuming app
     * called {@code initialize(..., loggingEnabled = true)} — so in a build with
     * logging off this branch returns a signature it believes is wrong and records
     * nothing. Reporting is the whole justification for not refusing, so an app that
     * wants the finding must enable logging; an app that cannot should be given the
     * fail-closed behaviour instead, which today means a library change rather than a
     * setting.
     */
    void verifySignature(SigningOperation operation, SecurityEnvironment environment,
                         byte[] inputSent, byte[] signature)
            throws SignatureAlgorithmException {
        byte[] certificate = certificates.get(operation.certificateType);
        if (certificate == null) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s: no %s certificate was read this session, so the signature is not"
                            + " checked locally", operation, operation.certificateType), null);
            return;
        }

        SignatureVerifier.Result result =
                SignatureVerifier.verify(certificate, environment, inputSent, signature);
        switch (result) {
            case MATCHED -> LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s: signature verifies against the card's own certificate", operation),
                    null);
            case NOT_CHECKED -> LoggingUtil.Companion.debugLog(TAG, String.format(
                    "%s: signature could not be checked locally — the certificate did not"
                            + " parse, the signature had an unusable shape, or this platform"
                            + " has no such algorithm. The signature is returned unchecked",
                    operation), null);
            case MISMATCHED -> {
                String message = String.format(
                        "%s: the card returned a signature that does not verify under this"
                                + " certificate. Either the algorithm or key reference the card"
                                + " described does not match what it actually signed with, or"
                                + " this is not the certificate for the key that signed — a"
                                + " location holding the other type's certificate looks exactly"
                                + " like this — the KeyUsage of each certificate is checked"
                                + " when it is read, and anything odd is logged there."
                                + " Environment: %s", operation, environment);
                if (environment.source() == SecurityEnvironment.Source.CARD) {
                    throw new SignatureAlgorithmException(message);
                }
                LoggingUtil.Companion.errorLog(TAG, message
                        + ". Not refused, because these are constants measured for this card"
                        + " model rather than anything the card said, and they are known to"
                        + " work — so this is more likely a limitation of the local check than"
                        + " a bad signature. Investigate before trusting the signature", null);
            }
        }
    }

    /** SELECT an EF by file id under the current DF and read it to the end. */
    private byte[] readEf(byte[] fileId) throws SmartCardReaderException {
        reader.transmit(0x00, 0xA4, 0x02, 0x0C, fileId, null);
        walkSelectedAnEf = true;
        return readUntilEof();
    }

    /**
     * The constants measured for this card model, for models that are not asked —
     * see {@link #resolveSecurityEnvironmentFromCard}. Only Estonian cards reach
     * this, and they are EC throughout.
     */
    protected abstract SecurityEnvironment measuredSecurityEnvironment(
            SigningOperation operation) throws SecurityEnvironmentException;

    /**
     * {@code hash} as an authentication needs it: wrapped in a PKCS#1
     * {@code DigestInfo} when the algorithm names no hash, otherwise untouched.
     *
     * <p>Deliberately not widened for a short EC hash, unlike
     * {@link #signingInput}. {@code INTERNAL AUTHENTICATE} has always been given
     * the caller's bytes as they are, and every caller passes a digest matching the
     * curve, so widening here would change the wire format of a working operation
     * to no purpose.
     */
    protected byte[] authenticationInput(byte[] hash, SecurityEnvironment environment)
            throws SmartCardReaderException {
        requireDigestFitsAlgorithm(hash, environment);
        if (environment.needsHostDigestInfo()) {
            return DigestInfo.wrap(hash);
        }
        return hash;
    }

    /**
     * {@code hash} as a signature needs it.
     *
     * <p>Three shapes, and the differences are not cosmetic:
     *
     * <ul>
     *   <li>An algorithm that names no hash will sign whatever it is handed, so
     *       the PKCS#1 {@code DigestInfo} has to be built here or the result is
     *       not an RS256 signature. The 2020 Latvian card's authentication key
     *       offers only such an algorithm.</li>
     *   <li>An EC hash shorter than the field is widened, which is what the card
     *       expects of a P-384 key given a shorter digest, and what this operation
     *       has always done.</li>
     *   <li>An RSA hash is never widened: those leading zeros would be signed as
     *       part of the value.</li>
     * </ul>
     */
    protected byte[] signingInput(byte[] hash, SecurityEnvironment environment)
            throws SmartCardReaderException {
        requireDigestFitsAlgorithm(hash, environment);
        if (environment.needsHostDigestInfo()) {
            return DigestInfo.wrap(hash);
        }
        if (environment.isRsa()) {
            return hash;
        }
        // Widened to the algorithm the card named for this key, not to a fixed 48.
        // A P-384 row asks for 48 and gets exactly what it always got; a P-256 row
        // asks for 32, where padding to 48 would hand the card sixteen zero bytes
        // followed by half the digest — which it would truncate back to its own field
        // size and sign, producing a signature over a value nobody chose. Nothing
        // downstream would catch that: this is the signing path, which verifySignature
        // deliberately does not cover.
        //
        // A card that names no algorithm keeps the historical width. That is every
        // Estonian card, whose 48 is measured rather than inferred, and it is why this
        // changes nothing for any card on record.
        SignatureAlgorithm named = environment.namedAlgorithm();
        return padWithZeroes(hash, named != null ? named.digestLength() : 48);
    }

    /**
     * Refuses a digest of the wrong length for an algorithm the card named.
     *
     * <p>The card builds the encoding from the hash it was told to expect, so a
     * digest of another length would be encoded as that hash and signed. Nothing
     * downstream would say so; the signature would simply not verify.
     */
    private void requireDigestFitsAlgorithm(byte[] hash, SecurityEnvironment environment)
            throws SignatureAlgorithmException {
        if (!environment.isRsa()) {
            // ECDSA signs the value it is given without encoding a hash identifier
            // into it, so a length that does not match the curve is the caller's
            // business, not a corruption.
            //
            // What that leaves open, precisely:
            //
            // On authentication, nothing. authenticationInput sends the caller's
            // bytes unchanged and verifySignature checks the signature against
            // those same bytes, so card and verifier agree at any length.
            //
            // On signing, two different things, and only one of them is a wrong
            // value. Where the row's named digest fits the key's curve, widening
            // is value-preserving — see padWithZeroes — so a 32-byte digest on a
            // P-384 key is signed as the integer the caller chose. What is wrong
            // there is the label: the token says ES384 over a SHA-256 digest,
            // which is the mislabelling the RSA branch below refuses. Where the
            // named digest is *wider than the curve* — a row naming ES384 for a
            // P-256 key, or the null branch's 48 for one — padding overshoots,
            // the card keeps the leftmost field-size bits, and it signs sixteen
            // zero bytes and half the digest. That one is a value nobody chose,
            // on the one path verifySignature does not cover.
            //
            // The two are never compared. The width comes from the card's row and
            // the label from the certificate's curve — permittedAlgorithms asks
            // the certificate and never the card for EC.
            //
            // Comparing them would cost no card read: `certificates` is right here,
            // and verifySignature already reads it that way — look if one is in
            // hand, skip silently if not. What it would cost is being inert where
            // it matters. The map holds only what a caller asked for in this
            // session, and the consumer signs on its own tap: its sign operation
            // calls calculateSignature without reading a certificate first, so the
            // map is empty exactly when a document is being signed. A clamp here
            // would fire only in sessions the application does not create, while
            // changing the wire in a case no capture exercises. So this waits on
            // the same question as the digest the caller is handed, not on the cost
            // of looking.
            return;
        }
        SignatureAlgorithm named = environment.namedAlgorithm();
        if (named != null) {
            if (hash.length != named.digestLength()) {
                // The card builds the encoding from the hash it was told to expect,
                // so a digest of another length would be encoded as that hash and
                // signed. Nothing downstream would say so.
                throw new SignatureAlgorithmException(String.format(
                        "This key signs with %s, so it needs a %d-byte hash, but was given"
                                + " %d bytes. Hash with the algorithm"
                                + " Token.signatureAlgorithm(type, certificate) returned.",
                        named.jwaName(), named.digestLength(), hash.length));
            }
            return;
        }

        // The key's algorithm row names no hash, so nothing on the card fixes which
        // one this is: the DigestInfo is built here from the digest handed in, and
        // whatever length that is becomes the algorithm the signature is over. That
        // makes a mismatch invisible — the signature verifies against its own
        // encoding, and only the name in the token is wrong. So the digest has to
        // match the algorithm we reported for this key, which for a hashless row is
        // the RSA default. Asked for rather than restated, so this check and the
        // answer it is checking cannot drift apart.
        SignatureAlgorithm assumed = SignatureAlgorithm.forRsaKey();
        if (hash.length != assumed.digestLength()) {
            throw new SignatureAlgorithmException(String.format(
                    "This key's algorithm names no hash, so %s is assumed and a %d-byte"
                            + " digest is expected, but was given %d bytes. A %d-byte digest"
                            + " would be signed as a different algorithm than the one"
                            + " reported, producing a token whose stated algorithm does not"
                            + " match its signature. Hash with the algorithm"
                            + " Token.signatureAlgorithm(type, certificate) returned.",
                    assumed.jwaName(), assumed.digestLength(), hash.length, hash.length));
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
     * no such certificate — when the card declines a step or the metadata does
     * not parse. Those failures are non-fatal by design: this runs only for
     * cards that were already about to error out, so an unfamiliar layout must
     * never become an unrelated exception.
     *
     * <p>A failure of the connection itself is rethrown instead. It is not this
     * card's layout being unknown, and swallowing it would have the caller
     * report {@link CertificateNotFoundException} — that the card permanently
     * holds no such certificate — for something a re-tap would fix.
     *
     * <p>Restoring the MAIN AID afterwards is {@link #certificate}'s job, so
     * that either exit can hand straight over without a wasted SELECT.
     */
    private byte[] readCertificateViaPkcs15(CertificateType type)
            throws SmartCardReaderException {
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
            if (e instanceof SmartCardReaderException card && cardResponse(card) == null) {
                // Not the card declining: the tag is gone, or SM has broken.
                // Every other route to the certificate would fail the same way,
                // so this is the answer rather than one more thing to fall back
                // from.
                throw card;
            }
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
    void selectAppletContext(AppletContext context) throws SmartCardReaderException {
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
        // Shaped before the PUK is verified. Doing it inside the transmit below
        // would let a malformed new code raise after a VERIFY had already gone
        // out — harmless in itself, but CodeFormatException promises that none
        // does, and the promise is worth more than the line it costs.
        byte[] newCodeField = code(newCode);
        selectMainAid();
        verifyCode(CodeType.PUK, pukCode);
        if (type.equals(CodeType.PIN2)) {
            selectQSCDAid();
        }
        try {
            reader.transmit(0x00, 0x2C, 0x02, Objects.requireNonNull(VERIFY_PIN_MAP.get(type)), newCodeField, null);
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
     * {@code hash} left-padded with zeroes to {@code width}, or unchanged when it is
     * already that long or longer.
     *
     * <p>Left-padding keeps the value: an ECDSA input is an integer, and leading
     * zeroes do not change it. That holds whatever {@code width} is, which is why
     * widening to a digest the key's own curve is paired with is safe — JWA pairs
     * each curve with a hash no longer than its field, so the padded value stays
     * inside it.
     *
     * <p>That is a guarantee about <em>a curve's own</em> algorithm, and not an
     * invariant of this method. Widen past the key's field — a row naming ES384 for
     * a P-256 key — and the card keeps the leftmost field-size bits, which is zeroes
     * and part of the digest rather than the digest. Nothing here can tell: the
     * caller passes a width, not a curve. See the call site, and the note in
     * {@code requireDigestFitsAlgorithm} for why the two are not compared.
     *
     * @param hash the digest that needs to be signed
     * @param width the length to pad up to, in bytes
     * @return {@code hash} left-padded to {@code width}, or {@code hash} itself when it
     *         is already at least that long
     * @throws IdCardException when padding the hash fails
     */
    protected static byte[] padWithZeroes(byte[] hash, int width) throws IdCardException {
        if (hash.length >= width) {
            return hash;
        }
        try (ByteArrayOutputStream toSign = new ByteArrayOutputStream()) {
            toSign.write(new byte[width - hash.length]);
            toSign.write(hash);
            return toSign.toByteArray();
        } catch (IOException e) {
            throw new IdCardException("Failed to Add padding to hash", e);
        }
    }
}
