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

import static com.google.common.primitives.Bytes.concat;

import android.annotation.SuppressLint;

import androidx.annotation.NonNull;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ee.ria.DigiDoc.smartcardreader.ApduResponseException;
import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;
import ee.ria.DigiDoc.smartcardreader.nfc.ApduEncryptor;
import ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReader;
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil;

/**
 * IdemiaWithPace extends Idemia APDU protocol with Secure Messaging and PACE capabilities
 * enabling the use over NFC. It must implement the ApduEncryptor interface so that
 * NfcSmartCardReader class has an oracle to encrypt C-APDUs and decrypt R-APDUs
 * so that the Idemia APDU protocol can remain mostly unchanged
 * @noinspection FieldCanBeLocal, SameParameterValue
 */
class IdemiaWithPace extends Idemia implements TokenWithPace, ApduEncryptor {
    private static final String TAG = IdemiaWithPace.class.getName();
    /**
     * Last bytes for padding used in establishing encryption key,
     * MAC key and nonce decryption key
     */
    final private byte PADDING_ENCK = 0x01;
    final private byte PADDING_MACK = 0x02;
    final private byte PADDING_NONCE_DECRYPTION = 0x03;

    /**
     * Padding indicator used in SM
     */
    final private byte PADDING_SM = (byte)0x80;

    /**
     * CLA, Plain
     */
    final private byte CLA_ISO = (byte)0x00;

    /**
     * CLA, Plain, command chaining
     */
    final private byte CLA_CHAIN = (byte)0x10;

    /**
     * INS, General Authenticate
     */
    final private byte INS_GA = (byte)0x86;

    /**
     * INS, Manage Security Environment
     */
    final private byte INS_MSE = (byte)0x22;

    /**
     * Supported SM data objects
     */
    final private byte DO85 = (byte)0x85;
    final private byte DO87 = (byte)0x87;
    final private byte DO8E = (byte)0x8E;
    final private byte DO97 = (byte) 0x97;
    final private byte DO99 = (byte) 0x99;

    /**
     * Length of MAC
     */
    final private byte MAC_LENGTH = 8;
    /**
     * Shared encryption key agreed over PACE
     */
    private byte[] keyEnc;

    /**
     * Shared MAC key agreed over PACE
     */
    private byte[] keyMAC;

    /**
     * PACE send sequence counter
     */
    private final byte[] ssc;

    /**
     * Block size used in padding secure messages
     */
    private final int BLOCK_SIZE = 16;

    /**
     * NfcSmartCardReader to provide the encryption/decryption for
     */
    private final NfcSmartCardReader nfcReader;

    /**
     * The measured key references, used only by {@link #measuredSecurityEnvironment}.
     *
     * <p>Primitives, not {@code Byte}: nothing assigns them any more — the Latvian
     * subclass that once did now refuses measured constants outright — so boxing only
     * kept an unboxing failure reachable in the one place that reads them.
     */
    protected byte authKeyRef = (byte) 0x81;
    protected byte signKeyRef = (byte) 0x9F;

    protected String paceEcSpec;
    protected byte paceDomainParam;

    /**
     * Initialize ID1 token with NfcSmartCardReader
     * @param reader
     */
    IdemiaWithPace(NfcSmartCardReader reader) {
        super(reader);
        nfcReader = reader;
        ssc = new byte[BLOCK_SIZE];
    }

    /**
     * Start PACE key-exchange with CAN
     * @param can
     * @throws SmartCardReaderException
     */
    public void tunnel(String can) throws SmartCardReaderException {
        try {
            byte[][] keys = establishPace(can.getBytes(StandardCharsets.UTF_8));
            keyEnc = keys[0];
            keyMAC = keys[1];
            // In case we were successful we notify the card that from now on
            // everything is encrypted
            nfcReader.setApduEncryptor(this);
        } catch (SmartCardReaderException ex) {
            if (ex instanceof ApduResponseException aex) {
                if ((aex.sw1 == (byte) 0x63) && (aex.sw2 == 0x00)) {
                    throw new PaceTunnelException(ex);
                }
            }
            throw ex;
        } catch (Exception ex) {
            // Include the cause's simple class name in the message so integrator
            // logs can distinguish e.g. a BouncyCastle IllegalArgumentException
            // (bad EC point) from an NPE (missing card response) at a glance.
            // The full cause stays attached via the second arg.
            throw new SmartCardReaderException(
                    "Could not establish tunnel: " + ex.getClass().getSimpleName(), ex);
        }
    }

    /**
     * We have to override the main AID selection from the base class, since over NFC the APDU
     * with P2 = 0x00 does not yield a positive output. Therefore we have to use APDU, where
     * P2=0x0C. Although unfortunate - this kind of difference in behaviour over NFC vs. over
     * wire can be expected
     * @throws SmartCardReaderException
     */
    protected void selectMainAid() throws SmartCardReaderException {
        byte[] data = new byte[] {
                (byte) 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
                0x07, 0x00, 0x00, (byte) 0xFE, 0x00, 0x00, 0x01, 0x00};
        reader.transmit(CLA_ISO, 0xA4, 0x04, 0x0C, data, null);
    }

    /**
     * Legacy PACE parameter ID — secp256r1 with id-PACE-ECDH-GM-AES-CBC-CMAC-256.
     * Used as a fallback when EF.CardAccess is unreadable or unparsable on this
     * card model, matching the hardcoded value used before EF.CardAccess parsing
     * was wired up. Cards that want a different curve must publish it correctly
     * in EF.CardAccess; we never silently downgrade a *successfully parsed*
     * value (the unsupported-curve check below still throws).
     */
    private static final byte LEGACY_PACE_PARAM_ID = (byte) 0x0C;

    /**
     * Read PACE domain parameter and EC curve from EF.CardAccess.
     * Accessible before PACE, in plaintext. Falls back to
     * {@link #LEGACY_PACE_PARAM_ID} if the file can't be read or parsed.
     */
    private void readPaceParametersFromCard() throws SmartCardReaderException {
        if (paceEcSpec != null) {
            return;
        }

        byte paramId = 0;
        try {
            reader.transmit(0x00, 0xA4, 0x02, 0x0C, new byte[]{0x01, 0x1C}, null);
            byte[] cardAccess = readBinaryFile();
            paramId = parsePaceParameterId(cardAccess);
        } catch (SmartCardReaderException e) {
            // EF.CardAccess select/read failed — could be a card variant where
            // the file isn't visible under the MAIN AID context, ACL-restricted,
            // or otherwise unreadable. Fall through to the legacy default rather
            // than failing PACE outright; every card that worked before this
            // file existed worked with the hardcoded 0x0C / secp256r1 anyway.
            LoggingUtil.Companion.debugLog(TAG,
                "EF.CardAccess read failed, using legacy PACE defaults: " + e.getMessage(),
                null);
        }

        if (paramId == 0) {
            paramId = LEGACY_PACE_PARAM_ID;
        }

        paceDomainParam = paramId;
        paceEcSpec = domainParamToCurveName(paramId);

        // Only throw when the card explicitly told us it wants a curve we don't
        // implement. A successful read+parse trumps the legacy default — better
        // a clear error here than a downstream MAC mismatch.
        if (paceEcSpec == null) {
            throw new SmartCardReaderException(
                "Unsupported PACE domain parameter: 0x" + Integer.toHexString(paramId & 0xFF)
            );
        }

        LoggingUtil.Companion.debugLog(TAG,
            String.format("PACE parameters: paramId=0x%02X, curve=%s", paramId, paceEcSpec),
            null
        );
    }

    /**
     * Set MSE Authentication Template
     *
     * @throws SmartCardReaderException
     */
    private void setMSEAuthenticationTemplate() throws SmartCardReaderException {
        byte[] data = new byte[] {
                (byte)0x80, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02,
                0x02, 0x04, 0x02, 0x04, (byte)0x83, 0x01, 0x02, (byte)0x84, 0x01, paceDomainParam};
        reader.transmit(CLA_ISO, INS_MSE, 0xC1, 0xA4, data, 0x00);
    }

    /**
     * Get GA Nonce
     * @return
     * @throws SmartCardReaderException
     */
    private byte[] getGAGetNonce() throws SmartCardReaderException {
        byte[] data = new byte[] {0x7C, 0x00};
        return reader.transmit(CLA_CHAIN, INS_GA, 0x00, 0x00, data, 0x00);
    }

    /**
     * GA Map Nonce
     * @param publicKey
     * @return
     * @throws SmartCardReaderException
     */
    private byte[] getGAMapNonce(byte[] publicKey) throws SmartCardReaderException {
        byte[] prefix = new byte[] {0x7c, 0x43, (byte)0x81, 0x41};
        byte[] data = concat(prefix, publicKey);
        return reader.transmit(CLA_CHAIN, INS_GA, 0x00, 0x00, data, 0x00);
    }

    /**
     * GA Key Agreement
     *
     * @param publicKey
     * @return
     * @throws SmartCardReaderException
     */
    private byte[] getGAKeyAgreement(byte[] publicKey) throws SmartCardReaderException {
        byte[] prefix = new byte[] {0x7c, 0x43, (byte)0x83, 0x41};
        byte[] data = concat(prefix, publicKey);
        return reader.transmit(CLA_CHAIN, INS_GA, 0x00, 0x00, data, 0x00);
    }

    /**
     * GA Mutual Authentication
     * @param mac
     * @return
     * @throws SmartCardReaderException
     */
    private byte[] getGAMutualAuthentication(byte[] mac) throws SmartCardReaderException {
        byte[] prefix = new byte[] {0x7C, 0x0A, (byte)0x85, 0x08};
        byte[] data = concat(prefix, mac);
        return reader.transmit(CLA_ISO, INS_GA, 0x00, 0x00, data, 0x00);
    }

    /**
     * Get Data for MAC
     * @param publicKey
     * @return
     */
    private byte[] getDataForMac(byte[] publicKey) {
        byte[] prefix = new byte[] {
                0x7f, 0x49, 0x4f, 0x06, 0x0a, 0x04, 0x00, 0x7f,
                0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04, (byte)0x86, 0x41};
        return concat(prefix, publicKey);
    }

    /**
     * Creates a cipher key
     *
     * @param basis    the array to be used as the basis for the key
     * @param lastByte the last byte in the appended padding
     * @return the constructed key
     */
    private byte[] createKey(byte[] basis, byte lastByte) throws NoSuchAlgorithmException {
        byte[] padding = new byte[] {0x00, 0x00, 0x00, lastByte};
        byte[] padded = concat(basis, padding);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(padded);
    }

    /**
     * Decrypts the nonce
     *
     * @param encryptedNonce the encrypted nonce received from the chip
     * @param CAN            the card access number provided by the user
     * @return the decrypted nonce
     */
    private byte[] decryptNonce(byte[] encryptedNonce, byte[] CAN) throws
            NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] decryptionKey = createKey(CAN, PADDING_NONCE_DECRYPTION);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(decryptionKey, "AES"),
                new IvParameterSpec(new byte[BLOCK_SIZE]));
        return cipher.doFinal(encryptedNonce);
    }

    /**
     * Calculates the message authentication code
     *
     * @param data   the byte array on which the CMAC algorithm is performed
     * @param keyMAC the key for performing CMAC
     * @return MAC
     */
    private byte[] getMAC(byte[] data, byte[] keyMAC) {
        BlockCipher blockCipher = new AESEngine();
        CMac cmac = new CMac(blockCipher);
        cmac.init(new KeyParameter(keyMAC));
        cmac.update(data, 0, data.length);
        byte[] MAC = new byte[cmac.getMacSize()];
        cmac.doFinal(MAC, 0);
        return Arrays.copyOf(MAC, MAC_LENGTH);
    }

    /**
     * Check that response has specific header bytes
     * @param header
     * @param response
     */
    private static void validateHeader(byte[] response, byte[] header) throws
            SmartCardReaderException {

        if (header.length > response.length) {
            throw new SmartCardReaderException(
                    "Response length is shorter than expected header length");
        }

        for (int i = 0; i < header.length; i++) {
            if (header[i] != response[i]) {
                throw new SmartCardReaderException(
                        "Unexpected byte at index " + i + " in the APDU header");
            }
        }
    }

    /**
     * Assert a response is exactly the expected length. Used after validateHeader
     * to catch malformed PACE GA responses early with a clear message, instead of
     * surfacing as opaque crypto errors from downstream decode/decrypt steps.
     */
    private static void validateResponseLength(byte[] response, int expected, String stage)
            throws SmartCardReaderException {
        if (response.length != expected) {
            throw new SmartCardReaderException(
                    "Unexpected " + stage + " response length: " + response.length
                            + " (expected " + expected + ")");
        }
    }

    /**
     * Generate private key in range [1, N-1]
     */
    private static BigInteger generateRandomPrivateKey(ECNamedCurveParameterSpec spec) {
        SecureRandom random = new SecureRandom();
        BigInteger n = spec.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (; ; ) {
            d = BigIntegers.createRandomBigInteger(nBitLength, random);

            if (isOutOfRangeD(d, n)) {
                continue;
            }

            if (WNafUtil.getNafWeight(d) < minWeight) {
                continue;
            }

            break;
        }

        return d;
    }

    private static boolean isOutOfRangeD(BigInteger d, BigInteger n) {
        return d.compareTo(BigInteger.ONE) < 0 || (d.compareTo(n) >= 0);
    }

    /**
     * PACE Key-Exchange with ID1
     *
     * @param can the card access number
     */
    private byte[][] establishPace(byte[] can) throws
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, SmartCardReaderException {

        selectMainAid();

        readPaceParametersFromCard();
        setMSEAuthenticationTemplate();

        byte[] response = getGAGetNonce();

        byte[] gaGetNonceResponseHeader = new byte[] {0x7C, 0x22, (byte)0x80, 0x20};
        validateHeader(response, gaGetNonceResponseHeader);
        // Encrypted nonce is always 32 bytes for the AES-CBC-CMAC-256 PACE variant
        // (header byte 0x20 = 32). Catch malformed/truncated responses here so the
        // failure surfaces with a clear message rather than as a downstream
        // IllegalBlockSizeException from the AES decrypt.
        validateResponseLength(response, gaGetNonceResponseHeader.length + 32, "GA Get Nonce");
        byte[] decryptedNonce = decryptNonce(
                Arrays.copyOfRange(
                        response, gaGetNonceResponseHeader.length, response.length),
                can);

        // generate an EC keypair and exchange public keys with the chip
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(paceEcSpec);

        // Uncompressed point encoding: 0x04 || X || Y, both coords curve-sized.
        // 65 bytes for the 256-bit curves, 97 bytes for 384-bit.
        int pointBytes = 1 + 2 * ((spec.getCurve().getFieldSize() + 7) / 8);

        BigInteger privateKey = generateRandomPrivateKey(spec);

        ECPoint publicKey = spec.getG().multiply(privateKey).normalize();
        response = getGAMapNonce(publicKey.getEncoded(false));

        // Extract bytes from R-APDU to represent card public key
        byte[] gaMapNonceHeader = new byte[] {0x7C, 0x43, (byte)0x82, 0x41};
        validateHeader(response, gaMapNonceHeader);
        validateResponseLength(response, gaMapNonceHeader.length + pointBytes, "GA Map Nonce");
        ECPoint cardPublicKey = spec.getCurve().decodePoint(
                Arrays.copyOfRange(response, gaMapNonceHeader.length, response.length));

        // calculate the new base point, use it to generate a new keypair
        // and exchange public keys
        ECPoint sharedSecret = cardPublicKey.multiply(privateKey);
        ECPoint mappedECBasePoint = spec.getG().multiply(
                new BigInteger(1, decryptedNonce)).add(sharedSecret).normalize();

        privateKey = generateRandomPrivateKey(spec);
        publicKey = mappedECBasePoint.multiply(privateKey).normalize();
        response = getGAKeyAgreement(publicKey.getEncoded(false));

        // Extract 65 bytes from R-APDU to represent card public key
        byte[] gaKeyAgreementHeader = new byte[] {0x7C, 0x43, (byte)0x84, 0x41};
        validateHeader(response, gaKeyAgreementHeader);
        validateResponseLength(response, gaKeyAgreementHeader.length + pointBytes, "GA Key Agreement");
        cardPublicKey = spec.getCurve().decodePoint(
                Arrays.copyOfRange(response, gaKeyAgreementHeader.length, response.length));

        // generate the session keys and exchange MACs to verify them
        byte[] secret = cardPublicKey.multiply(privateKey).
                normalize().getAffineXCoord().getEncoded();

        byte[] keyEnc = createKey(secret, PADDING_ENCK);
        byte[] keyMAC = createKey(secret, PADDING_MACK);
        byte[] MAC = getMAC(getDataForMac(cardPublicKey.getEncoded(false)), keyMAC);
        response = getGAMutualAuthentication(MAC);

        byte[] gaMutualAuthenticationHeader = new byte[] {0x7C, 0x0A, (byte)0x86, 0x08};
        validateHeader(response, gaMutualAuthenticationHeader);
        validateResponseLength(response, gaMutualAuthenticationHeader.length + MAC_LENGTH,
                "GA Mutual Authentication");

        // verify chip's MAC and return session keys
        MAC = getMAC(getDataForMac(publicKey.getEncoded(false)), keyMAC);
        byte[] cardMac = Arrays.copyOfRange(response,
                gaMutualAuthenticationHeader.length,
                gaMutualAuthenticationHeader.length + MAC_LENGTH);
        if (!Arrays.equals(cardMac, MAC)) {
            throw new SmartCardReaderException("Could not verify chip's MAC.");
        }
        return new byte[][]{keyEnc, keyMAC};

    }

    /**
     * Encrypt/Decrypt data with the agreed key
     *
     * @param data - data to be encrypted/decrypted
     * @param mode - encrypt or decrypt?
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    private byte[] encdecData(byte[] data, int mode) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyEnc, "AES");
        @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance(
                "AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] iv = Arrays.copyOf(cipher.doFinal(ssc), BLOCK_SIZE);
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, secretKeySpec, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private byte[] encryptData(byte[] data) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        return encdecData(data, Cipher.ENCRYPT_MODE);
    }

    private byte[] decryptData(byte[] data) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        return encdecData(data, Cipher.DECRYPT_MODE);
    }

    /**
     * Pad data to the block-size with 8000*
     *
     * @param data
     * @param blockSize
     * @return
     */
    private byte[] pad(byte[] data, int blockSize) {
        int padLen = (blockSize - data.length % blockSize);
        byte[] result = new byte[data.length + padLen];
        System.arraycopy(data, 0, result, 0, data.length);
        result[data.length] = PADDING_SM;
        return result;
    }

    /**
     * Unpad data that has been padded to the block size by 8000*
     *
     * @param data
     * @return
     */
    private byte[] unpad(byte[] data) {
        for (int i = data.length - 1; i >= 0; i--) {
            if (data[i] == PADDING_SM) {
                byte[] ret = new byte[i];
                System.arraycopy(data, 0, ret, 0, i);
                return ret;
            }
        }

        return data;
    }

    /**
     * For Debugging - bouncy does not survive nulls
     * @param data
     * @return
     */
    private String toHexString(byte[] data) {
        if (data == null) {
            return "NULL";
        }
        return Hex.toHexString(data);
    }

    /**
     * Encrypt C-APDU and protect with MAC
     *
     * @param cla
     * @param ins
     * @param p1
     * @param p2
     * @param data
     * @param le
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] encryptAndMac(int cla, int ins, int p1, int p2, byte[] data, Integer le)
            throws GeneralSecurityException, SmartCardReaderException {
        LoggingUtil.Companion.debugLog(TAG, String.format("C-APDU to encrypt: 0x%02X 0x%02X 0x%02X 0x%02X",
                (byte)cla, (byte)ins, (byte)p1, (byte)p2), null);

        incrementSSC(ssc);
        byte[] maskedHeader = new byte[] {
                (byte)((byte)cla | 0x0C), (byte) ins, (byte) p1, (byte) p2 };
        byte[] do8587 = getDo8587(ins, data);
        byte[] do97 = getDo97(le);
        byte[] do8e = getDo8e(maskedHeader, do8587, do97);

        int newLength = do8587.length + do97.length + do8e.length;
        SmApduLength.requireSingleByteLc(newLength);

        byte[] result = concat(
                maskedHeader,
                new byte[] {(byte) newLength},
                do8587,
                do97,
                do8e,
                new byte[] {0x00}
        );
        incrementSSC(ssc);
        LoggingUtil.Companion.debugLog(TAG, String.format("Encrypted C-APDU: %s", toHexString(result)), null);
        return result;
    }

    /**
     * Calculate DO8E object
     *
     * @param maskedHeader
     * @param do8587
     * @param do97
     * @return
     */
    @NonNull
    private byte[] getDo8e(byte[] maskedHeader, byte[] do8587, byte[] do97) {
        byte[] paddedMaskedHeader = pad(maskedHeader, BLOCK_SIZE);
        byte[] macData = concat(ssc, paddedMaskedHeader, do8587, do97);
        byte[] paddedMacData = macData;
        if (macData.length % BLOCK_SIZE != 0) {
            paddedMacData = pad(macData, BLOCK_SIZE);
        }
        return concat(new byte[] {DO8E, MAC_LENGTH}, getMAC(paddedMacData, keyMAC));
    }

    /**
     * Calculate DO97 object
     *
     * @param le
     * @return
     */
    @NonNull
    private byte[] getDo97(Integer le) {
        byte[] do97 = new byte[]{};
        if (le != null) {
            do97 = new byte[]{DO97, 0x01, le.byteValue()};
        }
        return do97;
    }

    /**
     * Calculate DO85/DO87 object
     *
     * @param ins
     * @param data
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    @NonNull
    private byte[] getDo8587(int ins, byte[] data) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException,
            SmartCardReaderException {
        byte[] do8587 = new byte[]{};

        if (data != null && data.length > 0) {
            byte[] paddedData;
            paddedData = pad(data, BLOCK_SIZE);
            byte[] dataEncrypted = encryptData(paddedData);
            if (ins % 2 == 0) {
                int innerLength = dataEncrypted.length + 1;
                SmApduLength.requireShortBerLength(innerLength, "DO87");
                do8587 = concat(new byte[]{DO87, (byte) innerLength, 0x01},
                        dataEncrypted);
            } else {
                SmApduLength.requireShortBerLength(dataEncrypted.length, "DO85");
                do8587 = concat(new byte[]{DO85, (byte) dataEncrypted.length}, dataEncrypted);
            }
        }
        return do8587;
    }

    /**
     * Validate R-APDU, check MAC and decrypt data if present. Only return data.
     *
     * @param response
     * @return
     * @throws GeneralSecurityException
     * @throws SmartCardReaderException
     */
    public byte[] decryptAndVerify(byte[] response) throws
            GeneralSecurityException, SmartCardReaderException {

        LoggingUtil.Companion.debugLog(TAG, String.format("Encrypted R-APDU: %s", Hex.toHexString(response)), null);

        // result shall be decrypted data or empty
        byte[] result = new byte[]{};

        int currentByte = 0;
        if ((response[currentByte] == DO87) || (response[currentByte] == DO85)) {

            boolean skip87header = (response[currentByte] == DO87);

            currentByte += 1;

            int size = response[currentByte] & 0xFF;
            LoggingUtil.Companion.debugLog(TAG, String.format(Locale.ENGLISH, "Encrypted data size %d ", size), null);

            currentByte += 1;

            if (size > 0x80) {
                int sizeLen = size & 0x0F;
                byte[] sizeBytes = new byte[sizeLen];
                System.arraycopy(response, currentByte, sizeBytes, 0, sizeLen);
                size = new BigInteger(1, sizeBytes).intValue();
                LoggingUtil.Companion.debugLog(TAG, String.format(Locale.ENGLISH,"size bytes %d, size %d", sizeLen, size), null);
                currentByte += sizeLen;
            }

            if (skip87header) {
                if (response[currentByte] != (byte) 0x01) {
                    throw new SmartCardReaderException("Invalid encryption header");
                }
                currentByte += 1; // skip encryption header
                size -= 1;
            }

            result = decryptData(
                    Arrays.copyOfRange(response, currentByte, currentByte + size));
            currentByte += size;
        }

        if (response[currentByte] == DO99) {
            if (!Hex.toHexString(response, currentByte, 4).equals("99029000")) {
                throw new SmartCardReaderException("Invalid status");
            }
            currentByte += 4;
        }

        int macStart = currentByte;
        if (response[currentByte] != DO8E) {
            LoggingUtil.Companion.debugLog(TAG, String.format(Locale.ENGLISH, "0x%02X, %d", response[currentByte], currentByte), null);
            throw new SmartCardReaderException("Missing MAC");
        }
        currentByte += 1;

        if (response[currentByte] != MAC_LENGTH) {
            throw new SmartCardReaderException("Unsupported MAC length");
        }
        currentByte += 1;

        byte[] cardMac = Arrays.copyOfRange(
                response, currentByte, currentByte + MAC_LENGTH);
        currentByte += MAC_LENGTH;

        byte[] rdata = Arrays.copyOfRange(response, 0, macStart);
        byte[] macData = pad(concat(ssc, rdata), BLOCK_SIZE);
        byte[] ourMac = getMAC(macData, keyMAC);
        LoggingUtil.Companion.debugLog(TAG, String.format("Card MAC: %s, our MAC: %s",
                Hex.toHexString(cardMac), Hex.toHexString(ourMac)), null);

        if (!Arrays.equals(cardMac, ourMac)) {
            throw new SmartCardReaderException("Could not verify chip's MAC.");
        }

        if (response.length - currentByte != 2) {
            throw new SmartCardReaderException("Malformed R-APDU");
        }

        LoggingUtil.Companion.debugLog(TAG, String.format("Decrypted data: %s", Hex.toHexString(result)), null);
        return unpad(result);
    }

    /**
     * Increment send sequence counter
     * @param ssc
     */
    private static void incrementSSC(byte[] ssc) {
        for (int i = ssc.length - 1; i >= 0; i--) {
            ssc[i]++;
            if (ssc[i] != 0) {
                break;
            }
        }
    }

    /**
     * MSE algorithm-reference template (DO 80) for the auth / sign / decrypt
     * MSE SET commands. Defaults match Estonian IDEMIA cards (4-byte algo IDs);
     * subclasses override to swap in card-specific identifiers. The
     * {@code 84 01 <keyRef>} key-reference DO is appended by the caller.
     */
    protected byte[] authMseTemplate() {
        return new byte[] {(byte) 0x80, 0x04, (byte) 0xFF, 0x20, 0x08, 0x00};
    }

    protected byte[] signMseTemplate() {
        return new byte[] {(byte) 0x80, 0x04, (byte) 0xFF, 0x15, 0x08, 0x00};
    }

    protected byte[] decryptMseTemplate() {
        return new byte[] {(byte) 0x80, 0x04, (byte) 0xFF, 0x30, 0x04, 0x00};
    }

    /**
     * Estonian IDEMIA's own templates and key references.
     *
     * <p>Reached only because Estonian cards are not asked to describe themselves —
     * see {@link #resolveSecurityEnvironmentFromCard}. Latvian cards never come
     * here: their values differ between personalisations that share an ATS, so a
     * constant would be wrong for some of them and
     * {@link SecurityEnvironmentException} is raised instead. The Latvian values
     * measured so far are recorded against the captures they came from, in
     * {@code IDEMIA_LV.md} §9-§11 and in the replay fixtures — but not in production
     * code, precisely so nobody is tempted to apply one to the wrong card. What
     * matters here is the rule they establish:
     * two Latvian cards sharing the "SeID" ATS use {@code 0x82}/{@code 0x9E} and
     * {@code 0x81}/{@code 0x9F}, and one of them is RSA, so no constant is right
     * for all of them.
     *
     * <p>Declares {@link SecurityEnvironmentException} without throwing it, so that a
     * subclass with no measured constants can refuse here rather than inherit
     * another card's.
     */
    @Override
    protected SecurityEnvironment measuredSecurityEnvironment(SigningOperation operation)
            throws SecurityEnvironmentException {
        return switch (operation) {
            case AUTHENTICATE -> new SecurityEnvironment(
                    authMseTemplate(), authKeyRef, false, false, null,
                    SecurityEnvironment.Source.MEASURED);
            case SIGN -> new SecurityEnvironment(
                    signMseTemplate(), signKeyRef, false, false, null,
                    SecurityEnvironment.Source.MEASURED);
            case DECRYPT -> new SecurityEnvironment(
                    decryptMseTemplate(), authKeyRef, false, false, null,
                    SecurityEnvironment.Source.MEASURED);
        };
    }

    /**
     * The algorithm this card will sign an authentication challenge with.
     *
     * <p>For an EC key the certificate is the whole answer — the curve implies the
     * hash — and nothing is read from the card.
     *
     * <p>For an RSA key the certificate settles nothing, so the card is asked: if
     * the key's PKCS#15 algorithm row names a hash, that is the answer and no
     * assumption is involved. Where the row names no hash — plain
     * {@code rsaEncryption}, which is what the 2020 Latvian card's authentication
     * key offers — the hash is decided by which {@code DigestInfo} we go on to
     * build, so the conventional default stands and is logged as a choice.
     *
     * <p>Refuses in one case that no card reaches: when
     * {@link #permittedAlgorithms(CertificateType, byte[])} allows several algorithms
     * and the default is not among them, there is nothing this method could both use
     * and report, so it raises {@link SignatureAlgorithmException} rather than name an
     * algorithm the key will not sign with. Reachable only by a subclass narrowing
     * what a key permits; it is checked because {@link Token} promises the answer is
     * always a member of that set, and a promise nothing enforces is one that fails
     * quietly.
     */
    @Override
    public SignatureAlgorithm signatureAlgorithm(CertificateType type, byte[] certificate)
            throws SmartCardReaderException {
        Set<SignatureAlgorithm> permitted = permittedAlgorithms(type, certificate);
        if (permitted.size() == 1) {
            return permitted.iterator().next();
        }

        // More than one is permitted only where the card named no hash, and then the
        // choice is this library's. Taken from the same place the digest-length check
        // takes it, so the two cannot disagree.
        SignatureAlgorithm ours = SignatureAlgorithm.forRsaKey();
        if (!permitted.contains(ours)) {
            // Unreachable while the only plural answer is the RSA set. Checked because
            // the Token contract promises this answer is a member of that set, and a
            // subclass narrowing permittedAlgorithms could otherwise break the promise
            // silently — the symptom would be a token whose named algorithm is not
            // what the card signed with, which is what this whole path exists to avoid.
            throw new SignatureAlgorithmException(String.format(
                    "%s key: the card permits %s, none of which is the %s this library"
                            + " would choose, so there is no algorithm it can both use and"
                            + " report", type, permitted, ours.jwaName()));
        }
        LoggingUtil.Companion.debugLog(TAG, String.format(
                "the card named no hash for its %s key, so %s is our choice out of %s —"
                        + " the DigestInfo we build is what fixes it",
                type, ours.jwaName(), permitted), null);
        return ours;
    }

    /**
     * Asks the card, which is the whole point: on this card model what a key can sign
     * with does not follow from the certificate, and on the Latvian ones it does not
     * follow from the model either.
     */
    @Override
    public Set<SignatureAlgorithm> permittedAlgorithms(CertificateType type,
                                                       byte[] certificate)
            throws SmartCardReaderException {
        SignatureAlgorithm fromCertificate = SignatureAlgorithm.forCertificate(certificate);
        if (!fromCertificate.isRsa()) {
            // The curve fixes both the hash and the reference; there is nothing to ask.
            return SignatureAlgorithm.only(fromCertificate);
        }

        SignatureAlgorithm named = cardNamedAlgorithm(SigningOperation.signingWith(type));
        if (named != null && named.isRsa()) {
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "the card names %s for its %s key", named.jwaName(), type), null);
            return SignatureAlgorithm.only(named);
        }
        return SignatureAlgorithm.rsaAlgorithms();
    }

    /**
     * What the card names for an operation's key, resolving the environment if it
     * has not been already. Leaves the card on the MAIN AID, since this is called
     * between reads rather than inside an operation.
     */
    private SignatureAlgorithm cardNamedAlgorithm(SigningOperation operation)
            throws SmartCardReaderException {
        try {
            selectAppletContext(operation.context);
            return securityEnvironment(operation).namedAlgorithm();
        } catch (SecurityEnvironmentException e) {
            // The card would not describe its keys, so there is no algorithm to
            // report — and this is deliberately not softened into the fallback
            // below. Returning RS256 here would name an algorithm for a card that
            // cannot sign at all: the caller would hash for it, put it in a token,
            // and get this same exception from authenticate() two lines later.
            // Failing now says what is wrong, before any of that work.
            //
            // Caught ahead of the transport check because it carries no cause, so
            // cardResponse() cannot tell it apart from a lost tag.
            throw e;
        } catch (SmartCardReaderException e) {
            if (cardResponse(e) == null) {
                // Not the card declining: the tag is gone, or SM has broken. Asking
                // what a key signs with is the first thing a caller does, so
                // answering "the card named no hash" here would hand back RS256 and
                // let the real failure surface later as something else entirely.
                throw e;
            }
            LoggingUtil.Companion.debugLog(TAG, String.format(
                    "could not ask the card which algorithm its %s key uses (%s)",
                    operation, e), null);
            return null;
        } finally {
            // In a finally because the javadoc promises it: the card is left on
            // MAIN whether the question was answered, declined, or cut short. Its
            // own failure is swallowed for the same reason as everywhere else —
            // it must not replace the error being reported.
            try {
                selectMainAid();
            } catch (Exception e) {
                LoggingUtil.Companion.debugLog(TAG, String.format(
                        "could not re-select MAIN AID after asking about the %s key (%s)",
                        operation, e), null);
            }
        }
    }

    @Override
    public byte[] authenticate(byte[] pin1, byte[] token) throws SmartCardReaderException {
        selectOberthurAid();
        SecurityEnvironment environment =
                securityEnvironment(SigningOperation.AUTHENTICATE);
        // Prepared before the PIN on purpose: this is where the digest is checked
        // against the algorithm the key signs with, and a mismatch should cost the
        // user nothing. No card I/O happens here, so the bytes that go out are the
        // same either way.
        byte[] input = authenticationInput(token, environment);
        verifyCode(CodeType.PIN1, pin1);

        reader.transmit(0x00, 0x22, 0x41, SigningOperation.AUTHENTICATE.mseSetP2,
                environment.mseSetBody(), null);
        byte[] signature = reader.transmit(0x00, 0x88, 0x00, 0x00, input, 0x00);

        // Checked here and not in calculateSignature: authentication callers have
        // already read the certificate, signing callers have not, and reading one
        // there costs about a second.
        verifySignature(SigningOperation.AUTHENTICATE, environment, input, signature);
        return signature;
    }

    @Override
    public byte[] calculateSignature(byte[] pin2, byte[] hash, boolean ecc) throws SmartCardReaderException {
        selectQSCDAid();
        SecurityEnvironment environment =
                securityEnvironment(SigningOperation.SIGN);
        // Prepared before the PIN, as in authenticate(): the digest-length check
        // lives in here, and a mismatch should not cost a verification.
        byte[] input = signingInput(hash, environment);
        verifyCode(CodeType.PIN2, pin2);

        reader.transmit(0x00, 0x22, 0x41, SigningOperation.SIGN.mseSetP2,
                environment.mseSetBody(), null);
        return reader.transmit(0x00, 0x2A, 0x9E, 0x9A, input, 0x00);
    }

    @Override
    public byte[] decrypt(byte[] pin1, byte[] data, boolean ecc) throws SmartCardReaderException {
        selectOberthurAid();
        SecurityEnvironment environment =
                securityEnvironment(SigningOperation.DECRYPT);
        verifyCode(CodeType.PIN1, pin1);

        reader.transmit(0x00, 0x22, 0x41, SigningOperation.DECRYPT.mseSetP2,
                environment.mseSetBody(), null);
        // Decipher takes the cryptogram with its leading padding indicator, not a
        // hash, so it is passed through untouched.
        return reader.transmit(0x00, 0x2A, 0x80, 0x86, concat(new byte[] {0x00}, data), 0x00);
    }

    /**
     * Read a binary file from the currently selected EF.
     */
    protected byte[] readBinaryFile() throws SmartCardReaderException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        while (true) {
            try {
                stream.write(reader.transmit(0x00, 0xB0, stream.size() >> 8, stream.size(), null, 0x00));
            } catch (ApduResponseException e) {
                if (e.sw1 == 0x6B && e.sw2 == 0x00) {
                    break; // offset out of range = end of file
                } else if (e.sw1 == 0x6A && e.sw2 == (byte) 0x82) {
                    break; // file not found
                } else {
                    throw e;
                }
            } catch (IOException e) {
                throw new SmartCardReaderException(e);
            }
        }
        return stream.toByteArray();
    }

    /**
     * Parse PACEInfo parameterId from EF.CardAccess.
     *
     * EF.CardAccess is ASN.1: SET OF SecurityInfo
     * PACEInfo ::= SEQUENCE { OID protocol, INTEGER version, INTEGER parameterId }
     *
     * Multiple SecurityInfo entries may share the { OID, INTEGER, INTEGER } shape
     * (e.g. ChipAuthenticationInfo); only the entry whose protocol OID matches
     * id-PACE-ECDH-GM-AES-CBC-CMAC-256 (the mechanism we use in MSE SET AT) is
     * a valid source for parameterId.
     *
     * @return parameterId byte, or 0 if not found
     */
    private static final byte[] PACE_PROTOCOL_OID = {
            0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04
    };

    private static byte parsePaceParameterId(byte[] cardAccess) {
        List<TLV> entries = TLV.parseAll(cardAccess);
        for (TLV entry : entries) {
            if (entry.children == null) {
                continue;
            }
            // SET contains SEQUENCEs (SecurityInfo entries)
            for (TLV child : entry.children) {
                byte param = readPaceParamFromSecurityInfo(child);
                if (param != 0) {
                    return param;
                }
            }
        }
        // Also check top-level SEQUENCEs (if no outer SET wrapper)
        for (TLV entry : entries) {
            byte param = readPaceParamFromSecurityInfo(entry);
            if (param != 0) {
                return param;
            }
        }
        return 0;
    }

    private static byte readPaceParamFromSecurityInfo(TLV securityInfo) {
        if (securityInfo.children == null || securityInfo.children.size() < 3) {
            return 0;
        }
        TLV oidTlv = securityInfo.children.get(0);
        if (oidTlv.getTag() != 0x06 || !Arrays.equals(oidTlv.getValue(), PACE_PROTOCOL_OID)) {
            return 0;
        }
        TLV paramTlv = securityInfo.children.get(2);
        if (paramTlv.getTag() == 0x02 && paramTlv.getValue().length == 1) {
            return paramTlv.getValue()[0];
        }
        return 0;
    }

    /**
     * Map a PACE parameterId to a JCA curve name.
     *
     * <p>Only 256-bit curves are wired up: every BER prefix and response-header
     * validator in {@link #establishPace} hard-codes 65-byte point lengths
     * (`0x41`) and a 79-byte CMAC input (`0x4F`). 384-bit support would
     * require derive-from-{@code pointBytes} encoding throughout, plus a card
     * to test against — neither is in scope here.
     *
     * <p>For 384-bit parameterIds (`0x0F` `secp384r1`, `0x10`
     * `brainpoolP384r1`), this returns {@code null}; the caller surfaces the
     * canonical "Unsupported PACE domain parameter" error.
     */
    private static String domainParamToCurveName(byte paramId) {
        return switch (paramId & 0xFF) {
            case 0x0C -> "secp256r1";
            case 0x0D -> "brainpoolP256r1";
            default -> null;
        };
    }

}
