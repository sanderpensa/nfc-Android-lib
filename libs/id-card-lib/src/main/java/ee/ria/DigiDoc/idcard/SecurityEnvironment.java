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

import org.bouncycastle.util.encoders.Hex;

/**
 * Everything one {@code MSE:SET} needs, resolved together.
 *
 * <p>Kept as one value because these are not independent lookups. The algorithm
 * reference and the key reference come from the same key directory entry and only
 * make sense as a pair — the 2020 Latvian card wants {@code 80 01 02} with key
 * {@code 0x81}, the 2026 one {@code 80 01 04} with key {@code 0x82}, and any
 * mixture of the two is a signature that verifies nowhere. Resolving them
 * separately is how they drift apart.
 */
final class SecurityEnvironment {

    /** Where the answer came from, which is worth logging when a tap misbehaves. */
    enum Source {
        /** Read from the card's own PKCS#15 metadata. */
        CARD,
        /** The constants measured from the cards we have, used when the card would not say. */
        MEASURED
    }

    /** The {@code 80 xx ...} algorithm object, tag and length included. */
    private final byte[] algorithmObject;
    private final byte keyReference;
    private final boolean rsa;
    private final boolean needsHostDigestInfo;
    private final SignatureAlgorithm namedAlgorithm;
    private final Source source;

    SecurityEnvironment(byte[] algorithmObject, byte keyReference, boolean rsa,
                        boolean needsHostDigestInfo, SignatureAlgorithm namedAlgorithm,
                        Source source) {
        this.algorithmObject = algorithmObject;
        this.keyReference = keyReference;
        this.rsa = rsa;
        this.needsHostDigestInfo = needsHostDigestInfo;
        this.namedAlgorithm = namedAlgorithm;
        this.source = source;
    }

    /**
     * The algorithm the card named for this key, or {@code null} when its
     * algorithm row names no hash and so settles nothing — which is the case for
     * both Latvian cards' authentication keys.
     */
    SignatureAlgorithm namedAlgorithm() {
        return namedAlgorithm;
    }

    /**
     * Whether the key is RSA, which changes how the input is prepared: an EC key
     * wants the hash widened to the field size, an RSA key must never be widened
     * because the padding is the card's job.
     */
    boolean isRsa() {
        return rsa;
    }

    /** The body of the {@code MSE:SET}: the algorithm object, then the key. */
    byte[] mseSetBody() {
        byte[] body = new byte[algorithmObject.length + 3];
        System.arraycopy(algorithmObject, 0, body, 0, algorithmObject.length);
        body[algorithmObject.length] = (byte) 0x84;
        body[algorithmObject.length + 1] = 0x01;
        body[algorithmObject.length + 2] = keyReference;
        return body;
    }

    /**
     * Whether the caller must wrap the digest in a PKCS#1 DigestInfo before
     * sending it, because the algorithm this environment selects does not name a
     * hash and so the card will sign the bytes as they arrive.
     */
    boolean needsHostDigestInfo() {
        return needsHostDigestInfo;
    }

    Source source() {
        return source;
    }

    @Override
    public String toString() {
        return String.format("%s (%s, algorithm=%s, key=0x%02x%s%s)", source,
                rsa ? "RSA" : "EC", Hex.toHexString(algorithmObject), keyReference & 0xFF,
                namedAlgorithm == null ? ", names no hash" : ", " + namedAlgorithm.jwaName(),
                needsHostDigestInfo ? ", caller supplies the DigestInfo" : "");
    }
}
