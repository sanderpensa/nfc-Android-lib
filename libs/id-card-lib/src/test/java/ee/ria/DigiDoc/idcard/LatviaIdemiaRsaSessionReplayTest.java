package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.bytes;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.err6B00;
import static ee.ria.DigiDoc.idcard.ApduReplayReader.ok;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * The first successful RSA session, replayed: the 2020 Latvian card
 * ("LV eID ICA 2021", RSA-2048) authenticating and signing, captured 2026-08-19.
 *
 * <p>Both operations are here because the card wants them prepared differently,
 * and that difference is the whole substance of RSA support:
 *
 * <ul>
 *   <li><b>Authentication</b> uses the key's only signing row, plain
 *       {@code rsaEncryption} at {@code 80 01 02}. It names no hash, so the card
 *       signs whatever arrives and the caller must build the PKCS#1
 *       {@code DigestInfo} — 51 bytes go out where an EC card sends 48.</li>
 *   <li><b>Signing</b> uses {@code sha256WithRSAEncryption} at {@code 80 01 42},
 *       which names its hash, so the bare 32-byte digest goes out and the card
 *       builds the encoding itself.</li>
 * </ul>
 *
 * <p>The closing assertion of each test is the strong one: the captured signature
 * is decrypted with the modulus of the key that made it and checked to be
 * {@code 00 01 FF..FF 00 || DigestInfo(SHA-256) || digest} over the digest that
 * was sent. That is what proves the input this library constructs is the input
 * that produces a valid RS256 signature — not merely that the card answered
 * {@code 90 00}. No arrangement of correct-looking APDUs can fake it.
 *
 * <p>Only the two moduli are embedded, not the certificates: a modulus carries no
 * cardholder identity, and it is all the verification needs.
 *
 * <p>Note the two key references, {@code 0x81} and {@code 0x9F}. They are the
 * Estonian values on a card whose ATS is the Latvian "SeID" one, and the profile
 * hardcodes {@code 0x82} / {@code 0x9E}. Every expectation below would fail
 * against the hardcoded values, which is why they come from the card.
 */
public final class LatviaIdemiaRsaSessionReplayTest {


    /** RFC 8017 DigestInfo prefix for SHA-256. */
    private static final String DIGEST_INFO_SHA256 = "3031300d060960864801650304020105000420";

    /** The hash the app asked the card to sign, recovered from the signature. */
    private static final String AUTH_DIGEST =
            "c86544a7df23b2fb6f0f07754bf1165bf83817df712c65ce2e3c3bfc6537b359";
    private static final String AUTH_SIGNATURE =
            "21737e83d192e5fead64b31e3dd501b6a561b1947198caa588f96da98d6c5d94"
                    + "7915614339c17f0e817fb02edb161bd6ca574a45a8aafcf666507039b681f9f1"
                    + "430129904a8f0b93cbb15dd9c98c59946aa3f0c151b1dec05c649303ec66b2ff"
                    + "6c24932e0a811fd3e64d805b0392cefd9482aa17a240095f65231779bf855b85"
                    + "9b2f4c4d5d72425b3c2192163df4345a0cbd93b45dc0ff76b8292fcefa584aa3"
                    + "6c7d7caac657a49f1e42df67270eb3f3729b2e659ee13fec182e37c6ae186782"
                    + "33220457c5edb7fa587adb03696d428e7b1bb87ec9ce2843bbf592e1455c405c"
                    + "67a242fefac0685fe592cdcc540593719f5e9a53114e6f22af9344de59064aa5";
    private static final String AUTH_KEY_MODULUS =
            "be04d847968960c27254d98d8ce5bb00762e44c89d3d25e6d98641193a79b4cd"
                    + "6f3b3197009382e96cfe47a6214505d4e8f2b0a6dbaa4f7cb5fb5384e3668b32"
                    + "467a058e0f842bf78678b00a4ea458103035cffa14550fcac585980a026e9f74"
                    + "05398d9527167ab7956c1da3f2b2e62f6010e52f01cd3d4b1a2700c51bbd10f2"
                    + "5b90393204fa3ba927c76542932f8dff4f842dd5ee987db956a327094347a9fc"
                    + "8ea94a7ae6aaff50d1c170681c066d12d795255acd6763ef0f475a2a21b42f68"
                    + "6cdc431f24776fb00bd0698bc1204a997d25c0d35e33a6949621a20bbbab7ba7"
                    + "0cc00327b207a025bec554d0422f43fc966f5beed38a9a4c4e3f876298a8b971";
    private static final String SIGN_DIGEST =
            "2ddd20043a3439a2f773852b5ed2a4dad26b38d3c2e9dd4d0515c6f85e2d0a5a";
    private static final String SIGN_SIGNATURE =
            "26e15b0b7c2c609db3243fab41dcd5ff72ae0fffd28bc0a9fd6e074a73fabe69"
                    + "c4df73008ef5768667025dca7ba5cd5da4254d20f09399919812553a7e4d2e08"
                    + "eaf2abc668d026274c1cda39058017cb554b23641d15c8cb7ea17a7803f3e9a4"
                    + "37540fc6bf903aef12cdeb2737076364abea2cda7ab2704239decbe5dc6d7579"
                    + "2dc7a024e1decb58e297c8de851c3c20f0f4ad89fb3345917a6bde02d37a8d16"
                    + "f45fa5464fce989d5601f840da9ac067d46455303fb7cfe03436fcfbf06e0110"
                    + "ebea2375456fa4cd30f6a22051b44429196af8165ada4267f293a82d4ad6945e"
                    + "3787816159bac0b3fd91a272455da3834f0b3e398de380933fe3e2e63e0bc5bd";
    private static final String SIGN_KEY_MODULUS =
            "c31ae2c6aab4b4bc15f1b2acc365ab26df0b9b16358820da57e4f99b2697f055"
                    + "dc48a5aa215882292c57811fcd49d916c60ebbb5bd8fe425a5a0b9fe24d13975"
                    + "fe4957f8e3cb00a6e524aabc2aecc738a7c34a6aefea2da42e62b35a16d9b770"
                    + "ef3d3c98e8be2099169881a2f59c2209efdc6b53073269008bd5cb8da1b99105"
                    + "20ee5479bf1298953f37722b08c1b9bfb7cc6c958517913143f9f534f84d6b4f"
                    + "57bffdac270f9f07dd2eea5802c386315893c28a7908ebd147a573aa911eafdc"
                    + "4868c9db6d5811c85eacb9ccefdbaa60ed0230a1af9298d6da3854652f123cb2"
                    + "993815d40059e5fe5e8b0869c8cf7f98b15d29bf2625821de5a3e7e1ae64a29b";

    @Test
    public void authenticate_sendsAHostBuiltDigestInfoToRawRsaAndGetsAValidRs256Signature()
            throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_OBERTHUR);
                    r.expectFileRead("5031", RsaCardMetadata.AUTH_EF_OD);
                    r.expectFileRead("7002", RsaCardMetadata.AUTH_PRKD);
                    // The walk left an EF selected, so the applet is re-selected.
                    r.expect(TestApdus.SEL_OBERTHUR_AID, ok());
                    r.expect("00200001" + "0c" + TestPins.PIN1_PADDED_FF, ok());
                    // Raw RSA under key 0x81 — the card's values, not the profile's.
                    r.expect("002241a4" + "06" + "800102" + "840181", ok());
                    // 0x33 = 51 bytes: the DigestInfo this side had to build. An EC
                    // card would see 48, and a bare digest here would be 32.
                    r.expect("00880000" + "33" + DIGEST_INFO_SHA256 + AUTH_DIGEST + "00",
                            bytes(AUTH_SIGNATURE));
                })
                .tunnel();

        byte[] signature = fixture.token.authenticate(
                TestPins.PIN1, Hex.decode(AUTH_DIGEST));

        assertThat(Hex.toHexString(signature)).isEqualTo(AUTH_SIGNATURE);
        assertThat(signature).hasLength(256);
        assertRs256Signature(AUTH_KEY_MODULUS, AUTH_DIGEST, signature);
        fixture.assertAllConsumed();
    }

    @Test
    public void calculateSignature_sendsTheBareDigestAndLetsTheCardEncodeIt() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_QSCD);
                    r.expectFileRead("5031", RsaCardMetadata.QSCD_EF_OD);
                    r.expectFileRead("7012", RsaCardMetadata.SIGN_PRKD);
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                    r.expect("00200085" + "0c" + TestPins.PIN2_PADDED_FF, ok());
                    // sha256WithRSAEncryption under key 0x9F.
                    r.expect("002241b6" + "06" + "800142" + "84019f", ok());
                    // 0x20 = 32 bytes, unwrapped: this row names its hash, so the
                    // card adds the DigestInfo. Wrapping here would double it.
                    r.expect("002a9e9a" + "20" + SIGN_DIGEST + "00", bytes(SIGN_SIGNATURE));
                })
                .tunnel();

        byte[] signature = fixture.token.calculateSignature(
                TestPins.PIN2, Hex.decode(SIGN_DIGEST), false);

        assertThat(Hex.toHexString(signature)).isEqualTo(SIGN_SIGNATURE);
        assertThat(signature).hasLength(256);
        // The card built the DigestInfo, and the result is the same structure the
        // authentication path builds by hand — which is why both verify as RS256.
        assertRs256Signature(SIGN_KEY_MODULUS, SIGN_DIGEST, signature);
        fixture.assertAllConsumed();
    }

    /**
     * The algorithm reported for the token comes from the card, not a default.
     *
     * <p>Resolution alone, without an operation around it: the applet is selected
     * by {@code calculateSignature} in real use, so the only AID select here is the
     * one resolution does itself to put the applet back after reading files.
     */
    @Test
    public void signatureAlgorithm_forTheSigningKeyIsTheOneTheCardNames() throws Exception {
        var fixture = ReplayFixture.lvSeid()
                .with(r -> {
                    r.expectFileRead("5032", RsaCardMetadata.TOKEN_INFO_QSCD);
                    r.expectFileRead("5031", RsaCardMetadata.QSCD_EF_OD);
                    r.expectFileRead("7012", RsaCardMetadata.SIGN_PRKD);
                    r.expect(TestApdus.SEL_QSCD_AID, ok());
                })
                .tunnel();

        SecurityEnvironment environment =
                fixture.token.securityEnvironment(SigningOperation.SIGN);

        assertThat(environment.source()).isEqualTo(SecurityEnvironment.Source.CARD);
        assertThat(environment.isRsa()).isTrue();
        assertThat(environment.namedAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);
        // The card encodes for this row, so nothing is wrapped on this side.
        assertThat(environment.needsHostDigestInfo()).isFalse();
        assertThat(Hex.toHexString(environment.mseSetBody())).isEqualTo("800142" + "84019f");
        fixture.assertAllConsumed();
    }

    /**
     * Decrypts the signature with the public modulus and checks the recovered
     * block is exactly what RS256 requires over {@code digestHex}.
     */
    private static void assertRs256Signature(String modulusHex, String digestHex,
                                             byte[] signature) throws Exception {
        BigInteger modulus = new BigInteger(modulusHex, 16);
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(modulus, BigInteger.valueOf(65537)));
        assertThat(key).isNotNull();

        byte[] recovered = new BigInteger(1, signature)
                .modPow(BigInteger.valueOf(65537), modulus).toByteArray();
        // BigInteger drops the leading zero of the 00 01 .. block.
        String block = Hex.toHexString(recovered);
        assertThat(block).startsWith("01ff");
        assertThat(block).endsWith(DIGEST_INFO_SHA256 + digestHex);

        // Padding must be all 0xFF up to the single 0x00 separator, and long
        // enough to fill the modulus — a short pad would still "end with" the
        // digest while being a forgeable block.
        int separator = block.indexOf("00", 2) / 2;
        assertThat(recovered).hasLength(255);
        assertThat(separator).isEqualTo(255 - 1 - (DIGEST_INFO_SHA256.length() + digestHex.length()) / 2);
        for (int i = 1; i < separator; i++) {
            assertThat(recovered[i]).isEqualTo((byte) 0xFF);
        }
    }

    /** SELECT the file, hand it back in 231-byte reads, then EOF. */
}
