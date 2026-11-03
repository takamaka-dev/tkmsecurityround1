package io.takamaka.crypto.tkmsecurityprovider.pqc.crypto.qteslaround1;

import io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r1.QTR1CypherProvider;
import io.takamaka.crypto.tkmsecurityprovider.util.adaptor.r1.QTR1KeyPairGenerator;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * qTESLA-p-I (round 1) key generation reduces the public polynomial T = A*s + e into [0, q) from BOTH sides
 * (Takamaka fix of 2026-11-03 in {@code QTESLA.generateKeyPair}, the P variants).
 *
 * The code this package was taken from (BouncyCastle 1.61) reduced from above only. About one key in 90,000 came out
 * with a coefficient slightly below zero after the lazy Montgomery multiplication plus the error polynomial; its sign
 * bits were packed into the public key, so the public key did not match the private key and EVERY signature failed to
 * verify. Found live on the xc2400 rig (2026-10-29): the reference client could not sign its slot E13S458 with the key
 * derived from the seed in {@code src/test/resources/badkey/xc2400-E13S458-bad-qtesla-ps1-seed.txt}.
 *
 * Pins: the SHA-256 prefixes below were produced by the PRE-FIX code (BouncyCastle 1.61 behaviour) for 5,002 keys;
 * the fix left every one of them byte-identical (public and private key) and changed only the one broken public key.
 * The private key of the broken pair is byte-identical too: the defect was in the packing of T, not in s or e.
 */
public class QTeslaPS1KeygenTwoSidedReductionTest {

    /** The first {@code nextBytes} of wallet-core's {@code SeededRandom(seed, scope, keyNumber)}: PBKDF2-HMAC-SHA512. */
    static final class WalletChainRandom extends SecureRandom {
        private final String seed, scope; private final int keyNumber; int calls;
        WalletChainRandom(String seed, String scope, int keyNumber) { this.seed = seed; this.scope = scope; this.keyNumber = keyNumber; }
        @Override public void nextBytes(byte[] bytes) {
            if (++calls > 1) throw new IllegalStateException("key generation asked for randomness more than once");
            try {
                PBEKeySpec spec = new PBEKeySpec(seed.toCharArray(), scope.getBytes(StandardCharsets.UTF_8), keyNumber, 8 * bytes.length);
                byte[] enc = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).getEncoded();
                System.arraycopy(enc, 0, bytes, 0, bytes.length);
            } catch (Exception ex) { throw new RuntimeException(ex); }
        }
    }

    static final String WALLET_KEY_CHAIN = "__WKCH__";

    /** PRE-FIX pins: seed, scope, key number, sha256(public key UrlBase64)[0:24], sha256(private secret)[0:24]. */
    static final String[][] GOOD_KEY_PINS = {
            {"abc", "_/y", "1", "78035a63315c5aa9c69b23dc", "9d3608f2db4adef8a700216e"},
            {"xc2400-pin-0000", "__WKCH__", "1", "e57c66fc4792564010e320f7", "cd1ab73d6e4b9c8b872ade19"},
            {"xc2400-pin-0001", "__WKCH__", "1", "b08ea461c10e17c20a588e2d", "5b8474cfa8555fb424fa8801"},
            {"xc2400-pin-0002", "__WKCH__", "1", "6dd1a852c58e98d39eb73945", "84ab53a53236a8be255752ca"},
            {"xc2400-pin-0003", "__WKCH__", "1", "9d4ca0e5ca55128e460950fe", "052236173917eb06b6dc5749"},
            {"xc2400-pin-0004", "__WKCH__", "1", "8e3ba701626c01f61192d7e4", "6e2fd15f538d9961f1bd84d2"},
            {"xc2400-pin-0005", "__WKCH__", "1", "85a75ca500a15554c7a9589b", "43df197fdc594677894429e7"},
            {"xc2400-pin-0006", "__WKCH__", "1", "f4b8e7e4954684de7fca898c", "1f1bddc4b0e71722de4517c1"},
            {"xc2400-pin-0007", "__WKCH__", "1", "8939d983e90f0beee75ac25d", "b0dc736747875a31dd95c0e2"},
            {"xc2400-pin-0008", "__WKCH__", "1", "b9af9bcfa7d085eba5f4b616", "748345a6b9bfdd3b659bae95"},
            {"xc2400-pin-0009", "__WKCH__", "1", "866ec2e916d55633f0961da5", "e3907da771d7678549fd676c"},
            {"xc2400-pin-0010", "__WKCH__", "1", "fef0c6ec490d43e60b6c2691", "3fc7386ec6ef5db744c513c2"},
            {"xc2400-pin-0011", "__WKCH__", "1", "5ce6ac949bc59732a8e8b52a", "0a4547f92829d6de59c769b8"},
            {"xc2400-pin-0012", "__WKCH__", "1", "d6141b0ad0519a413c315233", "65402430e26ba16d116cb7e6"},
            {"xc2400-pin-0013", "__WKCH__", "1", "2de35a45b9b0208669ecb177", "9f73b6b9c273c504b4903685"},
            {"xc2400-pin-0014", "__WKCH__", "1", "1861b8ebfe0f30408a122cc1", "72efbca922b19b7a17f5e4c2"},
            {"xc2400-pin-0015", "__WKCH__", "1", "7d61d41bcf5bf65d3a1b3075", "2d13627fdc89e1d6e3d8e3e5"},
            {"xc2400-pin-0016", "__WKCH__", "1", "ebcb4ba4896af1ebf2192b32", "9cdecb15bb3f2eaff90b4ea7"},
            {"xc2400-pin-0017", "__WKCH__", "1", "2996e2646f3e6b105da738aa", "6faa55fde3d07d9ee718a6b9"},
            {"xc2400-pin-0018", "__WKCH__", "1", "aa2e11e17599bd13788224b7", "d5154c260bc5ca57a293bef7"},
            {"xc2400-pin-0019", "__WKCH__", "1", "f28edb22a48e62fb02e4de7c", "8e5ecaaa560257bac3bcc0f3"}
    };

    static String badSeed() throws IOException {
        try (InputStream in = QTeslaPS1KeygenTwoSidedReductionTest.class.getResourceAsStream("/badkey/xc2400-E13S458-bad-qtesla-ps1-seed.txt")) {
            assertNotNull(in, "fixture missing");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    static String sha(byte[] b) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) sb.append(String.format("%02x", x));
        return sb.substring(0, 24);
    }

    static AsymmetricCipherKeyPair keyPair(String seed, String scope, int keyNumber) {
        return QTR1KeyPairGenerator.getKeyPair(new WalletChainRandom(seed, scope, keyNumber));
    }

    static String pkSha(AsymmetricCipherKeyPair kp) throws Exception {
        return sha(QTR1KeyPairGenerator.getStringPublicKey(kp).getBytes(StandardCharsets.UTF_8));
    }

    static String skSha(AsymmetricCipherKeyPair kp) throws Exception {
        return sha(((QTESLAPrivateKeyParameters) kp.getPrivate()).getSecret());
    }

    static int verifiedOf(AsymmetricCipherKeyPair kp, int messages, String label) throws Exception {
        String pk = QTR1KeyPairGenerator.getStringPublicKey(kp);
        int ok = 0;
        for (int i = 0; i < messages; i++) {
            String m = "msg-" + label + "-" + i;
            String sig = QTR1CypherProvider.sign(kp, m).getSignature();
            if (QTR1CypherProvider.verify(pk, sig, m).isValid()) ok++;
        }
        return ok;
    }

    @Test
    public void theXc2400BadSeedNowYieldsAKeyPairWhoseSignaturesVerify() throws Exception {
        AsymmetricCipherKeyPair kp = keyPair(badSeed(), WALLET_KEY_CHAIN, 1);   // index 0 = the slot key
        assertEquals("fa1b7240347988807e598a38", skSha(kp), "the private key must be the one the old code produced (s and e were sound)");
        assertNotEquals("b10d03ba588842e4b9b3f870", pkSha(kp), "the old, broken public key");
        assertEquals("eabf4b3e00ea486e8270bced", pkSha(kp), "the corrected public key");
        assertEquals(20, verifiedOf(kp, 20, "bad"), "every signature must verify with the generated public key (pre-fix: 0 of 20)");
    }

    @Test
    public void theOtherIndicesOfTheBadSeedAreUntouched() throws Exception {
        AsymmetricCipherKeyPair kp1 = keyPair(badSeed(), WALLET_KEY_CHAIN, 2);
        AsymmetricCipherKeyPair kp2 = keyPair(badSeed(), WALLET_KEY_CHAIN, 3);
        assertEquals("97834a5cb87a01dc6c35c4c6", pkSha(kp1)); assertEquals("0376c162125fac22264c904e", skSha(kp1));
        assertEquals("dfdbc9856356a6707fe1ffea", pkSha(kp2)); assertEquals("7c28402c072078f6972f8708", skSha(kp2));
        assertEquals(20, verifiedOf(kp1, 20, "idx1"));
        assertEquals(20, verifiedOf(kp2, 20, "idx2"));
    }

    @Test
    public void everyGoodKeyPairIsByteIdenticalToThePreFixCode() throws Exception {
        for (String[] pin : GOOD_KEY_PINS) {
            AsymmetricCipherKeyPair kp = keyPair(pin[0], pin[1], Integer.parseInt(pin[2]));
            assertEquals(pin[3], pkSha(kp), "public key changed for seed " + pin[0]);
            assertEquals(pin[4], skSha(kp), "private key changed for seed " + pin[0]);
        }
    }

    @Test
    public void generatedKeyPairsSignAndVerify() throws Exception {
        for (int i = 0; i < 40; i++) {
            AsymmetricCipherKeyPair kp = keyPair("two-sided-reduction-" + i, WALLET_KEY_CHAIN, 1);
            assertEquals(1, verifiedOf(kp, 1, "s" + i), "seed " + i);
        }
    }
}
