package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;


class EllipticCurveDecryptorTest {

    @ParameterizedTest(name = "decrypt for ecies using curve {0}")
    @ValueSource(strings = {"Tc26-Gost-3410-12-256-paramSetA", "secp256r1", "brainpoolP384t1", "wapip192v1", "c2pnb208w1", "prime192v2"})
    void test_decrypt_worksForDhEcies(final String curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, DecryptionException {
        Security.addProvider(new BouncyCastleProvider());
        final String transformation = "ECIES";
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH");

        keyPairGenerator.initialize(new ECGenParameterSpec(curve));
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final PrivateKey privateKey = keyPair.getPrivate();
        final Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        final String message = "This is a really long message that will be secured with elliptic curve cryptography. Isn't this amazing?";
        final byte[] cipherText = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        final TextDecryptor decryptor = new EllipticCurveDecryptor(transformation, privateKey.getEncoded());
        Assertions.assertThat(decryptor.decrypt(cipherText, null, StandardCharsets.UTF_8)).isEqualTo(message);
    }
}