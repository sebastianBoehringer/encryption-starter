package de.dhbw.cas.encryption.decryptors;


import de.dhbw.cas.encryption.exception.DecryptionException;
import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

class AsymmetricDecryptorTest {

    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Test
    void test_decrypt_worksForRsa() throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, NoSuchPaddingException, DecryptionException {

        final KeyPair keyPair = generateRsaKeyPair();

        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        final String message = "Crypto ist cool";
        final byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        final byte[] encryptedMessage = cipher.doFinal(messageBytes);

        final TextDecryptor decryptor = new AsymmetricDecryptor("RSA", null, keyPair.getPrivate().getEncoded());
        final String decrypted = decryptor.decrypt(encryptedMessage, null, StandardCharsets.UTF_8);

        Assertions.assertThat(decrypted).isEqualTo(message);
    }

    @ParameterizedTest(name = "decrypt for ecies using curve {0}")
    @ValueSource(strings = {"Tc26-Gost-3410-12-256-paramSetA", "secp256r1", "brainpoolP384t1", "wapip192v1", "c2pnb208w1", "prime192v2"})
    void test_decrypt_worksForDhEciesWithDifferentCurves(final String curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, DecryptionException {
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

        final TextDecryptor decryptor = new AsymmetricDecryptor(transformation, "EC", privateKey.getEncoded());
        Assertions.assertThat(decryptor.decrypt(cipherText, null, StandardCharsets.UTF_8)).isEqualTo(message);
    }

    @Test
    void test_constructor_failsIfWrongKeyIsPassed() throws NoSuchAlgorithmException {
        final KeyPair keyPair = generateRsaKeyPair();
        Assertions.assertThatThrownBy(() -> new AsymmetricDecryptor("RSA", null, keyPair.getPublic().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForUnknownTransformation() throws NoSuchAlgorithmException {
        final KeyPair keyPair = generateRsaKeyPair();
        Assertions.assertThatThrownBy(() -> new AsymmetricDecryptor("ILLEGAL", null, keyPair.getPrivate().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForWrongKey() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        final SecretKey secretKey = keyGenerator.generateKey();

        Assertions.assertThatThrownBy(() -> new AsymmetricDecryptor("RSA", null, secretKey.getEncoded()));
    }
}