package de.dhbw.cas.encryption.decryptors;


import de.dhbw.cas.encryption.exception.DecryptionException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

class SymmetricDecryptorTest {

    SecretKey generateAesKey() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    @Test
    void test_decrypt_worksForAes() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecryptionException {
        final SecretKey key = generateAesKey();

        final String transformation = "AES/ECB/PKCS5Padding";
        final Cipher aes = Cipher.getInstance(transformation);
        aes.init(Cipher.ENCRYPT_MODE, key);
        final String message = "Symmetrische Kryptographie funktioniert";
        final byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aes.doFinal(messageBytes);

        final TextDecryptor decryptor = new SymmetricDecryptor(transformation, null, key.getEncoded());
        final String decrypted = decryptor.decrypt(encrypted, null, StandardCharsets.UTF_8);
        Assertions.assertThat(decrypted).isEqualTo(message);
    }

    @Test
    void test_constructor_failsForUnknownAlgorithm() throws NoSuchAlgorithmException {
        final SecretKey secretKey = generateAesKey();
        Assertions.assertThatThrownBy(() -> new SymmetricDecryptor("ILLEGAL", null, secretKey.getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForUnknownTransformation() throws NoSuchAlgorithmException {
        final SecretKey secretKey = generateAesKey();
        Assertions.assertThatThrownBy(() -> new SymmetricDecryptor("AES/ILLEGAL", null, secretKey.getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForUnknownPadding() throws NoSuchAlgorithmException {
        final SecretKey secretKey = generateAesKey();
        Assertions.assertThatThrownBy(() -> new SymmetricDecryptor("AES/ECB/ILLEGAL_PADDING", null, secretKey.getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForInvalidKey() throws NoSuchAlgorithmException {
        final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        final KeyPair keyPair = rsaGenerator.generateKeyPair();

        Assertions.assertThatThrownBy(() -> new SymmetricDecryptor("AES_256", null, keyPair.getPublic().getEncoded()))
                .isInstanceOf(DecryptionException.class);
        Assertions.assertThatThrownBy(() -> new SymmetricDecryptor("AES_256", null, keyPair.getPrivate().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }
}