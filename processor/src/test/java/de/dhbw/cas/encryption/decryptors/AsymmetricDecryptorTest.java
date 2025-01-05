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

        final TextDecryptor decryptor = new AsymmetricDecryptor("RSA", keyPair.getPrivate().getEncoded());
        final String decrypted = decryptor.decrypt(encryptedMessage, null, StandardCharsets.UTF_8);

        Assertions.assertThat(decrypted).isEqualTo(message);
    }

    @Test
    void test_constructor_failsIfWrongKeyIsPassed() throws NoSuchAlgorithmException {
        final KeyPair keyPair = generateRsaKeyPair();
        Assertions.assertThatThrownBy(() -> new AsymmetricDecryptor("RSA", keyPair.getPublic().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForUnknownTransformation() throws NoSuchAlgorithmException {
        final KeyPair keyPair = generateRsaKeyPair();
        Assertions.assertThatThrownBy(() -> new AsymmetricDecryptor("ILLEGAL", keyPair.getPrivate().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForWrongKey() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        final SecretKey secretKey = keyGenerator.generateKey();

        Assertions.assertThatThrownBy(() -> new AsymmetricDecryptor("RSA", secretKey.getEncoded()));
    }
}