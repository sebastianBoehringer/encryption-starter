package de.dhbw.cas.encryption.decryptors;


import de.dhbw.cas.encryption.exception.DecryptionException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

class UnwrappingDecryptorTest {
    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private SecretKey generateAesKey() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    @Test
    void test_decrypt_worksWithRsaWrapping() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException, DecryptionException {
        final KeyPair keyPair = generateRsaKeyPair();
        final PublicKey wrappingKey = keyPair.getPublic();

        final SecretKey aesKey = generateAesKey();

        final String transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        final Cipher wrappingCipher = Cipher.getInstance(transformation);
        wrappingCipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedKey = wrappingCipher.wrap(aesKey);


        final Cipher encryptingCipher = Cipher.getInstance(UnwrappingDecryptor.TRANSFORMATION_USED_WITH_UNWRAPPED_KEY);
        final IvParameterSpec iv = new IvParameterSpec(new byte[encryptingCipher.getBlockSize()]);
        encryptingCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);

        final String message = "Wrapping and unwrapping can take some time";
        final byte[] encrypted = encryptingCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        final TextDecryptor decryptor = new UnwrappingDecryptor(transformation, wrappedKey, keyPair.getPrivate().getEncoded());
        final String decrypted = decryptor.decrypt(encrypted, iv.getIV(), StandardCharsets.UTF_8);
        Assertions.assertThat(decrypted).isEqualTo(message);
    }

    @Test
    void test_constructor_failsForInvalidAlgorithm() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        final KeyPair keyPair = generateRsaKeyPair();
        final PublicKey wrappingKey = keyPair.getPublic();

        final SecretKey aesKey = generateAesKey();

        final String transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        final Cipher wrappingCipher = Cipher.getInstance(transformation);
        wrappingCipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedKey = wrappingCipher.wrap(aesKey);
        Assertions.assertThatThrownBy(() -> new UnwrappingDecryptor("ILLEGAL", wrappedKey, keyPair.getPrivate().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }

    @Test
    void test_constructor_failsForPublicKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        final KeyPair keyPair = generateRsaKeyPair();
        final PrivateKey wrappingKey = keyPair.getPrivate();

        final SecretKey aesKey = generateAesKey();

        final String transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        final Cipher wrappingCipher = Cipher.getInstance(transformation);
        wrappingCipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedKey = wrappingCipher.wrap(aesKey);
        Assertions.assertThatThrownBy(() -> new UnwrappingDecryptor("ILLEGAL", wrappedKey, keyPair.getPublic().getEncoded()))
                .isInstanceOf(DecryptionException.class);
    }
}