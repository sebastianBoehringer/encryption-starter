package de.dhbw.cas.encryption.decryptors;


import de.dhbw.cas.encryption.exception.DecryptionException;
import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

class KemDecryptorTest {

    final String KEY_PAIR_ALGO = "X25519";

    private KeyPair generateX25519KeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_ALGO);
        return keyPairGenerator.generateKeyPair();
    }

    @Test
    void test_decrypt_worksForDhKem() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecryptionException {
        final String kemTransformation = "DHKEM";

        final KeyPair kp = generateX25519KeyPair();
        final KEM dhKem = KEM.getInstance(kemTransformation);
        final KEM.Encapsulator encapsulator = dhKem.newEncapsulator(kp.getPublic());
        final KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");

        final SecretKey secretKey = encapsulated.key();
        final Cipher aes = Cipher.getInstance(UnwrappingDecryptor.TRANSFORMATION_USED_WITH_UNWRAPPED_KEY);
        final IvParameterSpec iv = new IvParameterSpec(new byte[aes.getBlockSize()]);
        aes.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final String message = "KEM makes this go post quantum";
        final byte[] encrypted = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));

        TextDecryptor decryptor = new KemDecryptor(kemTransformation, KEY_PAIR_ALGO, encapsulated.encapsulation(), kp.getPrivate().getEncoded());
        Assertions.assertThat(decryptor.decrypt(encrypted, iv.getIV(), StandardCharsets.UTF_8)).isEqualTo(message);
    }

    @Test
    void test_decrypt_worksForMlKem() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecryptionException {
        Security.addProvider(new BouncyCastleProvider());

        final String kemTransformation = "ML-KEM";
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(kemTransformation);

        final KeyPair kp = kpg.generateKeyPair();
        final KEM dhKem = KEM.getInstance(kemTransformation);
        final KEM.Encapsulator encapsulator = dhKem.newEncapsulator(kp.getPublic());
        final KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");

        final SecretKey secretKey = encapsulated.key();
        final Cipher aes = Cipher.getInstance(UnwrappingDecryptor.TRANSFORMATION_USED_WITH_UNWRAPPED_KEY);
        final IvParameterSpec iv = new IvParameterSpec(new byte[aes.getBlockSize()]);
        aes.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final String message = "Another KEM algorithm is actually supported!👌👌👌👌";
        final byte[] encrypted = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));

        TextDecryptor decryptor = new KemDecryptor(kemTransformation, null, encapsulated.encapsulation(), kp.getPrivate().getEncoded());
        Assertions.assertThat(decryptor.decrypt(encrypted, iv.getIV(), StandardCharsets.UTF_8)).isEqualTo(message);
    }

}