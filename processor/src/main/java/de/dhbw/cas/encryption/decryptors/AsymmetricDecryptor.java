package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.AlgorithmUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@NullMarked
public class AsymmetricDecryptor implements TextDecryptor {
    private final Cipher cipher;
    private final PrivateKey privateKey;

    public AsymmetricDecryptor(final String transformation, @Nullable final String keyAlgorithm, final byte[] key)
            throws DecryptionException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmUtil.determineKeyAlgorithm(transformation, keyAlgorithm));
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
            cipher = Cipher.getInstance(transformation);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new DecryptionException(e);
        }
    }

    @Override
    public String toString() {
        return "AsymmetricDecryptor for transformation: " + cipher.getAlgorithm();
    }

    @Override
    public String decrypt(final byte[] encrypted, final byte @Nullable [] iv, final Charset charset)
            throws DecryptionException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            final byte[] bytes = cipher.doFinal(encrypted);
            return new String(bytes, charset);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new DecryptionException(e);
        }
    }
}
