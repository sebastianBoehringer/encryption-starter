package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.AlgorithmUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class SymmetricDecryptor implements TextDecryptor {
    private final Key key;
    private final Cipher cipher;

    public SymmetricDecryptor(final String transformation, final byte[] keyBytes) throws DecryptionException {
        try {
            key = new SecretKeySpec(keyBytes, AlgorithmUtil.getAlgorithmFromTransformation(transformation));
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new DecryptionException(e);
        }
    }

    @Override
    public String toString() {
        return "SymmetricDecryptor for transformation: " + cipher.getAlgorithm();
    }

    @Override
    public String decrypt(final byte[] encrypted, final byte[] iv, final Charset charset) throws DecryptionException {
        try {
            if (iv == null || iv.length == 0) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            }
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, charset);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                 InvalidAlgorithmParameterException e) {
            throw new DecryptionException(e);
        }
    }
}
