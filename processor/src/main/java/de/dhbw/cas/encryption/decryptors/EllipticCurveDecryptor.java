package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@NullMarked
public class EllipticCurveDecryptor implements TextDecryptor {

    private final Cipher cipher;
    private final Key key;

    public EllipticCurveDecryptor(final String transformation, final byte[] keyBytes)
            throws DecryptionException {
        try {
            cipher = Cipher.getInstance(transformation);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException e) {
            throw new DecryptionException(e);
        }
    }

    @Override
    public String toString() {
        return "EllipticCurveDecryptor for transformation: " + cipher.getAlgorithm();
    }

    @Override
    public String decrypt(byte[] encrypted, byte @Nullable [] iv, Charset charset) throws DecryptionException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            final byte[] bytes = cipher.doFinal(encrypted);
            return new String(bytes, charset);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new DecryptionException(e);
        }
    }
}
