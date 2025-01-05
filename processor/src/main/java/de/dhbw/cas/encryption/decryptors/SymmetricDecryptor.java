package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.AlgorithmUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.regex.Pattern;

@NullMarked
public class SymmetricDecryptor implements TextDecryptor {
    private static final Pattern GCM_PATTERN = Pattern.compile("/GCM/");
    private final Key key;
    private final Cipher cipher;

    public SymmetricDecryptor(final String transformation, final byte[] keyBytes)
            throws DecryptionException {
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
    public String decrypt(final byte[] encrypted, final byte @Nullable [] iv, final Charset charset)
            throws DecryptionException {
        try {
            if (iv == null || iv.length == 0) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                AlgorithmParameterSpec algorithmParameters = guessCorrectParameter(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameters);
            }
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, charset);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                 InvalidAlgorithmParameterException | InvalidParameterSpecException e) {
            throw new DecryptionException(e);
        }
    }

    private AlgorithmParameterSpec guessCorrectParameter(byte[] iv) throws InvalidParameterSpecException {
        if (cipher.getParameters() != null) {
            return switch (cipher.getParameters().getParameterSpec(AlgorithmParameterSpec.class)) {
                case final GCMParameterSpec ignored -> new GCMParameterSpec(iv.length, iv);
                default -> new IvParameterSpec(iv);
            };
        } else {
            if (GCM_PATTERN.matcher(cipher.getAlgorithm()).find()) {
                return new GCMParameterSpec(iv.length, iv);
            }
            return new IvParameterSpec(iv);
        }
    }
}
