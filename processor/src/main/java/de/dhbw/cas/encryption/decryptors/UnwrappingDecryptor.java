package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.AlgorithmUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@NullMarked
public class UnwrappingDecryptor implements TextDecryptor {

    public static String TRANSFORMATION_USED_WITH_UNWRAPPED_KEY = "AES/CBC/PKCS5Padding";
    private final TextDecryptor textDecryptor;

    public UnwrappingDecryptor(final String transformation, @Nullable final String keyAlgorithm,
                               final byte[] wrappedKeyBytes, final byte[] unwrapKeyBytes) throws DecryptionException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmUtil.determineKeyAlgorithm(transformation, keyAlgorithm));
            final Key unwrapKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(unwrapKeyBytes));
            final Cipher unwrapCipher = Cipher.getInstance(transformation);
            unwrapCipher.init(Cipher.UNWRAP_MODE, unwrapKey);
            textDecryptor = new SymmetricDecryptor(TRANSFORMATION_USED_WITH_UNWRAPPED_KEY, null,
                    unwrapCipher.unwrap(wrappedKeyBytes, TRANSFORMATION_USED_WITH_UNWRAPPED_KEY, Cipher.SECRET_KEY).getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException e) {
            throw new DecryptionException(e);
        }
    }

    @Override
    public String decrypt(byte[] encrypted, byte @Nullable [] iv, Charset charset) throws DecryptionException {
        return textDecryptor.decrypt(encrypted, iv, charset);
    }
}
