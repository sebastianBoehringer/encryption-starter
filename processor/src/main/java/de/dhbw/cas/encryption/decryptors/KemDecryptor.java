package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.AlgorithmUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@NullMarked
public class KemDecryptor implements TextDecryptor {

    private final TextDecryptor delegate;

    public KemDecryptor(final String kemTransformation, @Nullable final String keyAlgorithm,
                        final byte[] encapsulatedKey, final byte[] kemKey) throws DecryptionException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmUtil.determineKeyAlgorithm(kemTransformation, keyAlgorithm));
            final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kemKey));
            final KEM kem = KEM.getInstance(kemTransformation);
            final KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
            final SecretKey decapsulate = decapsulator.decapsulate(encapsulatedKey);
            delegate = new SymmetricDecryptor(UnwrappingDecryptor.TRANSFORMATION_USED_WITH_UNWRAPPED_KEY, null, decapsulate.getEncoded());
        } catch (DecapsulateException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            throw new DecryptionException(e);
        }
    }

    @Override
    public String decrypt(byte[] encrypted, byte @Nullable [] iv, Charset charset) throws DecryptionException {
        return delegate.decrypt(encrypted, iv, charset);
    }
}
