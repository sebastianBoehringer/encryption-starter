package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.nio.charset.Charset;

@NullMarked
public interface TextDecryptor {
    /**
     * Decrypts a given byte sequence to a string with the given charset
     *
     * @param encrypted The bytes to decrypt
     * @param charset   The charset to use for the generated string
     * @return A string generated from the decrypted bytes
     */
    String decrypt(final byte[] encrypted, final byte @Nullable [] iv, final Charset charset) throws DecryptionException;
}
