package de.dhbw.cas.encryption.decryptors;

import de.dhbw.cas.encryption.exception.DecryptionException;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.nio.charset.Charset;

public interface TextDecryptor {
    /**
     * Decrypts a given byte sequence to a string with the given charset
     *
     * @param encrypted The bytes to decrypt
     * @param charset   The charset to use for the generated string
     * @return A string generated from the decrypted bytes
     */
    String decrypt(@Nonnull final byte[] encrypted, @Nullable final byte[] iv, @Nonnull final Charset charset) throws DecryptionException;
}
