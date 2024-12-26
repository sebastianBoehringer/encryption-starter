package de.dhbw.cas.encryption.exception;

import org.jspecify.annotations.NonNull;

/**
 * Wraps other exceptions that might occur in the decryption process
 */
public class DecryptionException extends Exception {
    public DecryptionException(@NonNull Throwable cause) {
        super("Decryption exception due to " + cause.getClass().getName(), cause);
    }
}
