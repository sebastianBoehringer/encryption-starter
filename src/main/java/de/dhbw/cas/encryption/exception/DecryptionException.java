package de.dhbw.cas.encryption.exception;

/**
 * Wraps other exceptions that might occur in the decryption process
 */
public class DecryptionException extends Exception {
    public DecryptionException(Throwable cause) {
        super("Decryption exception due to " + cause.getClass().getName(), cause);
    }
}
