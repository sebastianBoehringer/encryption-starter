package de.dhbw.cas.encryption.util;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

@NullMarked
public final class AlgorithmUtil {
    private AlgorithmUtil() {
    }

    /**
     * Gets the algorithm from a transformation string
     * Algorithms for {@link javax.crypto.Cipher}s can contain transformation (e.g. which mode a block cipher should use).
     * This does not interop with the algorithm needed by {@link java.security.KeyFactory} or {@link javax.crypto.spec.SecretKeySpec}.
     * <p>
     * Technically AES can be specified to support only one key size with e.g. {@code AES_256}. This also is not compatible
     * with the mentioned classes.
     *
     * @param transformation The transformation to extract the key from
     * @return The algorithm mentioned in the transformation
     * @see javax.crypto.Cipher
     * @see <a href="https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html">Standard naming doc</a>
     */
    public static String getAlgorithmFromTransformation(final String transformation) {
        return transformation.split("/")[0].split("_")[0];
    }

    /**
     * @param transformation The transformation to get the algorithm from
     * @param keyAlgorithm An optional key (pair) generation algorithm that should take precedence
     * @return The key algorithm to use
     */
    public static String determineKeyAlgorithm(final String transformation, @Nullable final String keyAlgorithm) {
        if (keyAlgorithm == null || keyAlgorithm.isEmpty()) {
            return getAlgorithmFromTransformation(transformation);
        } else {
            return keyAlgorithm;
        }
    }
}
