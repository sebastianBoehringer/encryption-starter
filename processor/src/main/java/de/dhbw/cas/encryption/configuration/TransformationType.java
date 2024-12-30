package de.dhbw.cas.encryption.configuration;

import org.jspecify.annotations.NonNull;

public enum TransformationType {
    /**
     * For transformations using an asymmetric algorithm. RSA etc.
     */
    ASYMMETRIC,
    /**
     * For transformations using an algorithm based on elliptic curves. ECIES etc.
     */
    ELLIPTIC_CURVE,
    /**
     * For transformations using a type algorithm. AES etc.
     */
    SYMMETRIC,
    /**
     * For transformations that rely on key wrapping
     * The wrapping cipher is assumed to be asymmetric. The key is used for
     * {@link de.dhbw.cas.encryption.decryptors.UnwrappingDecryptor#TRANSFORMATION_USED_WITH_UNWRAPPED_KEY}.
     */
    WRAPPING;

    /**
     * @param type The type to convert to an enum instance. The type is converted to upper case
     * @return The enum constant matching the provided string
     * @throws IllegalArgumentException If the type cannot be matched
     */
    public static TransformationType getTransformationType(@NonNull final String type) {
        final var upperType = type.toUpperCase();
        return TransformationType.valueOf(upperType);
    }
}
