package de.dhbw.cas.encryption.configuration;

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
    SYMMETRIC;

    /**
     * @param type The type to convert to an enum instance. The type is converted to upper case
     * @return The enum constant matching the provided string
     * @throws IllegalArgumentException If the type cannot be matched
     */
    public static TransformationType getTransformationType(final String type) {
        final var upperType = type.toUpperCase();
        return TransformationType.valueOf(upperType);
    }
}
