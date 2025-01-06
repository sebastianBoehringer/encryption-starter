package de.dhbw.cas.encryption.configuration;


import de.dhbw.cas.encryption.util.HexConverter;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * This record encapsulates the configuration for {@link de.dhbw.cas.encryption.processor.DecryptingPropertiesPostProcessor}.
 * The properties this is configured from all start with {@link #PROPERTY_PREFIX}. The other property names follow
 * normal naming convention and are derived from the field name in this record. I.e. key, transformation, etc.
 * Multiple properties for {@link #properties} can be separated by a comma ({@code ','}).
 * {@link #key}, {@link #transformation} and {@link #type} are required properties.
 *
 * @param key            The bytes of the key. Required. The value of the property is interpreted as a path to the file
 *                       containing the key. This should usually be an absolute path to search the file system. If no file
 *                       with the given name exists there the classpath is searched instead
 * @param transformation The transformation to use to decrypt the properties. Required
 * @param keyAlgorithm   The algorithm for key generation. This is optional. If not present the algorithm is derived from the transformation
 * @param iv             The initialization vector to use. Optional, defaults to an empty array
 * @param type           The type of algorithm the transformation is based on. Required
 * @param properties     A list of property names to decode. Optional, defaults to an empty array
 * @param charset        The charset to use for the decrypted strings. Optional, defaults to US_ASCII
 * @param enabled        A flag to determine if decryption should be enabled. Optional, defaults to true
 * @param wrappingKey    The key used when wrapping or key encapsulation is used
 */
@NullMarked
public record DecryptionConfiguration(byte[] key, String transformation, @Nullable String keyAlgorithm, byte[] iv,
                                      TransformationType type, String[] properties, Charset charset, boolean enabled,
                                      byte[] wrappingKey) {
    public static final String PROPERTY_PREFIX = "dhbw.cas.decryption.";

    /**
     * Creates a configuration instance from the given environment
     * Usually this fails if a required property is missing. But if the processor is disabled, required properties are
     * also optional.
     *
     * @param environment The environment to load the properties from
     * @return The loaded configuration
     * @throws IllegalStateException When a required property is missing or the key could not be loaded from the provided file
     */
    public static DecryptionConfiguration fromEnvironment(final Environment environment) throws IllegalStateException {
        final boolean enabled = Boolean.parseBoolean(environment.getProperty(PROPERTY_PREFIX + "enabled", Boolean.TRUE.toString()));
        if (!enabled) {
            return new DecryptionConfiguration(new byte[0], "", "", new byte[0], TransformationType.SYMMETRIC, new String[0],
                    StandardCharsets.US_ASCII, false, new byte[0]);
        }
        final String keyFilePath = environment.getRequiredProperty(PROPERTY_PREFIX + "key");
        final String transformation = environment.getRequiredProperty(PROPERTY_PREFIX + "transformation");
        final String keyAlgorithm = environment.getProperty(PROPERTY_PREFIX + "key-algorithm");
        final String ivHex = environment.getProperty(PROPERTY_PREFIX + "iv", "");
        byte[] iv;
        if (ivHex.isEmpty()) {
            iv = new byte[0];
        } else {
            iv = HexConverter.loadBytesFromHexString(ivHex);
        }
        final String type = environment.getRequiredProperty(PROPERTY_PREFIX + "type");
        final String properties = environment.getProperty(PROPERTY_PREFIX + "properties", "");
        final String charsetName = environment.getProperty(PROPERTY_PREFIX + "charset", StandardCharsets.US_ASCII.name());
        final String wrappingKeyFilePath = environment.getProperty(PROPERTY_PREFIX + "wrapping-key", "");
        Charset charset = StandardCharsets.US_ASCII;
        if (!charsetName.isEmpty()) {
            try {
                charset = Charset.forName(charsetName);
            } catch (Exception e) {
                //if char set with provided name cannot be found we still default to US_ASCII
            }
        }
        try {
            final var key = findFile(keyFilePath);
            return new DecryptionConfiguration(key.orElseThrow(() -> new IllegalStateException("Key was not found")),
                    transformation, keyAlgorithm, iv, TransformationType.getTransformationType(type),
                    properties.isEmpty() ? new String[0] : properties.split(","), charset, true,
                    findFile(wrappingKeyFilePath).orElse(new byte[0]));
        } catch (IOException e) {
            throw new IllegalStateException("Could not load key data from file " + keyFilePath, e);
        }
    }

    private static Optional<byte[]> findFile(final String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            file = new ClassPathResource(path).getFile();
        }
        if (file.exists() && file.isFile()) {
            return Optional.of(HexConverter.loadBytesFromFile(file));
        }
        return Optional.empty();
    }


    @Override
    public String toString() {
        return "DecryptionConfiguration{" +
                "key=" + Arrays.toString(key) +
                ", transformation='" + transformation + '\'' +
                ", keyAlgorithm='" + keyAlgorithm + '\'' +
                ", iv=" + Arrays.toString(iv) +
                ", type=" + type +
                ", properties=" + Arrays.toString(properties) +
                ", charset=" + charset +
                ", enabled=" + enabled +
                ", wrappingKey=" + Arrays.toString(wrappingKey) +
                '}';
    }

    @Override
    public boolean equals(@Nullable final Object o) {
        if (!(o instanceof DecryptionConfiguration(
                byte[] otherKey, String otherTransformation, String otherKeyAlgorithm, byte[] otherIv,
                TransformationType otherType,
                String[] otherProperties, Charset otherCharset, boolean otherEnabled, byte[] otherWrappingKey
        ))) return false;
        return Objects.equals(type, otherType) && Objects.deepEquals(iv, otherIv) && Objects.deepEquals(key, otherKey)
                && Objects.equals(charset, otherCharset) && Objects.equals(transformation, otherTransformation)
                && Objects.deepEquals(properties, otherProperties) && Objects.equals(enabled, otherEnabled)
                && Objects.deepEquals(wrappingKey, otherWrappingKey) && Objects.equals(keyAlgorithm, otherKeyAlgorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(key), transformation, keyAlgorithm, Arrays.hashCode(iv), type,
                Arrays.hashCode(properties), charset, enabled, Arrays.hashCode(wrappingKey));
    }
}
