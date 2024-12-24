package de.dhbw.cas.encryption.configuration;


import org.springframework.core.env.Environment;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;

/**
 * This record encapsulates the configuration for {@link de.dhbw.cas.encryption.processor.DecryptingPropertiesPostProcessor}.
 * The properties this is configured from all start with {@link #PROPERTY_PREFIX}. The other property names follow
 * normal naming convention and are derived from the field name in this record. I.e. key-file, algorithm, etc.
 * Multiple properties for {@link #properties} can be separated by a comma ({@code ','})
 * {@link #keyFile}, {@link #algorithm} and {@link #symmetric} are required properties.
 *
 * @param keyFile    The file containing the hex string of the key
 * @param algorithm  The algorithm to use to decrypt the properties
 * @param symmetric  {@code True} if the algorithm is symmetric, {@code false} if it is asymmetric
 * @param properties A list of property names to decode
 */
public record DecryptionConfiguration(File keyFile, String algorithm, boolean symmetric, String[] properties) {
    public static final String PROPERTY_PREFIX = "dhbw.cas.decryption.";

    /**
     * @param environment The environment to load the properties from
     * @return The loaded configuration
     */
    public static DecryptionConfiguration fromEnvironment(Environment environment) {
        String keyFilePath = environment.getRequiredProperty(PROPERTY_PREFIX + "key-file");
        String algorithm = environment.getRequiredProperty(PROPERTY_PREFIX + "algorithm");
        Boolean symmetric = environment.getRequiredProperty(PROPERTY_PREFIX + "symmetric", Boolean.class);
        String properties = environment.getProperty(PROPERTY_PREFIX + "properties", "");
        return new DecryptionConfiguration(new File(keyFilePath), algorithm, symmetric,
                properties.isEmpty() ? new String[0] : properties.split(","));
    }

    @Override
    public String toString() {
        return "DecryptionConfiguration{" +
                "keyFile=" + keyFile +
                ", algorithm='" + algorithm + '\'' +
                ", symmetric=" + symmetric +
                ", properties=" + Arrays.toString(properties) +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DecryptionConfiguration(
                File otherKeyFile, String otherAlgorithm, boolean otherSymmetric, String[] otherProperties
        ))) {
            return false;
        }
        return symmetric == otherSymmetric && Objects.equals(keyFile, otherKeyFile)
                && Objects.equals(algorithm, otherAlgorithm) && Objects.deepEquals(properties, otherProperties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyFile, algorithm, symmetric, Arrays.hashCode(properties));
    }
}
