package de.dhbw.cas.encryption.configuration;


import de.dhbw.cas.encryption.util.HexConverter;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * This record encapsulates the configuration for {@link de.dhbw.cas.encryption.processor.DecryptingPropertiesPostProcessor}.
 * The properties this is configured from all start with {@link #PROPERTY_PREFIX}. The other property names follow
 * normal naming convention and are derived from the field name in this record. I.e. key-file, algorithm, etc.
 * Multiple properties for {@link #properties} can be separated by a comma ({@code ','})
 * {@link #key}, {@link #algorithm} and {@link #symmetric} are required properties.
 *
 * @param key        The bytes of the key. Required. The value of the property is interpreted as a path to the file containing the key.
 *                   This can either be an absolute path to search the file system. If no file with the given name exists
 *                   there the classpath is searched
 * @param algorithm  The algorithm to use to decrypt the properties. Required
 * @param iv         The initialization vector to use. Optional, defaults to an empty array
 * @param symmetric  {@code True} if the algorithm is symmetric, {@code false} if it is asymmetric. Required
 * @param properties A list of property names to decode. Optional, defaults to an empty array
 * @param charset    The charset to use for the decrypted strings. Optional, defaults to US_ASCII
 * @param enabled    A flag to determine if decryption should be enabled. Optional, defaults to true
 */
public record DecryptionConfiguration(byte[] key, String algorithm, byte[] iv, boolean symmetric, String[] properties,
                                      Charset charset, boolean enabled) {
    public static final String PROPERTY_PREFIX = "dhbw.cas.decryption.";

    /**
     * @param environment The environment to load the properties from
     * @return The loaded configuration
     */
    public static DecryptionConfiguration fromEnvironment(Environment environment) {
        String keyFilePath = environment.getRequiredProperty(PROPERTY_PREFIX + "key-file");
        String algorithm = environment.getRequiredProperty(PROPERTY_PREFIX + "algorithm");
        String ivHex = environment.getProperty(PROPERTY_PREFIX + "iv", "");
        byte[] iv;
        if (ivHex.isEmpty()) {
            iv = new byte[0];
        } else {
            iv = HexConverter.loadBytesFromHexString(ivHex);
        }
        Boolean symmetric = environment.getRequiredProperty(PROPERTY_PREFIX + "symmetric", Boolean.class);
        String properties = environment.getProperty(PROPERTY_PREFIX + "properties", "");
        String charsetName = environment.getProperty(PROPERTY_PREFIX + "charset", StandardCharsets.US_ASCII.name());
        Charset charset = StandardCharsets.US_ASCII;
        if (!charsetName.isEmpty()) {
            try {
                charset = Charset.forName(charsetName);
            } catch (Exception e) {
                //if char set with provided name cannot be found we still default to US_ASCII
            }
        }
        boolean enabled = Boolean.parseBoolean(environment.getProperty(PROPERTY_PREFIX + "enabled", Boolean.TRUE.toString()));
        try {

            return new DecryptionConfiguration(findFile(keyFilePath), algorithm, iv, symmetric,
                    properties.isEmpty() ? new String[0] : properties.split(","), charset, enabled);
        } catch (IOException e) {
            throw new IllegalStateException("Could not load key data from file " + keyFilePath, e);
        }
    }

    private static byte[] findFile(String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            file = new ClassPathResource(path).getFile();
        }
        if (file.exists() && file.isFile()) {
            return HexConverter.loadBytesFromFile(file);
        }
        throw new IllegalStateException("File not found in either file system or class path: " + path);
    }

    @Override
    public String toString() {
        return "DecryptionConfiguration{" +
                "key=" + Arrays.toString(key) +
                ", algorithm='" + algorithm + '\'' +
                ", iv=" + Arrays.toString(iv) +
                ", symmetric=" + symmetric +
                ", properties=" + Arrays.toString(properties) +
                ", charset=" + charset +
                ", enabled=" + enabled +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DecryptionConfiguration(
                byte[] otherKey, String otherAlgorithm, byte[] otherIv, boolean otherSymmetrical,
                String[] otherProperties, Charset otherCharset, boolean otherEnabled
        ))) return false;
        return symmetric == otherSymmetrical && Objects.deepEquals(iv, otherIv) && Objects.deepEquals(key, otherKey)
                && Objects.equals(charset, otherCharset) && Objects.equals(algorithm, otherAlgorithm)
                && Objects.deepEquals(properties, otherProperties) && Objects.equals(enabled, otherEnabled);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(key), algorithm, Arrays.hashCode(iv), symmetric,
                Arrays.hashCode(properties), charset, enabled);
    }
}
