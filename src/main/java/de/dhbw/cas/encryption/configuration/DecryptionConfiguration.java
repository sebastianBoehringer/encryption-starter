package de.dhbw.cas.encryption.configuration;


import de.dhbw.cas.encryption.util.HexConverter;
import org.springframework.core.env.Environment;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * This record encapsulates the configuration for {@link de.dhbw.cas.encryption.processor.DecryptingPropertiesPostProcessor}.
 * The properties this is configured from all start with {@link #PROPERTY_PREFIX}. The other property names follow
 * normal naming convention and are derived from the field name in this record. I.e. key-file, algorithm, etc.
 * Multiple properties for {@link #properties} can be separated by a comma ({@code ','})
 * {@link #keyFile}, {@link #algorithm} and {@link #symmetric} are required properties.
 *
 * @param keyFile    The file containing the hex string of the key. Required
 * @param algorithm  The algorithm to use to decrypt the properties. Required
 * @param iv         The initialization vector to use. Optional, defaults to an empty array
 * @param symmetric  {@code True} if the algorithm is symmetric, {@code false} if it is asymmetric. Required
 * @param properties A list of property names to decode. Optional, defaults to an empty array
 * @param charset    The charset to use for the decrypted strings. Optional, defaults to US_ASCII
 */
public record DecryptionConfiguration(File keyFile, String algorithm, byte[] iv, boolean symmetric, String[] properties,
                                      Charset charset) {
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
        return new DecryptionConfiguration(new File(keyFilePath), algorithm, iv, symmetric,
                properties.isEmpty() ? new String[0] : properties.split(","), charset);
    }

    @Override
    public String toString() {
        return "DecryptionConfiguration{" +
                "keyFile=" + keyFile +
                ", algorithm='" + algorithm + '\'' +
                ", iv=" + Arrays.toString(iv) +
                ", symmetric=" + symmetric +
                ", properties=" + Arrays.toString(properties) +
                ", charset=" + charset +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DecryptionConfiguration(
                File otherKeyFile, String otherAlgorithm, byte[] otherIv, boolean otherSymmetrical,
                String[] otherProperties, Charset otherCharset
        ))) return false;
        return symmetric == otherSymmetrical && Objects.deepEquals(iv, otherIv) && Objects.equals(keyFile, otherKeyFile)
                && Objects.equals(charset, otherCharset) && Objects.equals(algorithm, otherAlgorithm)
                && Objects.deepEquals(properties, otherProperties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyFile, algorithm, Arrays.hashCode(iv), symmetric, Arrays.hashCode(properties), charset);
    }
}
