package de.dhbw.cas.encryption.processor;

import de.dhbw.cas.encryption.configuration.DecryptionConfiguration;
import de.dhbw.cas.encryption.decryptors.AsymmetricDecryptor;
import de.dhbw.cas.encryption.decryptors.SymmetricDecryptor;
import de.dhbw.cas.encryption.decryptors.TextDecryptor;
import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.HexConverter;
import org.apache.commons.logging.Log;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * This class decrypts marked properties.
 * This allows users to include secrets in their configuration files without sharing them with the world. The processor
 * works by decrypting the properties and providing the application with another property source that includes the
 * decrypted properties. The name of the source is {@link #DECRYPTED_PROPERTY_SOURCE_NAME}. As that source is first
 * Spring consults it first for properties. Thus, the decrypted properties are properly passed on to dependant
 * frameworks like e.g. Hibernate.
 * The processor can be configured via properties. See {@link de.dhbw.cas.encryption.configuration.DecryptionConfiguration}
 */
@Order
public class DecryptingPropertiesPostProcessor implements EnvironmentPostProcessor {
    public static final String DECRYPTED_PROPERTY_SOURCE_NAME = "decrypted_properties";
    private final Log log;

    public DecryptingPropertiesPostProcessor(final DeferredLogFactory deferredLogFactory) {
        log = deferredLogFactory.getLog(this.getClass());
    }

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application) {
        try {

            log.debug("Trying to parse configuration");
            DecryptionConfiguration configuration = DecryptionConfiguration.fromEnvironment(environment);
            if (!configuration.enabled()) {
                log.debug("Configuration disables this processor");
                return;
            }
            log.debug("Successfully parsed configuration [" + configuration + "]. Creating decryptor");
            TextDecryptor decryptor;
            if (configuration.symmetric()) {
                decryptor = new SymmetricDecryptor(configuration.transformation(), configuration.key());
                log.debug("Successfully created symmetric decryptor [" + decryptor + "]");
            } else {
                decryptor = new AsymmetricDecryptor(configuration.transformation(), configuration.key());
                log.debug("Successfully created asymmetric decryptor [" + decryptor + "]");
            }

            log.debug("Starting to decrypt properties");
            Map<String, Object> decryptedProperties = getDecryptedProperties(environment, configuration, decryptor);
            environment.getPropertySources().addFirst(new MapPropertySource(DECRYPTED_PROPERTY_SOURCE_NAME, decryptedProperties));
            log.debug("Successfully added new property source to environment");
        } catch (DecryptionException e) {
            log.warn("Failed to decrypt properties", e);
        }
    }

    private Map<String, Object> getDecryptedProperties(final Environment environment,
                                                       final DecryptionConfiguration configuration,
                                                       final TextDecryptor decryptor) {
        Map<String, Object> propertiesToDecrypt = new HashMap<>();
        for (String property : configuration.properties()) {
            String value = environment.getProperty(property);
            if (value != null) {
                try {
                    String decryptedProperty = decryptor.decrypt(HexConverter.loadBytesFromHexString(value),
                            configuration.iv(), StandardCharsets.US_ASCII);
                    log.debug("Decrypted value [" + value + "] of property " + property + " to string of length " +
                            decryptedProperty.length());
                    propertiesToDecrypt.put(property, decryptedProperty);
                } catch (DecryptionException e) {
                    log.warn("Failed to decrypt property [" + property + "]", e);
                }

            } else {
                log.debug("Skipping property [" + property + "] as its value is null");
            }
        }
        return propertiesToDecrypt;
    }
}
