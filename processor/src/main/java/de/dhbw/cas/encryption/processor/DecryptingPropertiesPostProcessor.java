package de.dhbw.cas.encryption.processor;

import de.dhbw.cas.encryption.configuration.DecryptionConfiguration;
import de.dhbw.cas.encryption.decryptors.*;
import de.dhbw.cas.encryption.exception.DecryptionException;
import de.dhbw.cas.encryption.util.HexConverter;
import org.apache.commons.logging.Log;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;

import java.security.Security;
import java.util.Arrays;
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
@NullMarked
@Order
public class DecryptingPropertiesPostProcessor implements EnvironmentPostProcessor {
    public static final String DECRYPTED_PROPERTY_SOURCE_NAME = "decrypted_properties";
    private final Log log;

    public DecryptingPropertiesPostProcessor(final DeferredLogFactory deferredLogFactory) {
        log = deferredLogFactory.getLog(this.getClass());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment,
                                       final SpringApplication application) {
        try {

            log.debug("Trying to parse configuration");
            DecryptionConfiguration configuration = DecryptionConfiguration.fromEnvironment(environment);
            if (!configuration.enabled()) {
                log.debug("Configuration disables this processor");
                return;
            }
            log.debug("Successfully parsed configuration [" + configuration + "]. Creating decryptor");
            final TextDecryptor decryptor = switch (configuration.type()) {
                case SYMMETRIC -> new SymmetricDecryptor(configuration.transformation(), configuration.key());
                case ASYMMETRIC -> new AsymmetricDecryptor(configuration.transformation(), configuration.key());
                case ELLIPTIC_CURVE -> new EllipticCurveDecryptor(configuration.transformation(), configuration.key());
                case WRAPPING -> new UnwrappingDecryptor(configuration.transformation(), configuration.key(), configuration.wrappingKey());
            };
            log.debug("Successfully created Decryptor [" + decryptor + "]. Starting to decrypt properties: " +
                    Arrays.toString(configuration.properties()));

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
                            configuration.iv(), configuration.charset());
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
