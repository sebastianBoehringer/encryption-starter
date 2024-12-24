package de.dhbw.cas.encryption.processor;

import org.apache.commons.logging.Log;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

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

    public DecryptingPropertiesPostProcessor(DeferredLogFactory deferredLogFactory) {
        log = deferredLogFactory.getLog(this.getClass());
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        log.info("Hurra I was called");
        environment.getPropertySources().addFirst(createDummySource());
    }

    private MapPropertySource createDummySource() {
        MapPropertySource source = new MapPropertySource(DECRYPTED_PROPERTY_SOURCE_NAME,
                Map.of("spring.datasource.password", "bananenkey"));
        return source;
    }
}
