package de.dhbw.cas.encryption.processor;

import org.apache.commons.logging.Log;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

public class DecryptingPropertiesPostProcessor implements EnvironmentPostProcessor {
    private final Log log;
    public final static String DECRYPTED_PROPERTY_SOURCE_NAME = "decrypted_properties";

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
