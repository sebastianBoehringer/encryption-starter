package de.dhbw.cas.encryption.processor;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.logging.DeferredLogs;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;

import java.io.IOException;
import java.util.Properties;

class DecryptingPropertiesPostProcessorTest {

    private static final String DEFAULT_ENCRYPTED_PROPERTY_NAME = "spring.datasource.password";
    private static final String DEFAULT_ENCRYPTED_PROPERTY_DECRYPTED_VALUE = "root";
    private final DecryptingPropertiesPostProcessor processor = new DecryptingPropertiesPostProcessor(new DeferredLogs());

    private MockEnvironment setupMockEnv(String propertyFileName) throws IOException {
        ClassPathResource propertyFile = new ClassPathResource(propertyFileName);
        Properties properties = new Properties();
        properties.load(propertyFile.getInputStream());
        MockEnvironment env = new MockEnvironment();
        env.getPropertySources().addFirst(new PropertiesPropertySource("mock", properties));
        return env;
    }


    @ParameterizedTest(name = "can decrypt using {0}")
    @ValueSource(strings = {"aes.properties", "aes-cbc.properties", "des-ede.properties", "ecies.properties", "el-gamal.properties", "rsa.properties"})
    void test_postProcessEnvironment_canDecryptConfiguredPropertyWithMultipleDifferentAlgorithms(String propertyFileName) throws IOException {
        MockEnvironment environment = setupMockEnv("properties/" + propertyFileName);
        Assertions.assertThat(environment.getProperty(DEFAULT_ENCRYPTED_PROPERTY_NAME))
                .isNotEqualTo(DEFAULT_ENCRYPTED_PROPERTY_DECRYPTED_VALUE);
        // As we know the actual implementation does not rely on the second parameter we could also pass in null instead
        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertThat(environment.getProperty(DEFAULT_ENCRYPTED_PROPERTY_NAME))
                .isEqualTo(DEFAULT_ENCRYPTED_PROPERTY_DECRYPTED_VALUE);
    }

    @Test
    void test_postProcessEnvironment_doesNothingWhenDisabled() throws IOException {
        MockEnvironment environment = setupMockEnv("properties/unencrypted.properties");
        String preProcessingValue = environment.getProperty(DEFAULT_ENCRYPTED_PROPERTY_NAME);
        Assertions.assertThat(preProcessingValue).isNotEqualTo(DEFAULT_ENCRYPTED_PROPERTY_DECRYPTED_VALUE);

        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertThat(environment.getProperty(DEFAULT_ENCRYPTED_PROPERTY_NAME))
                .isNotEqualTo(DEFAULT_ENCRYPTED_PROPERTY_DECRYPTED_VALUE);
        Assertions.assertThat(environment.getProperty(DEFAULT_ENCRYPTED_PROPERTY_NAME)).isEqualTo(preProcessingValue);
    }
}