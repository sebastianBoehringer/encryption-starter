package de.dhbw.cas.encryption.configuration;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;

import java.io.File;
import java.util.stream.Stream;

import static de.dhbw.cas.encryption.configuration.DecryptionConfiguration.PROPERTY_PREFIX;

class DecryptionConfigurationTest {

    private static final Environment COMPLETE_ENVIRONMENT = new MockEnvironment()
            .withProperty(PROPERTY_PREFIX + "key-file", "src/test/resources/test-key-file.txt")
            .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
            .withProperty(PROPERTY_PREFIX + "symmetric", "true")
            .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password");

    static Stream<Arguments> incompleteConfigurations() {
        return Stream.of(
                Arguments.of(new MockEnvironment()),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
                        .withProperty(PROPERTY_PREFIX + "symmetric", "true")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "key-file", "src/test/resources/test-key-file.txt")
                        .withProperty(PROPERTY_PREFIX + "symmetric", "true")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "key-file", "src/test/resources/test-key-file.txt")
                        .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "symmetric", "true")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "key-file", "src/test/resources/test-key-file.txt")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password"))
        );
    }

    @ParameterizedTest
    @MethodSource("incompleteConfigurations")
    void test_fromEnvironment_failsWhenRequiredPropertiesAreMissing(Environment environment) {
        Assertions.assertThatThrownBy(() -> DecryptionConfiguration.fromEnvironment(environment))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void test_fromEnvironment_parsesCompleteConfiguration() {
        DecryptionConfiguration expected = new DecryptionConfiguration(
                new File("src/test/resources/test-key-file.txt"),
                "AES", true, new String[]{"spring.datasource.password", "spring.data.mongodb.password"}
        );
        DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(COMPLETE_ENVIRONMENT);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }

    @Test
    void test_fromEnvironment_convertsMissingOptionalPropertiesToEmpty() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(PROPERTY_PREFIX + "key-file", "src/test/resources/test-key-file.txt")
                .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
                .withProperty(PROPERTY_PREFIX + "symmetric", "true");

        DecryptionConfiguration expected = new DecryptionConfiguration(new File("src/test/resources/test-key-file.txt"),
                "AES", true, new String[0]);
        DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(environment);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }
}