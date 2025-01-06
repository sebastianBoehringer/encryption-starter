package de.dhbw.cas.encryption.configuration;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static de.dhbw.cas.encryption.configuration.DecryptionConfiguration.PROPERTY_PREFIX;

class DecryptionConfigurationTest {

    private static final Environment COMPLETE_ENVIRONMENT = new MockEnvironment()
            .withProperty(PROPERTY_PREFIX + "key", "single-hex-line.txt")
            .withProperty(PROPERTY_PREFIX + "transformation", "AES")
            .withProperty(PROPERTY_PREFIX + "iv", "4146")
            .withProperty(PROPERTY_PREFIX + "type", "symmetric")
            .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")
            .withProperty(PROPERTY_PREFIX + "charset", "UTF-8")
            .withProperty(PROPERTY_PREFIX + "enabled", "true")
            .withProperty(PROPERTY_PREFIX + "key-algorithm", "AES")
            .withProperty(PROPERTY_PREFIX + "wrapping-key", "single-hex-line.txt");

    static Stream<Arguments> incompleteConfigurations() {
        return Stream.of(
                Arguments.of(new MockEnvironment()),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "transformation", "AES")
                        .withProperty(PROPERTY_PREFIX + "type", "symmetric")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "key", "src/test/resources/test-key.txt")
                        .withProperty(PROPERTY_PREFIX + "type", "symmetric")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "key", "src/test/resources/test-key.txt")
                        .withProperty(PROPERTY_PREFIX + "transformation", "AES")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "type", "symmetric")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "transformation", "AES")
                        .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")),
                Arguments.of(new MockEnvironment()
                        .withProperty(PROPERTY_PREFIX + "key", "src/test/resources/test-key.txt")
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
        final DecryptionConfiguration expected = new DecryptionConfiguration(
                "Never gonna let you down".getBytes(StandardCharsets.UTF_8), "AES", "AES",
                "AF".getBytes(StandardCharsets.US_ASCII), TransformationType.SYMMETRIC,
                new String[]{"spring.datasource.password", "spring.data.mongodb.password"}, StandardCharsets.UTF_8,
                true, "Never gonna let you down".getBytes(StandardCharsets.UTF_8)
        );
        final DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(COMPLETE_ENVIRONMENT);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }

    @Test
    void test_fromEnvironment_appliesCorrectDefaultParameters() {
        final MockEnvironment environment = new MockEnvironment()
                .withProperty(PROPERTY_PREFIX + "key", "single-hex-line.txt")
                .withProperty(PROPERTY_PREFIX + "transformation", "AES")
                .withProperty(PROPERTY_PREFIX + "type", "symmetric");

        final DecryptionConfiguration expected = new DecryptionConfiguration(
                "Never gonna let you down".getBytes(StandardCharsets.US_ASCII), "AES", null, new byte[0],
                TransformationType.SYMMETRIC, new String[0], StandardCharsets.US_ASCII, true, new byte[0]);
        final DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(environment);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }

    @Test
    void test_fromEnvironment_succeedsWhenRequiredPropertiesAreMissingButProcessorIsDisabled() {
        final MockEnvironment environment = new MockEnvironment().withProperty(PROPERTY_PREFIX + "enabled", "false");
        final DecryptionConfiguration expected = DecryptionConfiguration.fromEnvironment(environment);

        Assertions.assertThat(expected).isNotNull();
        Assertions.assertThat(expected.enabled()).isFalse();
    }

    @Test
    void test_fromEnvironment_failsWhenProvidedPathToKeyIsDirectory() {
        final MockEnvironment environment = new MockEnvironment()
                .withProperty(PROPERTY_PREFIX + "key", "properties")
                .withProperty(PROPERTY_PREFIX + "type", "symmetric")
                .withProperty(PROPERTY_PREFIX + "transformation", "AES");
        Assertions.assertThatThrownBy(() -> DecryptionConfiguration.fromEnvironment(environment))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void test_equals_isFalseForDifferentObjects() {
        final DecryptionConfiguration test = DecryptionConfiguration.fromEnvironment(COMPLETE_ENVIRONMENT);

        Assertions.assertThat(test).isNotEqualTo(COMPLETE_ENVIRONMENT);
        Assertions.assertThat(test).isNotEqualTo(new Object());
        Assertions.assertThat(test).isNotEqualTo(PROPERTY_PREFIX);
    }
}