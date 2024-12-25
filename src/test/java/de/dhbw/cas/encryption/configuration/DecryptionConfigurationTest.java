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
            .withProperty(PROPERTY_PREFIX + "key-file", "single-hex-line.txt")
            .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
            .withProperty(PROPERTY_PREFIX + "iv", "4146")
            .withProperty(PROPERTY_PREFIX + "symmetric", "true")
            .withProperty(PROPERTY_PREFIX + "properties", "spring.datasource.password,spring.data.mongodb.password")
            .withProperty(PROPERTY_PREFIX + "charset", "UTF-8")
            .withProperty(PROPERTY_PREFIX + "enabled", "true");

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
                "Never gonna let you down".getBytes(StandardCharsets.UTF_8), "AES",
                "AF".getBytes(StandardCharsets.US_ASCII), true,
                new String[]{"spring.datasource.password", "spring.data.mongodb.password"}, StandardCharsets.UTF_8,
                true
        );
        DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(COMPLETE_ENVIRONMENT);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }

    @Test
    void test_fromEnvironment_appliesCorrectDefaultParameters() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(PROPERTY_PREFIX + "key-file", "single-hex-line.txt")
                .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
                .withProperty(PROPERTY_PREFIX + "symmetric", "true");

        DecryptionConfiguration expected = new DecryptionConfiguration(
                "Never gonna let you down".getBytes(StandardCharsets.US_ASCII), "AES", new byte[0], true,
                new String[0], StandardCharsets.US_ASCII, true);
        DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(environment);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }

    @Test
    void test_fromEnvironment_shouldNotFileOnMissingKeyFileIfDisabled() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(PROPERTY_PREFIX + "key-file", "i-do-not-exist.txt")
                .withProperty(PROPERTY_PREFIX + "algorithm", "AES")
                .withProperty(PROPERTY_PREFIX + "symmetric", "true")
                .withProperty(PROPERTY_PREFIX + "enabled", "false");
        DecryptionConfiguration expected = new DecryptionConfiguration(
                new byte[0], "AES", new byte[0], true, new String[0], StandardCharsets.US_ASCII, false
        );
        DecryptionConfiguration parsed = DecryptionConfiguration.fromEnvironment(environment);
        Assertions.assertThat(parsed).isEqualTo(expected);
    }
}