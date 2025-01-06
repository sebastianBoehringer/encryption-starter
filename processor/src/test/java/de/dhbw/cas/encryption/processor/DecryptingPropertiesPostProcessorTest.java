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

    private static final String PASSWORD_PROPERTY = "spring.datasource.password";
    private static final String DECRYPTED_PASSWORD_PROPERTY_VALUE = "root";

    private static final String URL_PROPERTY = "spring.datasource.url";
    private static final String DECRYPTED_URL_PROPERTY_VALUE = "jdbc:mariadb://localhost:3306/test";

    private static final String USERNAME_PROPERTY = "spring.datasource.username";
    private static final String DECRYPTED_USERNAME_PROPERTY_VALUE = "root";

    private static final String APPLICATION_NAME_PROPERTY = "spring.application.name";
    private static final String DECRYPTED_APPLICATION_NAME_PROPERTY_VALUE = "encryption-starter";

    private static final String UMLAUT_SENTENCE = "Die süße Hündin läuft in die Höhle des Bären, der sie zum Teekränzchen eingeladen hat, da sie seine drei schönen Krönchen gerettet hat";
    private final DecryptingPropertiesPostProcessor processor = new DecryptingPropertiesPostProcessor(new DeferredLogs());


    private MockEnvironment setupMockEnv(String propertyFileName) throws IOException {
        final ClassPathResource propertyFile = new ClassPathResource(propertyFileName);
        final Properties properties = new Properties();
        properties.load(propertyFile.getInputStream());
        final MockEnvironment env = new MockEnvironment();
        env.getPropertySources().addFirst(new PropertiesPropertySource("mock", properties));
        return env;
    }

    private void doDecryptionTesting(String propertyFileName) throws IOException {
        final MockEnvironment environment = setupMockEnv("properties/" + propertyFileName + ".properties");
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY))
                .isNotEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        // As we know the actual implementation does not rely on the second parameter we could also pass in null instead
        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY))
                .isEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
    }

    @ParameterizedTest(name = "can decrypt using {0}")
    @ValueSource(strings = {"aes", "aes-cbc", "aria-cbc", "blowfish", "camellia", "cast5", "cast6", "chacha", "des-ede",
            "dstu7624", "gost28147", "grainv1", "grain128", "hc128", "hc256", "idea", "noekeon", "rc2", "rc5", "rc6",
            "rijndael", "salsa20", "seed", "serpent", "shacal2", "skipjack", "sm4", "tea", "twofish", "threefish512",
            "vmpc", "vmpc-ksa3", "xtea", "xsalsa20", "zuc-128"})
    void test_postProcessEnvironment_canDecryptUsingSymmetricAlgorithms(String propertyFileName) throws IOException {
        doDecryptionTesting(propertyFileName);
    }

    @ParameterizedTest(name = "can decrypt using {0}")
    @ValueSource(strings = {"el-gamal", "rsa"})
    void test_postProcessEnvironment_canDecryptUsingAsymmetricAlgorithms(String propertyFileName) throws IOException {
        doDecryptionTesting(propertyFileName);
    }

    @ParameterizedTest(name = "can decrypt using {0}")
    @ValueSource(strings = {"ecies"})
    void test_postProcessEnvironment_canDecryptUsingEllipticCurveAlgorithms(String propertyFileName) throws IOException {
        doDecryptionTesting(propertyFileName);
    }

    @ParameterizedTest(name = "can unwrap and decrypt using {0}")
    @ValueSource(strings = "wrapped")
    void test_postProcessEnvironment_canDecryptUsingKeyUnwrappingBeforeDecrypting(String propertyFileName) throws IOException {
        doDecryptionTesting(propertyFileName);
    }

    @Test
    void test_postProcessEnvironment_doesNothingWhenDisabled() throws IOException {
        final MockEnvironment environment = setupMockEnv("properties/unencrypted.properties");
        final String preProcessingValue = environment.getProperty(PASSWORD_PROPERTY);
        Assertions.assertThat(preProcessingValue).isNotEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);

        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY))
                .isNotEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isEqualTo(preProcessingValue);
    }

    @Test
    void test_postProcessEnvironment_doesNotFailWhenPropertyIsWronglyEncrypted() throws IOException {
        final MockEnvironment environment = setupMockEnv("properties/aes-with-invalid-second-encrypted-property.properties");
        final String preProcessingValue = environment.getProperty(USERNAME_PROPERTY);
        processor.postProcessEnvironment(environment, new SpringApplication());
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        Assertions.assertThat(environment.getProperty(USERNAME_PROPERTY)).isEqualTo(preProcessingValue);
    }

    @Test
    void test_postProcessEnvironment_silentlySkipsMissingPropertiesThatShouldBeDecrypted() throws IOException {
        final MockEnvironment environment = setupMockEnv("properties/des-ede-with-additional-missing-property-to-decrypt.properties");
        Assertions.assertThat(environment.getProperty(USERNAME_PROPERTY)).isNull();
        processor.postProcessEnvironment(environment, new SpringApplication());
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        Assertions.assertThat(environment.getProperty(USERNAME_PROPERTY)).isNull();
    }

    @Test
    void test_postProcessEnvironment_correctlyDecryptsMultiplePropertiesIfConfigured() throws IOException {
        final MockEnvironment environment = setupMockEnv("properties/gost28147.properties");
        final String preprocessedUsername = environment.getProperty(USERNAME_PROPERTY);
        final String preprocessedPassword = environment.getProperty(PASSWORD_PROPERTY);
        final String preprocessedUrl = environment.getProperty(URL_PROPERTY);
        final String preprocessedName = environment.getProperty(APPLICATION_NAME_PROPERTY);

        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertThat(environment.getProperty(USERNAME_PROPERTY)).isNotEqualTo(preprocessedUsername);
        Assertions.assertThat(environment.getProperty(USERNAME_PROPERTY)).isEqualTo(DECRYPTED_USERNAME_PROPERTY_VALUE);

        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isNotEqualTo(preprocessedPassword);
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);

        Assertions.assertThat(environment.getProperty(URL_PROPERTY)).isNotEqualTo(preprocessedUrl);
        Assertions.assertThat(environment.getProperty(URL_PROPERTY)).isEqualTo(DECRYPTED_URL_PROPERTY_VALUE);

        Assertions.assertThat(environment.getProperty(APPLICATION_NAME_PROPERTY)).isNotEqualTo(preprocessedName);
        Assertions.assertThat(environment.getProperty(APPLICATION_NAME_PROPERTY)).isEqualTo(DECRYPTED_APPLICATION_NAME_PROPERTY_VALUE);
    }

    @Test
    void test_postProcessEnvironment_canProcessNonAsciiSymbolsWhenConfiguredForIt() throws IOException {
        final MockEnvironment environment = setupMockEnv("properties/aes-128-gcm.properties");
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isNotEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isNotEqualTo(UMLAUT_SENTENCE);
        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertThat(environment.getProperty(PASSWORD_PROPERTY)).isEqualTo(UMLAUT_SENTENCE);
    }

    /**
     * Configured IV was used as an {@link javax.crypto.spec.IvParameterSpec} so the {@link javax.crypto.Cipher} requires
     * it to be set as such.
     * The current implementation of the {@link de.dhbw.cas.encryption.decryptors.SymmetricDecryptor} correctly detects
     * the transformation to be in GCM so passes it as {@link javax.crypto.spec.GCMParameterSpec}. This causes decryption
     * to fail
     */
    @Test
    void test_postProcessEnvironment_failsWhenWrongIvIsPassed() throws IOException {
        MockEnvironment environment = setupMockEnv("properties/camellia-problem.properties");

        final String propertyPreDecryption = environment.getProperty(PASSWORD_PROPERTY);
        Assertions.assertThat(propertyPreDecryption).isNotEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        processor.postProcessEnvironment(environment, new SpringApplication());

        final String propertyPostDecryption = environment.getProperty(PASSWORD_PROPERTY);
        Assertions.assertThat(propertyPostDecryption).isNotEqualTo(DECRYPTED_PASSWORD_PROPERTY_VALUE);
        Assertions.assertThat(propertyPreDecryption).isEqualTo(propertyPostDecryption);
    }
}