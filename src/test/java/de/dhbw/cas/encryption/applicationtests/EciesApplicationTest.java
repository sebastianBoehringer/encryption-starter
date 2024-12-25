package de.dhbw.cas.encryption.applicationtests;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/ecies.properties")
class EciesApplicationTest {

    /**
     * Tests that the application starts up when decryption with ECIES is configured
     */
    @Test
    void test_applicationStartsWithCorrectlyConfiguredEciesEncryption(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }
}
