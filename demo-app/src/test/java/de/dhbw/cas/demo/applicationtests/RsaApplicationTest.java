package de.dhbw.cas.demo.applicationtests;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/rsa.properties")
class RsaApplicationTest {

    /**
     * Tests that the application starts up when decryption with RSA is configured
     */
    @Test
    void test_applicationStartsWithCorrectlyConfiguredRsaEncryption(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }
}
