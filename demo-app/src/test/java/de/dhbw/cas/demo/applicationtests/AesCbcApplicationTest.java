package de.dhbw.cas.demo.applicationtests;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/aes-cbc.properties")
class AesCbcApplicationTest {

    /**
     * Tests that the application starts up when decryption with AES/CBC is configured
     */
    @Test
    void test_applicationStartsWithCorrectlyConfiguredAesCbcEncryption(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }
}
