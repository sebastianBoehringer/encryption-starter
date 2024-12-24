package de.dhbw.cas.encryption;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/aes.properties")
class AesApplicationTest {
    /**
     * Tests that the application starts up when decryption with AES is configured
     */
    @Test
    void test_applicationStartsWithCorrectlyConfiguredAesEncryption(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }
}
