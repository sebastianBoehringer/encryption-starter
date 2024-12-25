package de.dhbw.cas.encryption.applicationtests;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/des-ede.properties")
class DesEdeApplicationTest {
    /**
     * Tests that the application starts up when decryption with DESede/CBC/PKCS5Padding is configured
     */
    @Test
    void test_applicationStartsWithCorrectlyConfiguredDesEdeCbcEncryption(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }
}
