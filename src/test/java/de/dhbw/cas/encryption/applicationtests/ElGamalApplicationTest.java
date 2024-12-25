package de.dhbw.cas.encryption.applicationtests;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/el-gamal.properties")
class ElGamalApplicationTest {
    /**
     * Tests that the application starts up when decryption with ElGamal is configured
     */
    @Test
    void test_applicationStartsWithCorrectlyConfiguredElGamalEncryption(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }
}
