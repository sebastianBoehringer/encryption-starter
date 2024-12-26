package de.dhbw.cas.demo.applicationtests;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/unencrypted.properties")
class UnencryptedApplicationTest {

    /**
     * Tests that the application starts up when all properties are unencrypted
     */
    @Test
    void test_applicationStartsWithUnencryptedProperties(ApplicationContext context) {
        Assertions.assertThat(context).isNotNull();
    }

}
