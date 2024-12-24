package de.dhbw.cas.encryption;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource("classpath:properties/unencrypted.properties")
class UnencryptedApplicationTests {

    @Test
    void test_applicationStartsWithUnencryptedProperties() {
        //This tests that the application in starts if all properties are unencrypted
    }

}
