package de.dhbw.cas.encryption;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectPackages({"de.dhbw.cas.encryption.configuration", "de.dhbw.cas.encryption.util",
        "de.dhbw.cas.encryption.processor", "de.dhbw.cas.encryption.decryptors"})
public class UnitTestSuite {
}
