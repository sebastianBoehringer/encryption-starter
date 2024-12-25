package de.dhbw.cas.encryption.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;


class AlgorithmUtilTest {

    static Stream<Arguments> transformationsAndExpectedAlgorithms() {
        return Stream.of(
                Arguments.of("AES/CBC/PKCS5Padding", "AES"),
                Arguments.of("AES_192", "AES"),
                Arguments.of("RSA", "RSA"),
                Arguments.of("RSA/ECB/PKCS1Padding", "RSA"),
                Arguments.of("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA")
        );
    }

    @ParameterizedTest
    @MethodSource("transformationsAndExpectedAlgorithms")
    void test_getAlgorithmFromTransformation_correctlyGetsAlgorithm(final String transformation, final String expected) {
        final String determinedAlgorithm = AlgorithmUtil.getAlgorithmFromTransformation(transformation);
        Assertions.assertThat(determinedAlgorithm).isEqualTo(expected);
    }
}