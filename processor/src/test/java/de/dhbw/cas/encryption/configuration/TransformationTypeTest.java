package de.dhbw.cas.encryption.configuration;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

class TransformationTypeTest {

    static Stream<Arguments> data() {
        return Stream.of(
                Arguments.of("symmetric", TransformationType.SYMMETRIC),
                Arguments.of("aSYmmetric", TransformationType.ASYMMETRIC),
                Arguments.of("eLlIpTiC_CuRvE", TransformationType.ELLIPTIC_CURVE),
                Arguments.of("WRAPPING", TransformationType.WRAPPING)
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void test_getTransformationType_correctlyDeterminesTypeFromString(String type, TransformationType expected) {
        Assertions.assertThat(TransformationType.getTransformationType(type)).isEqualTo(expected);
    }
}