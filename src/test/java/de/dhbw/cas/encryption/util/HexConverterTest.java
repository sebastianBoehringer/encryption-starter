package de.dhbw.cas.encryption.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.stream.Stream;

class HexConverterTest {

    static Stream<Arguments> randomStrings() {
        Random random = new Random();
        return Stream.of(
                Arguments.of(generateRandomString(random.nextInt(100))),
                Arguments.of(generateRandomString(random.nextInt(100))),
                Arguments.of(generateRandomString(random.nextInt(100))),
                Arguments.of(generateRandomString(random.nextInt(100))),
                Arguments.of(generateRandomString(random.nextInt(100)))
        );
    }

    static Stream<Arguments> byteDataAndExpectedHexString() {
        return Stream.of(
                Arguments.of("Never".getBytes(StandardCharsets.US_ASCII), "4E65766572"),
                Arguments.of("gonna".getBytes(StandardCharsets.US_ASCII), "676F6E6E61"),
                Arguments.of("give".getBytes(StandardCharsets.US_ASCII), "67697665"),
                Arguments.of("you".getBytes(StandardCharsets.US_ASCII), "796F75"),
                Arguments.of("up".getBytes(StandardCharsets.US_ASCII), "7570")
        );

    }

    static String generateRandomString(int length) {
        Random rand = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            // printable ascii characters are between 32 and 127 where 32 is space. 127 is delete and thus skipped. With
            // a random int between 0 (inclusive) and 95 (exclusive) we get the actual range of 32 to 126 with both ends
            // inclusive. See https://www.ascii-code.com for an ascii table
            sb.append((char) ((rand.nextInt(95)) + ' '));
        }
        return sb.toString();
    }

    @ParameterizedTest
    @MethodSource("byteDataAndExpectedHexString")
    void test_convertToHexString_writesBytesAsCorrectHexString(byte[] test, String expected) {
        Assertions.assertEquals(expected, HexConverter.convertToHexString(test));
    }

    @ParameterizedTest
    @MethodSource("byteDataAndExpectedHexString")
    void test_loadBytesFromHexString_correctlyConvertsHexStringToBytes(byte[] expected, String hexString) {
        Assertions.assertArrayEquals(expected, HexConverter.loadBytesFromHexString(hexString));
    }

    @ParameterizedTest
    @MethodSource("randomStrings")
    void test_classMethodsConvertBetweenThemselves(String test) {
        byte[] bytes = test.getBytes(StandardCharsets.UTF_8);
        String hexString = HexConverter.convertToHexString(bytes);
        byte[] loadedBytes = HexConverter.loadBytesFromHexString(hexString);
        Assertions.assertArrayEquals(bytes, loadedBytes);
        Assertions.assertEquals(test, new String(loadedBytes, StandardCharsets.UTF_8));
    }
}