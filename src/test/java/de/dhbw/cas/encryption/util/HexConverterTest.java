package de.dhbw.cas.encryption.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
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
        Assertions.assertThat(HexConverter.convertToHexString(test)).isEqualTo(expected);
    }

    @ParameterizedTest
    @MethodSource("byteDataAndExpectedHexString")
    void test_loadBytesFromHexString_correctlyConvertsHexStringToBytes(byte[] expected, String hexString) {
        Assertions.assertThat(HexConverter.loadBytesFromHexString(hexString)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"zzzzzz", "äöü", "ggg", ",,"})
    void test_loadBytesFromHexString_throwsOnInvalidCharacters(String invalidHexString) {
        Assertions.assertThatThrownBy(() -> HexConverter.loadBytesFromHexString(invalidHexString))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @MethodSource("randomStrings")
    void test_classMethodsConvertBetweenThemselves(String test) {
        byte[] bytes = test.getBytes(StandardCharsets.UTF_8);
        String hexString = HexConverter.convertToHexString(bytes);
        byte[] loadedBytes = HexConverter.loadBytesFromHexString(hexString);
        Assertions.assertThat(loadedBytes).isEqualTo(bytes);
        Assertions.assertThat(new String(loadedBytes, StandardCharsets.UTF_8)).isEqualTo(test);
    }


    @Test
    void test_loadBytesFromFile_correctlyLoadsFileWithSingleLine() throws IOException {
        File file = new File("./src/test/resources/single-hex-line.txt");
        Assertions.assertThat(file).exists();
        byte[] bytes = HexConverter.loadBytesFromFile(file);
        Assertions.assertThat(bytes).isEqualTo("Never gonna let you down".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void test_loadBytesFromFile_correctlyIgnoresContentOfOtherLines() throws IOException {
        File file = new File("./src/test/resources/multiple-hex-lines.txt");
        Assertions.assertThat(file).exists();
        byte[] bytes = HexConverter.loadBytesFromFile(file);
        Assertions.assertThat(bytes).isEqualTo("Never gonna let you down".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void test_loadBytesFromFile_throwsExceptionOnNonHexCharacter() {
        File file = new File("./src/test/resources/invalid-characters.txt");
        Assertions.assertThat(file).exists();
        Assertions.assertThatThrownBy(() -> HexConverter.loadBytesFromFile(file)).isInstanceOf(IllegalArgumentException.class);
    }
}