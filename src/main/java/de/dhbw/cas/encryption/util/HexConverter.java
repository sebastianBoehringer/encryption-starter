package de.dhbw.cas.encryption.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HexFormat;

/**
 * Converts between the string representation of a hex string and the byte
 */
public final class HexConverter {
    private static final HexFormat FORMAT = HexFormat.of().withUpperCase();

    private HexConverter() {
    }

    /**
     * @param bytes The bytes that should be written as a hex string
     * @return The hex string representing the given bytes
     */
    public static String convertToHexString(final byte[] bytes) {
        return FORMAT.formatHex(bytes);
    }

    /**
     * @param hexString The string in hex format to convert into bytes
     * @return The converted bytes
     * @throws IllegalArgumentException If the provided string is not in hex format
     */
    public static byte[] loadBytesFromHexString(final String hexString) throws IllegalArgumentException {
        return FORMAT.parseHex(hexString);
    }

    /**
     * Reads the first line from a file and interprets it as bytes
     *
     * @param file The file containing a hex string
     * @return The bytes converted from the hex string
     * @throws IllegalArgumentException If the provided string is not in hex format
     * @throws IOException              If anything goes wrong while reading the file
     */
    public static byte[] loadBytesFromFile(final File file) throws IllegalArgumentException, IOException {
        String firstLine;
        try (BufferedReader fileReader = new BufferedReader(new FileReader(file))) {
            firstLine = fileReader.readLine();
        }
        return loadBytesFromHexString(firstLine);
    }
}
