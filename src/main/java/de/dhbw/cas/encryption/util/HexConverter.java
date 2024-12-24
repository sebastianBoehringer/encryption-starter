package de.dhbw.cas.encryption.util;

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
     */
    public static byte[] loadBytesFromHexString(final String hexString) {
        return FORMAT.parseHex(hexString);
    }
}
