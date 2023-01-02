package utils;

import org.junit.jupiter.api.Test;
import utils.Utils;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    @Test
    void hexToBytes() {
        var bytes = Utils.hexToBytes("0f");
        assertArrayEquals(new byte[]{0x0f}, bytes);

        bytes = Utils.hexToBytes("0fffff");
        assertArrayEquals(new byte[]{0x0f, (byte) 0xff, (byte) 0xff}, bytes);
    }

    @Test
    void bytesToHex() {
        var hex = Utils.bytesToHex(new byte[]{(byte) 0x0f});
        assertEquals("0f", hex);

        hex = Utils.bytesToHex(new byte[]{0x0f, (byte) 0xff, (byte) 0xff});
        assertEquals("0fffff", hex);
    }
}
