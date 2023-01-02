package cryptotools.integrity;

import utils.Utils;

import java.util.Arrays;

public class IntegrityException extends Exception {

	public IntegrityException() {
	}

	public IntegrityException(byte[] expected, byte[] actual) {
		super("Expected: " + Utils.bytesToHex(expected) + "\nActual: " + Utils.bytesToHex(actual));
	}
}
