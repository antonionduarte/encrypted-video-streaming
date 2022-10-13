package cipherdata;

import encryptiontool.CryptoException;
import encryptiontool.EncryptionTool;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class EncryptConfig {
	private static final String CIPHER_CONFIG = "AES/ECB/PKCS5Padding";

	private static final String ARGS_CIPHER = "cipher";
	private static final String ARGS_DECIPHER = "decipher";

	public static byte[] decryptConfig(String key, File inputFile) throws CryptoException {
		return EncryptionTool.decrypt(key, null, CIPHER_CONFIG, inputFile);
	}

	public static byte[] encryptConfig(String key, File inputFile) throws CryptoException {
		return EncryptionTool.encrypt(key, null, CIPHER_CONFIG, inputFile);
	}

	public static void writeToFile(byte[] bytes, File file) throws IOException {
		try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
			fileOutputStream.write(bytes);
		}
	}

	public static void main(String[] args) throws CryptoException, IOException {
		if (args.length != 4) {
			System.err.println("Ex. If you want to use AES");
			System.err.println("Use: CipherConfig <cipher | decipher> <AES-key> <input-file> <output-file>");
			System.exit(-1);
		}

		var key = args[1];
		var inputFile = new File(args[2]);
		var outputFile = new File(args[3]);

		if (args[0].equals(ARGS_CIPHER)) {
			var ciphered = encryptConfig(key, inputFile);
			writeToFile(ciphered, outputFile);
		} else if (args[0].equals(ARGS_DECIPHER)) {
			var deciphered = decryptConfig(key, inputFile);
			writeToFile(deciphered, outputFile);
		} else {
			System.err.println("Error in cipher mode, must be either 'cipher' or 'decipher'");
		}
	}
}
