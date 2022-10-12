package encryptiontool;


// This is version 2 of CryptoStuff class (ex 3, Lab 1)
// In this version we separate the definition of ALGORITHM
// and the definition of CIPHERSUITE parameterization to be
// more clear and correct the utilization and generalization of
// use ...

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;


public class EncryptionTool {

	// For use in your TP1 implementation you must have the crytoconfigs
	// according to the StreamingServer crypto configs
	// because this is just an illustrative example with specific
	// defined configurations... Remember that for TP1 you
	// must have your own tool to encrypt the movie files that can
	// be used by your StreamingServer implementation

	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES/CTR/PKCS5Padding";
	// See this according to the configuration of StreamingServer
	// Initialization vector ... See this according to the cryptoconfig
	// of Streaming Server
	private static final byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0f, 0x0d, 0x0e, 0x0c, 0x0b, 0x0a, 0x09, 0x08};


	public static void encrypt(String key, File inputFile, File outputFile) throws CryptoException {
		doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
	}

	public static void decrypt(String key, File inputFile, File outputFile) throws CryptoException {
		doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
	}

	private static void doCrypto(int cipherMode, String key, File inputFile, File outputFile) throws CryptoException {
		try {
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
			Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(cipherMode, secretKey, ivSpec);

			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			byte[] outputBytes = cipher.doFinal(inputBytes);

			FileOutputStream outputStream = new FileOutputStream(outputFile);
			outputStream.write(outputBytes);

			inputStream.close();
			outputStream.close();
		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
		         IllegalBlockSizeException | InvalidAlgorithmParameterException | IOException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}
}
