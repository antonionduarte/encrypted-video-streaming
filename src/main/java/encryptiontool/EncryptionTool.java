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


	// See this according to the configuration of StreamingServer
	// Initialization vector ... See this according to the cryptoconfig
	// of Streaming Server

	// private static final byte[] ivBytes = new byte[]{ 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0f, 0x0d, 0x0e, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
	// private static final String TRANSFORMATION = "AES/CTR/PKCS5Padding";
	// private static final String ALGORITHM = "AES";

	public static byte[] encrypt(String key, byte[] iv, String algorithm, String cipherConfig,  File inputFile) throws CryptoException {
		return doCrypto(Cipher.ENCRYPT_MODE, key, iv, algorithm, cipherConfig, inputFile);
	}

	public static byte[] decrypt(String key, byte[] iv, String algorithm, String cipherConfig, File inputFile) throws CryptoException {
		return doCrypto(Cipher.DECRYPT_MODE, key, iv, algorithm, cipherConfig, inputFile);
	}

	private static byte[] doCrypto(int cipherMode, String key, byte[] iv, String algorithm, String cipherConfig, File inputFile) throws CryptoException {
		try {
			Key secretKey = new SecretKeySpec(key.getBytes(), algorithm);
			Cipher cipher = Cipher.getInstance(cipherConfig);

			if (iv == null) {
				cipher.init(cipherMode, secretKey);
			} else {
				IvParameterSpec ivSpec = new IvParameterSpec(iv);
				cipher.init(cipherMode, secretKey, ivSpec);
			}

			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			byte[] outputBytes = cipher.doFinal(inputBytes);
			inputStream.close();

			return outputBytes;
		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
		         IllegalBlockSizeException | InvalidAlgorithmParameterException | IOException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}
}
