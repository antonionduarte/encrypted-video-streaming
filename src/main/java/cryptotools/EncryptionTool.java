package cryptotools;


// This is version 2 of CryptoStuff class (ex 3, Lab 1)
// In this version we separate the definition of ALGORITHM
// and the definition of CIPHERSUITE parameterization to be
// more clear and correct the utilization and generalization of
// use ...

import config.parser.CipherConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;


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

	public static byte[] encrypt(CipherConfig config, byte[] plaintext) throws CryptoException {
		return doCrypto(Cipher.ENCRYPT_MODE, config, plaintext);
	}

	public static byte[] decrypt(CipherConfig config, byte[] ciphertext) throws CryptoException {
		return doCrypto(Cipher.DECRYPT_MODE, config, ciphertext);
	}

	private static byte[] doCrypto(int cipherMode, CipherConfig config, byte[] text) throws CryptoException {
		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());

		var algorithm = config.getCipher().split("/")[0];
		var key = config.getKey();
		var cipherSuite = config.getCipher();
		var iv = config.getIv();

		try {
			Key secretKey = new SecretKeySpec(key.getBytes(), algorithm);
			Cipher cipher = Cipher.getInstance(cipherSuite);

			if (iv == null) {
				cipher.init(cipherMode, secretKey);
			} else {
				IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
				cipher.init(cipherMode, secretKey, ivSpec);
			}

			return cipher.doFinal(text);

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
		         IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}
}
