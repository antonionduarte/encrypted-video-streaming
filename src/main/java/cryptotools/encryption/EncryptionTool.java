package cryptotools.encryption;

import config.CipherConfig;
import cryptotools.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EncryptionTool {
	public static byte[] encrypt(CipherConfig config, byte[] plaintext) throws CryptoException {
		return doCrypto(Cipher.ENCRYPT_MODE, config, plaintext);
	}

	public static byte[] decrypt(CipherConfig config, byte[] ciphertext) throws CryptoException {
		return doCrypto(Cipher.DECRYPT_MODE, config, ciphertext);
	}

	private static byte[] doCrypto(int cipherMode, CipherConfig config, byte[] text) throws CryptoException {
		var secretKey = config.getKey();
		var cipherSuite = config.getCipher();
		var ivSpec = config.getIv();

		try {
			Cipher cipher = Cipher.getInstance(cipherSuite);

			if (ivSpec == null) {
				cipher.init(cipherMode, secretKey);
			} else {
				cipher.init(cipherMode, secretKey, ivSpec);
			}

			return cipher.doFinal(text);

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
		         IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}
}
