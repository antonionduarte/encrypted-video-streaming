package cryptotools.encryption;

import config.CipherConfig;
import cryptotools.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class EncryptionTool {
	public static byte[] encrypt(CipherConfig config, byte[] plaintext) throws CryptoException {
		return doCrypto(Cipher.ENCRYPT_MODE, config, plaintext);
	}

	public static byte[] decrypt(CipherConfig config, byte[] ciphertext) throws CryptoException {
		return doCrypto(Cipher.DECRYPT_MODE, config, ciphertext);
	}

	private static byte[] doCrypto(int cipherMode, CipherConfig config, byte[] text) throws CryptoException {
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
