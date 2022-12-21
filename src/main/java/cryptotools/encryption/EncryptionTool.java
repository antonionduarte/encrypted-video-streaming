package cryptotools.encryption;

import config.CipherConfig;
import cryptotools.integrity.IntegrityException;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EncryptionTool {
	public static byte[] encrypt(CipherConfig config, byte[] plaintext) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		return doCrypto(Cipher.ENCRYPT_MODE, config, plaintext);
	}

	public static byte[] decrypt(CipherConfig config, byte[] ciphertext) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IntegrityException {
		try {
			return doCrypto(Cipher.DECRYPT_MODE, config, ciphertext);
		} catch (AEADBadTagException ex) {
			throw new IntegrityException();
		}
	}

	private static byte[] doCrypto(int cipherMode, CipherConfig config, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		var cipher = Cipher.getInstance(config.getCipher());

		if (config.getIv() != null) {
			cipher.init(cipherMode, config.getKey(), config.getIv());
		} else {
			cipher.init(cipherMode, config.getKey());
		}
		return cipher.doFinal(text);
	}
}
