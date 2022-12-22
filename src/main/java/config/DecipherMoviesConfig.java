package config;

import config.parser.ParseCipherConfigMap;
import cryptotools.integrity.IntegrityException;
import org.bouncycastle.crypto.CryptoException;
import utils.cipherutils.EncryptConfig;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Responsible for opening, deciphering and parsing MovieConfig.
 */
public class DecipherMoviesConfig {
	private final Map<String, CipherConfig> cipherConfig;

	public DecipherMoviesConfig(String key, String path) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, CryptoException, InvalidKeyException, IntegrityException {
		var cryptoConfigCiphered = new File(path);
		var decipheredJson = new String(EncryptConfig.decryptConfig(key, cryptoConfigCiphered));
		var parseMoviesConfig = ParseCipherConfigMap.parseConfig(decipheredJson);
		this.cipherConfig = new HashMap<>();

		for (var entry : parseMoviesConfig.entrySet()) {
			this.cipherConfig.put(entry.getKey(), new CipherConfig(entry.getValue()));
		}
	}

	public Map<String, CipherConfig> getCipherConfig() {
		return cipherConfig;
	}
}
