package config;

import config.parser.ParseCipherConfig;
import cryptotools.CryptoException;
import utils.cipherutils.EncryptConfig;

import java.io.File;
import java.io.IOException;
import java.util.Map;

/**
 * Responsible for opening, deciphering and parsing MovieConfig.
 */
public class DecipherCipherConfig {
	private final Map<String, CipherConfig> cipherConfig;

	public DecipherCipherConfig(String key, String path) throws CryptoException, IOException {
		var cryptoConfigCiphered = new File(path);
		var deciphered = new String(EncryptConfig.decryptConfig(key, cryptoConfigCiphered));
		var parseMoviesConfig = new ParseCipherConfig(deciphered);
		this.cipherConfig = parseMoviesConfig.parseConfig();
	}

	public Map<String, CipherConfig> getCipherConfig() {
		return cipherConfig;
	}

}
