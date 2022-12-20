package config;

import config.parser.ParseCipherConfigMap;
import cryptotools.CryptoException;
import utils.cipherutils.EncryptConfig;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Responsible for opening, deciphering and parsing MovieConfig.
 */
public class DecipherMoviesConfig {
	private final Map<String, CipherConfig> cipherConfig;

	public DecipherMoviesConfig(String key, String path) throws CryptoException, IOException {
		var cryptoConfigCiphered = new File(path);
		var deciphered = new String(EncryptConfig.decryptConfig(key, cryptoConfigCiphered));
		var parseMoviesConfig = new ParseCipherConfigMap(deciphered);
		this.cipherConfig = new HashMap<>();

		for (var entry : parseMoviesConfig.parseConfig().entrySet()) {
			this.cipherConfig.put(entry.getKey(), new CipherConfig(parseMoviesConfig.parseConfig().get(entry.getKey())));
		}
	}

	public Map<String, CipherConfig> getCipherConfig() {
		return cipherConfig;
	}
}
