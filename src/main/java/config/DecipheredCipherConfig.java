package config;

import cipherdata.EncryptConfig;
import config.parser.CipherConfig;
import config.parser.ParseCipherConfig;
import encryptiontool.CryptoException;

import java.io.File;
import java.util.Map;

/**
 * Responsible for opening, deciphering and parsing MovieConfig.
 */
public class DecipheredCipherConfig {
	private final Map<String, CipherConfig> cipherConfig;

	public DecipheredCipherConfig(String key, String path) throws CryptoException {
		var cryptoConfigCiphered = new File(path);
		var deciphered = new String(EncryptConfig.decipherConfig(key, cryptoConfigCiphered));
		var parseMoviesConfig = new ParseCipherConfig(deciphered);
		this.cipherConfig = parseMoviesConfig.parseConfig();
	}

	public Map<String, CipherConfig> getCipherConfig() {
		return cipherConfig;
	}
}
