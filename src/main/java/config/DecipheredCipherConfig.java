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
public class DecipheredCryptoConfig {
	private final Map<String, CipherConfig> cryptoConfig;

	public DecipheredCryptoConfig(String key, String path) throws CryptoException {
		var cryptoConfigCiphered = new File(path);
		var deciphered = new String(EncryptConfig.decipherConfig(key, cryptoConfigCiphered));
		var parseMoviesConfig = new ParseCipherConfig(deciphered);
		this.cryptoConfig = parseMoviesConfig.parseConfig();
	}

	public Map<String, CipherConfig> getCryptoConfig() {
		return cryptoConfig;
	}
}
