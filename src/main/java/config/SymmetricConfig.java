package config;

import config.parser.parser_objects.ParsedSymmetricConfig;

public class SymmetricConfig {
	private final String cipher;
	private final String integrity;
	private int keySize = 0;
	private int macKeySize;
	private int ivSize;

	public SymmetricConfig(String cipher, int keySize, String integrity, int macKeySize, int ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = integrity;
		this.macKeySize = macKeySize;
		this.ivSize = ivSize;
	}

	public SymmetricConfig(ParsedSymmetricConfig parsedSymmetricConfig) {
		var ivSize = parsedSymmetricConfig.getIvSize();
		var keySize = parsedSymmetricConfig.getKeySize();
		var macKeySize = parsedSymmetricConfig.getMacKeySize();

		this.ivSize = 0;
		this.keySize = 0;
		this.macKeySize = 0;

		if (ivSize != null) {
			this.ivSize = Integer.parseInt(ivSize);
		}
		if (keySize != null) {
			this.keySize = Integer.parseInt(keySize);
		}
		if (macKeySize != null) {
			this.macKeySize = Integer.parseInt(macKeySize);
		}

		this.cipher = parsedSymmetricConfig.getCipher();
		this.integrity = parsedSymmetricConfig.getIntegrity();
	}

	public String getCipher() {
		return cipher;
	}

	public int getKeySize() {
		return keySize;
	}

	public String getIntegrity() {
		return integrity;
	}

	public int getMacKeySize() {
		return macKeySize;
	}

	public int getIvSize() {
		return ivSize;
	}
}
