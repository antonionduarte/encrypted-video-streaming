package config.parser;

public class CryptoConfig {
	private final String cipher;
	private final String key;
	private final String iv;
	private final String integrity;
	private final String mackey;

	public CryptoConfig(String cipher, String key, String iv, String integrity, String mackey) {
		this.cipher = cipher;
		this.key = key;
		this.iv = iv;
		this.integrity = integrity;
		this.mackey = mackey;
	}

	public String getCipher() {
		return cipher;
	}

	public String getKey() {
		return key;
	}

	public String getIv() {
		return iv;
	}

	public String getIntegrity() {
		return integrity;
	}

	public String getMackey() {
		return mackey;
	}
}