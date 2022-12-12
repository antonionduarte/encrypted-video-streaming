package config.parser.parser_objects;

public class ParsedSymmetricConfig {
	private final String cipher;
	private final String keySize;
	private final String integrity;
	private final String macKeySize;
	private final String ivSize;

	public ParsedSymmetricConfig(String cipher, String keySize, String integrity, String macKeySize, String ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = integrity;
		this.macKeySize = macKeySize;
		this.ivSize = ivSize;
	}

	public String getIvSize() {
		return ivSize;
	}

	public String getIntegrity() {
		return integrity;
	}

	public String getCipher() {
		return cipher;
	}

	public String getKeySize() {
		return keySize;
	}

	public String getMacKeySize() {
		return macKeySize;
	}
}
