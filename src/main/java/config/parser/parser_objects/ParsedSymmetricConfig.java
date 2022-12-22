package config.parser.parser_objects;

public class ParsedSymmetricConfig {
	private final String cipher;
	private final int keySize;
	private final String integrity;
	private final int macKeySize;
	private final int ivSize;

	public ParsedSymmetricConfig(String cipher, int keySize, String integrity, int macKeySize, int ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = integrity;
		this.macKeySize = macKeySize;
		this.ivSize = ivSize;
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
