package config.parser.parser_objects;

public class ParsedHandshakeIntegrityConfig {
	private final String algorithm;
	private final String macKey;

	public ParsedHandshakeIntegrityConfig(String algorithm, String macKey) {
		this.algorithm = algorithm;
		this.macKey = macKey;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public String getMacKey() {
		return macKey;
	}
}
