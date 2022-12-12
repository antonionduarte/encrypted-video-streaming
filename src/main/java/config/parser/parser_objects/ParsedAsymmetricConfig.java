package config.parser.parser_objects;

public class ParsedAsymmetricConfig {
	private final String keyExchange;
	private final String numSize;
	private final String authentication;
	private final String keySize;

	public ParsedAsymmetricConfig(String keyExchange, String numSize, String authentication, String keySize) {
		this.keyExchange = keyExchange;
		this.numSize = numSize;
		this.authentication = authentication;
		this.keySize = keySize;
	}

	public String getKeyExchange() {
		return keyExchange;
	}

	public String getNumSize() {
		return numSize;
	}

	public String getAuthentication() {
		return authentication;
	}

	public String getKeySize() {
		return keySize;
	}
}
