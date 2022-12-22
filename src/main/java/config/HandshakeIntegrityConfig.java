package config;

import config.parser.parser_objects.ParsedHandshakeIntegrityConfig;
import utils.Utils;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class HandshakeIntegrityConfig {

	private final String algorithm;
	private final Key macKey;

	public HandshakeIntegrityConfig(ParsedHandshakeIntegrityConfig config) {
		this.algorithm = config.getAlgorithm();
		this.macKey = new SecretKeySpec(Utils.hexToBytes(config.getMacKey()), algorithm);
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public Key getMacKey() {
		return macKey;
	}
}
