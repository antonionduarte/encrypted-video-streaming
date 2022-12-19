package config;

import config.parser.parser_objects.ParsedCipherConfig;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public class CipherConfig {
	private final String cipher;
	private final String integrity;
	private final String integrityCheck;
	private Key key;
	private IvParameterSpec iv;
	private Key mackey;

	public CipherConfig(ParsedCipherConfig parsedCipherConfig) {
		var key = parsedCipherConfig.getKey();
		var iv = parsedCipherConfig.getIv();
		var macKey = parsedCipherConfig.getMacKey();

		if (key != null) {
			this.key = new SecretKeySpec(key.getBytes(), algFromCipher(parsedCipherConfig.getCipher()));
		}
		if (iv != null) {
			this.iv = new IvParameterSpec(iv.getBytes());
		}
		if (macKey != null) {
			this.mackey = new SecretKeySpec(macKey.getBytes(), parsedCipherConfig.getIntegrity());
		}

		this.cipher = parsedCipherConfig.getCipher();
		this.integrity = parsedCipherConfig.getIntegrity();
		this.integrityCheck = parsedCipherConfig.getIntegrityCheck();
	}

	public CipherConfig(byte[] secret, SymmetricConfig symmetricConfig) {
		var random = new SecureRandom(secret);
		var bytes = genBytes(random, symmetricConfig.getKeySize());

		this.cipher = symmetricConfig.getCipher();
		this.integrity = symmetricConfig.getIntegrity();
		this.key = new SecretKeySpec(bytes, algFromCipher(cipher));

		if (symmetricConfig.getIvSize() > 0) {
			bytes = genBytes(random, symmetricConfig.getIvSize());
			this.iv = new IvParameterSpec(bytes);
		}
		if (symmetricConfig.getMacKeySize() > 0) {
			bytes = genBytes(random, symmetricConfig.getMacKeySize());
			this.mackey = new SecretKeySpec(bytes, integrity);
		}

		this.integrityCheck = null;
	}

	private static String algFromCipher(String cipher) {
		return cipher.split("/")[0];
	}

	private static byte[] genBytes(SecureRandom random, int size) {
		var bytes = new byte[size];
		random.nextBytes(bytes);
		return bytes;
	}

	public String getCipher() {
		return cipher;
	}

	public Key getKey() {
		return key;
	}

	public IvParameterSpec getIv() {
		return iv;
	}

	public String getIntegrity() {
		return integrity;
	}

	public String getIntegrityCheck() {
		return integrityCheck;
	}

	public Key getMackey() {
		return mackey;
	}
}
