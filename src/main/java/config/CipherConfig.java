package config;

import config.parser.parser_objects.ParsedCipherConfig;
import utils.Utils;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Optional;

public class CipherConfig {
	private final String cipher;
	private final Key key;
	private final IvParameterSpec iv;
	private final String integrity;
	private final Key macKey;
	private final byte[] integrityCheck;

	public CipherConfig(ParsedCipherConfig parsedCipherConfig) {
		this.cipher = parsedCipherConfig.cipher();
		this.key = new SecretKeySpec(Utils.hexToBytes(parsedCipherConfig.key()), algFromCipher(cipher));
		this.iv = (parsedCipherConfig.iv() != null) ?
			new IvParameterSpec(Utils.hexToBytes(parsedCipherConfig.iv())) : null;
		this.integrity = parsedCipherConfig.integrity();
		this.macKey = (this.integrity != null) ?
			new SecretKeySpec(Utils.hexToBytes(parsedCipherConfig.macKey()), this.integrity) : null;
		this.integrityCheck = (parsedCipherConfig.integrityCheck() != null) ?
			Utils.hexToBytes(parsedCipherConfig.integrityCheck()) : null;
	}

	public CipherConfig(SymmetricConfig symmetricConfig, byte[] secret) {
		var random = new SecureRandom(secret);
		var bytes = genBytes(random, symmetricConfig.getKeySize());

		this.cipher = symmetricConfig.getCipher();
		this.key = new SecretKeySpec(bytes, algFromCipher(cipher));

		if (symmetricConfig.getIvSize() > 0) {
			bytes = genBytes(random, symmetricConfig.getIvSize());
			this.iv = new IvParameterSpec(bytes);
		} else {
			this.iv = null;
		}

		if (symmetricConfig.getIntegrity() != null) {
			this.integrity = symmetricConfig.getIntegrity();
			if (symmetricConfig.getMacKeySize() > 0) {
				bytes = genBytes(random, symmetricConfig.getMacKeySize());
				this.macKey = new SecretKeySpec(bytes, integrity);
			} else {
				this.macKey = null;
			}
		} else {
			this.integrity = null;
			this.macKey = null;
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

	public Key getMacKey() {
		return macKey;
	}

	public byte[] getIntegrityCheck() {
		return integrityCheck;
	}
}
