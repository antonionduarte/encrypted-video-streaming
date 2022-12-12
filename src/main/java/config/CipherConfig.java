package config;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public class CipherConfig {
	private final String cipher;
	private Key key;
	private IvParameterSpec iv;
	private final String integrity;
	private Key mackey;
	private final String integrityCheck;

	public CipherConfig(String cipher, String key, String iv, String integrity, String mackey, String integrityCheck) {
		if (key != null) this.key = new SecretKeySpec(key.getBytes(), algFromCipher(cipher));
		if (iv != null) this.iv = new IvParameterSpec(iv.getBytes());
		if (mackey != null) this.mackey = new SecretKeySpec(mackey.getBytes(), integrity);

		this.cipher = cipher;
		this.integrity = integrity;
		this.integrityCheck = integrityCheck;
	}

	public CipherConfig(byte[] secret, SymmetricConfig symmetricConfig) {
		this.cipher = symmetricConfig.cipher();
		this.integrity = symmetricConfig.integrity();
		var random = new SecureRandom(secret);

		var bytes = genBytes(random, symmetricConfig.keySize());
		this.key = new SecretKeySpec(bytes, algFromCipher(cipher));

		if (symmetricConfig.ivSize() > 0) {
			bytes = genBytes(random, symmetricConfig.ivSize());
			this.iv = new IvParameterSpec(bytes);
		}
		if (symmetricConfig.mackeySize() > 0) {
			bytes = genBytes(random, symmetricConfig.mackeySize());
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
