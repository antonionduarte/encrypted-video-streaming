package config;

import config.parser.parser_objects.ParsedCipherConfig;
import org.bouncycastle.util.encoders.Base64;
import utils.Utils;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;
import java.util.Random;

public class CipherConfig {
	private final String cipher;
	private final Key key;
	private final IvParameterSpec iv;
	private final String integrity;
	private final Key macKey;
	private final byte[] integrityCheck;

	public CipherConfig(ParsedCipherConfig parsedCipherConfig) {
		this.cipher = parsedCipherConfig.getCipher();
		this.key = new SecretKeySpec(Utils.hexToBytes(parsedCipherConfig.getKey()), algFromCipher(cipher));
		this.iv = (parsedCipherConfig.getIv() != null) ? new IvParameterSpec(Utils.hexToBytes(parsedCipherConfig.getIv())) : null;
		this.integrity = parsedCipherConfig.getIntegrity();
		this.macKey = (this.integrity != null && parsedCipherConfig.getMackey() != null) ?
				new SecretKeySpec(Utils.hexToBytes(parsedCipherConfig.getMackey()), this.integrity) : null;
		this.integrityCheck = (parsedCipherConfig.getIntegrityCheck() != null) ? Base64.decode(parsedCipherConfig.getIntegrityCheck()) : null;
	}

	public CipherConfig(SymmetricConfig symmetricConfig, byte[] secret) {
		var random = new Random();
		random.setSeed(Arrays.hashCode(secret));
		var bytes = genBytes(random, symmetricConfig.getKeySize() / 8);

		this.cipher = symmetricConfig.getCipher();
		this.key = new SecretKeySpec(bytes, algFromCipher(cipher));

		if (symmetricConfig.getIvSize() > 0) {
			bytes = genBytes(random, symmetricConfig.getIvSize() / 8);
			this.iv = new IvParameterSpec(bytes);
		} else {
			this.iv = null;
		}

		if (symmetricConfig.getIntegrity() != null) {
			this.integrity = symmetricConfig.getIntegrity();
			if (symmetricConfig.getMacKeySize() > 0) {
				bytes = genBytes(random, symmetricConfig.getMacKeySize() / 8);
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

	private static byte[] genBytes(Random random, int size) {
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
