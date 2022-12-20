package config;

import config.parser.parser_objects.ParsedCipherConfig;
import utils.Utils;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Optional;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class CipherConfig {
	public final String cipher;
	public final Optional<String> integrity;
	public final Optional<byte[]> integrityCheck;

	public Key key;
	public Optional<IvParameterSpec> iv;
	public Optional<Key> macKey;

	public CipherConfig(ParsedCipherConfig parsedCipherConfig) {
		this.cipher = parsedCipherConfig.cipher();
		this.key = new SecretKeySpec(Utils.hexToBytes(parsedCipherConfig.key()), algFromCipher(cipher));
		this.integrity = parsedCipherConfig.integrity() == null ? Optional.empty() : Optional.of(parsedCipherConfig.integrity());
		this.macKey = parsedCipherConfig.macKey() == null ? Optional.empty() : Optional.of(new SecretKeySpec(Utils.hexToBytes(parsedCipherConfig.macKey()), this.integrity.get()));
		this.integrityCheck = parsedCipherConfig.integrityCheck() == null ? Optional.empty() : Optional.of(Utils.hexToBytes(parsedCipherConfig.integrityCheck()));
	}

	public CipherConfig(SymmetricConfig symmetricConfig, byte[] secret) {
		var random = new SecureRandom(secret);
		var bytes = genBytes(random, symmetricConfig.keySize);

		this.cipher = symmetricConfig.cipher;
		this.key = new SecretKeySpec(bytes, algFromCipher(cipher));

		if (symmetricConfig.ivSize > 0) {
			bytes = genBytes(random, symmetricConfig.ivSize);
			this.iv = Optional.of(new IvParameterSpec(bytes));
		} else this.iv = Optional.empty();

		if (symmetricConfig.integrity.isPresent()) {
			this.integrity = symmetricConfig.integrity;
			if (symmetricConfig.macKeySize > 0) {
				bytes = genBytes(random, symmetricConfig.macKeySize);
				this.macKey = Optional.of(new SecretKeySpec(bytes, integrity.get()));
			} else this.macKey = Optional.empty();
		} else {
			this.integrity = Optional.empty();
			this.macKey = Optional.empty();
		}

		this.integrityCheck = Optional.empty();
	}

	private static String algFromCipher(String cipher) {
		return cipher.split("/")[0];
	}

	private static byte[] genBytes(SecureRandom random, int size) {
		var bytes = new byte[size];
		random.nextBytes(bytes);
		return bytes;
	}
}
