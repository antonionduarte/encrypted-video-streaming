package cryptotools.integrity;

import config.CipherConfig;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class IntegrityTool {

	public static void checkIntegrity(CipherConfig cipherConfig, byte[] data, byte[] integrity) throws IntegrityException, NoSuchAlgorithmException, InvalidKeyException {
		if (cipherConfig.getIntegrity() != null) {
			if (cipherConfig.getMacKey() != null) {
				checkMacIntegrity(cipherConfig.getIntegrity(), cipherConfig.getMacKey(), data, integrity);
			} else {
				checkHashIntegrity(cipherConfig.getIntegrity(), data, integrity);
			}
		} else {
			throw new IllegalArgumentException("No integrity algorithm in configuration");
		}
	}

	public static void checkMovieIntegrity(CipherConfig movieCipherConfig, byte[] data) throws IntegrityException, NoSuchAlgorithmException, InvalidKeyException {
		if (movieCipherConfig.getIntegrityCheck() != null) {
			checkIntegrity(movieCipherConfig, data, movieCipherConfig.getIntegrityCheck());
		} else {
			throw new IllegalArgumentException("No integrity check in configuration");
		}
	}

	public static void checkMacIntegrity(String macAlg, Key macKey, byte[] data, byte[] integrity) throws IntegrityException, NoSuchAlgorithmException, InvalidKeyException {
		var macBytes = buildMacIntegrity(macAlg, macKey, data);
		if (!Arrays.equals(macBytes, integrity)) {
			throw new IntegrityException();
		}
	}

	public static void checkHashIntegrity(String digestAlg, byte[] data, byte[] integrity) throws NoSuchAlgorithmException, IntegrityException {
		var hashBytes = buildHashIntegrity(digestAlg, data);
		if (!Arrays.equals(hashBytes, integrity)) {
			throw new IntegrityException();
		}
	}

	public static byte[] buildMacIntegrity(String macAlg, Key macKey, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
		var mac = Mac.getInstance(macAlg);
		mac.init(macKey);
		mac.update(data);
		return mac.doFinal();
	}

	public static byte[] buildHashIntegrity(String digestAlg, byte[] data) throws NoSuchAlgorithmException {
		var hash = MessageDigest.getInstance(digestAlg);
		hash.update(data);

		return hash.digest();
	}
}
