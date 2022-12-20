package cryptotools.integrity;

import config.CipherConfig;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class IntegrityTool {

	public static boolean checkIntegrity(CipherConfig cipherConfig, byte[] data, byte[] integrity) {
		try {
			if (cipherConfig.getMackey() == null) {
				return checkHashIntegrity(cipherConfig.getIntegrity(), data, integrity);
			} else {
				return checkMacIntegrity(cipherConfig.getIntegrity(), cipherConfig.getMackey(), data, integrity);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static byte[] buildIntegrity(CipherConfig cipherConfig, byte[] plainText, byte[] cipherText) {
		if (cipherConfig.getMackey() == null) {
			return buildHashIntegrity(cipherConfig.getIntegrity(), plainText);
		} else {
			return buildMacIntegrity(cipherConfig.getIntegrity(), cipherConfig.getMackey(), cipherText);
		}
	}

	public static boolean checkMovieIntegrity(CipherConfig movieCipherConfig, byte[] data) {
		return checkIntegrity(movieCipherConfig, data, Base64.getDecoder().decode(movieCipherConfig.getIntegrityCheck()));
	}

	public static boolean checkMacIntegrity(String macAlg, Key macKey, byte[] data, byte[] integrity) {
		var macBytes = buildMacIntegrity(macAlg, macKey, data);
		return Arrays.equals(macBytes, integrity);
	}

	private static boolean checkHashIntegrity(String digestAlg, byte[] data, byte[] integrity) throws NoSuchAlgorithmException {
		var hashBytes = buildHashIntegrity(digestAlg, data);
		return Arrays.equals(hashBytes, integrity);
	}

	public static byte[] buildMacIntegrity(String macAlg, Key macKey, byte[] data) {
		try {
			var mac = Mac.getInstance(macAlg);
			mac.init(macKey);
			mac.update(data);
			return mac.doFinal();
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] buildHashIntegrity(String digestAlg, byte[] data) {
		try {
			var hash = MessageDigest.getInstance(digestAlg);
			hash.update(data);

			return hash.digest();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
