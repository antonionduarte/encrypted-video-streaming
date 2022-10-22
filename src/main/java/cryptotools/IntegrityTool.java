package cryptotools;

import config.parser.CipherConfig;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class IntegrityTool {

	public static boolean checkIntegrity(CipherConfig cipherConfig, byte[] data, byte[] integrity) {
		try {
			if (cipherConfig.getMackey() == null) {
				return checkHashIntegrity(cipherConfig, data, integrity);
			} else {
				return checkHMacIntegrity(cipherConfig, data, integrity);
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	public static byte[] buildIntegrity(CipherConfig cipherConfig, byte[] plainText, byte[] cipherText) {
		try {
			if (cipherConfig.getMackey() == null) {
				return buildHashIntegrity(cipherConfig, plainText);
			} else {
				return buildHMacIntegrity(cipherConfig, cipherText);
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	private static boolean checkHMacIntegrity(CipherConfig cipherConfig, byte[] data, byte[] integrity) throws NoSuchAlgorithmException, InvalidKeyException {
		var hmacBytes = buildHMacIntegrity(cipherConfig, data);
		return Arrays.equals(hmacBytes, integrity);
	}

	private static boolean checkHashIntegrity(CipherConfig cipherConfig, byte[] data, byte[] integrity) throws NoSuchAlgorithmException {
		var hashBytes = buildHashIntegrity(cipherConfig, data);
		return Arrays.equals(hashBytes, integrity);
	}

	private static byte[] buildHMacIntegrity(CipherConfig cipherConfig, byte[] cipherText) throws NoSuchAlgorithmException, InvalidKeyException {
		var hmacAlgorithm = cipherConfig.getIntegrity();
		var hMacKey = new SecretKeySpec(cipherConfig.getMackey().getBytes(), hmacAlgorithm);
		var hMac = Mac.getInstance(hmacAlgorithm);

		hMac.init(hMacKey);
		hMac.update(cipherText);

		return hMac.doFinal();
	}

	private static byte[] buildHashIntegrity(CipherConfig cipherConfig, byte[] plainText) throws NoSuchAlgorithmException {
		var hash = MessageDigest.getInstance(cipherConfig.getIntegrity());
		hash.update(plainText);

		return hash.digest();
	}
}
