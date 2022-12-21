package cryptotools.key_agreement;

import config.AsymmetricConfig;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class KeyAgreementExecutor {
	private static final String DIGEST_ALG = "SHA1";
	private final KeyAgreement keyAgreement;
	private final KeyPair numPair;

	/**
	 * Generates a key agreement using the specified algorithm.
	 *
	 * @param config asymmetric config of the handshake
	 */
	public KeyAgreementExecutor(AsymmetricConfig config) throws NoSuchAlgorithmException, InvalidKeyException {
		this.keyAgreement = KeyAgreement.getInstance(config.getKeyExchange());
		this.numPair = generateNumPair(config);
		this.keyAgreement.init(numPair.getPrivate());
	}

	private static KeyPair generateNumPair(AsymmetricConfig config) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var keyPairGenerator = KeyPairGenerator.getInstance(config.getKeyExchange());
		if (config.getG() != null && config.getP() != null) {
			var paramSpec = new DHParameterSpec(config.getP(), config.getG());
			keyPairGenerator.initialize(paramSpec);
			return keyPairGenerator.generateKeyPair();
		} else {
			keyPairGenerator.initialize(config.getNumSize());
			var keyPair = keyPairGenerator.generateKeyPair();
			// Get the public key
			var publicKey = (DHPublicKey) keyPair.getPublic();
			// Get the DHParameterSpec object from the public key
			var dhParamSpec = publicKey.getParams();
			config.setG(dhParamSpec.getG());
			config.setP(dhParamSpec.getP());

			return keyPair;
		}
	}

	public static PublicKey getPubicNum(String alg, byte[] numBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Create a KeyFactory for the key's algorithm
		var keyFactory = KeyFactory.getInstance(alg);
		// Use the KeyFactory to recreate the key from the encoded form
		return keyFactory.generatePublic(new X509EncodedKeySpec(numBytes));
	}

	public Key getPublicNum() {
		return numPair.getPublic();
	}

	/**
	 * Generates a secret key using the specified algorithm.
	 *
	 * @param publicKey The public key of the other node.
	 * @return The secret value.
	 */
	public byte[] generateSecret(PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException {
		keyAgreement.doPhase(publicKey, true);

		var hash = MessageDigest.getInstance(DIGEST_ALG);
		return hash.digest(keyAgreement.generateSecret());
	}
}
