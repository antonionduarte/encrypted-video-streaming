package cryptotools.key_agreement;

import config.AsymmetricConfig;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

public class KeyAgreementExecutor {
	private static final String DIGEST_ALG = "SHA1";
	private final KeyAgreement keyAgreement;
	private final KeyPair numPair;

	/**
	 * Generates a key agreement using the specified algorithm.
	 *
	 * @param config asymmetric config of the handshake
	 */
	public KeyAgreementExecutor(AsymmetricConfig config) {
		try {
			this.keyAgreement = KeyAgreement.getInstance(config.keyExchange);

			this.numPair = generateNumPair(config);

			this.keyAgreement.init(numPair.getPrivate());
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
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

	private static KeyPair generateNumPair(AsymmetricConfig config) {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance(config.keyExchange);
			if (config.G.isPresent() && config.p.isPresent()) {
				var paramSpec = new DHParameterSpec(config.p.get(), config.G.get());
				keyPairGenerator.initialize(paramSpec);
				return keyPairGenerator.generateKeyPair();
			} else {
				keyPairGenerator.initialize(config.numSize);
				var keyPair = keyPairGenerator.generateKeyPair();
				// Get the public key
				var publicKey = (DHPublicKey) keyPair.getPublic();
				// Get the DHParameterSpec object from the public key
				var dhParamSpec = publicKey.getParams();
				config.G = Optional.of(dhParamSpec.getG());
				config.p = Optional.of(dhParamSpec.getP());

				return keyPair;
			}
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
			throw new RuntimeException(ex);
		}
	}

	public static Key decodePublicNum(String alg, byte[] numBytes) {
		try {
			// Create a KeyFactory for the key's algorithm
			var keyFactory = KeyFactory.getInstance(alg);
			// Use the KeyFactory to recreate the key from the encoded form
			return keyFactory.generatePublic(new X509EncodedKeySpec(numBytes));
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
}
