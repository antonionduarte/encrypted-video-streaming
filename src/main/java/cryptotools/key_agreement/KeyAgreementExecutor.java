package cryptotools.key_agreement;

import config.AsymmetricConfig;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

public class KeyAgreementExecutor {
	private static final String HASH_DIGEST = "SHA256";
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
		var hash = MessageDigest.getInstance(HASH_DIGEST);
		keyAgreement.doPhase(publicKey, true);
		return hash.digest(keyAgreement.generateSecret());
	}

	private static KeyPair generateNumPair(AsymmetricConfig config) {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance(config.keyExchange);
			if (config.G.isPresent() && config.p.isPresent()) {
				var paramSpec = new DHParameterSpec(config.p.get(), config.G.get());
				keyPairGenerator.initialize(paramSpec);
			} else {
				keyPairGenerator.initialize(config.numSize);
				//TODO get G and p from initialized keyPairGenerator
				BigInteger G = null;
				BigInteger p = null;

				config.G = Optional.of(G);
				config.p = Optional.of(p);
			}
			return keyPairGenerator.generateKeyPair();

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
