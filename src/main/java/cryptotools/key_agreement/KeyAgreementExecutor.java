package cryptotools.key_agreement;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class KeyAgreementExecutor {
	private static final String HASH_DIGEST = "SHA256";
	private final KeyAgreement keyAgreement;
	private final KeyPair numPair;

	/**
	 * Generates a key agreement using the specified algorithm.
	 *
	 * @param agreementAlg The algorithm of the agreement, something such as "DH" for Diffie-Hellman.
	 * @param numSize       Size of the num pair to used for the agreement.
	 */
	public KeyAgreementExecutor(String agreementAlg, int numSize) {
		this.numPair = KeyAgreementExecutor.generateNumPair(agreementAlg, numSize);
		try {
			this.keyAgreement = KeyAgreement.getInstance(agreementAlg);
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

	public static KeyPair generateNumPair(String alg, int size) {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance(alg);
			keyPairGenerator.initialize(size);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
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
