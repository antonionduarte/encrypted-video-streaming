package cryptotools.key_agreement;

import javax.crypto.KeyAgreement;
import java.security.*;

public class KeyAgreementExecutor {
	//TODO make configurable perhaps
	public static final String HASH_DIGEST = "SHA1";

	private final KeyAgreement keyAgreement;
	private final KeyPair numPair;

	/**
	 * Generates a key agreement using the specified algorithm.
	 *
	 * @param agreementType The type of the agreement, something such as "DH" for Diffie-Hellman.
	 * @param numSize       Size of the num pair to used for the agreement.
	 */
	public KeyAgreementExecutor(String agreementType, int numSize) throws NoSuchAlgorithmException, InvalidKeyException {
		this.numPair = KeyAgreementExecutor.generateKeyPair(agreementType, numSize);
		this.keyAgreement = KeyAgreement.getInstance(agreementType);
		this.keyAgreement.init(numPair.getPrivate());
	}

	public static KeyPair generateKeyPair(String keyType, int size) throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyType);
		keyPairGenerator.initialize(size);
		return keyPairGenerator.generateKeyPair();
	}

	public Key getPublicNum() {
		return numPair.getPublic();
	}

	public Key getPrivateNum() {
		return numPair.getPrivate();
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
}
