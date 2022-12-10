package cryptotools.key_agreement;

import javax.crypto.KeyAgreement;
import java.security.*;

public class SecretGenerator {
	public static final String HASH_DIGEST = "SHA1";

	private final KeyAgreement keyAgreement;

	public static KeyPair generateKeyPair(String keyType, int size) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyType);
		keyPairGenerator.initialize(size);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Generates a key agreement using the specified algorithm.
	 * @param agreementType The type of the agreement, something such as "DH" for Diffie-Hellman.
	 * @param keyPair The key pair to use for the agreement at this node.
	 */
	public SecretGenerator(String agreementType, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException {
		this.keyAgreement = KeyAgreement.getInstance(agreementType);
		this.keyAgreement.init(keyPair.getPrivate());
	}

	/**
	 * Generates a secret key using the specified algorithm.
	 * @param publicKey The public key of the other node.
	 * @return The secret value.
	 */
	public byte[] generateSecret(PublicKey publicKey) throws Exception {
		var hash = MessageDigest.getInstance(HASH_DIGEST);
		keyAgreement.doPhase(publicKey, true);
		return hash.digest(keyAgreement.generateSecret());
	}
}
