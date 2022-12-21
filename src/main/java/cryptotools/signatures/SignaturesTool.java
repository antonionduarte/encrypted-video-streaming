package cryptotools.signatures;

import config.AsymmetricConfig;
import protocols.rtss.handshake.exceptions.AuthenticationException;

import java.security.*;

public class SignaturesTool {

	public static void verifySignature(AsymmetricConfig config, PublicKey publicKey, byte[] originalData, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, AuthenticationException {
		// Initialize the Signature object with the desired signature algorithm
		Signature sig = Signature.getInstance("SHA256with" + config.getAuthentication());

		// Initialize the Signature object for verification, passing in the public key
		sig.initVerify(publicKey);

		// Update the Signature object with the original data
		sig.update(originalData);

		// Check if the signature is valid
		if (!sig.verify(signature))
			throw new AuthenticationException();
	}

	/**
	 * Creates a digital signature.
	 */
	public static byte[] createSignature(AsymmetricConfig config, PrivateKey key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		// Create a Signature object and initialize it with the private key
		Signature sig = Signature.getInstance("SHA256with" + config.getAuthentication());

		sig.initSign(key);

		// Update the signature object with the data that you want to sign
		sig.update(data);

		// Generate the signature
		return sig.sign();
	}
}
