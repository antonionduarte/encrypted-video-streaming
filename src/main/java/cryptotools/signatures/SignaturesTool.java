package cryptotools.signatures;

import config.AsymmetricConfig;

import java.security.*;
import java.security.cert.X509Certificate;

public class SignaturesTool {
	/**
	 * Verifies a digital signature using an X509 certificate.
	 */
	public static boolean verifySignature(byte[] signature, byte[] data, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		PublicKey key = certificate.getPublicKey();

		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(key);

		// Update the signature object with the data that was signed
		sig.update(data);

		// Verify the signature
		return sig.verify(signature);
	}

	/**
	 * Creates a digital signature.
	 */
	public static byte[] createSignature(AsymmetricConfig config, PrivateKey key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		// Create a Signature object and initialize it with the private key
		Signature sig = Signature.getInstance("SHA256with" + config.authentication);

		sig.initSign(key);

		// Update the signature object with the data that you want to sign
		sig.update(data);

		// Generate the signature
		return sig.sign();
	}
}
