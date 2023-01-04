package cryptotools.keystore;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreTool {

	private static final String STORE_TYPE = "PKCS12";

	public static KeyPair keyPairFromKeyStore(String keyStorePath, String alias, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
		// load the KeyStore
		KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
		var fileInputStream = new FileInputStream(keyStorePath);
		keyStore.load(fileInputStream, password.toCharArray());

		// get the private key
		var privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

		// get the public key
		var certificate = keyStore.getCertificate(alias);
		var publicKey = certificate.getPublicKey();

		return new KeyPair(publicKey, privateKey);
	}

	public static KeyStore getTrustStore(String truststorePath, String password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
		KeyStore trustStore = KeyStore.getInstance(STORE_TYPE);
		FileInputStream trustStoreInputStream = new FileInputStream(truststorePath);
		trustStore.load(trustStoreInputStream, password.toCharArray());
		trustStoreInputStream.close();
		return trustStore;
	}
}
