package cryptotools.certificates;

import config.AsymmetricConfig;
import utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateTool {
	/**
	 * Gets a certificate from a file.
	 */
	public static X509Certificate certificateFromFile(String filePath) throws CertificateException, IOException {
		var certificateBytes = Utils.getFileBytes(filePath);
		CertificateFactory factory = CertificateFactory.getInstance(CertificateChain.CERT_TYPE);
		return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificateBytes));
	}

	/**
	 * Gets a certificate from a truststore.
	 */
	public static X509Certificate certificateFromTruststore(String truststorePath, String alias, String password)
			throws CertificateException, IOException {
		// Load the truststore file
		var truststoreInputStream = new FileInputStream(truststorePath);
		try {
			var truststore = KeyStore.getInstance(KeyStore.getDefaultType());
			truststore.load(truststoreInputStream, password.toCharArray());

			return (X509Certificate) truststore.getCertificate(alias);
		} catch (NoSuchAlgorithmException | KeyStoreException ex) {
			throw new RuntimeException(ex);
		}
	}
}
