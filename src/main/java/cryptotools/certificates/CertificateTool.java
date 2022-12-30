package cryptotools.certificates;

import utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
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
	public static X509Certificate certificateFromTruststore(KeyStore trustStore, String alias) throws KeyStoreException {
		return (X509Certificate) trustStore.getCertificate(alias);
	}
}
