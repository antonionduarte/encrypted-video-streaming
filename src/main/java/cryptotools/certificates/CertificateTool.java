package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateTool {
	public static final String CERT_TYPE = "X509";



	/**
	 * Gets a certificate from a byte array.
	 */
	public static X509Certificate certificateFromBytes(byte[] certificateBytes) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance(CERT_TYPE);
		return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificateBytes));
	}
}
