package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateTool {
	public static final String ROOT_CERTIFICATE = "config/common/certs/ca_RSA_2048.cer";
	public static final String CERT_TYPE = "X509"; // TODO: Make this a param maybe?

	/**
	 * Gets a certificate from a byte array.
	 */
	public static X509Certificate certificateFromBytes(byte[] certificateBytes) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance(CERT_TYPE);
		return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificateBytes));
	}

	/**
	 * Verifies a chain certificate.
	 */
	public static boolean verifyCertificates(X509Certificate rootCertificate, X509Certificate signedCertificate) {
		try {
			// Load the local copy of the root certificate
			FileInputStream rootCertFile = new FileInputStream(ROOT_CERTIFICATE);
			CertificateFactory certificateFactory = CertificateFactory.getInstance(CERT_TYPE);
			X509Certificate localRootCertificate = (X509Certificate) certificateFactory.generateCertificate(rootCertFile);

			// Check if the received root certificate is the same as the local copy
			if (!rootCertificate.equals(localRootCertificate)) {
				// the root certificate has been tampered with
				return false;
			}

			// Verify the signed certificate using the root certificate
			PublicKey rootPublicKey = rootCertificate.getPublicKey();
			signedCertificate.verify(rootPublicKey);

			// Check if the signed certificate is signed by the root certificate
			signedCertificate.checkValidity();

			// Check if the signed certificate's issuer is the same as the root certificate's subject
			Principal rootSubject = rootCertificate.getSubjectX500Principal();
			Principal signedIssuer = signedCertificate.getIssuerX500Principal();
			return signedIssuer.equals(rootSubject);

			// If all checks pass, the certificates are valid
		} catch (Exception e) {
			// If any errors occur, the certificates are invalid
			return false;
		}
	}
}
