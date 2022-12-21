package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Represents a certificate certificates. It is assumed the trust anchor is the last certificate in the chain.
 * Serialized format: [length][size_cert1][cert1][size_cert2][cert2]...[size_certN][certN]
 */
public record CertificateChain(X509Certificate... certificates) {

	public static final String CERT_TYPE = "X.509";

	public byte[] serializedChain() {
		try {
			// create a certificate factory
			var cf = CertificateFactory.getInstance(CERT_TYPE);

			// create a list of certificates
			List<Certificate> certList = new ArrayList<>(Arrays.asList(certificates));

			// encode the certificates
			return cf.generateCertPath(certList).getEncoded();
		} catch (CertificateException ex) {
			throw new RuntimeException(ex);
		}
	}

	public static CertificateChain deserializeChain(byte[] bytes) {
		try {
			// create a certificate factory
			CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE);

			// decode the certificates
			var certPath = cf.generateCertPath(new ByteArrayInputStream(bytes));
			var certList = certPath.getCertificates();
			X509Certificate[] certificates = new X509Certificate[certList.size()];
			for (int i = 0; i < certList.size(); i++) {
				certificates[i] = (X509Certificate) certList.get(i);
			}
			return new CertificateChain(certificates);
		} catch (CertificateException ex) {
			throw new RuntimeException(ex);
		}
	}

	// TODO not sure about name
	public X509Certificate leafCertificate() {
		return certificates[0];
	}

	public X509Certificate rootCertificate() {
		return certificates[certificates.length - 1];
	}
}
