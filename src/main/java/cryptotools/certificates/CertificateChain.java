package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Represents a certificate chain.
 * <p>
 * Serialized format: [length][size_cert1][cert1][size_cert2][cert2]...[size_certN][certN]
 */
public record CertificateChain(X509Certificate... chain) {

	public static final String CERT_TYPE = "X.509";

	public byte[] serializedChain() {
		try {
			// create a certificate factory
			var cf = CertificateFactory.getInstance(CERT_TYPE);

			// create a list of certificates
			List<Certificate> certList = new ArrayList<>(Arrays.asList(chain));

			// encode the certificates
			return cf.generateCertPath(certList).getEncoded();
		} catch (CertificateException ex) {
			throw new RuntimeException(ex);
		}
	}

	public static CertificateChain deserializeChain(byte[] bytes) {
		try {
			// create a certificate factory
			CertificateFactory cf = CertificateFactory.getInstance("X.509");

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
}
