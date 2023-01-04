package cryptotools.certificates;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public record CertificateVerifier(KeyStore trustStore) {

	private static final String TRUSTMANAGER_TYPE = "PKIX";

	/**
	 * Verify the validity of a certificate chain
	 *
	 * @param chain certificate chain to verify
	 */
	public void verifyCertificateChain(CertificateChain chain) throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
		checkAuthenticity(chain);
		checkDateValidity(chain);
	}

	private void checkAuthenticity(CertificateChain chain) throws CertificateException, KeyStoreException, NoSuchAlgorithmException {
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TRUSTMANAGER_TYPE);
		trustManagerFactory.init(trustStore);
		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		for (TrustManager trustManager : trustManagers) {
			if (trustManager instanceof X509TrustManager) {
				((X509TrustManager) trustManager).checkServerTrusted(chain.certificates(), "RSA");
				return;
			}
		}
		throw new CertificateException("No X509TrustManager found in TrustManagerFactory");
	}

	private void checkDateValidity(CertificateChain chain) throws CertificateNotYetValidException, CertificateExpiredException {
		Date currentDate = new Date();
		for (X509Certificate certificate : chain.certificates()) {
			certificate.checkValidity(currentDate);
		}
	}
}