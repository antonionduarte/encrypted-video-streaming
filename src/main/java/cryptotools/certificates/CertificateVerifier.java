package cryptotools.certificates;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateVerifier {
	private static final String TRUSTSTORE_TYPE = "PKCS12";

	private final KeyStore trustStore;

	public CertificateVerifier(KeyStore trustStore) {
		this.trustStore = trustStore;
	}

	public void verify(X509Certificate[] chain) throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TRUSTSTORE_TYPE);
		trustManagerFactory.init(trustStore);
		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		for (TrustManager trustManager : trustManagers) {
			if (trustManager instanceof X509TrustManager) {
				((X509TrustManager) trustManager).checkServerTrusted(chain, "RSA"); // TODO: Make authType configurable?
				return; //TODO: I also don't know if this verifies the certificate itself, probably not.
			}
		}
		throw new CertificateException("No X509TrustManager found in TrustManagerFactory");
	}
}