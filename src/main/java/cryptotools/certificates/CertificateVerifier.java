package cryptotools.certificates;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Date;

public class CertificateVerifier {

	private final KeyStore trustStore;

	public CertificateVerifier(KeyStore trustStore) {
		this.trustStore = trustStore;
	}

	/**
	 * Verify the validity of a certificate chain
	 *
	 * @param chain certificate chain to verify
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public void verifyCertificateChain(CertificateChain chain) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, CertPathValidatorException, InvalidAlgorithmParameterException {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(chain.certificates()));
		PKIXParameters params = new PKIXParameters(trustStore);
		params.setRevocationEnabled(true);
		CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");

		certPathValidator.validate(certPath, params);
		checkRootCertificate(chain.rootCertificate());
		checkDateValidity(chain);
	}

	private void checkRootCertificate(X509Certificate rootCertificate) throws KeyStoreException, CertificateException {
		String rootAlias = trustStore.getCertificateAlias(rootCertificate);
		if (rootAlias == null) {
			throw new CertificateException("Root certificate is not trusted");
		}
	}

	private void checkDateValidity(CertificateChain chain) throws CertificateNotYetValidException, CertificateExpiredException {
		Date currentDate = new Date();
		for (X509Certificate certificate : chain.certificates()) {
			certificate.checkValidity(currentDate);
		}
	}
}