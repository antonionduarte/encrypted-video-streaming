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
		CertPathValidator certPathValidator = CertPathValidator.getInstance(CertificateChain.STORE_TYPE);
		CertificateFactory certificateFactory = CertificateFactory.getInstance(CertificateChain.CERT_TYPE);
		CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(chain.certificates()));
		PKIXBuilderParameters params = new PKIXBuilderParameters(trustStore, new X509CertSelector());
		params.setRevocationEnabled(true);

		certPathValidator.validate(certPath, params);
		checkDateValidity(chain);
	}

	private void checkDateValidity(CertificateChain chain) throws CertificateNotYetValidException, CertificateExpiredException {
		Date currentDate = new Date();
		for (X509Certificate certificate : chain.certificates()) {
			certificate.checkValidity(currentDate);
		}
	}
}