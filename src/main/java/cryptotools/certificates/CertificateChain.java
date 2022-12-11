package cryptotools.certificates;

import java.security.cert.X509Certificate;

public class CertificateChain {
	private final X509Certificate certificate;
	private final X509Certificate rootCertificate;

	public CertificateChain(X509Certificate certificate, X509Certificate rootCertificate) {
		this.certificate = certificate;
		this.rootCertificate = rootCertificate;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public X509Certificate getRootCertificate() {
		return rootCertificate;
	}

	public byte[] getSerializedChain() {
		return null; // TODO: Implement
	}
}
