package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateChain {
	private final X509Certificate certificate;
	private final X509Certificate rootCertificate;

	public CertificateChain(X509Certificate certificate, X509Certificate rootCertificate) {
		this.certificate = certificate;
		this.rootCertificate = rootCertificate;
	}

	/**
	 * Returns a certificate chain from a byte[].
	 * Format of the byte[] should be something such as:
	 * sizeof(certificate) || certificate || sizeof(root_certificate) || root_certificate
	 */
	public CertificateChain(byte[] certificateChain) throws IOException, CertificateException {
		var stream = new ByteArrayInputStream(certificateChain);
		
		var certificateSize = stream.read();
		var certificateBytes = stream.readNBytes(certificateSize);

		var rootCertificateSize = stream.read();
		var rootCertificateBytes = stream.readNBytes(rootCertificateSize);

		this.certificate = CertificateTool.certificateFromBytes(certificateBytes);
		this.rootCertificate = CertificateTool.certificateFromBytes(rootCertificateBytes);
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
