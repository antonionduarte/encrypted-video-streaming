package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
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

	public byte[] getSerializedChain() throws CertificateEncodingException {
		var certificateBytes = certificate.getEncoded();
		var certificateSize = certificateBytes.length;

		var rootCertificateBytes = rootCertificate.getEncoded();
		var rootCertificateSize = rootCertificateBytes.length;

		var stream = new ByteArrayOutputStream();
		stream.write(certificateSize);
		stream.write(certificateBytes, 0, certificateSize);
		stream.write(rootCertificateSize);
		stream.write(rootCertificateBytes, 0, rootCertificateSize);

		return stream.toByteArray();
	}
}
