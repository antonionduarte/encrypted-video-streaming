package cryptotools.certificates;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Represents a certificate chain.
 * <p>
 * Serialized format: [length][size_cert1][cert1][size_cert2][cert2]...[size_certN][certN]
 */
public class CertificateChain {
	private static final String CERTIFICATE_TYPE = "X.509";

	private final X509Certificate[] chain;

	public CertificateChain(X509Certificate[] chain) {
		this.chain = chain;
	}

	public X509Certificate[] getChain() {
		return chain;
	}

	/**
	 * Returns a certificate chain from a byte[]. Format of the byte[] should be something such as:
	 * [length][size_cert1][cert1][size_cert2][cert2]...[size_certN][certN]
	 */
	public CertificateChain(byte[] certificateChain) throws IOException, CertificateException {
		var stream = new ByteArrayInputStream(certificateChain);

		var length = stream.read();
		var certificates = new X509Certificate[length];

		for (int i = 0; i < length; i++) {
			var size = stream.read();
			var certificate = stream.readNBytes(size);
			certificates[i] = (X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).generateCertificate(new ByteArrayInputStream(certificate));
		}

		this.chain = certificates;
	}

	/**
	 * Returns a byte[] representation of the certificate chain.
	 * Serialized format: [length][size_cert1][cert1][size_cert2][cert2]...[size_certN][certN]
	 */
	public byte[] getSerializedChain() throws CertificateEncodingException {
		var stream = new ByteArrayOutputStream();
		stream.write(chain.length);

		for (X509Certificate certificate : chain) {
			var certificateBytes = certificate.getEncoded();
			stream.write(certificateBytes.length);
			stream.write(certificateBytes, 0, certificateBytes.length);
		}

		return stream.toByteArray();
	}
}
