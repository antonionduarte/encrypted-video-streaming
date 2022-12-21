package handshake;

import comms.TCPSocket;
import config.AsymmetricConfig;
import config.CipherConfig;
import config.HandshakeIntegrityConfig;
import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.certificates.CertificateVerifier;
import cryptotools.integrity.IntegrityException;
import cryptotools.key_agreement.KeyAgreementExecutor;
import cryptotools.signatures.SignaturesTool;
import handshake.exceptions.AuthenticationException;
import handshake.messages.FirstMessage;
import handshake.messages.SecondMessage;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

public class RtssHandshake {
	private final CertificateChain certificateChain;
	private final AsymmetricConfig asymConfig;
	private final List<SymmetricConfig> symConfigList;
	private final KeyPair authenticationKeys;
	private final HandshakeIntegrityConfig integrityConfig;
	private final CertificateVerifier certVerifier;
	private final KeyAgreementExecutor keyAgreementExecutor;

	public CipherConfig decidedCipherSuite;

	public RtssHandshake(CertificateChain certificateChain, AsymmetricConfig asymConfig,
						 List<SymmetricConfig> symConfigList, KeyPair authenticationKeys,
						 HandshakeIntegrityConfig integrityConfig, CertificateVerifier certVerifier) {
		this.certificateChain = certificateChain;
		this.asymConfig = asymConfig;
		this.symConfigList = symConfigList;
		this.authenticationKeys = authenticationKeys;
		this.integrityConfig = integrityConfig;
		this.certVerifier = certVerifier;

		this.keyAgreementExecutor = new KeyAgreementExecutor(asymConfig);
	}

	/**
	 * Start handshake and send first message
	 *
	 * @param targetAddress server address
	 * @throws AuthenticationException when authentication fails
	 */
	public void start(InetSocketAddress targetAddress) throws AuthenticationException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		var socket = new TCPSocket();
		socket.connect(targetAddress);
		byte[] signature = SignaturesTool.createSignature(
				asymConfig,
				authenticationKeys.getPrivate(),
				keyAgreementExecutor.getPublicNum().getEncoded());
		var firstMessage = new FirstMessage(asymConfig, symConfigList, certificateChain, signature);
		socket.sendMessage(firstMessage.encode(integrityConfig.algorithm, integrityConfig.macKey));
		waitServer();
	}

	/**
	 * Wait client connection in given port and send it second message.
	 *
	 * @param port to listen
	 * @return InetSocketAddress of connecting client
	 */
	public InetSocketAddress waitClientConnection(int port)
			throws IntegrityException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, KeyStoreException {
		var socket = new TCPSocket();
		var clientSocket = socket.waitConnection(port);
		var firstMessageBytes = socket.waitMessage();
		var firstMessage = FirstMessage.decode(integrityConfig.algorithm, integrityConfig.macKey, firstMessageBytes);
		//TODO ...
		certVerifier.verifyCertificateChain(firstMessage.asymConfig, firstMessage.certChain);

		var secondMessage = new SecondMessage();
		//TODO ...
		PublicKey clientPubNum = null; //TODO get from first message
		var secret = keyAgreementExecutor.generateSecret(clientPubNum);
		this.decidedCipherSuite = new CipherConfig(secondMessage.symConfig, secret);

		return clientSocket;
	}

	/**
	 * Wait for handshake's second message
	 */
	private void waitServer() throws AuthenticationException {
		//TODO
	}

	/**
	 * Wait for handshake's third message
	 *
	 * @return name of movie client requests
	 */
	private String waitClientMovieRequest() {
		//TODO
	}
}
