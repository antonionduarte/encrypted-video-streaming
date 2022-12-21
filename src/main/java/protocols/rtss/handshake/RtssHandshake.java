package protocols.rtss.handshake;

import comms.TCPSocket;
import config.*;
import cryptotools.certificates.CertificateChain;
import cryptotools.certificates.CertificateVerifier;
import cryptotools.integrity.IntegrityException;
import cryptotools.key_agreement.KeyAgreementExecutor;
import cryptotools.repetition.exceptions.RepeatedMessageException;
import cryptotools.signatures.SignaturesTool;
import protocols.rtss.handshake.exceptions.AuthenticationException;
import protocols.rtss.handshake.exceptions.NoCiphersuiteMatchException;
import protocols.rtss.handshake.messages.FirstMessage;
import protocols.rtss.handshake.messages.SecondMessage;
import utils.Utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class RtssHandshake {
	private final CertificateChain certificateChain;
	private final List<AsymmetricConfig> asymmetricConfigList;
	private final List<SymmetricConfig> symmetricConfigList;
	private final KeyPair authenticationKeys;
	private final HandshakeIntegrityConfig integrityConfig;
	private final CertificateVerifier certVerifier;

	private final TCPSocket socket;
	private KeyAgreementExecutor keyAgreementExecutor;

	public CipherConfig decidedCipherSuite;

	RtssHandshake(CertificateChain certificateChain, List<AsymmetricConfig> asymmetricConfigList,
	                     List<SymmetricConfig> symmetricConfigList, KeyPair authenticationKeys,
	                     HandshakeIntegrityConfig integrityConfig, CertificateVerifier certVerifier) {
		this.certificateChain = certificateChain;
		this.asymmetricConfigList = asymmetricConfigList;
		this.symmetricConfigList = symmetricConfigList;
		this.authenticationKeys = authenticationKeys;
		this.integrityConfig = integrityConfig;
		this.certVerifier = certVerifier;

		this.socket = new TCPSocket();
	}

	RtssHandshake(CertificateChain certificateChain, AsymmetricConfig asymmetricConfig,
						 List<SymmetricConfig> symmetricConfigList, KeyPair authenticationKeys,
						 HandshakeIntegrityConfig integrityConfig, CertificateVerifier certVerifier) {
		this(certificateChain, List.of(asymmetricConfig), symmetricConfigList, authenticationKeys, integrityConfig, certVerifier);
	}

	/**
	 * Start handshake and send first message
	 *
	 * @param targetAddress server address
	 */
	public void start(InetSocketAddress targetAddress) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, RepeatedMessageException, CertPathValidatorException, InvalidAlgorithmParameterException, IntegrityException, CertificateException, KeyStoreException, InvalidKeySpecException, AuthenticationException {
		socket.connect(targetAddress);

		// choose first one
		var chosenAsymConfig = asymmetricConfigList.get(0);
		this.keyAgreementExecutor = new KeyAgreementExecutor(chosenAsymConfig);

		var pubNumBytes = keyAgreementExecutor.getPublicNum().getEncoded();
		byte[] signature = SignaturesTool.createSignature(chosenAsymConfig, authenticationKeys.getPrivate(), pubNumBytes);

		var firstMessage = new FirstMessage(chosenAsymConfig, symmetricConfigList, certificateChain, pubNumBytes, signature);
		socket.sendMessage(firstMessage.serialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey()));

		waitServer();
	}

	/**
	 * Wait client connection in given port and send second message.
	 *
	 * @param port to listen
	 * @return InetSocketAddress of connecting client
	 */
	public InetSocketAddress waitClientConnection(int port) throws IntegrityException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, KeyStoreException, CertPathValidatorException, InvalidAlgorithmParameterException, RepeatedMessageException, NoCiphersuiteMatchException, InvalidKeySpecException, SignatureException, AuthenticationException {
		var clientSocket = socket.waitConnection(port);
		var firstMessageBytes = socket.receiveMessage();

		// integrity and repetition is checked in this deserialization
		var firstMessage = FirstMessage.deserialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey(), firstMessageBytes);

		// choose configs
		var asymConfig = Utils.firstIntersection(List.of(firstMessage.asymConfig()), asymmetricConfigList);
		var symConfig = Utils.firstIntersection(firstMessage.symConfigList(), symmetricConfigList);
		if (asymConfig == null || symConfig == null) throw new NoCiphersuiteMatchException();

		certVerifier.verifyCertificateChain(firstMessage.certChain());

		SignaturesTool.verifySignature(
				asymConfig,
				firstMessage.certChain().leafCertificate().getPublicKey(),
				firstMessage.pubNumBytes(),
				firstMessage.signature());

		this.keyAgreementExecutor = new KeyAgreementExecutor(asymConfig);
		var clientPubNum = KeyAgreementExecutor.getPubicNum(asymConfig.getKeyExchange(), firstMessage.pubNumBytes());
		var secret = keyAgreementExecutor.generateSecret(clientPubNum);
		this.decidedCipherSuite = new CipherConfig(symConfig, secret);

		var pubNumBytes = keyAgreementExecutor.getPublicNum().getEncoded();
		byte[] signature = SignaturesTool.createSignature(
				asymConfig,
				authenticationKeys.getPrivate(),
				pubNumBytes
		);
		var secondMessage = new SecondMessage(symConfig, this.certificateChain, pubNumBytes, signature);
		socket.sendMessage(secondMessage.serialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey()));

		return clientSocket;
	}


	/**
	 * Wait for handshake's second message
	 */
	private void waitServer() throws IOException, RepeatedMessageException, IntegrityException, NoSuchAlgorithmException, InvalidKeyException, CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException, KeyStoreException, InvalidKeySpecException, AuthenticationException, SignatureException {
		var secondMessageBytes = socket.receiveMessage();

		// integrity and repetition is checked in this deserialization
		var secondMessage = SecondMessage.deserialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey(), secondMessageBytes);

		// verify certificate chain
		certVerifier.verifyCertificateChain(secondMessage.certChain());

		var asymConfig = asymmetricConfigList.get(0);

		SignaturesTool.verifySignature(
				asymConfig,
				secondMessage.certChain().leafCertificate().getPublicKey(),
				secondMessage.pubNumBytes(),
				secondMessage.signature());

		var serverPubNum = KeyAgreementExecutor.getPubicNum(asymConfig.getKeyExchange(), secondMessage.pubNumBytes());
		var secret = keyAgreementExecutor.generateSecret(serverPubNum);
		this.decidedCipherSuite = new CipherConfig(secondMessage.symConfig(), secret);
	}

	/**
	 * Send movie request.
	 *
	 * @param movie name to request
«	 */
	public void requestMovie(String movie) {

	}

	/**
	 * Wait for movie request.
	 *
	 * @return name of movie client requests
	 */
	public String waitClientMovieRequest() {
		return null;
	}
}
