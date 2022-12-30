package protocols.rtss.handshake;

import config.AsymmetricConfig;
import config.CipherConfig;
import config.HandshakeIntegrityConfig;
import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.certificates.CertificateVerifier;
import cryptotools.integrity.IntegrityException;
import cryptotools.key_agreement.KeyAgreementExecutor;
import cryptotools.repetition.exceptions.RepeatedMessageException;
import cryptotools.signatures.SignatureTool;
import protocols.rtss.RtssProtocol;
import protocols.rtss.handshake.exceptions.AuthenticationException;
import protocols.rtss.handshake.exceptions.NoCiphersuiteMatchException;
import protocols.rtss.handshake.messages.FirstMessage;
import protocols.rtss.handshake.messages.SecondMessage;
import server.StreamServer;
import utils.Loader;
import utils.Utils;
import utils.comms.TCPSocket;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class RtssHandshake implements Closeable {
	public static class RtssHandshakeBuilder {
		private CertificateChain certificateChain;
		private List<AsymmetricConfig> asymmetricConfigList;
		private List<SymmetricConfig> symmetricConfigList;
		private KeyPair authenticationKeys;
		private HandshakeIntegrityConfig integrityConfig;
		private CertificateVerifier certificateVerifier;

		public RtssHandshakeBuilder setCertificateChain(CertificateChain certificateChain) {
			this.certificateChain = certificateChain;
			return this;
		}

		public RtssHandshakeBuilder setAsymmetricConfigList(List<AsymmetricConfig> asymmetricConfigList) {
			this.asymmetricConfigList = asymmetricConfigList;
			return this;
		}

		public RtssHandshakeBuilder setSymmetricConfigList(List<SymmetricConfig> symmetricConfigList) {
			this.symmetricConfigList = symmetricConfigList;
			return this;
		}

		public RtssHandshakeBuilder setAuthenticationKeys(KeyPair authenticationKeys) {
			this.authenticationKeys = authenticationKeys;
			return this;
		}

		public RtssHandshakeBuilder setIntegrityConfig(HandshakeIntegrityConfig integrityConfig) {
			this.integrityConfig = integrityConfig;
			return this;
		}

		public RtssHandshakeBuilder setCertificateVerifier(CertificateVerifier certificateVerifier) {
			this.certificateVerifier = certificateVerifier;
			return this;
		}

		public RtssHandshake build() {
			return new RtssHandshake(certificateChain, asymmetricConfigList, symmetricConfigList, authenticationKeys, integrityConfig, certificateVerifier);
		}
	}

	private final List<AsymmetricConfig> asymmetricConfigList;
	private final List<SymmetricConfig> symmetricConfigList;
	private final HandshakeIntegrityConfig integrityConfig;
	private final CertificateVerifier certificateVerifier;
	private final TCPSocket socket;

	private KeyPair authenticationKeys;
	private CertificateChain certificateChain;
	private KeyAgreementExecutor keyAgreementExecutor;
	private CipherConfig decidedCipherSuite;

	private RtssHandshake(CertificateChain certificateChain, List<AsymmetricConfig> asymmetricConfigList, List<SymmetricConfig> symmetricConfigList, KeyPair authenticationKeys, HandshakeIntegrityConfig integrityConfig, CertificateVerifier certificateVerifier) {
		this.certificateChain = certificateChain;
		this.asymmetricConfigList = asymmetricConfigList;
		this.symmetricConfigList = symmetricConfigList;
		this.authenticationKeys = authenticationKeys;
		this.integrityConfig = integrityConfig;
		this.certificateVerifier = certificateVerifier;
		this.socket = new TCPSocket();
	}

	/**
	 * Start handshake and send first message.
	 *
	 * @param targetAddress server address.
	 */
	public InetSocketAddress start(InetSocketAddress targetAddress) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, RepeatedMessageException, CertPathValidatorException, InvalidAlgorithmParameterException, IntegrityException, CertificateException, KeyStoreException, InvalidKeySpecException, AuthenticationException {
		var clientAddress = socket.connect(targetAddress);

		// choose first one
		var chosenAsymmetricConfig = asymmetricConfigList.get(0);
		this.keyAgreementExecutor = new KeyAgreementExecutor(chosenAsymmetricConfig);

		var pubNumBytes = keyAgreementExecutor.getPublicNum().getEncoded();
		byte[] signature = SignatureTool.createSignature(chosenAsymmetricConfig, authenticationKeys.getPrivate(), pubNumBytes);

		var firstMessage = new FirstMessage(chosenAsymmetricConfig, symmetricConfigList, certificateChain, pubNumBytes, signature);
		socket.sendMessage(firstMessage.serialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey()));

		waitServer();

		return clientAddress;
	}

	/**
	 * Wait client connection in given port and send second message.
	 *
	 * @param port to listen.
	 * @return InetSocketAddress of connecting client.
	 */
	public InetSocketAddress waitClientConnection(int port) throws IntegrityException, IOException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, KeyStoreException, CertPathValidatorException, InvalidAlgorithmParameterException, RepeatedMessageException, NoCiphersuiteMatchException, InvalidKeySpecException, SignatureException, AuthenticationException {
		var clientSocket = socket.waitConnection(port);
		var firstMessageBytes = socket.receiveMessage();

		// integrity and repetition is checked in this deserialization
		var firstMessage = FirstMessage.deserialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey(), firstMessageBytes);
		var asymmetricConfig = Utils.firstIntersection(List.of(firstMessage.asymConfig()), asymmetricConfigList);
		var symmetricConfig = Utils.firstIntersection(firstMessage.symConfigList(), symmetricConfigList);
		if (asymmetricConfig == null || symmetricConfig == null) {
			throw new NoCiphersuiteMatchException();
		}

		var alias = String.format(StreamServer.ALIAS_MASK, asymmetricConfig.getAuthentication(), asymmetricConfig.getKeySize());
		this.authenticationKeys = Loader.readKeyPair(StreamServer.KEYSTORE_PATH, alias, System.getenv(StreamServer.KEYSTORE_PASSWORD_ENV));
		var path = String.format(StreamServer.CERTIFICATE_PATH_MASK, asymmetricConfig.getAuthentication(), asymmetricConfig.getKeySize());
		var caAlias = String.format(StreamServer.CA_ALIAS_MASK, asymmetricConfig.getAuthentication(), asymmetricConfig.getKeySize());
		this.certificateChain = Loader.readCertificates(path, certificateVerifier.trustStore(), caAlias);

		certificateVerifier.verifyCertificateChain(asymmetricConfig.getAuthentication(), firstMessage.certChain());

		SignatureTool.verifySignature(asymmetricConfig, firstMessage.certChain().leafCertificate().getPublicKey(), firstMessage.pubNumBytes(), firstMessage.signature());

		this.keyAgreementExecutor = new KeyAgreementExecutor(asymmetricConfig);
		var clientPubNum = KeyAgreementExecutor.getPubicNum(asymmetricConfig.getKeyExchange(), firstMessage.pubNumBytes());
		var secret = keyAgreementExecutor.generateSecret(clientPubNum);
		this.decidedCipherSuite = new CipherConfig(symmetricConfig, secret);

		var pubNumBytes = keyAgreementExecutor.getPublicNum().getEncoded();
		byte[] signature = SignatureTool.createSignature(asymmetricConfig, authenticationKeys.getPrivate(), pubNumBytes);
		var secondMessage = new SecondMessage(symmetricConfig, this.certificateChain, pubNumBytes, signature);
		socket.sendMessage(secondMessage.serialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey()));

		return clientSocket;
	}


	/**
	 * Wait for handshake's second message.
	 */
	private void waitServer() throws IOException, RepeatedMessageException, IntegrityException, NoSuchAlgorithmException, InvalidKeyException, CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException, KeyStoreException, InvalidKeySpecException, AuthenticationException, SignatureException {
		var secondMessageBytes = socket.receiveMessage();

		// integrity and repetition is checked in this deserialization
		var secondMessage = SecondMessage.deserialize(integrityConfig.getAlgorithm(), integrityConfig.getMacKey(), secondMessageBytes);

		// verify certificate chain

		var asymmetricConfig = asymmetricConfigList.get(0);

		certificateVerifier.verifyCertificateChain(asymmetricConfig.getAuthentication(), secondMessage.certChain());

		SignatureTool.verifySignature(asymmetricConfig, secondMessage.certChain().leafCertificate().getPublicKey(), secondMessage.pubNumBytes(), secondMessage.signature());

		var serverPubNum = KeyAgreementExecutor.getPubicNum(asymmetricConfig.getKeyExchange(), secondMessage.pubNumBytes());
		var secret = keyAgreementExecutor.generateSecret(serverPubNum);
		this.decidedCipherSuite = new CipherConfig(secondMessage.symConfig(), secret);
	}

	public CipherConfig getDecidedCipherSuite() {
		return decidedCipherSuite;
	}

	/**
	 * Send movie request.
	 *
	 * @param movie name to request.
	 */
	public void requestMovie(String movie) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
		var movieBytes = new RtssProtocol(decidedCipherSuite).encrypt(movie.getBytes(StandardCharsets.UTF_8));
		socket.sendMessage(movieBytes);
	}

	/**
	 * Wait for movie request.
	 *
	 * @return name of movie client requests.
	 */
	public String waitClientMovieRequest() throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, RepeatedMessageException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		var message = socket.receiveMessage();
		var movieBytes = new RtssProtocol(decidedCipherSuite).decrypt(message);
		return new String(movieBytes, StandardCharsets.UTF_8);
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}
}
