package handshake;

import config.AsymmetricConfig;
import config.CipherConfig;
import config.HandshakeIntegrityConfig;
import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.key_agreement.KeyAgreementExecutor;
import cryptotools.signatures.SignaturesTool;
import handshake.exceptions.AuthenticationException;
import handshake.exceptions.NoCiphersuiteException;
import handshake.messages.FirstMessage;
import handshake.messages.SecondMessage;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.List;

public class RtssHandshake {
	private final KeyAgreementExecutor keyAgreementExecutor;
	private final CertificateChain certificateChain;
	private final AsymmetricConfig asymConfig;
	private final List<SymmetricConfig> symConfigList;
	private final KeyPair authenticationKeys;
	private final HandshakeIntegrityConfig integrityConfig;

	public CipherConfig decidedCipherSuite;
	public RtssHandshake(CertificateChain certificateChain, AsymmetricConfig asymConfig,
						 List<SymmetricConfig> symConfigList, KeyPair authenticationKeys,
						 HandshakeIntegrityConfig integrityConfig) {
		this.certificateChain = certificateChain;
		this.asymConfig = asymConfig;
		this.symConfigList = symConfigList;
		this.authenticationKeys = authenticationKeys;
		this.integrityConfig = integrityConfig;

		this.keyAgreementExecutor = new KeyAgreementExecutor(asymConfig);
	}

	public void start(InetSocketAddress targetAddress) throws AuthenticationException {
		try (var socket = new Socket(targetAddress.getAddress().getHostAddress(), targetAddress.getPort())) {
			byte[] signature = SignaturesTool.createSignature();
			var firstMessage = new FirstMessage(asymConfig, symConfigList, certificateChain, signature);
			socket.getOutputStream().write(firstMessage.encode(integrityConfig.algorithm, integrityConfig.macKey));
			waitServer();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * (Wait for handshake's first message)
	 */
	public InetSocketAddress waitClientConnection(InetSocketAddress serverAddress) throws AuthenticationException, NoCiphersuiteException {
		try (var serverSocket = new ServerSocket(serverAddress.getPort())) {
			Socket clientSocket = serverSocket.accept();
			var secondMessage = new SecondMessage(...);
			//TODO ...
			PublicKey clientPubNum = null; //TODO get from first message
			var secret = keyAgreementExecutor.generateSecret(clientPubNum);
			this.decidedCipherSuite = new CipherConfig(secondMessage.symConfig, secret);
			clientSocket.getOutputStream().write(secondMessage);
			return new InetSocketAddress(clientSocket.getInetAddress(), clientSocket.getPort());
		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * (Wait for handshake's second message)
	 */
	private void waitServer() throws AuthenticationException {
		//TODO
	}

	/**
	 * (Wait for handshake's third message)
 	 */
	private void waitClientMovieRequest() {
		//TODO
	}
}
