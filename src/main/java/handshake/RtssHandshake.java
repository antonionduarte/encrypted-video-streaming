package handshake;

import config.CipherConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.key_agreement.KeyAgreementExecutor;
import handshake.exceptions.AuthenticationException;
import handshake.exceptions.NoCiphersuiteException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class RtssHandshake {
	public static final String KEY_AGREEMENT = "DH"; // TODO: Replace this with something taken from a CipherSuite object

	private final InetSocketAddress selfAddress;
	private final KeyAgreementExecutor keyAgreementExecutor;
	private final CertificateChain certificateChain;
	private CipherConfig chosenCiphersuite;
	private byte[] secret;

	public RtssHandshake(InetSocketAddress selfAddress, CertificateChain certificateChain) throws Exception {
		this.certificateChain = certificateChain;
		this.selfAddress = selfAddress;
		var numSize = 2048; //TODO: read from assymetric config
		this.keyAgreementExecutor = new KeyAgreementExecutor(KEY_AGREEMENT, numSize);
	}

	public void start(InetSocketAddress targetAddress) throws AuthenticationException {
		try (var clientSocket = new Socket(selfAddress.getAddress().getHostAddress(), selfAddress.getPort())) {
			clientSocket.connect(targetAddress);
			var firstMessage = generateFirstMessage();
			clientSocket.getOutputStream().write(firstMessage);
			waitServer();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public InetSocketAddress waitClient() throws AuthenticationException, NoCiphersuiteException {
		Socket clientSocket;
		try (var serverSocket = new ServerSocket(selfAddress.getPort())) {
			clientSocket = serverSocket.accept();
			var secondMessage = generateSecondMessage();
			//TODO ...
			PublicKey remotePubNum = null; //TODO get from second message
			this.secret = keyAgreementExecutor.generateSecret(remotePubNum);
			clientSocket.getOutputStream().write(secondMessage);
		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
		return new InetSocketAddress(clientSocket.getInetAddress(), clientSocket.getPort());
	}

	public byte[] getSecret() {
		return secret;
	}

	private void waitServer() throws AuthenticationException {

		//TODO
	}

	private byte[] generateFirstMessage() {
		// ==================================A==================================
		// Yb || G || p || cs_list || KpubBox || Sig_KprivBox(box.chain || time) || HMAC_KMac(A)
		// ?
		return null; //TODO
	}

	private byte[] generateSecondMessage() {
		// ==============================B================================
		// Ys || cs || KpubServer || Sig_KprivServer(server.chain || time) || HMAC_KMac(B)
		// ?
		return null; //TODO
	}
}
