package handshake;

import cryptotools.certificates.CertificateChain;
import cryptotools.key_agreement.SecretGenerator;
import handshake.exceptions.AuthenticationException;
import handshake.exceptions.NoCiphersuiteException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class RtssHandshake {
	public static final String KEY_AGREEMENT = "DH"; // TODO: Replace this with something taken from a CipherSuite object

	private final InetSocketAddress selfAddress;
	private final SecretGenerator secretGenerator;
	private final CertificateChain certificateChain;
	private byte[] secret;

	public RtssHandshake(InetSocketAddress selfAddress, CertificateChain certificateChain) throws Exception {
		var keyPair = SecretGenerator.generateKeyPair(KEY_AGREEMENT, 2048);
		this.certificateChain = certificateChain;
		this.selfAddress = selfAddress;
		this.secretGenerator = new SecretGenerator(KEY_AGREEMENT, keyPair);
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
		try (var serverSocket = new ServerSocket(selfAddress.getPort())) {
			var clientSocket = serverSocket.accept();
			//TODO
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return null;
	}

	public byte[] getSecret() {
		return secret;
	}

	private void waitServer() throws AuthenticationException {
		//TODO
	}

	private byte[] generateFirstMessage() {
		// dh_parameters (pubkey) ||
		return null; //TODO
	}
}
