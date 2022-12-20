package handshake;

import config.AsymmetricConfig;
import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.key_agreement.KeyAgreementExecutor;
import cryptotools.signatures.SignaturesTool;
import handshake.exceptions.AuthenticationException;
import handshake.exceptions.NoCiphersuiteException;
import handshake.messages.FirstMessage;
import handshake.messages.SecondMessage;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
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
	private byte[] secret;

	public RtssHandshake(CertificateChain certificateChain, AsymmetricConfig asymConfig,
						 List<SymmetricConfig> symConfigList, KeyPair authenticationKeys) {
		this.certificateChain = certificateChain;
		this.asymConfig = asymConfig;
		this.symConfigList = symConfigList;
		this.keyAgreementExecutor = new KeyAgreementExecutor(asymConfig.authAlg(), asymConfig.numSize());
		this.authenticationKeys = authenticationKeys;
	}

	public void start(InetSocketAddress targetAddress) throws AuthenticationException {
		try (var socket = new Socket(targetAddress.getAddress().getHostAddress(), targetAddress.getPort())) {
			byte[] signature = SignaturesTool.createSignature();
			var firstMessage = new FirstMessage(asymConfig, symConfigList, certificateChain, signature);
			socket.getOutputStream().write(firstMessage.encode("HMAC256", mackey)); //TODO set in shared static config
			waitServer();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public InetSocketAddress waitClient(InetSocketAddress serverAddress) throws AuthenticationException, NoCiphersuiteException {
		Socket clientSocket;
		try (var serverSocket = new ServerSocket(serverAddress.getPort())) {
			clientSocket = serverSocket.accept();
			var secondMessage = new SecondMessage(...);
			//TODO ...
			PublicKey clientPubNum = null; //TODO get from first message
			this.secret = keyAgreementExecutor.generateSecret(clientPubNum);
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

}
