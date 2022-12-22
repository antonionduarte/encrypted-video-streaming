package protocols.rtss.handshake;

import config.CipherConfig;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.exceptions.RepeatedMessageException;
import protocols.rtss.handshake.exceptions.AuthenticationException;
import protocols.rtss.handshake.exceptions.NoCiphersuiteMatchException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class RtssHandshakeExecutor {
	public static CipherConfig performHandshakeClient(RtssHandshake handshake, InetSocketAddress serverAddress, String movieName) throws InvalidAlgorithmParameterException, AuthenticationException, IntegrityException, CertificateException, IOException, NoSuchAlgorithmException, SignatureException, KeyStoreException, InvalidKeyException, CertPathValidatorException, RepeatedMessageException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		handshake.start(serverAddress);
		handshake.requestMovie(movieName);
		handshake.close();
		return handshake.getDecidedCipherSuite();
	}

	public static RtssResultServer performHandshakeServer(RtssHandshake handshake, int port) throws InvalidAlgorithmParameterException, NoCiphersuiteMatchException, AuthenticationException, IntegrityException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException, CertPathValidatorException, RepeatedMessageException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		var clientAddress = handshake.waitClientConnection(port);
		var movieName = handshake.waitClientMovieRequest();
		handshake.close();
		return new RtssResultServer(movieName, clientAddress, handshake.getDecidedCipherSuite());
	}
}
