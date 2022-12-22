package securesocket;

import cryptotools.encryption.EncryptionTool;
import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SecureSocket implements Closeable {

	private final DatagramSocket datagramSocket;

	public SecureSocket(SocketAddress socketAddress) throws SocketException {
		this.datagramSocket = new DatagramSocket(socketAddress);
	}

	public void send(SecureDatagramPacket secureDatagramPacket) throws IOException {
		datagramSocket.send(secureDatagramPacket.toDatagramPacket());
	}

	public void receive(byte[] buffer, SecureDatagramPacket secureDatagramPacket) throws IOException, IntegrityException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException {
		var inPacket = new DatagramPacket(buffer, buffer.length);
		datagramSocket.receive(inPacket);

		var cipherText = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
		var plainText = secureDatagramPacket.getProtocol().decrypt(cipherText);

		secureDatagramPacket.setData(plainText);
	}


	@Override
	public void close() {
		datagramSocket.close();
	}
}
