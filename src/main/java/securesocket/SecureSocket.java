package securesocket;

import cryptotools.CryptoException;
import cryptotools.EncryptionTool;
import cryptotools.IntegrityException;
import cryptotools.IntegrityTool;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.HashSet;
import java.util.Set;

public class SecureSocket implements Closeable {

	private final DatagramSocket datagramSocket;
	private final SocketAddress socketAddress;
	private final Set<Integer> receivedNonces;

	public SecureSocket(SocketAddress socketAddress) throws SocketException {
		this.datagramSocket = new DatagramSocket();
		this.receivedNonces = new HashSet<>();
		this.socketAddress = socketAddress;
	}

	public void send(SecureDatagramPacket secureDatagramPacket) throws IOException {
		secureDatagramPacket.encryptData();
		datagramSocket.send(secureDatagramPacket.toDatagramPacket());
	}

	public void receive(SecureDatagramPacket secureDatagramPacket) throws IOException, IntegrityException, CryptoException {
		var buffer = new byte[1024 * 4];
		var inPacket = new DatagramPacket(buffer, buffer.length);
		datagramSocket.receive(inPacket);

		var inputStream = new ByteArrayInputStream(secureDatagramPacket.getData());
		var size = new BigInteger(inputStream.readNBytes(4)).intValue();
		var cipherText = inputStream.readNBytes(size);
		var integrity = inputStream.readAllBytes();
		var cipherConfig = secureDatagramPacket.getCipherConfig();

		byte[] plainText = null;
		var isVerified = true;

		// Check integrity
		if (cipherConfig.getMackey() != null) {
			isVerified = IntegrityTool.checkIntegrity(cipherConfig, cipherText, integrity);
		} else if (cipherConfig.getIntegrity() != null) {
			plainText = EncryptionTool.decrypt(cipherConfig, cipherText);
			isVerified = IntegrityTool.checkIntegrity(cipherConfig, plainText, integrity);
		}
		if (plainText == null) {
			plainText = EncryptionTool.decrypt(cipherConfig, cipherText);
		}

		if (!isVerified) {
			throw new IntegrityException();
		}

		// Check nonce
		inputStream = new ByteArrayInputStream(plainText);
		var nonce = new BigInteger(inputStream.readNBytes(4)).intValue();
		if (receivedNonces.contains(nonce)) {
			throw new IntegrityException();
		}

		receivedNonces.add(nonce);
		secureDatagramPacket.setData(inputStream.readAllBytes());
	}

	@Override
	public void close() throws IOException {
		datagramSocket.close();
	}
}
