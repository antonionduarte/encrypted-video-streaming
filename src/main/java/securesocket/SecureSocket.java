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
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

public class SecureSocket implements Closeable {

	private final DatagramSocket datagramSocket;
	private final Set<Integer> receivedNonces;

	public SecureSocket(SocketAddress socketAddress) throws SocketException {
		this.datagramSocket = new DatagramSocket(socketAddress);
		this.receivedNonces = new HashSet<>();
	}

	public void send(SecureDatagramPacket secureDatagramPacket) throws IOException {
		datagramSocket.send(secureDatagramPacket.toDatagramPacket());
	}

	public void receive(byte[] buffer, SecureDatagramPacket secureDatagramPacket) throws IOException, IntegrityException, CryptoException {
		var inPacket = new DatagramPacket(buffer, buffer.length);
		datagramSocket.receive(inPacket);

		var inputStream = new ByteArrayInputStream(inPacket.getData());
		var size = ByteBuffer.wrap(inputStream.readNBytes(4)).getInt();
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

		this.receivedNonces.add(nonce);
		secureDatagramPacket.setData(inputStream.readAllBytes());
	}

	@Override
	public void close() {
		datagramSocket.close();
	}
}
