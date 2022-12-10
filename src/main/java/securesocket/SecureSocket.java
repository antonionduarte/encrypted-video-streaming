package securesocket;

import cryptotools.CryptoException;
import cryptotools.encryption.EncryptionTool;
import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
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

		var inputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData(), 0, inPacket.getLength()));
		var size = inputStream.readInt();
		var cipherText = inputStream.readNBytes(size);
		var integrity = inputStream.readAllBytes();
		var cipherConfig = secureDatagramPacket.getCipherConfig();

		var plainText = EncryptionTool.decrypt(cipherConfig, cipherText);
		var verified = true;

		// Check integrity
		if (cipherConfig.getMackey() != null) {
			verified = IntegrityTool.checkIntegrity(cipherConfig, cipherText, integrity);
		} else if (cipherConfig.getIntegrity() != null) {
			verified = IntegrityTool.checkIntegrity(cipherConfig, plainText, integrity);
		}

		if (!verified) {
			throw new IntegrityException();
		}

		// Check nonce
		var nonceInputStream = new DataInputStream(new ByteArrayInputStream(plainText));
		var nonce = nonceInputStream.readInt();
		if (!receivedNonces.add(nonce)) {
			throw new IntegrityException();
		}

		secureDatagramPacket.setData(nonceInputStream.readAllBytes());
	}


	@Override
	public void close() {
		datagramSocket.close();
	}
}
