package securesocket;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;

public class SecureSocket implements Closeable {

	private final DatagramSocket datagramSocket;
	private long seqNumber;

	public SecureSocket() throws SocketException {
		this.datagramSocket = new DatagramSocket();
	}

	public void send(SecureDatagramPacket secureDatagramPacket) throws IOException {
		secureDatagramPacket.encryptData();
		//TODO: Integrity
		datagramSocket.send(secureDatagramPacket.toDatagramPacket());
	}

	public void receive(SecureDatagramPacket secureDatagramPacket) throws IOException {
		// TODO: Check for the necessary integrity checks, decrypt the contents of the buffer
		ByteArrayInputStream inputStream = new ByteArrayInputStream(secureDatagramPacket.getData());
		var nonce = new BigInteger(inputStream.readNBytes(4)).intValue();


		// and if the integrity checks aren't met, maybe throw an Exception that the server must handle(?)
	}

	@Override
	public void close() throws IOException {
		datagramSocket.close();
	}
}
