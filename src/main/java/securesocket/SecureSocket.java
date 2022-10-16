package securesocket;

import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;

public class SecureSocket implements Closeable {

	private final DatagramSocket datagramSocket;
	private long seqNumber;

	public SecureSocket() throws SocketException {
		this.datagramSocket = new DatagramSocket();
		this.seqNumber = 0;
	}

	public void send(SecureDatagramPacket secureDatagramPacket) {
		// TODO...
		seqNumber++;
	}

	public void receive(SecureDatagramPacket secureDatagramPacket) {
		// TODO: Check for the necessary integrity checks, decrypt the contents of the buffer
		// and if the integrity checks aren't met, maybe throw an Exception that the server must handle(?)
	}

	@Override
	public void close() throws IOException {
		datagramSocket.close();
	}
}
