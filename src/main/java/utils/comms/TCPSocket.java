package utils.comms;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

public class TCPSocket implements Closeable {
	private Socket socket;
	private InputStream inputStream;
	private OutputStream outputStream;


	// Connect to a remote host. Returns the socket used in the connection.
	public InetSocketAddress connect(InetSocketAddress address) throws IOException {
		System.out.println("Connecting to " + address);
		socket = new Socket();
		socket.connect(address);
		inputStream = socket.getInputStream();
		outputStream = socket.getOutputStream();

		return (InetSocketAddress) socket.getLocalSocketAddress();
	}

	// Send a message to the remote host
	public void sendMessage(byte[] message) throws IOException {
		System.out.println("Sending Message size = " + message.length);

		var buffer = ByteBuffer.allocate(4 + message.length)
				.putInt(message.length).put(message);
		outputStream.write(buffer.array());
		outputStream.flush();
	}

	// Receive a message from the remote host
	public byte[] receiveMessage() throws IOException {
		System.out.println("Waiting for message");

		byte[] sizeBytes = new byte[4];
		inputStream.read(sizeBytes);
		int size = ByteBuffer.wrap(sizeBytes).getInt();

		byte[] message = new byte[size];
		inputStream.read(message);

		System.out.println("Received Message size = " + size);
		return message;
	}

	// Wait for a connection from a remote host
	public InetSocketAddress waitConnection(int port) throws IOException {
		System.out.println("Waiting for connection in port " + port);
		try (ServerSocket serverSocket = new ServerSocket(port)) {
			socket = serverSocket.accept();
			inputStream = socket.getInputStream();
			outputStream = socket.getOutputStream();
			System.out.println("Client connected: " + socket.getRemoteSocketAddress());
			return (InetSocketAddress) socket.getRemoteSocketAddress();
		}
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}
}