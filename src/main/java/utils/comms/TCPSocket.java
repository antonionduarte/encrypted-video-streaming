package utils.comms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class TCPSocket {
	private Socket socket;
	private InputStream inputStream;
	private OutputStream outputStream;

	// Connect to a remote host
	public void connect(InetSocketAddress address) throws IOException {
		socket = new Socket();
		socket.connect(address);
		inputStream = socket.getInputStream();
		outputStream = socket.getOutputStream();
	}

	// Send a message to the remote host
	public void sendMessage(byte[] message) throws IOException {
		outputStream.write(message);
		outputStream.flush();
	}

	// Receive a message from the remote host
	public byte[] receiveMessage() throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byteArrayOutputStream.write(buffer, 0, bytesRead);
		}
		return byteArrayOutputStream.toByteArray();
	}

	// Wait for a connection from a remote host
	public InetSocketAddress waitConnection(int port) throws IOException {
		try (ServerSocket serverSocket = new ServerSocket(port)) {
			socket = serverSocket.accept();
			inputStream = socket.getInputStream();
			outputStream = socket.getOutputStream();
			return (InetSocketAddress) socket.getRemoteSocketAddress();
		}
	}
}