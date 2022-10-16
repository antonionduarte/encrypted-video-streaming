package securesocket;

import config.parser.CipherConfig;

import java.net.InetSocketAddress;

public class SecureDatagramPacket {

	private byte[] buffer;
	private final InetSocketAddress address;

	/**
	 * New SecureDatagramPacket, to be used by the SecureSocket.
	 * It correctly formats the contents in the buffer that are going to be sent through the Socket, according
	 * to the received cipherConfig.
	 * The DatagramPacket is directly encapsulated in this class because it needs a seqNumber which is going
	 * to be controlled by the SecureSocket.
	 * @param buffer The bytes to be sent.
	 * @param length The length of the buffer.
	 * @param address The address to be sent.
	 * @param cipherConfig The cipherConfig to be used to correctly encrypt the buffer.
	 */
	public SecureDatagramPacket(byte[] buffer, int length, InetSocketAddress address, CipherConfig cipherConfig) {
		this.address = address;
		// TODO...
	}

	public byte[] getBuffer() {
		return buffer;
	}

	public InetSocketAddress getAddress() {
		return address;
	}
}
