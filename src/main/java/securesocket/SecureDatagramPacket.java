package securesocket;

import config.parser.CipherConfig;
import encryptiontool.CryptoException;
import encryptiontool.EncryptionTool;

import java.net.InetSocketAddress;

public class SecureDatagramPacket {

	private byte[] data;
	private final CipherConfig cipherConfig;
	private InetSocketAddress address;

	/**
	 * New SecureDatagramPacket, to be used by the SecureSocket.
	 * It correctly formats the contents in the buffer that are going to be sent through the Socket, according
	 * to the received cipherConfig.
	 * The DatagramPacket is directly encapsulated in this class because it needs a seqNumber which is going
	 * to be controlled by the SecureSocket.
	 * @param data The bytes to be sent.
	 * @param length The length of the buffer.
	 * @param address The address to be sent.
	 * @param cipherConfig The cipherConfig to be used to correctly encrypt the buffer.
	 */
	public SecureDatagramPacket(byte[] data, int length, InetSocketAddress address, CipherConfig cipherConfig) {
		this.address = address;
		this.cipherConfig = cipherConfig;
		this.data = data;

		encryptData();
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public byte[] getData() {
		return data;
	}

	public void setAddress(InetSocketAddress address) {
		this.address = address;
	}

	public InetSocketAddress getAddress() {
		return address;
	}

	//call this before sending?
	public void encryptData() {
		try {
			data = EncryptionTool.encrypt(cipherConfig, data);
		} catch (CryptoException e) {
			throw new RuntimeException(e);
		}
	}

	//call this when receiving?
	public void decryptData() {
		try {
			data = EncryptionTool.decrypt(cipherConfig, data);
		} catch (CryptoException e) {
			throw new RuntimeException(e);
		}
	}
}
