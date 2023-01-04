package securesocket;

import cryptotools.integrity.IntegrityException;
import protocols.SecureProtocol;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SecureDatagramPacket {

	private final SecureProtocol protocol;
	private byte[] data;
	private InetSocketAddress address;

	/**
	 * New SecureDatagramPacket, to be used by the SecureSocket. It correctly formats the contents in the buffer that
	 * are going to be sent through the Socket, according to the received protocol. The DatagramPacket is directly
	 * encapsulated in this class because it needs a seqNumber which is going to be controlled by the SecureSocket.
	 *
	 * @param data         The bytes to be sent.
	 * @param address      The address to be sent.
	 * @param protocol     The protocol being used to encrypt/decrypt this packet.
	 */
	public SecureDatagramPacket(byte[] data, InetSocketAddress address, SecureProtocol protocol) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IntegrityException {
		this.address = address;
		this.protocol = protocol;
		this.encryptData(data);
	}

	public SecureDatagramPacket(SecureProtocol protocol) {
		this.protocol = protocol;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public SecureProtocol getProtocol() {
		return protocol;
	}

	public void encryptData(byte[] plainText) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IntegrityException {
		this.data = protocol.encrypt(plainText);
	}

	public DatagramPacket toDatagramPacket() {
		return new DatagramPacket(data, data.length, address);
	}
}
