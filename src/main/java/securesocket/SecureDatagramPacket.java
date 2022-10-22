package securesocket;

import config.parser.CipherConfig;
import encryptiontool.CryptoException;
import encryptiontool.EncryptionTool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureDatagramPacket {

	private byte[] data;
	private final CipherConfig cipherConfig;
	private InetSocketAddress address;
	private final SecureRandom random;

	/**
	 * New SecureDatagramPacket, to be used by the SecureSocket.
	 * It correctly formats the contents in the buffer that are going to be sent through the Socket, according
	 * to the received cipherConfig.
	 * The DatagramPacket is directly encapsulated in this class because it needs a seqNumber which is going
	 * to be controlled by the SecureSocket.
	 * @param data The bytes to be sent.
	 * @param address The address to be sent.
	 * @param cipherConfig The cipherConfig to be used to correctly encrypt the buffer.
	 */
	public SecureDatagramPacket(byte[] data, InetSocketAddress address, CipherConfig cipherConfig) throws NoSuchAlgorithmException {
		this.address = address;
		this.cipherConfig = cipherConfig;
		this.data = data ;
		this.random = SecureRandom.getInstanceStrong();
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

	public void encryptData() {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			var nonce = random.nextInt();

			outputStream.write(nonce);
			outputStream.write(data);

			//E(k, nonce || M)
			data = EncryptionTool.encrypt(cipherConfig, outputStream.toByteArray());
		} catch (CryptoException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] decryptData() {
		try {
			return EncryptionTool.decrypt(cipherConfig, data);
		} catch (CryptoException e) {
			throw new RuntimeException(e);
		}
	}

	public DatagramPacket toDatagramPacket() {
		return new DatagramPacket(data, data.length);
	}
}
