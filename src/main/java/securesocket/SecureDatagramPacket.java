package securesocket;

import config.parser.CipherConfig;
import cryptotools.CryptoException;
import cryptotools.EncryptionTool;
import cryptotools.IntegrityTool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class SecureDatagramPacket {

	private byte[] data;
	private final CipherConfig cipherConfig;
	private InetSocketAddress address;

	/**
	 * New SecureDatagramPacket, to be used by the SecureSocket. It correctly formats the contents in the buffer that
	 * are going to be sent through the Socket, according to the received cipherConfig. The DatagramPacket is directly
	 * encapsulated in this class because it needs a seqNumber which is going to be controlled by the SecureSocket.
	 *
	 * @param data         The bytes to be sent.
	 * @param address      The address to be sent.
	 * @param cipherConfig The cipherConfig to be used to correctly encrypt the buffer.
	 */
	public SecureDatagramPacket(byte[] data, InetSocketAddress address, CipherConfig cipherConfig) throws NoSuchAlgorithmException {
		this.address = address;
		this.cipherConfig = cipherConfig;
		this.encryptData(data);
	}

	public SecureDatagramPacket(CipherConfig cipherConfig) {
		this.cipherConfig = cipherConfig;
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

	public CipherConfig getCipherConfig() {
		return cipherConfig;
	}

	public InetSocketAddress getAddress() {
		return address;
	}

	public void encryptData(byte[] plainText) {
		try {
			var outputStream = new ByteArrayOutputStream();
			var nonce = SecureRandom.getInstanceStrong().nextInt();

			outputStream.write(ByteBuffer.allocate(4).putInt(nonce).array());
			outputStream.write(plainText);

			// Format: nonce || M
			var plainTextWithNonce = outputStream.toByteArray();

			// Format: E(k, nonce || M)
			var cipherText = EncryptionTool.encrypt(cipherConfig, plainTextWithNonce);

			// Format: size(E(k, nonce || M)) || E(k, nonce || M)
			outputStream.reset();
			outputStream.write(ByteBuffer.allocate(4).putInt(cipherText.length).array());
			outputStream.write(cipherText, 0, cipherText.length);

			// Format: size(E(k, nonce || M)) || E(k, nonce || M) || ( HMAC(E(k, nonce || M)) or H(nonce || M) )
			byte[] integrity;
			if (cipherConfig.getIntegrity() != null) {
				integrity = IntegrityTool.buildIntegrity(cipherConfig, plainTextWithNonce, cipherText);
				outputStream.write(integrity);
			}
			this.data = outputStream.toByteArray();

		} catch (CryptoException | IOException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public DatagramPacket toDatagramPacket() {
		var packet = new DatagramPacket(data, data.length);
		packet.setSocketAddress(address);
		return packet;
	}
}
