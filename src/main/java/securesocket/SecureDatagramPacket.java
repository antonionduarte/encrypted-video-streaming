package securesocket;

import config.parser.CipherConfig;
import cryptotools.CryptoException;
import cryptotools.EncryptionTool;
import cryptotools.IntegrityTool;

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
		this.data = data;
		this.encryptData(); // TODO: Check if you can do this uwu :3
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

	public void encryptData() {
		try {
			var outputStream = new ByteArrayOutputStream();
			var nonce = SecureRandom.getInstanceStrong().nextInt();

			outputStream.write(nonce);
			outputStream.write(data);

			// Format: nonce || M
			var plainText = outputStream.toByteArray();

			// Format: E(k, nonce || M)
			var cipherText = EncryptionTool.encrypt(cipherConfig, plainText);

			outputStream.reset();
			outputStream.write(cipherText.length);
			outputStream.write(cipherText);

			// Format: size(E(k, nonce || M)) || E(k, nonce || M)
			var dataWithSize = outputStream.toByteArray();

			// Format: size(E(k, nonce || M)) || E(k, nonce || M) || (HMAC(E(k, nonce || M)) or Hash(nonce || M))
			byte[] integrity;

			if (cipherConfig.getIntegrity() != null) {
				integrity = IntegrityTool.buildIntegrity(cipherConfig, plainText, cipherText);

				outputStream.reset();
				outputStream.write(dataWithSize);
				outputStream.write(integrity);
				this.data = outputStream.toByteArray();
			} else
				this.data = dataWithSize;

		} catch (CryptoException | IOException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public DatagramPacket toDatagramPacket() {
		return new DatagramPacket(data, data.length);
	}
}
