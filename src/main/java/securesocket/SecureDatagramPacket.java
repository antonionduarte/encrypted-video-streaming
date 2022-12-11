package securesocket;

import config.CipherConfig;
import cryptotools.CryptoException;
import cryptotools.encryption.EncryptionTool;
import cryptotools.integrity.IntegrityTool;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureDatagramPacket {

	private final CipherConfig cipherConfig;
	private byte[] data;
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

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public CipherConfig getCipherConfig() {
		return cipherConfig;
	}

	public InetSocketAddress getAddress() {
		return address;
	}

	public void setAddress(InetSocketAddress address) {
		this.address = address;
	}

	public void encryptData(byte[] plainText) {
		try {
			// Generate nonce
			var nonce = SecureRandom.getInstanceStrong().nextInt();

			// Format: nonce || M
			var plainTextWithNonce = new byte[4 + plainText.length];
			ByteBuffer.wrap(plainTextWithNonce).putInt(nonce).put(plainText);

			// Format: E(k, nonce || M)
			var cipherText = EncryptionTool.encrypt(cipherConfig, plainTextWithNonce);

			// Format: size(E(k, nonce || M)) || E(k, nonce || M)
			var cipherTextWithSize = new byte[4 + cipherText.length];
			ByteBuffer.wrap(cipherTextWithSize).putInt(cipherText.length).put(cipherText);

			// Format: size(E(k, nonce || M)) || E(k, nonce || M) || ( MAC(E(k, nonce || M)) or H(nonce || M) )
			if (cipherConfig.getIntegrity() != null) {
				var integrity = IntegrityTool.buildIntegrity(cipherConfig, plainTextWithNonce, cipherText);
				this.data = new byte[cipherTextWithSize.length + integrity.length];
				ByteBuffer.wrap(this.data).put(cipherTextWithSize).put(integrity);
			} else {
				this.data = cipherTextWithSize;
			}
		} catch (CryptoException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public DatagramPacket toDatagramPacket() {
		return new DatagramPacket(data, data.length, address);
	}
}
