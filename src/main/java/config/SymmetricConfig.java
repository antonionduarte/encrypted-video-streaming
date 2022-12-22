package config;

import config.parser.parser_objects.ParsedSymmetricConfig;

import java.io.*;

public class SymmetricConfig {
	private final String cipher;
	private final String integrity;
	private final int keySize;
	private final int macKeySize;
	private final int ivSize;

	public SymmetricConfig(String cipher, int keySize, String integrity, int macKeySize, int ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = integrity;
		this.macKeySize = macKeySize;
		this.ivSize = ivSize;
	}

	public SymmetricConfig(ParsedSymmetricConfig parsedSymmetricConfig) {
		this.cipher = parsedSymmetricConfig.getCipher();
		this.keySize = parsedSymmetricConfig.getKeySize();
		this.integrity = parsedSymmetricConfig.getIntegrity();
		this.macKeySize = parsedSymmetricConfig.getMacKeySize();
		this.ivSize = parsedSymmetricConfig.getIvSize();
	}

	public static SymmetricConfig deserialize(byte[] bytes) throws IOException {
		var dataInputStream = new DataInputStream(new ByteArrayInputStream(bytes));

		var cipher = dataInputStream.readUTF();
		var keySize = dataInputStream.readInt();

		if (dataInputStream.available() == 0) {
			return new SymmetricConfig(cipher, keySize, null, 0, 0);
		} else if (dataInputStream.available() == 4) {
			return new SymmetricConfig(cipher, keySize, null, 0, dataInputStream.readInt());
		} else {
			var integrity = dataInputStream.readUTF();
			var macKeySize = dataInputStream.readInt();
			var ivSize = dataInputStream.available() == 4 ? dataInputStream.readInt() : 0;
			return new SymmetricConfig(cipher, keySize, integrity, macKeySize, ivSize);
		}
	}

	public byte[] serialize() throws IOException {
		var byteArrayOutputStream = new ByteArrayOutputStream();
		var dataOutputStream = new DataOutputStream(byteArrayOutputStream);

		dataOutputStream.writeUTF(cipher);
		dataOutputStream.writeInt(keySize);

		if (integrity != null) {
			dataOutputStream.writeUTF(integrity);
			if (macKeySize == 0) {
				dataOutputStream.writeInt(macKeySize);
			}
		}

		if (ivSize == 0) {
			dataOutputStream.writeInt(ivSize);
		}

		return byteArrayOutputStream.toByteArray();
	}

	public String getCipher() {
		return cipher;
	}

	public String getIntegrity() {
		return integrity;
	}

	public int getKeySize() {
		return keySize;
	}

	public int getMacKeySize() {
		return macKeySize;
	}

	public int getIvSize() {
		return ivSize;
	}
}
