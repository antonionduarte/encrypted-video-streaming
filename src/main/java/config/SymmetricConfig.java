package config;

import config.parser.parser_objects.ParsedSymmetricConfig;

import java.io.*;
import java.util.Objects;

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
		var ivSize = dataInputStream.readInt();
		var macKeySize = dataInputStream.readInt();

		if (dataInputStream.available() == 0)
			return new SymmetricConfig(cipher, keySize, null, macKeySize, ivSize);
		else
			return new SymmetricConfig(cipher, keySize, dataInputStream.readUTF(), macKeySize, ivSize);
	}

	public byte[] serialize() throws IOException {
		var byteArrayOutputStream = new ByteArrayOutputStream();
		var dataOutputStream = new DataOutputStream(byteArrayOutputStream);

		dataOutputStream.writeUTF(cipher);
		dataOutputStream.writeInt(keySize);
		dataOutputStream.writeInt(ivSize);
		dataOutputStream.writeInt(macKeySize);
		if (integrity != null)  dataOutputStream.writeUTF(integrity);

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

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		SymmetricConfig that = (SymmetricConfig) o;
		return keySize == that.keySize && macKeySize == that.macKeySize && ivSize == that.ivSize && cipher.equals(that.cipher) && Objects.equals(integrity, that.integrity);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cipher, integrity, keySize, macKeySize, ivSize);
	}
}
