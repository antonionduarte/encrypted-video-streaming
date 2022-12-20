package config;

import config.parser.parser_objects.ParsedSymmetricConfig;

import java.io.*;
import java.util.Optional;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")

public class SymmetricConfig {
	public final String cipher;
	public final Optional<String> integrity;
	public int keySize;
	public int macKeySize;
	public int ivSize;

	public SymmetricConfig(String cipher, int keySize, String integrity, int macKeySize, int ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = Optional.of(integrity);
		this.macKeySize = macKeySize;
		this.ivSize = ivSize;
	}

	public SymmetricConfig(String cipher, int keySize, int ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = Optional.empty();
		this.macKeySize = 0;
		this.ivSize = ivSize;
	}

	public SymmetricConfig(ParsedSymmetricConfig parsedSymmetricConfig) {
		this.cipher = parsedSymmetricConfig.cipher();
		this.keySize = parsedSymmetricConfig.keySize();
		this.integrity = parsedSymmetricConfig.integrity() == null ? Optional.empty() : Optional.of(parsedSymmetricConfig.integrity());
		this.macKeySize = parsedSymmetricConfig.macKeySize();
		this.ivSize = parsedSymmetricConfig.ivSize();
	}

	public static SymmetricConfig fromBytes(byte[] bytes) throws IOException {
		var dataInputStream = new DataInputStream(new ByteArrayInputStream(bytes));

		var cipher = dataInputStream.readUTF();
		var keySize = dataInputStream.readInt();

		if (dataInputStream.available() == 0) {
			return new SymmetricConfig(cipher, keySize, 0);
		} else if (dataInputStream.available() == 4) {
			return new SymmetricConfig(cipher, keySize, dataInputStream.readInt());
		} else {
			var integrity = dataInputStream.readUTF();
			var macKeySize = dataInputStream.readInt();
			var ivSize = dataInputStream.available() == 4 ? dataInputStream.readInt() : 0;
			return new SymmetricConfig(cipher, keySize, integrity, macKeySize, ivSize);
		}
	}

	public byte[] toBytes() throws IOException {
		var byteArrayOutputStream = new ByteArrayOutputStream();
		var dataOutputStream = new DataOutputStream(byteArrayOutputStream);

		dataOutputStream.writeUTF(cipher);
		dataOutputStream.writeInt(keySize);

		if (integrity.isPresent()) {
			dataOutputStream.writeUTF(integrity.get());
			if (macKeySize == 0) dataOutputStream.writeInt(macKeySize);
		}

		if (ivSize == 0) dataOutputStream.writeInt(ivSize);

		return byteArrayOutputStream.toByteArray();
	}
}
