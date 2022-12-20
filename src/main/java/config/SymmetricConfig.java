package config;

import config.parser.parser_objects.ParsedSymmetricConfig;

import java.io.*;
import java.util.Optional;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")

public class SymmetricConfig {
	public final String cipher;
	public int keySize;
	public final Optional<String> integrity;
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
		this.integrity = parsedSymmetricConfig.integrity() == null ? Optional.empty() :
				Optional.of(parsedSymmetricConfig.integrity());
		this.macKeySize = parsedSymmetricConfig.macKeySize();
		this.ivSize = parsedSymmetricConfig.ivSize();
	}

    public byte[] toBytes() throws IOException {
		var bos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(bos);

		dos.writeUTF(cipher);
		dos.writeInt(keySize);

		if (integrity.isPresent()) {
			dos.writeUTF(integrity.get());
			if (macKeySize == 0) dos.writeInt(macKeySize);
		}
		if (ivSize == 0) dos.writeInt(ivSize);

		return bos.toByteArray();
    }

	public static SymmetricConfig fromBytes(byte[] bytes) throws IOException {
		var dis = new DataInputStream(new ByteArrayInputStream(bytes));

		var cipher = dis.readUTF();
		var keySize = dis.readInt();

		if (dis.available() == 0) {
			return new SymmetricConfig(cipher, keySize, 0);
		} else if (dis.available() == 4) {
			return new SymmetricConfig(cipher, keySize, dis.readInt());
		} else {
			var integrity = dis.readUTF();
			var macKeySize = dis.readInt();
			var ivSize = dis.available() == 4 ? dis.readInt() : 0;
			return new SymmetricConfig(cipher, keySize, integrity, macKeySize, ivSize);
		}
	}
}
