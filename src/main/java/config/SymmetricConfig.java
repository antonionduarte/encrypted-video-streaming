package config;

import config.parser.parser_objects.ParsedSymmetricConfig;

import java.io.*;

public class SymmetricConfig {
	public final String cipher;
	public int keySize;
	public final String integrity;
	public int macKeySize;
	public int ivSize;

	public SymmetricConfig(String cipher, int keySize, String integrity, int macKeySize, int ivSize) {
		this.cipher = cipher;
		this.keySize = keySize;
		this.integrity = integrity;
		this.macKeySize = macKeySize;
		this.ivSize = ivSize;
	}

	public SymmetricConfig(ParsedSymmetricConfig parsedSymmetricConfig) {
		this.cipher = parsedSymmetricConfig.cipher();
		this.keySize = parsedSymmetricConfig.keySize();
		this.integrity = parsedSymmetricConfig.integrity();
		this.macKeySize = parsedSymmetricConfig.macKeySize();
		this.ivSize = parsedSymmetricConfig.ivSize();
	}

    public byte[] toBytes() throws IOException {
		var bos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(bos);

		dos.writeUTF(cipher);
		dos.writeInt(keySize);
		dos.writeUTF(integrity);
		dos.writeInt(macKeySize);
		dos.writeInt(ivSize);

		return bos.toByteArray();
    }

	public static SymmetricConfig fromBytes(byte[] bytes) throws IOException {
		var dis = new DataInputStream(new ByteArrayInputStream(bytes));

		var cipher = dis.readUTF();
		var keySize = dis.readInt();
		var integrity = dis.readUTF();
		var macKeySize = dis.readInt();
		var ivSize = dis.readInt();

		return new SymmetricConfig(cipher, keySize, integrity, macKeySize, ivSize);
	}
}
