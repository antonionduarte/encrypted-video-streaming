package config;

import config.parser.parser_objects.ParsedAsymmetricConfig;

import java.io.*;
import java.math.BigInteger;

public class AsymmetricConfig {

	private final String authentication;
	private final String keyExchange;
	private final int keySize;
	private final int numSize;
	private BigInteger g;
	private BigInteger p;


	public AsymmetricConfig(String authentication, int keySize, String keyExchange, int numSize, BigInteger g, BigInteger p) {
		this.authentication = authentication;
		this.keySize = keySize;
		this.keyExchange = keyExchange;
		this.numSize = numSize;
		this.g = g;
		this.p = p;
	}

	public AsymmetricConfig(ParsedAsymmetricConfig parsedConfig) {
		this.authentication = parsedConfig.authentication();
		this.keySize = parsedConfig.keySize();
		this.keyExchange = parsedConfig.keyExchange();
		this.numSize = parsedConfig.numSize();

		if (parsedConfig.g() != null && parsedConfig.p() != null) {
			this.g = new BigInteger(parsedConfig.g(), 16);
			this.p = new BigInteger(parsedConfig.p(), 16);
		}
	}

	public static AsymmetricConfig deserialize(byte[] bytes) throws IOException {
		var dataInputStream = new DataInputStream(new ByteArrayInputStream(bytes));

		String authentication = dataInputStream.readUTF();
		int keySize = dataInputStream.readInt();
		String keyExchange = dataInputStream.readUTF();
		int numSize = dataInputStream.readInt();
		if (dataInputStream.available() > 0) {
			var g = new BigInteger(dataInputStream.readNBytes(dataInputStream.readInt()));
			var p = new BigInteger(dataInputStream.readAllBytes());
			return new AsymmetricConfig(authentication, keySize, keyExchange, numSize, g, p);
		} else {
			return new AsymmetricConfig(authentication, keySize, keyExchange, numSize, null, null);
		}
	}

	public byte[] serialize() throws IOException {
		var byteArrayOutputStream = new ByteArrayOutputStream();
		var dataOutputStream = new DataOutputStream(byteArrayOutputStream);

		dataOutputStream.writeUTF(authentication);
		dataOutputStream.writeInt(keySize);
		dataOutputStream.writeUTF(keyExchange);
		dataOutputStream.writeInt(numSize);

		if (g != null && p != null) {
			var gBytes = g.toByteArray();
			dataOutputStream.write(gBytes.length);
			dataOutputStream.write(gBytes);
			dataOutputStream.write(p.toByteArray());
		}

		return byteArrayOutputStream.toByteArray();
	}

	public String getAuthentication() {
		return authentication;
	}

	public int getKeySize() {
		return keySize;
	}

	public String getKeyExchange() {
		return keyExchange;
	}

	public int getNumSize() {
		return numSize;
	}

	public BigInteger getG() {
		return g;
	}

	public void setG(BigInteger g) {
		this.g = g;
	}

	public BigInteger getP() {
		return p;
	}

	public void setP(BigInteger p) {
		this.p = p;
	}
}
