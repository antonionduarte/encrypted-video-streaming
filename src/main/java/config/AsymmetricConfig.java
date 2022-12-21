package config;

import config.parser.parser_objects.ParsedAsymmetricConfig;

import java.io.*;
import java.math.BigInteger;
import java.util.Optional;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class AsymmetricConfig {

	private final String authentication;
	private final int keySize;
	private final String keyExchange;
	private final int numSize;
	private Optional<BigInteger> G;
	private Optional<BigInteger> p;


	public AsymmetricConfig(String authentication, int keySize, String keyExchange, int numSize, BigInteger G, BigInteger p) {
		this.authentication = authentication;
		this.keySize = keySize;
		this.keyExchange = keyExchange;
		this.numSize = numSize;
		this.G = Optional.of(G);
		this.p = Optional.of(p);
	}

	public AsymmetricConfig(String authentication, int keySize, String keyExchange, int numSize) {
		this.authentication = authentication;
		this.keySize = keySize;
		this.keyExchange = keyExchange;
		this.numSize = numSize;
		this.G = Optional.empty();
		this.p = Optional.empty();
	}

	public AsymmetricConfig(ParsedAsymmetricConfig parsedConfig) {
		this.authentication = parsedConfig.authentication();
		this.keySize = parsedConfig.keySize();
		this.keyExchange = parsedConfig.keyExchange();
		this.numSize = parsedConfig.numSize();
		if (parsedConfig.G() == null || parsedConfig.p() == null) {
			this.G = Optional.empty();
			this.p = Optional.empty();
		} else {
			this.G = Optional.of(new BigInteger(parsedConfig.G(), 16));
			this.p = Optional.of(new BigInteger(parsedConfig.p(), 16));
		}
	}

	public static AsymmetricConfig fromBytes(byte[] bytes) throws IOException {
		var dataInputStream = new DataInputStream(new ByteArrayInputStream(bytes));

		String authentication = dataInputStream.readUTF();
		int keySize = dataInputStream.readInt();
		String keyExchange = dataInputStream.readUTF();
		int numSize = dataInputStream.readInt();
		if (dataInputStream.available() > 0) {
			var G = new BigInteger(dataInputStream.readNBytes(dataInputStream.readInt()));
			var p = new BigInteger(dataInputStream.readAllBytes());
			return new AsymmetricConfig(authentication, keySize, keyExchange, numSize, G, p);
		} else {
			return new AsymmetricConfig(authentication, keySize, keyExchange, numSize);
		}
	}

	public byte[] toBytes() throws IOException {
		var byteArrayOutputStream = new ByteArrayOutputStream();
		var dataOutputStream = new DataOutputStream(byteArrayOutputStream);

		dataOutputStream.writeUTF(authentication);
		dataOutputStream.writeInt(keySize);
		dataOutputStream.writeUTF(keyExchange);
		dataOutputStream.writeInt(numSize);
		if (G.isPresent()) {
			var gBytes = G.get().toByteArray();
			dataOutputStream.write(gBytes.length);
			dataOutputStream.write(gBytes);
		}
		if (p.isPresent()) {
			dataOutputStream.write(p.get().toByteArray());
		}

		return byteArrayOutputStream.toByteArray();
	}
}
