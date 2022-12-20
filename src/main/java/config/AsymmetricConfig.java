package config;

import config.parser.parser_objects.ParsedAsymmetricConfig;
import utils.Utils;

import java.io.*;
import java.math.BigInteger;
import java.util.Optional;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class AsymmetricConfig {

    public final String authentication;
    public final int keySize;
    public final String keyExchange;
    public final int numSize;
    public Optional<BigInteger> G;
    public Optional<BigInteger> p;


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
        }
        else {
            this.G = Optional.of(new BigInteger(parsedConfig.G(), 16));
            this.p = Optional.of(new BigInteger(parsedConfig.p(), 16));
        }
    }

    public byte[] toBytes() throws IOException {
        var bos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(bos);

        dos.writeUTF(authentication);
        dos.writeInt(keySize);
        dos.writeUTF(keyExchange);
        dos.writeInt(numSize);
        if (G.isPresent()) {
            var gBytes = G.get().toByteArray();
            dos.write(gBytes.length);
            dos.write(gBytes);
        }
        if (p.isPresent())
            dos.write(p.get().toByteArray());

        return bos.toByteArray();
    }

    public static AsymmetricConfig fromBytes(byte[] bytes) throws IOException {
        var dis = new DataInputStream(new ByteArrayInputStream(bytes));

        String authentication = dis.readUTF();
        int keySize = dis.readInt();
        String keyExchange = dis.readUTF();
        int numSize = dis.readInt();
        if (dis.available() > 0) {
            var G = new BigInteger(dis.readNBytes(dis.readInt()));
            var p = new BigInteger(dis.readAllBytes());
            return new AsymmetricConfig(authentication, keySize, keyExchange, numSize, G, p);
        } else
            return new AsymmetricConfig(authentication, keySize, keyExchange, numSize);
    }
}
