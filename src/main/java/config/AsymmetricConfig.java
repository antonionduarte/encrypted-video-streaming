package config;

import java.io.*;
import java.util.Optional;

public record AsymmetricConfig(String authAlg,
                               int keySize,
                               String keyExAlg,
                               int numSize,
                               Optional<byte[]> G,
                               Optional<byte[]> p) {

    public byte[] toBytes() throws IOException {
        var bos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(bos);

        dos.writeUTF(authAlg);
        dos.writeInt(keySize);
        dos.writeUTF(keyExAlg);
        dos.writeInt(numSize);
        if (G.isPresent())
            dos.write(G.get());
        if (p.isPresent())
            dos.write(p.get());

        return bos.toByteArray();
    }

    public static AsymmetricConfig fromBytes(byte[] bytes) throws IOException {
        var dis = new DataInputStream(new ByteArrayInputStream(bytes));

        String authAlg = dis.readUTF();
        int keySize = dis.readInt();
        String keyExAlg = dis.readUTF();
        int numSize = dis.readInt();
        Optional<byte[]> G = Optional.empty();
        Optional<byte[]> p = Optional.empty();
        if (dis.available() == 0) {
            G = Optional.of(dis.readNBytes(numSize));
            p = Optional.of(dis.readNBytes(numSize));
        }

        return new AsymmetricConfig(authAlg, keySize, keyExAlg, numSize, G, p);
    }
}
