import config.parser.CipherConfig;
import config.parser.ParseCipherConfig;
import cryptotools.IntegrityException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;
import statistics.PrintStats;
import utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.security.Security;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class Proxy {
    private static final String CONFIG_PATH = "config/proxy/config.properties";
    private static final String PROPERTY_REMOTE = "remote";
    private static final String PROPERTY_DESTINATIONS = "localdelivery";
    private static final String STREAM_CIPHER_CONFIG = "config/cryptoconfig.json";

    public static void main(String[] args) throws Exception {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Proxy Running");
        var inputStream = new FileInputStream(CONFIG_PATH);
        var properties = new Properties();
        properties.load(inputStream);
        var remote = properties.getProperty(PROPERTY_REMOTE);
        var destinations = properties.getProperty(PROPERTY_DESTINATIONS);

        SocketAddress inSocketAddress = Utils.parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Utils::parseSocketAddress).collect(Collectors.toSet());
        try (var fis = new FileInputStream(STREAM_CIPHER_CONFIG)) {
            String json = new String(fis.readAllBytes());
            CipherConfig cipherConfig = new ParseCipherConfig(json).parseConfig().values().iterator().next();

            System.out.println("Remote: " + remote);

            try (SecureSocket inSocket = new SecureSocket(inSocketAddress)) {
                try (DatagramSocket outSocket = new DatagramSocket()) {
                    byte[] buffer = new byte[4096]; // prev 8192

                    int size;
                    var csize = 0;
                    var count = 0;
                    long beginningTime = -1; // ref. time

                    while (true) {
                        SecureDatagramPacket inPacket = new SecureDatagramPacket(cipherConfig);
                        try {
                            inSocket.receive(buffer, inPacket);

                            DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));
                            var type = dataInputStream.readInt(); // 0 = FRAME, 1 = END
                            var messageType = MESSAGE_TYPE.values()[type];// convert to enum

                            if (messageType == MESSAGE_TYPE.END) {
                                break; // stream ended.
                            }

                            var data = dataInputStream.readAllBytes(); // data

                            if (beginningTime == -1) beginningTime = System.nanoTime();
                            size = data.length; // size of the frame
                            csize = csize + size; // cumulative size of the frames sent
                            // can't know timestamp of the frame
                            count += 1; // number of frames

                            System.out.print("*"); // print an asterisk for each frame received.
                            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                                outSocket.send(new DatagramPacket(data, data.length, outSocketAddress));
                            }
                        } catch (IntegrityException e) {
                            System.out.print("-"); // print a dash for denied frame
                        }
                    }
                    long tend = System.nanoTime(); // "The end" time
                    int duration = (int) ((tend - beginningTime) / 1000000000); // duration of the transmission

                    PrintStats.printStats(cipherConfig, count, csize / count, csize, duration, count / duration, (8 * (csize) / duration) / 1000);
                }
            }
        }

        System.out.println("Stream ended.");
    }

    public enum MESSAGE_TYPE {
        FRAME, END
    }
}
