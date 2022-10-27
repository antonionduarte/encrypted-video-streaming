import config.parser.CipherConfig;
import config.parser.ParseCipherConfig;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class Proxy {
	private static final String CONFIG_PATH = "config/proxy/config.properties";
	private static final String PROPERTY_REMOTE = "remote";
	private static final String PROPERTY_DESTINATIONS = "localdelivery";
	private static final String STREAM_CIPHER_CONFIG = "config/box-cryptoconfig.json";

	public enum MESSAGE_TYPE {
		FRAME, END
	}

	public static void main(String[] args) throws Exception {
		System.out.println("Proxy Running");
		var inputStream = new FileInputStream(CONFIG_PATH);
		var properties = new Properties();
		properties.load(inputStream);
		var remote = properties.getProperty(PROPERTY_REMOTE);
		var destinations = properties.getProperty(PROPERTY_DESTINATIONS);

		SocketAddress inSocketAddress = parseSocketAddress(remote);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Proxy::parseSocketAddress).collect(Collectors.toSet());
		String json = new String(new FileInputStream(STREAM_CIPHER_CONFIG).readAllBytes());
		CipherConfig cipherConfig = new ParseCipherConfig(json).parseConfig().values().iterator().next();

		System.out.println("Remote: " + remote);

		try (SecureSocket inSocket = new SecureSocket(inSocketAddress)) {
			try (DatagramSocket outSocket = new DatagramSocket()) {
				byte[] buffer = new byte[8192];

				while (true) {
					SecureDatagramPacket inPacket = new SecureDatagramPacket(cipherConfig);
					inSocket.receive(inPacket);

					InputStream dataInputStream = new ByteArrayInputStream(inPacket.getData());
					var type = dataInputStream.readNBytes(1); // 0 = FRAME, 1 = END
					var data = dataInputStream.readAllBytes(); // data
					var messageType = type[0] == 0 ? MESSAGE_TYPE.FRAME : MESSAGE_TYPE.END; // convert to enum

					if (messageType == MESSAGE_TYPE.END) {
						break; // stream ended.
					}

					System.out.print("*"); // print a dot for each frame received.
					for (SocketAddress outSocketAddress : outSocketAddressSet) {
						outSocket.send(new DatagramPacket(data, data.length, outSocketAddress));
					}
				}
			}
		}

		System.out.println("Stream ended.");
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
