import config.parser.CipherConfig;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;

import java.io.FileInputStream;
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

	public static void main(String[] args) throws Exception {
		System.out.println("Proxy Running");
		var inputStream = new FileInputStream(CONFIG_PATH);
		var properties = new Properties();
		properties.load(inputStream);
		var remote = properties.getProperty(PROPERTY_REMOTE);
		var destinations = properties.getProperty(PROPERTY_DESTINATIONS);

		SocketAddress inSocketAddress = parseSocketAddress(remote);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Proxy::parseSocketAddress).collect(Collectors.toSet());

		CipherConfig cipherConfig = null; // TODO: Get correct cipherConfig.

		try (SecureSocket inSocket = new SecureSocket(inSocketAddress)) {
			try (DatagramSocket outSocket = new DatagramSocket()) {
				byte[] buffer = new byte[4 * 1024];

				while (true) {
					SecureDatagramPacket inPacket = new SecureDatagramPacket(cipherConfig);
					inSocket.receive(inPacket);

					System.out.print("*");
					for (SocketAddress outSocketAddress : outSocketAddressSet) {
						outSocket.send(inPacket.toDatagramPacket());
					}
				}
			}
		}
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
