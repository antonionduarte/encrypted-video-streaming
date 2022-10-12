package proxy;

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

class Proxy {
	private static final String CONFIG_PATH = "config/proxy/config.properties";

	public static void main(String[] args) throws Exception {
		InputStream inputStream = new FileInputStream(CONFIG_PATH);
		Properties properties = new Properties();
		properties.load(inputStream);
		String remote = properties.getProperty("remote");
		String destinations = properties.getProperty("localdelivery");

		SocketAddress inSocketAddress = parseSocketAddress(remote);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Proxy::parseSocketAddress).collect(Collectors.toSet());

		try (DatagramSocket inSocket = new DatagramSocket(inSocketAddress)) {
			try (DatagramSocket outSocket = new DatagramSocket()) {
				byte[] buffer = new byte[4 * 1024];

				while (true) {
					DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
					inSocket.receive(inPacket);  // if remote is unicast

					System.out.print("*");
					for (SocketAddress outSocketAddress : outSocketAddressSet) {
						outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
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
