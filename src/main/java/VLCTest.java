import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Properties;

public class VLCTest {

	private static final String CONFIG_PATH = "config/proxy/config.properties";
	private static final String PROPERTY_DESTINATIONS = "localdelivery";

	public static void main(String[] args) throws IOException {
		InputStream inputStream = new FileInputStream(CONFIG_PATH);
		Properties properties = new Properties();
		properties.load(inputStream);
		String destinations = properties.getProperty(PROPERTY_DESTINATIONS);
		destinations = "224.42.0.3:7777";

		SocketAddress inSocketAddress = parseSocketAddress(destinations);
		try (DatagramSocket inSocket = new DatagramSocket(inSocketAddress)) {
			byte[] buffer = new byte[4 * 1024];
			while (true) {
				DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
				inSocket.receive(inPacket);  // if remote is unicast
				System.out.print("-");
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
