package utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;

public class Utils {
	public static byte[] getFileBytes(String filePath) throws IOException {
		try (FileInputStream fis = new FileInputStream(filePath)) {
			return fis.readAllBytes();
		}
	}

	public static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
