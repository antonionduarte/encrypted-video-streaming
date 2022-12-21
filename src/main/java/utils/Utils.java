package utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.List;

public class Utils {

	public static byte[] hexToBytes(String hex) {
		String base64 = Base64.getEncoder().encodeToString(hex.getBytes());

		// Convert the base64 string to a byte array
		return Base64.getDecoder().decode(base64);
	}

	public static String bytesToHex(byte[] bytes) {
		// Encode the byte array as a base64 string
		String base64 = Base64.getEncoder().encodeToString(bytes);

		// Decode the base64 string to a hexadecimal string
		return new String(Base64.getDecoder().decode(base64));
	}

	public static <T> T firstIntersection(List<T> list1, List<T> list2) {
		return list1.stream()
				.filter(list2::contains)
				.findFirst()
				.orElse(null);
	}

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
