import org.bouncycastle.jce.provider.BouncyCastleProvider;
import server.StreamServer;

import java.security.Security;

public class Server {

	private static final String ADDRESS = "127.0.0.1", PORT = "5000";

	public static void main(String[] args) throws Exception {
		if (args.length != 3) {
			System.out.println("Error, use: StreamServer <movie> <ip-multicast-address> <port>");
			System.out.println("        or: StreamServer <movie> <ip-unicast-address> <port>");
			System.exit(-1);
		}

		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());

		var streamServer = new StreamServer(args[0], ADDRESS, PORT, args[1], args[2]);
		streamServer.run();
	}
}
