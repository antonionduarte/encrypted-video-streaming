import server.StreamServer;

public class Server {

	public static void main(String[] args) throws Exception {
		if (args.length != 3) {
			System.out.println("Error, use: StreamServer <movie> <ip-multicast-address> <port>");
			System.out.println("        or: StreamServer <movie> <ip-unicast-address> <port>");
			System.exit(-1);
		}

		var streamServer = new StreamServer(args[0], args[1], args[2]);
		streamServer.run();
	}
}
