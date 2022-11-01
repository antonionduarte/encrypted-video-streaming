import server.StreamServer;

public class Server {

	private static final String ADDRESS = "127.0.0.1", PORT = "5000";

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			System.out.println("Error, use: StreamServer <movie>");
			System.exit(-1);
		}

		var streamServer = new StreamServer(args[0], ADDRESS, PORT);
		streamServer.run();
	}
}
