package server;

import cipherdata.EncryptMovies;
import config.DecipherCipherConfig;
import config.parser.CipherConfig;
import encryptiontool.CryptoException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Map;

public class StreamServer {
	private final String address;
	private final String port;
	private final String movie;

	private final Map<String, CipherConfig> moviesConfig;

	private static final String CIPHER_CONFIG_ENV = "CRYPTO_CONFIG_KEY";
	private static final String CIPHER_CONFIG_PATH = "movies/ciphered/cryptoconfig.json.enc";

	public StreamServer(String movie, String address, String port) throws CryptoException {
		this.movie = movie;
		this.address = address;
		this.port = port;
		this.moviesConfig = new DecipherCipherConfig(System.getenv(CIPHER_CONFIG_ENV), CIPHER_CONFIG_PATH).getCipherConfig();
	}

	public void run() throws Exception {
		System.out.println("Server running");
		var plainMovie = EncryptMovies.decryptMovie(moviesConfig.get(movie.split("/")[2]), movie);

		int size;
		var csize = 0;
		var count = 0;
		long time;

		var buff = new byte[4096];

		DataInputStream g = new DataInputStream(new ByteArrayInputStream(plainMovie));

		try (DatagramSocket s = new DatagramSocket()) {
			InetSocketAddress address = new InetSocketAddress(this.address, Integer.parseInt(port));
			DatagramPacket p = new DatagramPacket(buff, buff.length, address);

			long t0 = System.nanoTime(); // Ref. time
			long q0 = 0;

			while (g.available() > 0) {
				size = g.readShort(); // size of the frame
				csize = csize + size;
				time = g.readLong();  // timestamp of the frame

				if (count == 0) {
					q0 = time; // ref. time in the stream
				}

				count += 1;
				g.readFully(buff, 0, size);
				p.setData(buff, 0, size);
				p.setSocketAddress(address);

				long t = System.nanoTime(); // what time is it?
				// Decision about the right time to transmit
				Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));
				// Send datagram (udp packet) w/ payload frame)
				// Frames sent in clear (no encryption)
				s.send(p);
				// Just for awareness... (debug)
				System.out.print(".");
			}

			long tend = System.nanoTime(); // "The end" time
			long duration = (tend - t0) / 1000000000;

			System.out.println();
			System.out.println("Done! all frames sent: " + count);

			System.out.println("Movie duration " + duration + " s");
			System.out.println("Throughput " + count / duration + " fps");
			System.out.println("Throughput " + (8L * (csize) / duration) / 1000 + " Kbps");
		}
	}
}



