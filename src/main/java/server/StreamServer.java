package server;

import cipherdata.EncryptMovies;
import config.DecipherCipherConfig;
import config.parser.CipherConfig;
import config.parser.ParseCipherConfig;
import cryptotools.CryptoException;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Map;

public class StreamServer {
	private final InetSocketAddress serverAddress;
	private final InetSocketAddress remoteAddress;
	private final String movie;

	private final Map<String, CipherConfig> moviesConfig;

	private static final String CIPHER_CONFIG_ENV = "CRYPTO_CONFIG_KEY";
	private static final String CIPHER_CONFIG_PATH = "movies/ciphered/cryptoconfig.json.enc";
	private static final String STREAM_CIPHER_CONFIG = "config/box-cryptoconfig.json";

	public StreamServer(String movie, String serverAddressStr, String serverPort, String remoteAddressStr, String remotePort) throws CryptoException, IOException {
		this.movie = movie;
		this.serverAddress = new InetSocketAddress(serverAddressStr, Integer.parseInt(serverPort));;
		this.remoteAddress = new InetSocketAddress(remoteAddressStr, Integer.parseInt(remotePort));;
		this.moviesConfig = new DecipherCipherConfig(System.getenv(CIPHER_CONFIG_ENV), CIPHER_CONFIG_PATH).getCipherConfig();
	}

	public enum MESSAGE_TYPE {
		FRAME,
		END
	}

	public byte[] appendMessageType(MESSAGE_TYPE messageType, byte[] data) throws IOException {
		var outputStream = new ByteArrayOutputStream();
		outputStream.write(ByteBuffer.allocate(4).putInt(messageType.ordinal()).array());
		outputStream.write(data);
		return outputStream.toByteArray();
	}

	public void run() throws Exception {
		System.out.println("Server running");
		var plainMovie = EncryptMovies.decryptMovie(moviesConfig.get(movie.split("/")[2]), movie);

		int size;
		var csize = 0;
		var count = 0;
		long time;


		String json = new String(new FileInputStream(STREAM_CIPHER_CONFIG).readAllBytes());
		CipherConfig cipherConfig = new ParseCipherConfig(json).parseConfig().values().iterator().next();

		DataInputStream dataStream = new DataInputStream(new ByteArrayInputStream(plainMovie));

		try (SecureSocket socket = new SecureSocket(serverAddress)) {
			byte[] buff;

			long beginningTime = System.nanoTime(); // ref. time
			long q0 = 0; // time of the last packet sent

			while (dataStream.available() > 0) {
				size = dataStream.readShort(); // size of the frame
				csize = csize + size; // cumulative size of the frames sent
				time = dataStream.readLong();  // timestamp of the frame

				if (count == 0) { // first packet
					q0 = time; // ref. time in the stream
				}
				count += 1; // number of frames
				buff = new byte[size];
				dataStream.readFully(buff, 0, size); // read the frame
				buff = appendMessageType(MESSAGE_TYPE.FRAME, buff);
				SecureDatagramPacket packet = new SecureDatagramPacket(buff, remoteAddress, cipherConfig);

				// Decision about the right time to transmit
				//long t = System.nanoTime(); // what time is it?
				//Thread.sleep(Math.max(0, ((time - q0) - (t - beginningTime)) / 1000000)); // sleep until the right time
				socket.send(packet);
				System.out.print(".");
			}

			// send the end of the stream
			buff = appendMessageType(MESSAGE_TYPE.END, new byte[0]);
			SecureDatagramPacket packet = new SecureDatagramPacket(buff, remoteAddress, cipherConfig);
			socket.send(packet);

			long tend = System.nanoTime(); // "The end" time
			long duration = (tend - beginningTime) / 1000000000; // duration of the transmission

			System.out.println();
			System.out.println("Done! all frames sent: " + count);

			System.out.println("Movie duration " + duration + " s");
			System.out.println("Throughput " + count / duration + " fps");
			System.out.println("Throughput " + (8L * (csize) / duration) / 1000 + " Kbps");
		}
	}
}



