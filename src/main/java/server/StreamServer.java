package server;

import config.DecipherCipherConfig;
import config.CipherConfig;
import config.parser.ParseCipherConfig;
import cryptotools.CryptoException;
import cryptotools.integrity.IntegrityTool;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;
import statistics.Stats;
import utils.Utils;
import utils.cipherutils.EncryptMovies;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class StreamServer {
	private static final String CIPHER_CONFIG_ENV = "CRYPTO_CONFIG_KEY";
	private static final String CIPHER_CONFIG_PATH = "movies/ciphered/cryptoconfig.json.enc";
	private static final String STREAM_CIPHER_CONFIG = "config/box-cryptoconfig.json";

	private final InetSocketAddress serverAddress;
	private final String movie;
	private final Map<String, CipherConfig> moviesConfig;

	private InetSocketAddress remoteAddress;

	public StreamServer(String movie, String serverAddressStr, String serverPort) throws CryptoException, IOException {
		this.movie = movie;
		this.serverAddress = new InetSocketAddress(serverAddressStr, Integer.parseInt(serverPort));
		this.moviesConfig = new DecipherCipherConfig(System.getenv(CIPHER_CONFIG_ENV), CIPHER_CONFIG_PATH).getCipherConfig();
	}

	public byte[] appendMessageType(MESSAGE_TYPE messageType, byte[] data) throws IOException {
		var outputStream = new ByteArrayOutputStream();
		outputStream.write(ByteBuffer.allocate(4).putInt(messageType.ordinal()).array());
		outputStream.write(data);
		return outputStream.toByteArray();
	}

	private byte[] getMovieBytes() throws IOException, CryptoException {
		var movieCipherConfig = moviesConfig.get(movie.split("/")[2]);
		// check integrity of dat.enc file
		if (!IntegrityTool.checkMovieIntegrity(movieCipherConfig, Files.readAllBytes(Path.of(movie)))) {
			System.err.println("Movie integrity not checked");
			System.exit(1);
		}
		return EncryptMovies.decryptMovie(movieCipherConfig, movie);
	}

	public void run() throws Exception {
		System.out.println("Server running");

		byte[] plainMovie = getMovieBytes();

		int frameSize;
		var cumulativeSize = 0;
		var frameCount = 0;
		long frameTimestamp;

		try (var fileInputStream = new FileInputStream(STREAM_CIPHER_CONFIG)) {
			var json = new String(fileInputStream.readAllBytes());
			var cipherConfig = new ParseCipherConfig(json).parseConfig().values().iterator().next();
			var address = new ParseCipherConfig(json).parseConfig().keySet().iterator().next();

			this.remoteAddress = Utils.parseSocketAddress(address);

			DataInputStream dataStream = new DataInputStream(new ByteArrayInputStream(plainMovie));

			try (SecureSocket socket = new SecureSocket(serverAddress)) {
				byte[] frameData;

				long beginningTime = System.nanoTime(); // ref. time
				long timeOfLastPacketSent = 0; // time of the last packet sent

				while (dataStream.available() > 0) {
					frameSize = dataStream.readShort(); // size of the frame
					cumulativeSize += frameSize; // cumulative size of the frames sent
					frameTimestamp = dataStream.readLong();  // timestamp of the frame

					if (frameCount == 0) { // first packet
						timeOfLastPacketSent = frameTimestamp; // ref. time in the stream
					}

					frameCount++; // number of frames
					frameData = new byte[frameSize];
					dataStream.readFully(frameData, 0, frameSize); // read the frame
					frameData = appendMessageType(MESSAGE_TYPE.FRAME, frameData);
					SecureDatagramPacket packet = new SecureDatagramPacket(frameData, remoteAddress, cipherConfig);

					// decision about the right time to transmit
					long currentTime = System.nanoTime(); // what time is it?
					Thread.sleep(Math.max(0, ((frameTimestamp - timeOfLastPacketSent) - (currentTime - beginningTime)) / 1000000)); // sleep until the right time
					socket.send(packet);
					System.out.print(".");
				}

				// send the end of the stream
				frameData = appendMessageType(MESSAGE_TYPE.END, new byte[0]);
				SecureDatagramPacket packet = new SecureDatagramPacket(frameData, remoteAddress, cipherConfig);
				socket.send(packet);

				long transmissionEndTime = System.nanoTime(); // "The end" time
				int duration = (int) ((transmissionEndTime - beginningTime) / 1000000000); // duration of the transmission

				var stats = new Stats.StatsBuilder()
						.withConfig(cipherConfig)
						.withNumFrames(frameCount)
						.withAvgFrameSize(cumulativeSize / frameCount)
						.withMovieSize(cumulativeSize)
						.withElapsedTime(duration)
						.withFrameRate(frameCount / duration)
						.withThroughPut((8 * (cumulativeSize / duration)) / 1000000)
						.build();
				stats.printStats();
			}
		}
	}

	public enum MESSAGE_TYPE {
		FRAME,
		END
	}
}



