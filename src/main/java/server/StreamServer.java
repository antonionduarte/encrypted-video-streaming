package server;

import config.CipherConfig;
import config.DecipherMoviesConfig;
import cryptotools.certificates.CertificateVerifier;
import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;
import cryptotools.keystore.KeyStoreTool;
import protocols.rtss.RtssProtocol;
import protocols.rtss.handshake.RtssHandshake;
import protocols.rtss.handshake.RtssHandshakeExecutor;
import protocols.rtss.handshake.ResultServer;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;
import statistics.Stats;
import utils.Loader;
import utils.cipherutils.EncryptMovies;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class StreamServer {
	private static final String CIPHER_CONFIG_ENV = "CRYPTO_CONFIG_KEY";
	private static final String MOVIES_CIPHER_CONFIG_PATH = "movies/ciphered/cryptoconfig.json.enc";

	private static final String ASYM_CONFIG_PATH = "config/server/asymmetric-config.json";
	private static final String SYM_CONFIG_PATH = "config/server/symmetric-config.json";
	private static final String INTEGRITY_CONFIG_PATH = "config/common/handshake-integrity.json";

	public static final String KEYSTORE_PASSWORD_ENV = "SERVER_PASSWORD";
	private static final String TRUSTSTORE_PASSWORD_ENV = "TRUSTSTORE_PASSWORD";

	public static final String CA_ALIAS_MASK = "ca_%s_%d";
	public static final String ALIAS_MASK = "server_%s_%d";

	public static final String CERTIFICATE_PATH_MASK = "certs/server/certs/server_%s_%d.cer";
	public static final String KEYSTORE_PATH = "certs/server/server.pkcs12";
	private static final String TRUSTSTORE_PATH = "certs/common/truststore.pkcs12";

	private static final String CIPHERED_MOVIE_DIR = "movies/ciphered/";
	private static final String MOVIE_SUFFIX = ".dat.enc";

	private final InetSocketAddress serverAddress;
	private final Map<String, CipherConfig> moviesConfig;

	public StreamServer(String serverAddressStr, int serverPort) throws Exception {
		this.serverAddress = new InetSocketAddress(serverAddressStr, serverPort);
		this.moviesConfig = new DecipherMoviesConfig(System.getenv(CIPHER_CONFIG_ENV), MOVIES_CIPHER_CONFIG_PATH).getCipherConfig();
	}

	private static byte[] appendMessageType(MESSAGE_TYPE messageType, byte[] data) throws IOException {
		var outputStream = new ByteArrayOutputStream();
		outputStream.write(ByteBuffer.allocate(4).putInt(messageType.ordinal()).array());
		outputStream.write(data);
		return outputStream.toByteArray();
	}

	/**
	 * Performs the handshake using the RTSS Handshake Class.
	 */
	private static ResultServer performHandshake(int port) throws Exception {
		var asymmetricConfigList = Loader.readAsymConfigList(ASYM_CONFIG_PATH);
		var symmetricConfigList = Loader.readSymConfigList(SYM_CONFIG_PATH);
		var integrityConfig = Loader.readIntegrityConfig(INTEGRITY_CONFIG_PATH);
		var trustStore = KeyStoreTool.getTrustStore(TRUSTSTORE_PATH, System.getenv(TRUSTSTORE_PASSWORD_ENV));
		var certificateVerifier = new CertificateVerifier(trustStore);

		RtssHandshake.RtssHandshakeBuilder builder = new RtssHandshake.RtssHandshakeBuilder();
		var handshake = builder
				.setAsymmetricConfigList(asymmetricConfigList)
				.setSymmetricConfigList(symmetricConfigList)
				.setIntegrityConfig(integrityConfig)
				.setCertificateVerifier(certificateVerifier).build();
		return RtssHandshakeExecutor.performHandshakeServer(handshake, port);
	}

	private byte[] getMovieBytes(String movieName) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IntegrityException {

		var movieCipherConfig = moviesConfig.get(movieName + MOVIE_SUFFIX);
		// check integrity of dat.enc file
		var path = CIPHERED_MOVIE_DIR + movieName + MOVIE_SUFFIX;
		IntegrityTool.checkMovieIntegrity(movieCipherConfig, Files.readAllBytes(Path.of(path)));

		return EncryptMovies.decryptMovie(movieCipherConfig, path);
	}

	public void run() throws Exception {
		System.out.println("Server running");

		int frameSize;
		var cumulativeSize = 0;
		var frameCount = 0;
		long frameTimestamp;

		//var cipherConfig = new CipherConfig(new ParseCipherConfigMap(json).parseConfig().values().iterator().next());
		var result = performHandshake(serverAddress.getPort());
		var cipherConfig = result.cipherConfig();
		var rtss = new RtssProtocol(cipherConfig);

		InetSocketAddress clientAddress = result.clientAddress();
		var movieName = result.movieName();

		byte[] plainMovie = getMovieBytes(movieName);

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
				SecureDatagramPacket packet = new SecureDatagramPacket(frameData, clientAddress, rtss);

				// decision about the right time to transmit
				long currentTime = System.nanoTime(); // what time is it?
				Thread.sleep(Math.max(0, ((frameTimestamp - timeOfLastPacketSent) - (currentTime - beginningTime)) / 1000000)); // sleep until the right time
				socket.send(packet);
				System.out.print(".");
			}

			// send the end of the stream
			frameData = appendMessageType(MESSAGE_TYPE.END, new byte[0]);
			SecureDatagramPacket packet = new SecureDatagramPacket(frameData, clientAddress, rtss);
			socket.send(packet);

			long transmissionEndTime = System.nanoTime(); // "The end" time
			int duration = (int) ((transmissionEndTime - beginningTime) / 1000000000); // duration of the transmission

			var stats = new Stats.StatsBuilder().withConfig(cipherConfig).withNumFrames(frameCount).withAvgFrameSize(cumulativeSize / frameCount).withMovieSize(cumulativeSize).withElapsedTime(duration).withFrameRate(frameCount / duration).withThroughPut((8 * (cumulativeSize / duration)) / 1000000).build();
			stats.printStats();
		}
	}

	public enum MESSAGE_TYPE {
		FRAME, END
	}
}



