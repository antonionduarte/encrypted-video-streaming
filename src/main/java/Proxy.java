import config.CipherConfig;
import cryptotools.certificates.CertificateVerifier;
import cryptotools.integrity.IntegrityException;
import cryptotools.keystore.KeyStoreTool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import protocols.rtss.RtssProtocol;
import protocols.rtss.handshake.ResultClient;
import protocols.rtss.handshake.RtssHandshake;
import protocols.rtss.handshake.RtssHandshakeExecutor;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;
import server.StreamServer;
import statistics.Stats;
import utils.Loader;
import utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

public class Proxy {
	private static final String PROPERTY_REMOTE = "remote";
	private static final String PROPERTY_DESTINATIONS = "localdelivery";

	private static final String CONFIG_PATH = "config/proxy/config.properties";
	private static final String ASYM_CONFIG_PATH = "config/proxy/asymmetric-config.json";
	private static final String SYM_CONFIG_PATH = "config/proxy/symmetric-config.json";
	private static final String INTEGRITY_CONFIG_PATH = "config/common/handshake-integrity.json";

	private static final String KEYSTORE_PASSWORD_ENV = "PROXY_PASSWORD";
	private static final String TRUSTSTORE_PASSWORD_ENV = "TRUSTSTORE_PASSWORD";

	private static final String CA_ALIAS_MASK = "ca_%s_%d";
	private static final String ALIAS_MASK = "proxy_%s_%d";

	private static final String CERTIFICATE_PATH_MASK = "certs/proxy/certs/proxy_%s_%d.cer";
	private static final String KEYSTORE_PATH = "certs/proxy/proxy.pkcs12";
	private static final String TRUSTSTORE_PATH = "certs/common/truststore.pkcs12";

	/**
	 * Performs the handshake using the RTSS Handshake Class.
	 */
	private static ResultClient performHandshake(InetSocketAddress serverAddress, String movieName) throws Exception {
		var asymmetricConfig = Loader.readAsymConfig(ASYM_CONFIG_PATH);
		var symmetricConfigList = Loader.readSymConfigList(SYM_CONFIG_PATH);
		var integrityConfig = Loader.readIntegrityConfig(INTEGRITY_CONFIG_PATH);
		var alias = String.format(ALIAS_MASK, asymmetricConfig.getAuthentication(), asymmetricConfig.getKeySize());
		var keyPair = Loader.readKeyPair(KEYSTORE_PATH, alias, System.getenv(KEYSTORE_PASSWORD_ENV));
		var trustStore = KeyStoreTool.getTrustStore(TRUSTSTORE_PATH, System.getenv(TRUSTSTORE_PASSWORD_ENV));
		var certificatePath = String.format(CERTIFICATE_PATH_MASK, asymmetricConfig.getAuthentication(), asymmetricConfig.getKeySize());
		var caAlias = String.format(CA_ALIAS_MASK, asymmetricConfig.getAuthentication(), asymmetricConfig.getKeySize());
		var certificateChain = Loader.readCertificates(certificatePath, trustStore, caAlias);
		var certificateVerifier = new CertificateVerifier(trustStore);

		RtssHandshake.RtssHandshakeBuilder builder = new RtssHandshake.RtssHandshakeBuilder();
		var handshake = builder.setCertificateChain(certificateChain)
				.setAsymmetricConfigList(List.of(asymmetricConfig))
				.setSymmetricConfigList(symmetricConfigList)
				.setAuthenticationKeys(keyPair)
				.setIntegrityConfig(integrityConfig)
				.setCertificateVerifier(certificateVerifier).build();
		return RtssHandshakeExecutor.performHandshakeClient(handshake, serverAddress, movieName);
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			System.out.println("Error, use: Proxy <movie>");
			System.exit(-1);
		}

		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());

		System.out.println("Proxy Running");

		var movieName = args[0];
		var inputStream = new FileInputStream(CONFIG_PATH);
		var properties = new Properties();

		properties.load(inputStream);

		var remote = properties.getProperty(PROPERTY_REMOTE);
		var destinations = properties.getProperty(PROPERTY_DESTINATIONS);

		var serverAddress = Utils.parseSocketAddress(remote);
		var outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Utils::parseSocketAddress).collect(Collectors.toSet());

		//var cipherConfig = new CipherConfig(new ParseCipherConfigMap(json).parseConfig().values().iterator().next());
		var result = performHandshake(serverAddress, movieName);
		var cipherConfig = result.cipherConfig();
		var selfAddress = result.clientAddress();
		var rtss = new RtssProtocol(cipherConfig);

		try (SecureSocket inSocket = new SecureSocket(selfAddress)) {
			try (DatagramSocket outSocket = new DatagramSocket()) {
				byte[] buffer = new byte[4096]; // prev 8192

				int size;
				int cumulativeSize = 0;
				int frameCount = 0;
				long beginningTime = -1; // ref. time

				while (true) {
					SecureDatagramPacket inPacket = new SecureDatagramPacket(rtss);
					try {
						inSocket.receive(buffer, inPacket);

						DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));
						var type = dataInputStream.readInt(); // 0 = FRAME, 1 = END
						var messageType = MESSAGE_TYPE.values()[type];// convert to enum

						if (messageType == MESSAGE_TYPE.END) {
							break; // stream ended.
						}

						var data = dataInputStream.readAllBytes(); // data

						if (beginningTime == -1) {
							beginningTime = System.nanoTime();
						}

						size = data.length; // size of the frame
						cumulativeSize = cumulativeSize + size; // cumulative size of the frames sent
						frameCount += 1; // number of frames

						System.out.print("*"); // print an asterisk for each frame received.
						for (SocketAddress outSocketAddress : outSocketAddressSet) {
							outSocket.send(new DatagramPacket(data, data.length, outSocketAddress));
						}
					} catch (IntegrityException e) {
						System.out.print("-"); // print a dash for denied frame
					}
				}

				long endTime = System.nanoTime(); // "the end" time
				int duration = (int) ((endTime - beginningTime) / 1000000000); // duration of the transmission

				var stats = new Stats.StatsBuilder()
						.withConfig(cipherConfig)
						.withNumFrames(frameCount)
						.withAvgFrameSize(cumulativeSize / frameCount)
						.withMovieSize(cumulativeSize)
						.withElapsedTime(duration)
						.withFrameRate(frameCount / duration)
						.withThroughPut((cumulativeSize / duration) / 1024)
						.build();
				stats.printStats();
			}
		}

		System.out.println("Stream ended.");
	}

	public enum MESSAGE_TYPE {
		FRAME, END
	}
}
