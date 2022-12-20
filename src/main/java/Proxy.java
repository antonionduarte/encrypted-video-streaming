import config.AsymmetricConfig;
import config.CipherConfig;
import config.HandshakeIntegrityConfig;
import config.SymmetricConfig;
import config.parser.ParseAsymmetricConfigList;
import config.parser.ParseHandshakeIntegrityConfig;
import config.parser.ParseSymmetricConfigList;
import cryptotools.certificates.CertificateChain;
import cryptotools.certificates.CertificateTool;
import cryptotools.integrity.IntegrityException;
import cryptotools.keystore.KeyStoreTool;
import handshake.RtssHandshake;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import securesocket.SecureDatagramPacket;
import securesocket.SecureSocket;
import statistics.Stats;
import utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

public class Proxy {
	private static final String PROPERTY_REMOTE = "remote";
	private static final String PROPERTY_DESTINATIONS = "localdelivery";

	private static final String CONFIG_PATH = "config/box/config.properties";
	private static final String ASYM_CONFIG_PATH = "config/box/asymmetric-config.json";
	private static final String SYM_CONFIG_PATH = "config/box/symmetric-config.json";
	private static final String INTEGRITY_CONFIG_PATH = "config/common/handshake-integrity.json";

	private static final String KEYSTORE_PASSWORD_ENV = "box_password";
	private static final String TRUSTSTORE_PASSWORD_ENV = "truststore_password";

	private static final String CA_ALIAS_MASK = "ca_%s_%d";
	private static final String BOX_ALIAS_MASK = "box_%s_%d";

	private static final String CERTIFICATE_PATH_MASK = "certs/box/box_%s_%d.cer";
	private static final String KEYSTORE_PATH = "certs/box/box.pkcs12";
	private static final String TRUSTSTORE_PATH = "certs/common/truststore.pkcs12";


	private static AsymmetricConfig readAsymConfig() throws IOException {
		// only need the first one
		var parsedConfig = new ParseAsymmetricConfigList(ASYM_CONFIG_PATH).parseConfig().get(0);
		return new AsymmetricConfig(parsedConfig);
	}

	private static List<SymmetricConfig> readSymConfigList() throws IOException {
		var parsedConfigList = new ParseSymmetricConfigList(SYM_CONFIG_PATH).parseConfig();
		return parsedConfigList.stream().map(config -> new SymmetricConfig(config)).collect(Collectors.toList());
	}

	private static HandshakeIntegrityConfig readIntegrityConfig() throws IOException {
		var parsedConfig = new ParseHandshakeIntegrityConfig(INTEGRITY_CONFIG_PATH).parseConfig();
		return new HandshakeIntegrityConfig(parsedConfig);
	}

	private static KeyPair readKeyPair(AsymmetricConfig config) {
		var alias = String.format(BOX_ALIAS_MASK, config.authentication, config.keySize);
		var password = System.getenv(KEYSTORE_PASSWORD_ENV);
		return KeyStoreTool.keyPairFromKeyStore(KEYSTORE_PATH, alias, password);
	}

	/**
	 * Reads the box and ca certificates, and returns a certificate chain object.
	 */
	private static CertificateChain readCertificates(AsymmetricConfig config) throws IOException, CertificateException {
		var path = String.format(CERTIFICATE_PATH_MASK, config.authentication, config.keySize);
		var boxCertificate = CertificateTool.certificateFromFile(path);

		var alias = String.format(CA_ALIAS_MASK, config.authentication, config.keySize);
		var password = System.getenv(TRUSTSTORE_PASSWORD_ENV);
		var caCertificate = CertificateTool.certificateFromTruststore(TRUSTSTORE_PATH, alias, password);
		return new CertificateChain(caCertificate, boxCertificate);
	}

	/**
	 * Performs the handshake using the RTSS Handshake Class.
	 */
	private static CipherConfig performHandshake(InetSocketAddress serverAddress) throws Exception {
		var asymConfig = readAsymConfig();
		var symConfigList = readSymConfigList();
		var integrityConfig = readIntegrityConfig();
		var keyPair = readKeyPair(asymConfig);
		var certificateChain = readCertificates(asymConfig);

		var handshake = new RtssHandshake(certificateChain, asymConfig, symConfigList, keyPair, integrityConfig);
		handshake.start(serverAddress);
		return handshake.decidedCipherSuite;
	}

	public static void main(String[] args) throws Exception {
		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("Proxy Running");

		var inputStream = new FileInputStream(CONFIG_PATH);
		var properties = new Properties();
		properties.load(inputStream);
		var remote = properties.getProperty(PROPERTY_REMOTE);
		var destinations = properties.getProperty(PROPERTY_DESTINATIONS);

		var inSocketAddress = Utils.parseSocketAddress(remote);
		var outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Utils::parseSocketAddress).collect(Collectors.toSet());

		//var cipherConfig = new CipherConfig(new ParseCipherConfigMap(json).parseConfig().values().iterator().next());
		var cipherConfig = performHandshake(inSocketAddress);

		try (SecureSocket inSocket = new SecureSocket(inSocketAddress)) {
			try (DatagramSocket outSocket = new DatagramSocket()) {
				byte[] buffer = new byte[4096]; // prev 8192

				int size;
				int cumulativeSize = 0;
				int frameCount = 0;
				long beginningTime = -1; // ref. time

				while (true) {
					SecureDatagramPacket inPacket = new SecureDatagramPacket(cipherConfig);
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
						.withThroughPut((8 * (cumulativeSize / duration)) / 1000000)
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
