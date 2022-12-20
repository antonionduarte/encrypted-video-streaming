import config.CipherConfig;
import config.parser.ParseCipherConfigMap;
import cryptotools.certificates.CertificateChain;
import cryptotools.certificates.CertificateTool;
import cryptotools.integrity.IntegrityException;
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
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;
import java.util.stream.Collectors;

public class Proxy {
	private static final String PROPERTY_REMOTE = "remote";
	private static final String PROPERTY_DESTINATIONS = "localdelivery";
	private static final String CONFIG_PATH = "config/proxy/config.properties";
	private static final String STREAM_CIPHER_CONFIG_PATH = "config/box-cryptoconfig.json";
	//TODO beware the masks
	private static final String BOX_CERTIFICATE_PATH = "certs/box/box_%s_%d.cer";
	private static final String CA_CERTIFICATE_PATH = "certs/common/ca_%s_%d.cer";



	/**
	 * Reads the box and ca certificates, and returns a certificate chain object.
	 */
	private static CertificateChain readCertificates() throws IOException, CertificateException {
		var boxCertificate = CertificateTool.certificateFromBytes(Utils.getFileBytes(BOX_CERTIFICATE_PATH));
		//TODO get cacert from trustore
		var caCertificate = CertificateTool.certificateFromBytes(Utils.getFileBytes(CA_CERTIFICATE_PATH));
		return new CertificateChain(new X509Certificate[]{boxCertificate, caCertificate});
	}

	/**
	 * Performs the handshake using the RTSS Handshake Class.
	 */
	private static CipherConfig performHandshake(InetSocketAddress serverAddress) throws Exception {
		var certificateChain = readCertificates();
		// TODO get other stuff to handshake
		var handshake = new RtssHandshake(certificateChain);
		handshake.start(serverAddress);
		// TODO: get cipherconfig from secret
		return null;
	}

	public static void main(String[] args) throws Exception {
		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("Proxy Running");

		var inputStream = new FileInputStream(CONFIG_PATH);
		var properties = new Properties();
		var remote = properties.getProperty(PROPERTY_REMOTE);
		var destinations = properties.getProperty(PROPERTY_DESTINATIONS);

		properties.load(inputStream);

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
