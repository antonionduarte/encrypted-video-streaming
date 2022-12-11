package utils.cipherutils;

import config.CipherConfig;
import config.parser.ParseCipherConfig;
import cryptotools.CryptoException;
import cryptotools.encryption.EncryptionTool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

public class EncryptMovies {
	public static final String MOVIE_PATH = "movies/plain/";
	public static final String CIPHERED_MOVIE_PATH = "movies/ciphered/";
	public static final String MOVIE_CIPHER_CONFIG_PATH = "movies/plain/cryptoconfig.json";

	public static byte[] decryptMovie(CipherConfig config, String filename) throws CryptoException, IOException {
		return EncryptionTool.decrypt(config, Files.readAllBytes(Path.of(filename)));
	}

	public static void main(String[] args) throws IOException, CryptoException {
		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());

		try (FileInputStream fileInputStream = new FileInputStream(MOVIE_CIPHER_CONFIG_PATH)) {
			var configJson = new String(fileInputStream.readAllBytes());
			var config = new ParseCipherConfig(configJson).parseConfig();

			for (var cipheredName : config.keySet()) {
				var split = cipheredName.split("\\.");
				var filename = split[0] + "." + split[1];
				var cipherConfig = config.get(cipheredName);
				var outputBytes = EncryptionTool.encrypt(cipherConfig, Files.readAllBytes(Path.of(MOVIE_PATH + filename)));
				EncryptConfig.writeToFile(outputBytes, new File(CIPHERED_MOVIE_PATH + cipheredName));
			}
		}
	}
}
