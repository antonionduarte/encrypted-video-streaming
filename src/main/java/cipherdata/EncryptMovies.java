package cipherdata;

import config.parser.ParseCipherConfig;
import encryptiontool.CryptoException;
import encryptiontool.EncryptionTool;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class EncryptMovies {

	public static final String MOVIE_PATH = "movies/plain/";
	public static final String CIPHERED_MOVIE_PATH = "movies/ciphered/";
	public static final String MOVIE_CIPHER_CONFIG_PATH = "movies/plain/cryptoconfig.json";

	public static void main(String[] args) throws IOException, CryptoException {
		try (FileInputStream fileInputStream = new FileInputStream(MOVIE_CIPHER_CONFIG_PATH)) {
			var configJson = new String(fileInputStream.readAllBytes());
			var config = new ParseCipherConfig(configJson).parseConfig();

			for (var cipheredName : config.keySet()) {
				var split = cipheredName.split("\\.");
				var filename = split[0] + "." + split[1];
				var cipherConfig = config.get(cipheredName);
				var key = cipherConfig.getKey();
				var iv = cipherConfig.getIv().getBytes();
				var cipher = cipherConfig.getCipher();
				var outputBytes = EncryptionTool.encrypt(key, iv, cipher, new File(MOVIE_PATH + filename));
				EncryptConfig.writeToFile(outputBytes, new File(CIPHERED_MOVIE_PATH + cipheredName));
			}
		}
	}
}
