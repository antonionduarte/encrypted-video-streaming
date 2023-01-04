package utils.cipherutils;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import config.CipherConfig;
import config.parser.ParseCipherConfigMap;
import cryptotools.integrity.IntegrityTool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.Utils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class GenerateIntegrityCheck {

	public static final String MOVIE_PATH = "movies/plain/";
	public static final String CIPHERED_MOVIE_PATH = "movies/ciphered/";
	public static final String MOVIE_CIPHER_CONFIG_PATH = "movies/plain/cryptoconfig.json";

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException {
		if (args.length != 0) {
			System.err.println("Use: GenerateMovieIntegrity");
			System.exit(-1);
		}

		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());

		var config = new ParseCipherConfigMap(MOVIE_CIPHER_CONFIG_PATH).parseConfig();

		for (var cipheredName : config.keySet()) {
			var split = cipheredName.split("\\.");
			var filename = split[0] + "." + split[1];
			var parsedConfig = config.get(cipheredName);
			var cipherConfig = new CipherConfig(parsedConfig);
			byte[] integrityBytes =
			(cipherConfig.getMacKey() == null) ?
				IntegrityTool.buildHashIntegrity(cipherConfig.getIntegrity(),
						Files.readAllBytes(Path.of(MOVIE_PATH + filename)))
			:
				IntegrityTool.buildMacIntegrity(cipherConfig.getIntegrity(), cipherConfig.getMacKey(),
						Files.readAllBytes(Path.of(CIPHERED_MOVIE_PATH + cipheredName)));
			parsedConfig.setIntegrityCheck(Utils.bytesToHex(integrityBytes));
		}

		var gson = new GsonBuilder()
				.setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_DASHES)
				.setPrettyPrinting()
				.create();
		var jsonBytes = gson.toJson(config).getBytes();

		try (FileOutputStream fileOutputStream = new FileOutputStream(MOVIE_CIPHER_CONFIG_PATH)) {
			fileOutputStream.write(jsonBytes);
		}
	}
}
