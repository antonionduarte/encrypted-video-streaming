package utils.cipherutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

public class GenerateIntegrityCheck {

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException {
		if (args.length < 2 || args.length > 3) {
			System.err.println("Use: java cipherdata.GenerateMovieIntegrity <mac|digest alg> <binary> <mackey?>");
			System.exit(-1);
		}

		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());

		byte[] result;
		var alg = args[0];
		var fileData = Files.readAllBytes(Path.of(args[1]));

		if (args.length == 2) {
			var hash = MessageDigest.getInstance(alg);
			hash.update(fileData);
			result = hash.digest();
		} else {
			var keyBytes = args[2].getBytes();
			var mac = Mac.getInstance(alg);
			var mackey = new SecretKeySpec(keyBytes, alg);
			mac.init(mackey);
			mac.update(fileData);
			result = mac.doFinal();
		}
		System.out.println(Base64.getEncoder().encodeToString(result));

	}
}
