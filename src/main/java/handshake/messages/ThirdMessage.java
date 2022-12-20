package handshake.messages;

import cryptotools.integrity.IntegrityException;

import java.io.IOException;
import java.security.Key;

public class ThirdMessage implements Message {
	public static ThirdMessage decode(String macAlg, Key macKey, byte[] bytes) throws IOException, IntegrityException {
		return null;
	}

	//TODO
	@Override
	public byte[] encode(String macAlg, Key macKey) throws IOException {


		return new byte[0];
	}
}
