package handshake.messages;

import cryptotools.integrity.IntegrityTool;

import java.io.*;
import java.security.Key;

public interface Message {

	static byte[] msgBytesWithIntegrity(String macAlg, Key macKey, byte[] msg) throws IOException {
		var baos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(baos);

		byte[] integrityBytes = IntegrityTool.buildMacIntegrity(macAlg, macKey, msg);
		dos.writeInt(integrityBytes.length);
		dos.write(integrityBytes);
		dos.write(msg);

		return baos.toByteArray();
	}

	static boolean checkMsgBytesIntegrity(String macAlg, Key macKey, byte[] bytes) throws IOException {
		var dis = new DataInputStream(new ByteArrayInputStream(bytes));

		var integrityBytes = dis.readNBytes(dis.readInt());
		var msg = dis.readAllBytes();
		return IntegrityTool.checkMacIntegrity(macAlg, macKey, msg, integrityBytes);
	}

	byte[] encode(String macAlg, Key macKey) throws IOException;
}
