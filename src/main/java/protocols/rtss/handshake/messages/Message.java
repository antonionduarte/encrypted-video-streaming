package protocols.rtss.handshake.messages;

import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface Message {

	static byte[] msgBytesWithIntegrity(String macAlg, Key macKey, byte[] msg) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		var baos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(baos);

		byte[] integrityBytes = IntegrityTool.buildMacIntegrity(macAlg, macKey, msg);
		dos.writeInt(integrityBytes.length);
		dos.write(integrityBytes);
		dos.write(msg);

		return baos.toByteArray();
	}

	static void checkMsgBytesIntegrity(String macAlg, Key macKey, byte[] bytes) throws IOException, IntegrityException, NoSuchAlgorithmException, InvalidKeyException {
		var dis = new DataInputStream(new ByteArrayInputStream(bytes));

		var integrityBytes = dis.readNBytes(dis.readInt());
		var msg = dis.readAllBytes();
		IntegrityTool.checkMacIntegrity(macAlg, macKey, msg, integrityBytes);
	}

	byte[] serialize(String macAlg, Key macKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException;
}
