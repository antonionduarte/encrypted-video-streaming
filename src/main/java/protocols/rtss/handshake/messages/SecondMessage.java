package protocols.rtss.handshake.messages;

import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.NonceProcessor;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public record SecondMessage(SymmetricConfig symConfig, CertificateChain certChain,
							byte[] pubNumBytes, byte[] signature) implements Message {

	public static SecondMessage deserialize(String macAlg, Key macKey, byte[] bytes) throws IOException, IntegrityException, RepeatedMessageException, NoSuchAlgorithmException, InvalidKeyException {
		// integrity check
		Message.checkMsgBytesIntegrity(macAlg, macKey, bytes);

		var dis = new DataInputStream(new ByteArrayInputStream(bytes));
		//skip integrity
		dis.skipBytes(dis.readInt());

		// Read and process the nonce
		NonceProcessor.getInstance().receiveNonce(dis.readInt());

		// Read the SymmetricConfig
		byte[] symConfigBytes = dis.readNBytes(dis.readInt());
		var symConfig = SymmetricConfig.deserialize(symConfigBytes);

		// Read the CertificateChain
		byte[] certChainBytes = dis.readNBytes(dis.readInt());
		var certChain = CertificateChain.deserialize(certChainBytes);

		// Read the pubNum
		byte[] pubNumBytes = dis.readNBytes(dis.readInt());

		// Read the signature
		byte[] signature = dis.readAllBytes();

		return new SecondMessage(symConfig, certChain, pubNumBytes, signature);
	}

	@Override
	public byte[] serialize(String macAlg, Key macKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		byte[] symConfigBytes = symConfig.serialize();
		byte[] certChainBytes = certChain.serialize();

		// Create a ByteArrayOutputStream
		var baos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(baos);

		// Write the nonce
		dos.writeInt(NonceProcessor.getInstance().generateNonce());

		// Write the SymmetricConfig
		dos.writeInt(symConfigBytes.length);
		dos.write(symConfigBytes);

		// Write the CertificateChain
		dos.writeInt(certChainBytes.length);
		dos.write(certChainBytes);

		// Write the pubNum
		dos.writeInt(pubNumBytes.length);
		dos.write(pubNumBytes);

		// Write the signature
		dos.write(signature);

		return Message.msgBytesWithIntegrity(macAlg, macKey, baos.toByteArray());
	}
}