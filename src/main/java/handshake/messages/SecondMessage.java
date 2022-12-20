package handshake.messages;

import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;

import java.io.*;
import java.security.Key;
import java.security.cert.CertificateEncodingException;

public class SecondMessage implements Message {

	public final SymmetricConfig symConfig;
	public final CertificateChain certChain;
	public final byte[] signature;

	public SecondMessage(SymmetricConfig symConfig, CertificateChain certChain, byte[] signature) {
		this.symConfig = symConfig;
		this.certChain = certChain;
		this.signature = signature;
	}


	@Override
	public byte[] encode(String macAlg, Key macKey) throws IOException {
		byte[] symConfigBytes = symConfig.toBytes();
		byte[] certChainBytes = certChain.serializedChain();

		// Create a ByteArrayOutputStream
		var baos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(baos);

		// Write the SymmetricConfig
		dos.writeInt(symConfigBytes.length);
		dos.write(symConfigBytes);

		// Write the CertificateChain
		dos.writeInt(certChainBytes.length);
		dos.write(certChainBytes);

		// Write the signature
		dos.write(signature);

		return Message.msgBytesWithIntegrity(macAlg, macKey, baos.toByteArray());
	}

	public static SecondMessage decode(String macAlg, Key macKey, byte[] bytes) throws IOException, IntegrityException {
		// integrity check
		if (Message.checkMsgBytesIntegrity(macAlg, macKey, bytes))
			throw new IntegrityException();

		var dis = new DataInputStream(new ByteArrayInputStream(bytes));
		//skip integrity
		dis.skipBytes(dis.readInt());

		// Read the SymmetricConfig
		byte[] symConfigBytes = dis.readNBytes(dis.readInt());
		var symConfig = SymmetricConfig.fromBytes(symConfigBytes);

		// Read the CertificateChain
		byte[] certChainBytes = dis.readNBytes(dis.readInt());
		var certChain = CertificateChain.deserializeChain(certChainBytes);

		// Read the signature
		byte[] signature = dis.readAllBytes();

		return new SecondMessage(symConfig, certChain, signature);
	}
}
