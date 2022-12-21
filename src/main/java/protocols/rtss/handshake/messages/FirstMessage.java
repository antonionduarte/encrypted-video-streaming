package protocols.rtss.handshake.messages;

import config.AsymmetricConfig;
import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.NonceProcessor;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public record FirstMessage(AsymmetricConfig asymConfig, List<SymmetricConfig> symConfigList, CertificateChain certChain,
                           byte[] pubNumBytes, byte[] signature) implements Message {

	public static FirstMessage deserialize(String macAlg, Key macKey, byte[] bytes) throws IntegrityException, IOException, RepeatedMessageException, NoSuchAlgorithmException, InvalidKeyException {
		// integrity check
		Message.checkMsgBytesIntegrity(macAlg, macKey, bytes);

		var dis = new DataInputStream(new ByteArrayInputStream(bytes));
		//skip integrity
		dis.skipBytes(dis.readInt());

		// Read and process the nonce
		NonceProcessor.getInstance().receiveNonce(dis.readInt());

		// Read the AsymmetricConfig
		byte[] asymConfigBytes = dis.readNBytes(dis.readInt());
		var asymConfig = AsymmetricConfig.deserialize(asymConfigBytes);

		// Read the List<SymmetricConfig>
		int symConfigListSize = dis.readInt();
		var symConfigList = new ArrayList<SymmetricConfig>(symConfigListSize);
		for (int i = 0; i < symConfigListSize; i++) {
			byte[] symConfigBytes = dis.readNBytes(dis.readInt());
			var symConfig = SymmetricConfig.deserialize(symConfigBytes);
			symConfigList.add(symConfig);
		}

		// Read the CertificateChain
		byte[] certChainBytes = dis.readNBytes(dis.readInt());
		var certChain = CertificateChain.deserialize(certChainBytes);

		// Read the pubNum
		byte[] pubNumBytes = dis.readNBytes(dis.readInt());

		// Read the signature
		var signature = dis.readAllBytes();

		return new FirstMessage(asymConfig, symConfigList, certChain, pubNumBytes, signature);
	}

	@Override
	public byte[] serialize(String macAlg, Key macKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		var byteArrayOutputStream = new ByteArrayOutputStream();
		var dataOutputStream = new DataOutputStream(byteArrayOutputStream);

		// Write the nonce
		dataOutputStream.writeInt(NonceProcessor.getInstance().generateNonce());

		// Write the AsymmetricConfig
		dataOutputStream.writeInt(asymConfig.serialize().length);
		dataOutputStream.write(asymConfig.serialize());

		// Write the List<SymmetricConfig>
		dataOutputStream.writeInt(symConfigList.size());
		for (SymmetricConfig symConfig : symConfigList) {
			dataOutputStream.writeInt(symConfig.serialize().length);
			dataOutputStream.write(symConfig.serialize());
		}

		// Write the CertificateChain
		var certChainBytes = certChain.serialize();
		dataOutputStream.writeInt(certChainBytes.length);
		dataOutputStream.write(certChainBytes);

		// Write the pubNum
		dataOutputStream.writeInt(pubNumBytes.length);
		dataOutputStream.write(pubNumBytes);

		// Write the signature
		dataOutputStream.write(signature);

		return Message.msgBytesWithIntegrity(macAlg, macKey, byteArrayOutputStream.toByteArray());
	}
}
