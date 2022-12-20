package handshake.messages;

import config.AsymmetricConfig;
import config.SymmetricConfig;
import cryptotools.certificates.CertificateChain;
import cryptotools.integrity.IntegrityException;

import java.io.*;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

public class FirstMessage implements Message {

	public final AsymmetricConfig asymConfig;
	public final List<SymmetricConfig> symConfigList;
	public final CertificateChain certChain;
	public final byte[] signature;

	public FirstMessage(AsymmetricConfig asymConfig, List<SymmetricConfig> symConfigList, CertificateChain certChain,
						byte[] signature) {
		this.asymConfig = asymConfig;
		this.symConfigList = symConfigList;
		this.certChain = certChain;
		this.signature = signature;
	}

	public static FirstMessage decode(String macAlg, Key macKey, byte[] bytes) throws IntegrityException, IOException {
		// integrity check
		if (Message.checkMsgBytesIntegrity(macAlg, macKey, bytes))
			throw new IntegrityException();

		var dis = new DataInputStream(new ByteArrayInputStream(bytes));
		//skip integrity
		dis.skipBytes(dis.readInt());

		// Read the AsymmetricConfig
		byte[] asymConfigBytes = dis.readNBytes(dis.readInt());
		var asymConfig = AsymmetricConfig.fromBytes(asymConfigBytes);

		// Read the List<SymmetricConfig>
		int symConfigListSize = dis.readInt();
		var symConfigList = new ArrayList<SymmetricConfig>(symConfigListSize);
		for (int i = 0; i < symConfigListSize; i++) {
			byte[] symConfigBytes = dis.readNBytes(dis.readInt());
			var symConfig = SymmetricConfig.fromBytes(symConfigBytes);
			symConfigList.add(symConfig);
		}

		// Read the CertificateChain
		byte[] certChainBytes = dis.readNBytes(dis.readInt());
		var certChain = CertificateChain.deserializeChain(certChainBytes);

		// Read the signature
		var signature = dis.readAllBytes();

		return new FirstMessage(asymConfig, symConfigList, certChain, signature);
	}

	@Override
	public byte[] encode(String macAlg, Key macKey) throws IOException {
		var baos = new ByteArrayOutputStream();
		var dos = new DataOutputStream(baos);

		// Write the AsymmetricConfig
		dos.writeInt(asymConfig.toBytes().length);
		dos.write(asymConfig.toBytes());

		// Write the List<SymmetricConfig>
		dos.writeInt(symConfigList.size());
		for (SymmetricConfig symConfig : symConfigList) {
			dos.writeInt(symConfig.toBytes().length);
			dos.write(symConfig.toBytes());
		}

		// Write the CertificateChain
		var certChainBytes = certChain.serializedChain();
		dos.writeInt(certChainBytes.length);
		dos.write(certChainBytes);

		// Write the signature
		dos.write(signature);

		return Message.msgBytesWithIntegrity(macAlg, macKey, baos.toByteArray());
	}
}
