package protocols.rtss;

import config.CipherConfig;
import cryptotools.encryption.EncryptionTool;
import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;
import cryptotools.repetition.NonceProcessor;
import protocols.SecureProtocol;
import protocols.rtss.constructions.ConstructionManager;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class RtssProtocol extends SecureProtocol {

    private final ConstructionManager constructions;

    public RtssProtocol(CipherConfig cipherConfig) {
        super(cipherConfig);
        this.constructions = new ConstructionManager(cipherConfig);
    }

    @Override
    public byte[] encrypt(byte[] data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Generate nonce
        var nonce = NonceProcessor.getInstance().generateNonce();

        byte[] encryptedData;
        // NONE (could be using GCM mode)
        // E(k, nonce || M)
        if (cipherConfig.getIntegrity() == null) {
            ByteBuffer.wrap(encryptedData).putInt(nonce).put()
            return E
        }
        // HASH
        //
        else if (cipherConfig.getIntegrity() != null && cipherConfig.getMacKey() == null) {

        }
        // MAC

        else {

        }



        // Format: nonce || M
        var plainTextWithNonce = new byte[4 + data.length];
        ByteBuffer.wrap(plainTextWithNonce).putInt(nonce).put(data);

        // Format: E(k, nonce || M)
        var cipherText = EncryptionTool.encrypt(cipherConfig, plainTextWithNonce);

        // Format: size(E(k, nonce || M)) || E(k, nonce || M)
        var cipherTextWithSize = new byte[4 + cipherText.length];
        ByteBuffer.wrap(cipherTextWithSize).putInt(cipherText.length).put(cipherText);

        // Format: size(E(k, nonce || M)) || E(k, nonce || M) || ( MAC(E(k, nonce || M)) or H(nonce || M) )
        byte[] encryptedData;
        if (cipherConfig.getIntegrity() != null) {
            byte[] integrity;
            if (cipherConfig.getMacKey() != null)
                integrity = IntegrityTool.buildMacIntegrity(cipherConfig.getIntegrity(), cipherConfig.getMacKey(), cipherText);
            else
                integrity = IntegrityTool.buildHashIntegrity(cipherConfig.getIntegrity(), plainTextWithNonce);
            encryptedData =  new byte[cipherTextWithSize.length + integrity.length];
            ByteBuffer.wrap(encryptedData).put(cipherTextWithSize).put(integrity);
        } else {
            encryptedData = cipherTextWithSize;
        }

        return encryptedData;
    }



    @Override
    public byte[] decrypt(byte[] encryptedData, int len) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var dis = new DataInputStream(new ByteArrayInputStream(encryptedData, 0, len));
        var size = dis.readInt();
        var cipherText = dis.readNBytes(size);
        var integrity = dis.readAllBytes();

        var plainText = EncryptionTool.decrypt(cipherConfig, cipherText);

        // Check integrity
        if (cipherConfig.getMacKey() != null) {
            IntegrityTool.checkIntegrity(cipherConfig, cipherText, integrity);
        } else if (cipherConfig.getIntegrity() != null) {
            IntegrityTool.checkIntegrity(cipherConfig, plainText, integrity);
        }

        // Check nonce
        var nonceInputStream = new DataInputStream(new ByteArrayInputStream(plainText));
        var nonce = nonceInputStream.readInt();
        if (!receivedNonces.add(nonce)) {
            throw new IntegrityException();
        }
    }
}
