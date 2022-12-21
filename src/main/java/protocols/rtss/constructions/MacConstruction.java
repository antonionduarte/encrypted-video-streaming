package protocols.rtss.constructions;

import config.CipherConfig;
import cryptotools.encryption.EncryptionTool;
import cryptotools.integrity.IntegrityException;
import cryptotools.integrity.IntegrityTool;
import cryptotools.repetition.NonceProcessor;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

// X = nonce || E(k, M)
// msg = X || MAC(kmac, X)
public class MacConstruction extends Construction {

    public MacConstruction(CipherConfig cipherConfig) {
        super(cipherConfig);
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Encrypt the plaintext
        byte[] ciphertext = EncryptionTool.encrypt(cipherConfig, plainText);

        // Concatenate the nonce and ciphertext into a single byte array
        ByteBuffer buffer = ByteBuffer.allocate(4 + ciphertext.length);
        int nonce = NonceProcessor.getInstance().generateNonce();
        buffer.putInt(nonce);
        buffer.put(ciphertext);
        byte[] data = buffer.array();

        // Compute the MAC of the data
        byte[] macValue = IntegrityTool.buildMacIntegrity(cipherConfig.getIntegrity(), cipherConfig.getMacKey(), data);

        // Concatenate the data and the MAC value
        buffer = ByteBuffer.allocate(data.length + macValue.length + 4);
        buffer.putInt(data.length);
        buffer.put(data);
        buffer.put(macValue);
        return buffer.array();
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException {
        // Split the encoded data into the data and the MAC value
        ByteBuffer buffer = ByteBuffer.wrap(cipherText);
        byte[] data = new byte[buffer.getInt()];
        buffer.get(data);
        byte[] macValue = new byte[buffer.remaining()];
        buffer.get(macValue);

        // Check the MAC of the data
        IntegrityTool.checkIntegrity(cipherConfig, data, macValue);

        // Split the data into the nonce and ciphertext
        buffer = ByteBuffer.wrap(data);
        int nonce = buffer.getInt();
        NonceProcessor.getInstance().receiveNonce(nonce);

        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        // Decrypt the ciphertext
        return EncryptionTool.decrypt(cipherConfig, ciphertext);
    }
}
