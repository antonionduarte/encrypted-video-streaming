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

// X = nonce || M
// msg: E(k, X) || H(X)
public class HashConstruction extends Construction {

    protected HashConstruction(CipherConfig cipherConfig, byte[] plainText) {
        super(cipherConfig, plainText);
    }

    protected HashConstruction(CipherConfig cipherConfig) {
        super(cipherConfig);
    }

    @Override
    protected byte[] encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Convert the nonce to a byte array
        int nonce = NonceProcessor.getInstance().generateNonce();
        byte[] nonceBytes = ByteBuffer.allocate(4).putInt(nonce).array();

        // Concatenate the nonce and plainText into a single byte array
        ByteBuffer buffer = ByteBuffer.allocate(nonceBytes.length + plainText.length);
        buffer.put(nonceBytes);
        buffer.put(plainText);
        byte[] data = buffer.array();

        // Compute the hash of the data
        byte[] hash = IntegrityTool.buildHashIntegrity(cipherConfig.getIntegrity(), data);

        // Encrypt the data using the given key
        byte[] ciphertext = EncryptionTool.encrypt(cipherConfig, data);

        // Concatenate the ciphertext and the hash
        buffer = ByteBuffer.allocate(ciphertext.length + hash.length);
        buffer.put(ciphertext);
        buffer.put(hash);
        return buffer.array();
    }

    @Override
    protected void decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException {

    }
}
