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

    public HashConstruction(CipherConfig cipherConfig) {
        super(cipherConfig);
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
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
        buffer = ByteBuffer.allocate(ciphertext.length + hash.length + 4);

        buffer.putInt(ciphertext.length);
        buffer.put(ciphertext);
        buffer.put(hash);
        return buffer.array();
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException {
        // public the encoded data into the ciphertext and the hash
        ByteBuffer buffer = ByteBuffer.wrap(cipherText);
        byte[] ciphertext = new byte[buffer.getInt()];
        buffer.get(ciphertext);

        byte[] hash = new byte[buffer.remaining()];
        buffer.get(hash);

        // Decrypt the ciphertext
        byte[] data = EncryptionTool.decrypt(cipherConfig, ciphertext);

        // Check the hash of the decrypted data
        IntegrityTool.checkIntegrity(cipherConfig, data, hash);

        // Split the decrypted data into the nonce and message
        buffer = ByteBuffer.wrap(data);

        int nonce = buffer.getInt();
        NonceProcessor.getInstance().receiveNonce(nonce);

        var plainText = new byte[buffer.remaining()];
        buffer.get(plainText);
        return plainText;
    }
}
