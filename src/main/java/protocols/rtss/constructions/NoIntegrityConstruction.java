package protocols.rtss.constructions;

import config.CipherConfig;
import cryptotools.encryption.EncryptionTool;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.NonceProcessor;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

//E(nonce || M)
public class NoIntegrityConstruction extends Construction {
    protected NoIntegrityConstruction(CipherConfig cipherConfig, byte[] plainText) {
        super(cipherConfig);
        this.plainText = plainText;
    }

    protected NoIntegrityConstruction(CipherConfig cipherConfig) {
        super(cipherConfig);
    }

    @Override
    protected byte[] encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Concatenate the nonce and plaintext into a single byte array
        ByteBuffer buffer = ByteBuffer.allocate(4 + plainText.length);
        int nonce = NonceProcessor.getInstance().generateNonce();
        buffer.putInt(nonce);
        buffer.put(plainText);
        byte[] data = buffer.array();

        return EncryptionTool.encrypt(cipherConfig, data);
    }

    @Override
    protected void decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException {
        var plainTextWithNonce = EncryptionTool.decrypt(cipherConfig, cipherText);

        // Split the decrypted data into the nonce and message

        ByteBuffer buffer = ByteBuffer.wrap(plainTextWithNonce);
        var nonce = buffer.getInt();
        NonceProcessor.getInstance().receiveNonce(nonce);

        this.plainText = new byte[buffer.remaining()];
        buffer.get(plainText);
    }

    public byte[] getPlainText() {
        return plainText;
    }
}
