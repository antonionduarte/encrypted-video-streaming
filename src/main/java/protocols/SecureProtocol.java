package protocols;

import config.CipherConfig;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public abstract class SecureProtocol {

    protected final CipherConfig cipherConfig;

    protected SecureProtocol(CipherConfig cipherConfig) {
        this.cipherConfig = cipherConfig;
    }

    public abstract byte[] encrypt(byte[] data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException;

    public abstract byte[] decrypt(byte[] encryptedData) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException;
}
