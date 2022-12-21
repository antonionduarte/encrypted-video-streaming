package protocols.rtss.constructions;

import config.CipherConfig;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.exceptions.RepeatedMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public abstract class Construction {

    protected final CipherConfig cipherConfig;
    protected byte[] plainText;

    protected Construction(CipherConfig cipherConfig, byte[] plainText) {
        this.cipherConfig = cipherConfig;
        this.plainText = plainText;
    }

    protected Construction(CipherConfig cipherConfig) {
        this.cipherConfig = cipherConfig;
    }

    protected abstract byte[] encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException;

    protected abstract void decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException;

    public byte[] getPlainText() {
        return plainText;
    }
}
