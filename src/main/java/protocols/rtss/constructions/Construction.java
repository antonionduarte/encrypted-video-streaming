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

    protected Construction(CipherConfig cipherConfig) {
        this.cipherConfig = cipherConfig;
    }

    public abstract byte[] encrypt(byte[] plainText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException;

    public abstract byte[] decrypt(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException;
}
