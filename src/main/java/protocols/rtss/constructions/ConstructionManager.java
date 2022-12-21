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

public class ConstructionManager {

    private final CipherConfig cipherConfig;

    public ConstructionManager(CipherConfig cipherConfig) {
        this.cipherConfig = cipherConfig;
    }

    public byte[] noIntegrity(byte[] plainText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return new NoIntegrityConstruction(cipherConfig, plainText).encrypt();
    }
    public byte[] decryptNoIntegrity(byte[] cipherText) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, RepeatedMessageException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var construction = new NoIntegrityConstruction(cipherConfig);
        construction.decrypt(cipherText);
        return construction.plainText;
    }

}
