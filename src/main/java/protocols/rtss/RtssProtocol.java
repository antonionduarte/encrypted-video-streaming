package protocols.rtss;

import config.CipherConfig;
import cryptotools.integrity.IntegrityException;
import cryptotools.repetition.exceptions.RepeatedMessageException;
import protocols.SecureProtocol;
import protocols.rtss.constructions.HashConstruction;
import protocols.rtss.constructions.MacConstruction;
import protocols.rtss.constructions.NoIntegrityConstruction;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class RtssProtocol extends SecureProtocol {

    public RtssProtocol(CipherConfig cipherConfig) {
        super(cipherConfig);
    }

    @Override
    public byte[] encrypt(byte[] data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (cipherConfig.getIntegrity() == null) {
            return new NoIntegrityConstruction(cipherConfig).encrypt(data);
        } else if (cipherConfig.getIntegrity() != null && cipherConfig.getMacKey() == null) {
            return new HashConstruction(cipherConfig).encrypt(data);
        } else {
            return new MacConstruction(cipherConfig).encrypt(data);
        }
    }



    @Override
    public byte[] decrypt(byte[] encryptedData) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IntegrityException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, RepeatedMessageException {
        if (cipherConfig.getIntegrity() == null) {
            return new NoIntegrityConstruction(cipherConfig).decrypt(encryptedData);
        } else if (cipherConfig.getIntegrity() != null && cipherConfig.getMacKey() == null) {
            return new HashConstruction(cipherConfig).decrypt(encryptedData);
        } else {
            return new MacConstruction(cipherConfig).decrypt(encryptedData);
        }
    }
}
