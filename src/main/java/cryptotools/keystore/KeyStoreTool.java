package cryptotools.keystore;

import javax.imageio.IIOException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreTool {

    private static final String KEYSTORE_TYPE = "PKCS12";

    public static KeyPair keyPairFromKeyStore(String keyStorePath, String alias, String password) {
        try {
            // load the KeyStore
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            var is = new FileInputStream(keyStorePath);
            keyStore.load(is, password.toCharArray());

            // get the private key
            var privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

            // get the public key
            var cert = keyStore.getCertificate(alias);
            var publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, privateKey);
        } catch (CertificateException | UnrecoverableKeyException | KeyStoreException | IOException |
                 NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static KeyStore getTrustStore(String truststorePath, String password) throws
            IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
        FileInputStream trustStoreInputStream = new FileInputStream(truststorePath);
        trustStore.load(trustStoreInputStream, password.toCharArray());
        trustStoreInputStream.close();
        return trustStore;
    }
}
