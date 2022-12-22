package utils;

import config.AsymmetricConfig;
import config.HandshakeIntegrityConfig;
import config.SymmetricConfig;
import config.parser.ParseAsymmetricConfigList;
import config.parser.ParseHandshakeIntegrityConfig;
import config.parser.ParseSymmetricConfigList;
import cryptotools.certificates.CertificateChain;
import cryptotools.certificates.CertificateTool;
import cryptotools.keystore.KeyStoreTool;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.stream.Collectors;

public class Loader {

    public static AsymmetricConfig readAsymConfig(String path) throws IOException {
        // only need the first one
        var parsedConfig = new ParseAsymmetricConfigList(path).parseConfig().get(0);
        return new AsymmetricConfig(parsedConfig);
    }

    public static List<AsymmetricConfig> readAsymConfigList(String path) throws IOException {
        // only need the first one
        var parsedConfigList = new ParseAsymmetricConfigList(path).parseConfig();
        return parsedConfigList.stream().map(config -> new AsymmetricConfig(config)).collect(Collectors.toList());
    }

    public static List<SymmetricConfig> readSymConfigList(String path) throws IOException {
        var parsedConfigList = new ParseSymmetricConfigList(path).parseConfig();
        return parsedConfigList.stream().map(config -> new SymmetricConfig(config)).collect(Collectors.toList());
    }

    public static HandshakeIntegrityConfig readIntegrityConfig(String path) throws IOException {
        var parsedConfig = new ParseHandshakeIntegrityConfig(path).parseConfig();
        return new HandshakeIntegrityConfig(parsedConfig);
    }

    public static KeyPair readKeyPair(String path, String alias, String password) {
        return KeyStoreTool.keyPairFromKeyStore(path, alias, password);
    }

    /**
     * Reads the proxy and ca certificates, and returns a certificate certificates object.
     */
    public static CertificateChain readCertificates(String path, KeyStore trustStore) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        var proxyCertificate = CertificateTool.certificateFromFile(path);

        var alias = proxyCertificate.getIssuerX500Principal().getName();
        var caCertificate = CertificateTool.certificateFromTruststore(trustStore, alias);
        return new CertificateChain(proxyCertificate, caCertificate);
    }
}
