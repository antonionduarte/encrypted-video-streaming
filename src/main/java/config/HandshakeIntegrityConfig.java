package config;

import config.parser.parser_objects.ParsedHandshakeIntegrityConfig;
import utils.Utils;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class HandshakeIntegrityConfig {

    public String algorithm;
    public Key macKey;

    public HandshakeIntegrityConfig(ParsedHandshakeIntegrityConfig config) {
        this.algorithm = config.algorithm();
        this.macKey = new SecretKeySpec(Utils.hexToBytes(config.macKey()), algorithm);
    }
}
