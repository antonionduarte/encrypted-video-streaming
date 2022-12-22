package config.parser.parser_objects;

public class ParsedCipherConfig {
    private final String cipher;
    private final String key;
    private final String iv;
    private final String integrity;
    private final String macKey;
    private final String integrityCheck;

    public ParsedCipherConfig(String cipher,
                              String key,
                              String iv,
                              String integrity,
                              String macKey,
                              String integrityCheck) {
        this.cipher = cipher;
        this.key = key;
        this.iv = iv;
        this.integrity = integrity;
        this.macKey = macKey;
        this.integrityCheck = integrityCheck;
    }

    public String getCipher() {
        return cipher;
    }

    public String getKey() {
        return key;
    }

    public String getIv() {
        return iv;
    }

    public String getIntegrity() {
        return integrity;
    }

    public String getMacKey() {
        return macKey;
    }

    public String getIntegrityCheck() {
        return integrityCheck;
    }
}