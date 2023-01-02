package config.parser.parser_objects;

public class ParsedCipherConfig {
    private final String cipher;
    private final String key;
    private final String iv;
    private final String integrity;
    private final String mackey;
    private String integrityCheck;

    public ParsedCipherConfig(String cipher,
                              String key,
                              String iv,
                              String integrity,
                              String mackey,
                              String integrityCheck) {
        this.cipher = cipher;
        this.key = key;
        this.iv = iv;
        this.integrity = integrity;
        this.mackey = mackey;
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

    public String getMackey() {
        return mackey;
    }

    public String getIntegrityCheck() {
        return integrityCheck;
    }

    public void setIntegrityCheck(String integrityCheck) {
        this.integrityCheck = integrityCheck;
    }
}