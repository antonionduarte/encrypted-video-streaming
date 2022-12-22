package config.parser.parser_objects;

public class ParsedAsymmetricConfig {
    private final String authentication;
    private final int keySize;
    private final String keyExchange;
    private final int numSize;
    private final String g;
    private final String p;

    public ParsedAsymmetricConfig(String authentication,
                                  int keySize,
                                  String keyExchange,
                                  int numSize,
                                  String g,
                                  String p) {
        this.authentication = authentication;
        this.keySize = keySize;
        this.keyExchange = keyExchange;
        this.numSize = numSize;
        this.g = g;
        this.p = p;
    }

    public String getAuthentication() {
        return authentication;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getKeyExchange() {
        return keyExchange;
    }

    public int getNumSize() {
        return numSize;
    }

    public String getG() {
        return g;
    }

    public String getP() {
        return p;
    }
}