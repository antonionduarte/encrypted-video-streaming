package config.parser.parser_objects;

public record ParsedAsymmetricConfig(String authentication,
                                     int keySize,
                                     String keyExchange,
                                     int numSize,
                                     String G,
                                     String p) {
}
