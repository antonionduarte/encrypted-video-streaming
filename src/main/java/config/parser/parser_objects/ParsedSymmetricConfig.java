package config.parser.parser_objects;

public record ParsedSymmetricConfig(String cipher,
                                    int keySize,
                                    String integrity,
                                    int macKeySize,
                                    int ivSize) {
}
