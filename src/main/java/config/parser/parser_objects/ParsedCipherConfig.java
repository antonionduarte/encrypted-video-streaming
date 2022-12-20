package config.parser.parser_objects;

public record ParsedCipherConfig(String cipher,
								 String key,
								 String iv,
								 String integrity,
								 String macKey,
								 String integrityCheck) {
}
