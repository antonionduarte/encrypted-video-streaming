package config;

public record SymmetricConfig(String cipher, int keySize, String integrity, boolean isMac) {
}
