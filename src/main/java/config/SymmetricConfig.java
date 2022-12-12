package config;

public record SymmetricConfig(String cipher, int keySize, int ivSize, String integrity, int mackeySize) {
}
