package config.parser;

import config.parser.parser_objects.ParsedHandshakeIntegrityConfig;

import java.io.IOException;

public class ParseHandshakeIntegrityConfig extends ParseConfig<ParsedHandshakeIntegrityConfig> {
	public ParseHandshakeIntegrityConfig(String jsonConfigPath) throws IOException {
		super(jsonConfigPath);
	}

	@Override
	public ParsedHandshakeIntegrityConfig parseConfig() {
		return gson.fromJson(json, ParsedHandshakeIntegrityConfig.class);
	}
}
