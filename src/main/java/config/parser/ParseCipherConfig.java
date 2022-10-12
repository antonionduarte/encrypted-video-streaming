package config.parser;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Map;

public class ParseCryptoConfig {
	private final Gson gson;
	private final String json;

	public ParseCryptoConfig(String config) {
		this.gson = new Gson();
		this.json = config;
	}

	public Map<String, CryptoConfig> parseConfig() {
		Type mapType = new TypeToken<Map<String, CryptoConfig>>() {}.getType();
		return gson.fromJson(json, mapType);
	}
}


