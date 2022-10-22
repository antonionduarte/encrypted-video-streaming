package config.parser;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Map;

public class ParseCipherConfig {
	private final Gson gson;
	private final String json;

	public ParseCipherConfig(String config) {
		this.gson = new Gson();
		this.json = config;
	}

	public Map<String, CipherConfig> parseConfig() {
		Type mapType = new TypeToken<Map<String, CipherConfig>>() {
		}.getType();
		return gson.fromJson(json, mapType);
	}
}


