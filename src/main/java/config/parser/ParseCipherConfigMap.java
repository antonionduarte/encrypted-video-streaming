package config.parser;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import config.parser.parser_objects.ParsedCipherConfig;

import java.lang.reflect.Type;
import java.util.Map;

public class ParseCipherConfigMap implements ParseConfig<Map<String, ParsedCipherConfig>> {
	private final Gson gson;
	private final String json;

	public ParseCipherConfigMap(String config) {
		this.gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_DASHES).create();
		this.json = config;
	}

	public Map<String, ParsedCipherConfig> parseConfig() {
		Type mapType = new TypeToken<Map<String, ParsedCipherConfig>>() {}.getType();
		return gson.fromJson(json, mapType);
	}
}


