package config.parser;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import config.parser.parser_objects.ParsedCipherConfig;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

public class ParseCipherConfigMap extends ParseConfig<Map<String, ParsedCipherConfig>> {

	public ParseCipherConfigMap(String jsonConfigPath) throws IOException {
		super(jsonConfigPath);
	}

	public Map<String, ParsedCipherConfig> parseConfig() {
		Type mapType = new TypeToken<Map<String, ParsedCipherConfig>>() {}.getType();
		return gson.fromJson(json, mapType);
	}
}


