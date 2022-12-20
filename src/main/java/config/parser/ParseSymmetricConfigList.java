package config.parser;

import com.google.gson.reflect.TypeToken;
import config.parser.parser_objects.ParsedSymmetricConfig;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.List;

public class ParseSymmetricConfigList extends ParseConfig<List<ParsedSymmetricConfig>> {

	public ParseSymmetricConfigList(String jsonConfigPath) throws IOException {
		super(jsonConfigPath);
	}

	@Override
	public List<ParsedSymmetricConfig> parseConfig() {
		// Define the list's element type
		Type listType = new TypeToken<List<ParsedSymmetricConfig>>() {
		}.getType();

		// Deserialize the JSON string
		return gson.fromJson(json, listType);
	}
}
