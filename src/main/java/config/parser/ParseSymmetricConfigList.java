package config.parser;

import com.google.gson.reflect.TypeToken;
import config.parser.parser_objects.ParsedAsymmetricConfig;
import config.parser.parser_objects.ParsedSymmetricConfig;

import java.lang.reflect.Type;
import java.util.List;

public class ParseSymmetricConfigList extends ParseConfig<List<ParsedSymmetricConfig>> {

	protected ParseSymmetricConfigList(String config) {
		super(config);
	}

	@Override
	public List<ParsedSymmetricConfig> parseConfig() {
		// Define the list's element type
		Type listType = new TypeToken<List<ParsedSymmetricConfig>>(){}.getType();

		// Deserialize the JSON string
		return gson.fromJson(json, listType);
	}

}
