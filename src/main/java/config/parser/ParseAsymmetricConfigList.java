package config.parser;

import com.google.gson.reflect.TypeToken;
import config.parser.parser_objects.ParsedAsymmetricConfig;

import java.lang.reflect.Type;
import java.util.List;

public class ParseAsymmetricConfigList extends ParseConfig<List<ParsedAsymmetricConfig>> {

	protected ParseAsymmetricConfigList(String config) {
		super(config);
	}

	@Override
	public List<ParsedAsymmetricConfig> parseConfig() {
		// Define the list's element type
		Type listType = new TypeToken<List<ParsedAsymmetricConfig>>(){}.getType();

		// Deserialize the JSON string
		return gson.fromJson(json, listType);
	}

}
