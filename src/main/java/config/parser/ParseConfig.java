package config.parser;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import utils.Utils;

import java.io.IOException;

public abstract class ParseConfig<T> {

	protected final Gson gson;
	protected final String json;

	protected ParseConfig(String jsonConfigPath) throws IOException {
		this.gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_DASHES).create();
		this.json = new String(Utils.getFileBytes(jsonConfigPath));
	}

	/**
	 * Parses the config file and returns a correctly formatted config (or collection of) objects.
	 *
	 * @return A correctly formatted config (or collection of) objects.
	 */
	public abstract T parseConfig();
}
