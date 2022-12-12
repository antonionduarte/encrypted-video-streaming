package config.parser;

public interface ParseConfig<T> {

	/**
	 * Parses the config file and returns a correctly formatted config (or collection of) objects.
	 * @return A correctly formatted config (or collection of) objects.
	 */
	public T parseConfig();

}
