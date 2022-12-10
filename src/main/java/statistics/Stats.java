package statistics;

import config.parser.CipherConfig;

import java.util.HexFormat;

public class Stats {
	private final CipherConfig config;
	private final int numFrames;
	private final int avgFrameSize;
	private final int movieSize;
	private final int elapsedTime;
	private final int frameRate;
	private final int throughPut;

	public Stats(CipherConfig config, int numFrames, int avgFrameSize, int movieSize, int elapsedTime, int frameRate, int throughPut) {
		this.config = config;
		this.numFrames = numFrames;
		this.avgFrameSize = avgFrameSize;
		this.movieSize = movieSize;
		this.elapsedTime = elapsedTime;
		this.frameRate = frameRate;
		this.throughPut = throughPut;
	}

	private Stats(StatsBuilder builder) {
		this.config = builder.config;
		this.numFrames = builder.numFrames;
		this.avgFrameSize = builder.avgFrameSize;
		this.movieSize = builder.movieSize;
		this.elapsedTime = builder.elapsedTime;
		this.frameRate = builder.frameRate;
		this.throughPut = builder.throughPut;
	}

	public void printStats() {
		System.out.println("---------------------------------------------");
		System.out.println("Streaming Server observed Indicators and Statistics");
		System.out.println("---------------------------------------------");
		System.out.println("Streamed Movie and used Cryptographic Configs");
		System.out.println("---------------------------------------------");
		System.out.println("Used ciphersuite ALG/MODE/PADDING: " + config.getCipher());
		System.out.println("Used Key (hexadecimal rep.): " + HexFormat.of().formatHex(config.getKey().getBytes()));
		System.out.println("Used Keysize: (bytes)" + config.getKey().length());
		System.out.println("Used Hash or Mac for integrity checks: " + config.getIntegrity());
		System.out.println();
		System.out.println("---------------------------------------------");
		System.out.println("Performance indicators of streaming");
		System.out.println("delivered to receiver Box(es)");
		System.out.println("---------------------------------------------");
		System.out.println("Nr of sent frames: " + numFrames);
		System.out.println("Average frame size (bytes): " + avgFrameSize);
		System.out.println("Movie size sent (all frames): " + movieSize);
		System.out.println("Total elapsed time of streamed movie (sec): " + elapsedTime);
		System.out.println("Average sent frame rate (frames/sec): " + frameRate);
		System.out.println("Observed throughput (KBytes/sec): " + throughPut);
	}

	public static class StatsBuilder {
		private CipherConfig config;
		private int numFrames;
		private int avgFrameSize;
		private int movieSize;
		private int elapsedTime;
		private int frameRate;
		private int throughPut;

		public StatsBuilder withConfig(CipherConfig config) {
			this.config = config;
			return this;
		}

		public StatsBuilder withNumFrames(int numFrames) {
			this.numFrames = numFrames;
			return this;
		}

		public StatsBuilder withAvgFrameSize(int avgFrameSize) {
			this.avgFrameSize = avgFrameSize;
			return this;
		}

		public StatsBuilder withMovieSize(int movieSize) {
			this.movieSize = movieSize;
			return this;
		}

		public StatsBuilder withElapsedTime(int elapsedTime) {
			this.elapsedTime = elapsedTime;
			return this;
		}

		public StatsBuilder withFrameRate(int frameRate) {
			this.frameRate = frameRate;
			return this;
		}

		public StatsBuilder withThroughPut(int throughPut) {
			this.throughPut = throughPut;
			return this;
		}

		public Stats build() {
			return new Stats(this);
		}
	}
}