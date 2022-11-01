package statistics;/*
 * StreamingServerPrintStats.java
 * This is an auxiliary class to be used to obtain and to print
 * experimental observatons from instrumenation results for
 * streaming conditions, as measured dyamically by the
 * Streaming Server
 *
 * You must design and implement this, with the required methods
 * to print the rrquired statistics for the experimental evaluation of
 * different cryptographic configurations used for the required
 * RTSSP protocol
 */

// ..... Implement the code

// For the required statistics use this as reference for
// the observations you must print from your new Streaming Server
// implementation to support the RTSSP protocol

// PrintStats
// You must implement th code to compute and obtain
// the statistics and metrics for each received stream
// processed and delivered by the Box (to the media player)
// The idea is to capture the necessary instrumentation of
// received and processed streams using the input variables
// for PritStats to print (in the end of each streaming) the
// related experimental observations for practical analysis
// The idea is to capture the statistics below

import config.parser.CipherConfig;

import java.util.Arrays;

public class PrintStats {
	public static void printStats(CipherConfig config, int numFrames, int avgFrameSize, int movieSize, int elapsedTime,
								  int frameRate, int throughPut) {
		System.out.println("---------------------------------------------");
		System.out.println("Streaming Server observed Indicators and Statistics");
		System.out.println("---------------------------------------------");
		System.out.println("Streamed Movie and used Cryptographic Configs");
		System.out.println("---------------------------------------------");
		System.out.println("Used ciphersuite ALG/MODE/PADDING: " + config.getCipher());
		System.out.println("Used Key (hexadecimal rep.): " + Arrays.toString(config.getKey().getBytes()));
		System.out.println("Used Keysize: (bytes)" + config.getKey());
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
}