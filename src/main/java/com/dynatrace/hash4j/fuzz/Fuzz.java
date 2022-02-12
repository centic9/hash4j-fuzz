package com.dynatrace.hash4j.fuzz;

import com.dynatrace.hash4j.hashing.Hashing;


/**
 * This class provides a simple target for fuzzing the schemaless
 * metric parser with Jazzer
 *
 * It uses DatapointParserFactory.parse() calls to produce the
 */
public class Fuzz {
	public static void fuzzerTestOneInput(byte[] input) {
		Hashing.murmur3_128().hashToLong(input, (bytes, hashSink) -> hashSink.putBytes(bytes));
	}
}
