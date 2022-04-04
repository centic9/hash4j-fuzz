package com.dynatrace.hash4j.fuzz;

import com.dynatrace.hash4j.hashing.Hashing;


/**
 * This class provides a simple target for fuzzing the hist4j package.
 *
 * Currently the library only provides an implementation of Murmur3 which
 * is tested here.
 */
public class Fuzz {
	public static void fuzzerTestOneInput(byte[] input) {
		Hashing.murmur3_128().hashToLong(input, (bytes, hashSink) -> hashSink.putBytes(bytes));

		Hashing.murmur3_32().hashBytesToInt(input);

		Hashing.wyhashFinal3().hashBytesToLong(input);

		Hashing.wyhashFinal3().hashBytesToInt(input);
	}
}
