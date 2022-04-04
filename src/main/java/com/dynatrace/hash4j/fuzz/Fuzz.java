package com.dynatrace.hash4j.fuzz;

import com.dynatrace.hash4j.hashing.*;


/**
 * This class provides a simple target for fuzzing the hist4j package.
 *
 * Currently the library only provides an implementation of Murmur3 which
 * is tested here.
 */
public class Fuzz {
	public static void fuzzerTestOneInput(byte[] input) {
		Hasher128 hasher128 = Hashing.murmur3_128();
		HashFunnel<byte[]> hashFunnel = (bytes, hashSink) -> hashSink.putBytes(bytes);
		hasher128.hashToLong(input, hashFunnel);
		hasher128.hashToLong(input, hashFunnel);

		hasher128.hashBytesToInt(input);
		hasher128.hashBytesToInt(input);

		Hasher32 hasher32 = Hashing.murmur3_32();
		hasher32.hashBytesToInt(input);
		hasher32.hashBytesToInt(input);

		Hasher64 hasher64Long = Hashing.wyhashFinal3();
		hasher64Long.hashBytesToLong(input);
		hasher64Long.hashBytesToLong(input);

		Hasher64 hasher64Int = Hashing.wyhashFinal3();
		hasher64Int.hashBytesToInt(input);
		hasher64Int.hashBytesToInt(input);
	}
}
