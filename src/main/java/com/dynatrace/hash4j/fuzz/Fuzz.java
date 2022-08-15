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
		hash128(hasher128, input);

		Hasher64 hasher64Long = Hashing.wyhashFinal3();
		hash64(hasher64Long, input);

		Hasher64 komihash64Long = Hashing.komihash4_3();
		hash64(komihash64Long, input);

		Hasher32 hasher32 = Hashing.murmur3_32();
		hash32(hasher32, input);
	}

	private static void hash128(Hasher128 hasher, byte[] input) {
		hasher.hashBytesTo128Bits(input);
		hasher.hashCharsTo128Bits(new String(input));

		hash64(hasher, input);
	}

	private static void hash64(Hasher64 hasher, byte[] input) {
		HashFunnel<byte[]> hashFunnel = (bytes, hashSink) -> hashSink.putBytes(bytes);
		hasher.hashToLong(input, hashFunnel);
		hasher.hashToLong(input, hashFunnel);

		hasher.hashBytesToLong(input);
		hasher.hashBytesToLong(input);
		hasher.hashCharsToLong(new String(input));

		hash32(hasher, input);
	}

	private static void hash32(Hasher32 hasher, byte[] input) {
		hasher.hashBytesToInt(input);
		hasher.hashBytesToInt(input);
		hasher.hashCharsToInt(new String(input));

		hash(hasher, input);
	}

	private static void hash(Hasher hasher, byte[] input) {
		HashStream stream = hasher.hashStream();
		stream.putBytes(input);

		if (input.length >= 1) {
			stream.putByte(input[0]);

			stream.putBoolean((input[0] & 1) == 1);
			stream.putBooleans(new boolean[] { (input[0] & 1) == 1 });
			stream.putBooleanArray(new boolean[] { (input[0] & 1) == 1 });

			stream.putChar((char)input[0]);
			stream.putChars(new char[] { (char)input[0] });
			stream.putCharArray(new char[] { (char)input[0] });

			if (input.length >= 4) {
				int i = input[0] + (input[1] << 8) + (input[1] << 16) + (input[1] << 24);
				stream.putInt(i);
				stream.putInts(new int[] { i });
				stream.putIntArray(new int[] { i });

				stream.putFloat(Float.intBitsToFloat(i));
				stream.putFloats(new float[] { Float.intBitsToFloat(i) });
				stream.putFloatArray(new float[] { Float.intBitsToFloat(i) });
			}

			if (input.length >= 8) {
				long l = input[0] + (input[1] << 8) + (input[2] << 16) + (input[3] << 24) +
						((long) input[4] << 32) + ((long) input[5] << 40) + ((long) input[6] << 48) + ((long) input[7] << 56);

				stream.putLong(l);
				stream.putLongs(new long[] { l });
				stream.putLongArray(new long[] { l });

				stream.putDouble(Double.longBitsToDouble(l));
				stream.putDoubles(new double[] { Double.longBitsToDouble(l) });
				stream.putDoubleArray(new double[] { Double.longBitsToDouble(l) });
			}

			stream.getAsInt();
			try {
				stream.getAsLong();
			} catch (UnsupportedOperationException e) {
				// expected here
			}
			try {
				stream.get();
			} catch (UnsupportedOperationException e) {
				// expected here
			}
			stream.getHashBitSize();
		}
	}
}
