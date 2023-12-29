package com.dynatrace.hash4j.fuzz;

import com.dynatrace.hash4j.hashing.HashFunnel;
import com.dynatrace.hash4j.hashing.HashStream32;
import com.dynatrace.hash4j.hashing.Hasher128;
import com.dynatrace.hash4j.hashing.Hasher32;
import com.dynatrace.hash4j.hashing.Hasher64;
import com.dynatrace.hash4j.hashing.Hashing;

import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;


/**
 * This class provides a simple target for fuzzing the hash4j package.
 *
 * It sends the input to all the hash-algorithms implemented by hash4j
 */
public class Fuzz {
	public static void fuzzerTestOneInput(byte[] input) {
		Hasher32 hasher32 = Hashing.murmur3_32();
		hash32(hasher32, input);

		Hasher128 hasher128 = Hashing.murmur3_128();
		hash128(hasher128, input);

		Hasher64 komihash4_64Long = Hashing.komihash4_3();
		hash64(komihash4_64Long, input);

		Hasher64 komihash5_64Long = Hashing.komihash5_0();
		hash64(komihash5_64Long, input);

		Hasher64 wyhashFinal3 = Hashing.wyhashFinal3();
		hash64(wyhashFinal3, input);

		Hasher64 wyhashFinal4 = Hashing.wyhashFinal4();
		hash64(wyhashFinal4, input);

		Hasher64 farmHash = Hashing.farmHashNa();
		hash64(farmHash, input);

		Hasher64 polymurHash = Hashing.polymurHash2_0(1, 2);
		hash64(polymurHash, input);
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

	private static void hash(Hasher32 hasher, byte[] input) {
		HashStream32 stream = hasher.hashStream();
		stream.putBytes(input);

		HashFunnel<byte[]> hashFunnel = (bytes, hashSink) -> hashSink.putBytes(bytes);
		stream.putNullable(input, hashFunnel);

		if (input.length >= 1) {
			stream.putByte(input[0]);

			boolean b = (input[0] & 1) == 1;
			stream.putBoolean(b);
			stream.putBooleans(new boolean[] {b});
			stream.putBooleanArray(new boolean[] {b});

			stream.putChar((char)input[0]);
			stream.putChars(new char[] { (char)input[0] });
			stream.putCharArray(new char[] { (char)input[0] });

			stream.putString(new String(input));

			if (input.length >= 2) {
				short s = (short) (input[0] + (input[1] << 8));
				stream.putShort(s);
				stream.putShorts(new short[] { s });
				stream.putShortArray(new short[] { s });
			}

			if (input.length >= 4) {
				int i = input[0] + (input[1] << 8) + (input[1] << 16) + (input[1] << 24);
				stream.putInt(i);
				stream.putInts(new int[] { i });
				stream.putIntArray(new int[] { i });
				stream.putOptionalInt(OptionalInt.of(i));

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
				stream.putOptionalLong(OptionalLong.of(l));

				double d = Double.longBitsToDouble(l);
				stream.putDouble(d);
				stream.putDoubles(new double[] {d});
				stream.putDoubleArray(new double[] {d});
				stream.putOptionalDouble(OptionalDouble.of(d));
			}

			stream.getAsInt();
			try {
				stream.getAsInt();
			} catch (UnsupportedOperationException e) {
				// expected here
			}
			stream.getHashBitSize();
		}
	}
}
